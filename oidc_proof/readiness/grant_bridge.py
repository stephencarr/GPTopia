"""LOCAL V2 ADAPTER SEAM, not wired into any application/deployment.

Provider and admission resolvers must be authoritative, current and transactional
in production. This module does not implement them or any migration/reconnect UI.
"""
from dataclasses import dataclass
import math
import time
import jwt
from identity import AUDIENCE, AuthenticationError, Principal

@dataclass(frozen=True)
class ProviderGrant:
    issuer: str
    oauth_grant_id: str
    owner: str
    client_id: str
    scopes: frozenset
    active: bool
    expires_at: float

@dataclass(frozen=True)
class ApplicationAdmission:
    admission_id: str
    issuer: str
    oauth_grant_id: str
    owner: str
    client_id: str
    actor: str
    control_domain: str
    spaces: frozenset
    scopes: frozenset
    active: bool
    expires_at: float


def text(value):
    return isinstance(value, str) and 0 < len(value) <= 200 and not any(ord(c) <= 32 or ord(c) == 127 for c in value)


def future(value, now):
    return type(value) in (int, float) and math.isfinite(value) and value > now


class GrantBoundVerifier:
    """Explicit portable profile; never auto-selected as fallback from legacy auth.

    resolve_grant(issuer, oauth_grant_id) -> ProviderGrant | None
    resolve_admission(issuer, oauth_grant_id) -> ApplicationAdmission | None
    Resolvers throwing or returning stale/unknown/mismatched values deny access.
    No token-controlled URLs and no actor claims accepted.
    """
    def __init__(self, *, issuer, resource, key_client, resolve_grant, resolve_admission):
        self.issuer, self.resource = issuer, resource
        self.keys, self.grant, self.admission = key_client, resolve_grant, resolve_admission

    def __call__(self, token):
        try:
            key = self.keys.get_signing_key_from_jwt(token).key
            c = jwt.decode(token, key, algorithms=['RS256'], issuer=self.issuer,
                audience=self.resource, options={'require':['iss','aud','sub','client_id','gptopia_grant_id','iat','exp','scope']})
            now = time.time()
            if any(not text(c[k]) for k in ('iss','sub','client_id','gptopia_grant_id')):
                raise ValueError('malformed binding')
            if (not future(c['exp'], now) or type(c['iat']) not in (int,float)
                    or not math.isfinite(c['iat']) or not 0 < c['exp']-c['iat'] <= 3600
                    or not isinstance(c['scope'],str)):
                raise ValueError('claims')
            g = self.grant(self.issuer, c['gptopia_grant_id'])
            a = self.admission(self.issuer, c['gptopia_grant_id'])
            if not isinstance(g,ProviderGrant) or not isinstance(a,ApplicationAdmission):
                raise ValueError('unknown')
            expected = (self.issuer,c['gptopia_grant_id'],c['sub'],c['client_id'])
            if (g.issuer,g.oauth_grant_id,g.owner,g.client_id) != expected or (a.issuer,a.oauth_grant_id,a.owner,a.client_id) != expected:
                raise ValueError('binding mismatch')
            if g.active is not True or a.active is not True or not future(g.expires_at,now) or not future(a.expires_at,now):
                raise ValueError('inactive')
            if not all(text(v) for v in (a.admission_id,a.actor,a.control_domain)):
                raise ValueError('admission attribution')
            if any(not isinstance(v,frozenset) or not all(text(s) for s in v) for v in (a.spaces,a.scopes,g.scopes)):
                raise ValueError('admission scopes')
            return Principal(a.actor,self.issuer,a.owner,a.control_domain,a.spaces,
                frozenset(c['scope'].split()) & g.scopes & a.scopes,AUDIENCE,
                min(c['exp'],g.expires_at,a.expires_at),assurance='verified',
                client_id=a.client_id,grant_id=a.admission_id)
        except Exception:
            raise AuthenticationError('invalid grant-bound credentials') from None


class ProofBoundary:
    """Single-process proof coordinator, NOT durable or multi-process admission.

    Serializes local state changes and token verification + kernel operation.
    Never exports/reuses a cached Principal. A production implementation needs
    durable atomic state/revocation across provider and kernel processes.
    """
    def __init__(self, kernel, *, issuer, resource, key_client):
        from threading import RLock
        self.lock = RLock()
        self.kernel = kernel
        self._grants, self._admissions = {}, {}
        self.verifier = GrantBoundVerifier(issuer=issuer,resource=resource,key_client=key_client,
            resolve_grant=lambda iss,gid:self._grants.get((iss,gid)),
            resolve_admission=lambda iss,gid:self._admissions.get((iss,gid)))

    def initialize_fresh_registry(self, pairs):
        """Explicit V2 proof DB only. Refuses any pre-existing identity/registry."""
        from kernel import initialize_schema
        with self.lock, self.kernel.connection() as db:
            initialize_schema(db)
            if db.execute('SELECT count(*) FROM identities').fetchone()[0] or db.execute("SELECT 1 FROM sqlite_master WHERE name='admission_bindings'").fetchone():
                raise ValueError('fresh proof database required; legacy migration forbidden')
            db.executescript('''
                CREATE TABLE proof_binding_version(version INTEGER NOT NULL CHECK(version=2));
                INSERT INTO proof_binding_version VALUES(2);
                CREATE TABLE admission_bindings(grant_id TEXT PRIMARY KEY, actor TEXT NOT NULL UNIQUE,
                    issuer TEXT NOT NULL, subject TEXT NOT NULL, client_id TEXT NOT NULL, control_domain TEXT NOT NULL);
                CREATE TRIGGER admission_binding_no_update BEFORE UPDATE ON admission_bindings BEGIN SELECT RAISE(ABORT,'immutable admission binding'); END;
                CREATE TRIGGER admission_binding_no_delete BEFORE DELETE ON admission_bindings BEGIN SELECT RAISE(ABORT,'immutable admission binding'); END;
            ''')
            grants, admissions = {}, {}
            db.execute('BEGIN IMMEDIATE')
            try:
                for g,a in pairs:
                    key=(g.issuer,g.oauth_grant_id)
                    if key in grants or (a.issuer,a.oauth_grant_id,a.owner,a.client_id)!=(g.issuer,g.oauth_grant_id,g.owner,g.client_id):
                        raise ValueError('duplicate or mismatched grant binding')
                    db.execute('INSERT INTO admission_bindings VALUES(?,?,?,?,?,?)',
                        (a.admission_id,a.actor,a.issuer,a.owner,a.client_id,a.control_domain))
                    db.execute('INSERT INTO identities VALUES(?,?)',(a.actor,'[]'))
                    for space in a.spaces:
                        db.execute('INSERT INTO members VALUES(?,?)',(space,a.actor))
                    grants[key],admissions[key]=g,a
                db.commit()
            except Exception:
                db.rollback()
                raise
            self._grants,self._admissions=grants,admissions

    def revoke(self, issuer, oauth_grant_id):
        from dataclasses import replace
        with self.lock:
            key=(issuer,oauth_grant_id)
            self._grants[key]=replace(self._grants[key],active=False)

    def request(self, token, request):
        with self.lock:
            return self.kernel.request(self.verifier(token),request)
