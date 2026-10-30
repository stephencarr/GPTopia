"""Local-only durable admission prototype. No public approval/enrollment endpoint.

Approval is an operator capability, not authenticated by this module. Never expose
approve/revoke/inspect to participant tools. JWT verification stays in production.
"""
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from identity import AuthenticationError, Principal, AUDIENCE


class AdmissionDenied(AuthenticationError):
    """Safe category for an already signature-verified caller; no record contents."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class AdmissionStore:
    def __init__(self, path, *, owner_issuer, owner_subject, roots, deadline):
        from production import https_url, bounded_text
        https_url(owner_issuer)
        if not bounded_text(owner_subject) or not isinstance(roots, frozenset) or not roots:
            raise ValueError('explicit operator owner and root ceiling required')
        from kernel import IDENT
        if any(not isinstance(r, str) or not IDENT.fullmatch(r) for r in roots):
            raise ValueError('invalid root ceiling')
        if type(deadline) not in (float, int) or not time.time() < deadline <= time.time()+7*86400:
            raise ValueError('original finite pilot deadline required')
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.owner = (owner_issuer, owner_subject)
        self.roots, self.deadline = roots, deadline
        from kernel import initialize_schema
        with self.connect() as db:
            initialize_schema(db)
            db.executescript('''
            CREATE TABLE IF NOT EXISTS onboarding_policy (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), policy TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS durable_admissions (
                grant_id TEXT PRIMARY KEY, actor TEXT UNIQUE NOT NULL,
                issuer TEXT NOT NULL, subject TEXT NOT NULL, client_id TEXT NOT NULL,
                grant_json TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('approved','active','revoked')),
                approved_at REAL NOT NULL, activated_at REAL, revoked_at REAL,
                UNIQUE(issuer, subject, client_id));
            CREATE TABLE IF NOT EXISTS admission_audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, grant_id TEXT NOT NULL,
                action TEXT NOT NULL, at REAL NOT NULL);
            CREATE TRIGGER IF NOT EXISTS durable_binding_immutable BEFORE UPDATE OF
              grant_id,actor,issuer,subject,client_id,grant_json ON durable_admissions
              BEGIN SELECT RAISE(ABORT,'immutable approved binding'); END;
            CREATE TRIGGER IF NOT EXISTS durable_no_delete BEFORE DELETE ON durable_admissions
              BEGIN SELECT RAISE(ABORT,'admission records cannot be deleted'); END;
            CREATE TRIGGER IF NOT EXISTS durable_revocation_terminal BEFORE UPDATE OF state ON durable_admissions
              WHEN OLD.state='revoked' AND NEW.state!='revoked'
              BEGIN SELECT RAISE(ABORT,'revocation is terminal'); END;
            ''')
            policy = json.dumps([owner_issuer, owner_subject, sorted(roots), deadline], separators=(',',':'))
            db.execute('INSERT OR IGNORE INTO onboarding_policy VALUES (1,?)', (policy,))
            if db.execute('SELECT policy FROM onboarding_policy').fetchone()[0] != policy:
                raise ValueError('persisted owner/root/deadline policy cannot be changed')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def approve(self, grant_id, grant):
        """TRUSTED OPERATOR ONLY: persist reviewed consent, never accept peer input.

        No access token, client secret, or invitation bearer secret is created.
        Existing bindings are not imported automatically; exact explicit approval
        can adopt an existing matching immutable registry entry without rebinding.
        """
        from production import validate_admissions
        validate_admissions({grant_id: grant})
        if (grant['issuer'], grant['subject']) != self.owner:
            raise ValueError('owner mismatch')
        if not set(grant['spaces']) <= self.roots or grant['expires_at'] > self.deadline:
            raise ValueError('approval exceeds root or original deadline ceiling')
        encoded = json.dumps(grant, sort_keys=True, separators=(',',':'))
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM durable_admissions WHERE grant_id=?', (grant_id,)).fetchone()
            if row:
                if row['grant_json'] != encoded or row['state'] == 'revoked':
                    raise ValueError('approval conflict or revoked invitation')
                return self._summary(row)
            if db.execute('SELECT COUNT(*) FROM durable_admissions').fetchone()[0] >= 10:
                raise ValueError('lifetime admission quota exceeded')
            # Check historical registry before reserving an invitation.
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='admission_bindings'").fetchone():
                old = db.execute('SELECT * FROM admission_bindings WHERE grant_id=? OR actor=? OR (issuer=? AND subject=? AND client_id=?)',
                                 (grant_id,grant['actor'],grant['issuer'],grant['subject'],grant['client_id'])).fetchall()
                expected = (grant_id,grant['actor'],grant['issuer'],grant['subject'],grant['client_id'],grant['control_domain'])
                if old and (len(old)!=1 or tuple(old[0])!=expected):
                    raise ValueError('historical binding conflict')
            db.execute('INSERT INTO durable_admissions VALUES (?,?,?,?,?,?,?, ?,NULL,NULL)',
                       (grant_id,grant['actor'],grant['issuer'],grant['subject'],grant['client_id'],encoded,'approved',time.time()))
            db.execute('INSERT INTO admission_audit(grant_id,action,at) VALUES (?,?,?)',(grant_id,'approved',time.time()))
            return self._summary(db.execute('SELECT * FROM durable_admissions WHERE grant_id=?',(grant_id,)).fetchone())

    def resolve(self, claims):
        """Only JWTVerifier may pass signature-validated claims here.

        This is a trusted injection seam, NOT a token or arbitrary-JSON verifier.
        """
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM durable_admissions WHERE issuer=? AND subject=? AND client_id=?',
                             (claims['iss'],claims['sub'],claims['azp'])).fetchone()
            if not row:
                raise AdmissionDenied('admission_required')
            grant = json.loads(row['grant_json'])
            self._live(row, grant)
            if row['state']=='approved':
                # register_admissions is deliberately not called: it commits. The
                # registry, membership and activation must share this transaction.
                self._activate(db, row, grant)
            return Principal(grant['actor'],claims['iss'],claims['sub'],grant['control_domain'],
                             frozenset(grant['spaces']),frozenset(claims['scope'].split()) & frozenset(grant['scopes']),
                             AUDIENCE,min(claims['exp'],grant['expires_at'],self.deadline),assurance='verified',
                             client_id=claims['azp'],grant_id=row['grant_id'])

    @staticmethod
    def _activate(db, row, grant):
        db.execute('CREATE TABLE IF NOT EXISTS admission_bindings (grant_id TEXT PRIMARY KEY,actor TEXT NOT NULL UNIQUE,issuer TEXT NOT NULL,subject TEXT NOT NULL,client_id TEXT NOT NULL,control_domain TEXT NOT NULL,UNIQUE(issuer,subject,client_id))')
        for sql in ["CREATE TRIGGER IF NOT EXISTS admission_binding_no_update BEFORE UPDATE ON admission_bindings BEGIN SELECT RAISE(ABORT,'immutable admission binding'); END", "CREATE TRIGGER IF NOT EXISTS admission_binding_no_delete BEFORE DELETE ON admission_bindings BEGIN SELECT RAISE(ABORT,'immutable admission binding'); END"]:
            db.execute(sql)
        expected=(row['grant_id'],grant['actor'],grant['issuer'],grant['subject'],grant['client_id'],grant['control_domain'])
        old=db.execute('SELECT * FROM admission_bindings WHERE grant_id=?',(row['grant_id'],)).fetchone()
        if old is not None and tuple(old)!=expected:
            raise AdmissionDenied('binding_conflict')
        if old is None:
            if db.execute('SELECT 1 FROM identities WHERE id=?',(grant['actor'],)).fetchone():
                raise AdmissionDenied('binding_conflict')
            db.execute('INSERT INTO admission_bindings VALUES (?,?,?,?,?,?)',expected)
        db.execute('INSERT OR IGNORE INTO identities VALUES (?,?)',(grant['actor'],'[]'))
        for space in grant['spaces']:
            db.execute('INSERT OR IGNORE INTO members VALUES (?,?)',(space,grant['actor']))
        db.execute("UPDATE durable_admissions SET state='active',activated_at=? WHERE grant_id=?",(time.time(),row['grant_id']))
        db.execute('INSERT INTO admission_audit(grant_id,action,at) VALUES (?,?,?)',(row['grant_id'],'activated',time.time()))

    def _live(self, row, grant):
        if row['state']=='revoked':
            raise AdmissionDenied('admission_revoked')
        if time.time() >= min(grant['expires_at'],self.deadline):
            raise AdmissionDenied('admission_expired')

    def revoke(self, grant_id):
        """TRUSTED OPERATOR ONLY. Terminal; no restart or token expiry needed."""
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            changed=db.execute("UPDATE durable_admissions SET state='revoked',revoked_at=? WHERE grant_id=? AND state!='revoked'",(time.time(),grant_id)).rowcount
            if changed:
                db.execute('INSERT INTO admission_audit(grant_id,action,at) VALUES (?,?,?)',(grant_id,'revoked',time.time()))
            return bool(changed)

    def self_test(self, verifier, token, *, requested_scopes=('world:discover',)):
        """Local bootstrap diagnostic; token stays in memory, never echoed.

        The supplied verifier must be the approved JWTVerifier for this store.
        This calls verification (and may activate an approved invitation), not a
        world write. No token probe can enroll an unapproved owner or client.
        """
        from production import JWTVerifier
        from identity import SCOPES
        if not isinstance(verifier, JWTVerifier) or verifier.admission_store is not self:
            raise ValueError('this store requires its configured JWT verifier')
        if not isinstance(requested_scopes, (list, tuple)) or any(s not in SCOPES.values() for s in requested_scopes):
            raise ValueError('known requested scopes required')
        try:
            principal = verifier(token)
        except AdmissionDenied as exc:
            return {'ready': False, 'code': exc.code, 'next_action': 'request_owner_review'}
        except AuthenticationError:
            return {'ready': False, 'code': 'invalid_credentials', 'next_action': 'use_host_oauth_login'}
        # Re-read after verification: do not return a cached pre-revocation view.
        with self.connect() as db:
            row = db.execute('SELECT * FROM durable_admissions WHERE grant_id=?', (principal.grant_id,)).fetchone()
            grant = json.loads(row['grant_json'])
            try:
                self._live(row, grant)
            except AdmissionDenied as exc:
                return {'ready': False, 'code': exc.code, 'next_action': 'request_owner_review'}
            missing = sorted(set(requested_scopes) - principal.scopes)
            return {'ready': not missing, 'code': 'permission_missing' if missing else 'ready',
                    'actor': principal.actor, 'authorized_spaces': sorted(principal.spaces),
                    'effective_scopes': sorted(principal.scopes),
                    'available_operations': sorted(op for op, scope in SCOPES.items() if scope in principal.scopes),
                    'missing_requested_scopes': missing, 'expires_at': principal.expires_at,
                    'next_action': 'request_scope_review_not_repeated_login' if missing else 'discover_authorized_space'}

    @staticmethod
    def _summary(row):
        return {'grant_id':row['grant_id'],'actor':row['actor'],'state':row['state'],
                'approved_at':row['approved_at'],'activated_at':row['activated_at'],'revoked_at':row['revoked_at']}

    def inspect(self, grant_id):
        """TRUSTED OPERATOR ONLY; not an identity enumeration API."""
        with self.connect() as db:
            row=db.execute('SELECT * FROM durable_admissions WHERE grant_id=?',(grant_id,)).fetchone()
            if not row:return None
            result=self._summary(row)
            grant=json.loads(row['grant_json'])
            result['effective_state']='expired' if row['state']!='revoked' and time.time()>=min(grant['expires_at'],self.deadline) else row['state']
            return result


def enforce_current(db, principal, op, space):
    """Called inside kernel BEGIN IMMEDIATE: revocation serializes with writes.

    Presence of this table opts the DB into durable mode; missing rows fail closed.
    A request already committed before revoke is not retroactively erased.
    """
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='durable_admissions'").fetchone():
        return
    from kernel import Fault
    from identity import SCOPES
    row=db.execute('SELECT * FROM durable_admissions WHERE grant_id=?',(principal.grant_id,)).fetchone()
    if row is None or row['state']!='active':
        raise Fault('forbidden','admission_inactive')
    grant=json.loads(row['grant_json'])
    expected=(grant['actor'],grant['issuer'],grant['subject'],grant['client_id'],grant['control_domain'])
    actual=(principal.actor,principal.issuer,principal.subject,principal.client_id,principal.control_domain)
    if actual!=expected:
        raise Fault('forbidden','binding_mismatch')
    policy=json.loads(db.execute('SELECT policy FROM onboarding_policy WHERE singleton=1').fetchone()[0])
    if time.time()>=min(grant['expires_at'],policy[3]):
        raise Fault('forbidden','admission_expired')
    if space not in grant['spaces'] or SCOPES.get(op) not in grant['scopes']:
        raise Fault('forbidden','admission_permission_missing')
