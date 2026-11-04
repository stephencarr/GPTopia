"""Deny-by-default HTTPS resource boundary. Not an MCP implementation or OAuth issuer."""
import asyncio
import json
import math
import os
import sqlite3
import time
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlsplit

import jwt
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from identity import AUDIENCE, AuthenticationError, Principal, SCOPES
from kernel import Kernel, MAX_BODY, initialize_schema


def bounded_text(value, maximum=200):
    return isinstance(value, str) and 0 < len(value) <= maximum and not any(ord(c) <= 32 or ord(c) == 127 for c in value)


def https_url(value):
    if not bounded_text(value, 2048):
        raise ValueError('canonical HTTPS URL required')
    p = urlsplit(value)
    if (p.scheme != 'https' or not p.hostname or p.username or p.password
            or p.query or p.fragment or '\\' in value or p.port == 0):
        raise ValueError('canonical HTTPS URL required')
    return value


def resource_origin(value):
    https_url(value)
    p = urlsplit(value)
    if p.path or value != 'https://' + p.netloc:
        raise ValueError('resource must be an HTTPS origin without path or trailing slash')
    return value


def validate_admissions(admissions):
    """Validate trusted configuration before any database initialization or serving."""
    from kernel import IDENT
    if not isinstance(admissions, dict) or len(admissions) > 10:
        raise ValueError('admissions must be a bounded grant-ID mapping')
    actors, bindings = set(), set()
    now = time.time()
    for grant_id, grant in admissions.items():
        if not isinstance(grant_id, str) or not IDENT.fullmatch(grant_id) or not isinstance(grant, dict):
            raise ValueError('invalid admission grant ID or grant')
        if set(grant) != {'issuer', 'subject', 'client_id', 'actor', 'control_domain', 'spaces', 'scopes', 'expires_at'}:
            raise ValueError('explicit issuer/subject/client grant binding required')
        if not bounded_text(grant.get('issuer')) or not bounded_text(grant.get('subject')):
            raise ValueError('invalid admission owner binding')
        https_url(grant['issuer'])
        for field in ['actor', 'control_domain', 'client_id']:
            if not bounded_text(grant.get(field)):
                raise ValueError('invalid admission identity binding')
        if not IDENT.fullmatch(grant['actor']) or grant['actor'] in actors:
            raise ValueError('invalid or duplicate actor')
        actors.add(grant['actor'])
        binding = (grant['issuer'], grant['subject'], grant['client_id'])
        if binding in bindings:
            raise ValueError('duplicate issuer/subject/client binding')
        bindings.add(binding)
        for field in ['spaces', 'scopes']:
            values = grant.get(field)
            if (not isinstance(values, list) or not 0 < len(values) <= 20
                    or not all(bounded_text(v) for v in values) or len(values) != len(set(values))):
                raise ValueError('invalid admission scope list')
        if any(not IDENT.fullmatch(v) for v in grant['spaces']) or not set(grant['scopes']) <= set(SCOPES.values()):
            raise ValueError('unknown scopes or malformed spaces')
        expiry = grant.get('expires_at')
        if type(expiry) not in (int, float) or not math.isfinite(expiry) or not now < expiry <= now + 7*86400:
            raise ValueError('admission expiry must be within seven days')
    return admissions


def register_admissions(db, admissions):
    """Local operator registry: never silently reassign a historical actor or grant."""
    validate_admissions(admissions)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS admission_bindings (
      grant_id TEXT PRIMARY KEY, actor TEXT NOT NULL UNIQUE, issuer TEXT NOT NULL,
      subject TEXT NOT NULL, client_id TEXT NOT NULL, control_domain TEXT NOT NULL,
      UNIQUE(issuer,subject,client_id));
    CREATE TRIGGER IF NOT EXISTS admission_binding_no_update BEFORE UPDATE ON admission_bindings
      BEGIN SELECT RAISE(ABORT,'immutable admission binding'); END;
    CREATE TRIGGER IF NOT EXISTS admission_binding_no_delete BEFORE DELETE ON admission_bindings
      BEGIN SELECT RAISE(ABORT,'immutable admission binding'); END;
    """)
    db.execute('BEGIN IMMEDIATE')
    try:
        for gid, grant in admissions.items():
            values = (gid, grant['actor'], grant['issuer'], grant['subject'], grant['client_id'], grant['control_domain'])
            previous = db.execute('SELECT grant_id,actor,issuer,subject,client_id,control_domain FROM admission_bindings WHERE grant_id=?', (gid,)).fetchone()
            if previous is not None:
                if tuple(previous) != values:
                    raise ValueError('admission grant rebinding forbidden')
            else:
                if db.execute('SELECT 1 FROM identities WHERE id=?', (grant['actor'],)).fetchone():
                    raise ValueError('existing actor has no matching immutable admission binding')
                db.execute('INSERT INTO admission_bindings VALUES (?,?,?,?,?,?)', values)
            db.execute('INSERT OR IGNORE INTO identities VALUES (?,?)', (grant['actor'], '[]'))
            for space in grant['spaces']:
                db.execute('INSERT OR IGNORE INTO members VALUES (?,?)', (space, grant['actor']))
        db.commit()
    except Exception:
        db.rollback()
        raise


class JWTVerifier:
    """Only approved issuer keys and operator-maintained admission grant trusted.

    No token issuance, dynamic issuer discovery, payload-selected URLs, fixture
    credentials or custom cryptography. Revocation: remove admission/redeploy;
    access token lifetime capped at one hour; grant expiry capped externally.
    """
    def __init__(self, issuer, resource, jwks_url, admissions, client_claim='azp', key_client=None):
        self.issuer, self.resource = https_url(issuer), resource_origin(resource)
        https_url(jwks_url)
        if client_claim != 'azp':
            raise ValueError('only Auth0 default access-token profile signed azp is supported')
        validated = validate_admissions(admissions)
        if any(g['issuer'] != self.issuer for g in validated.values()):
            raise ValueError('admission issuer differs from configured issuer')
        # Freeze a detached snapshot; configuration changes require reviewed restart.
        self.admissions = MappingProxyType({gid: MappingProxyType({k: tuple(v) if isinstance(v, list) else v
                                       for k, v in g.items()}) for gid, g in validated.items()})
        self.bindings = MappingProxyType({(g['issuer'], g['subject'], g['client_id']): (gid, g)
                                         for gid, g in self.admissions.items()})
        self.keys = key_client or jwt.PyJWKClient(https_url(jwks_url), cache_keys=False, lifespan=60, timeout=3)

    def __call__(self, token):
        try:
            key = self.keys.get_signing_key_from_jwt(token).key
            c = jwt.decode(token, key, algorithms=['RS256'], audience=self.resource, issuer=self.issuer,
                           options={'require': ['exp', 'iat', 'iss', 'sub', 'aud', 'azp']})
            now = time.time()
            if (type(c['iat']) not in (int, float) or type(c['exp']) not in (int, float)
                    or not math.isfinite(c['iat']) or not math.isfinite(c['exp']) or not 0 < c['exp'] - c['iat'] <= 3600):
                raise ValueError('token lifetime')
            if not isinstance(c.get('scope'), str):
                raise ValueError('scope')
            if not bounded_text(c.get('sub')) or not bounded_text(c.get('azp')):
                raise ValueError('missing owner/client binding')
            match = self.bindings.get((c['iss'], c['sub'], c['azp']))
            if not match:
                raise ValueError('not admitted')
            grant_id, grant = match
            if not now < grant['expires_at']:
                raise ValueError('not admitted')
            return Principal(grant['actor'], self.issuer, c['sub'], grant['control_domain'],
                             frozenset(grant['spaces']), frozenset(c['scope'].split()) & frozenset(grant['scopes']),
                             AUDIENCE, min(c['exp'], grant['expires_at']), assurance='verified',
                             client_id=c['azp'], grant_id=grant_id)
        except Exception:
            raise AuthenticationError('invalid credentials') from None


READ_ONLY_SCOPES = ('events:read', 'messages:read', 'objects:read', 'world:discover')


def advertised_scope_list(value=None):
    """Discovery hint only; never consumed by token verification or admissions."""
    if value is None:
        return list(READ_ONLY_SCOPES)
    if (not isinstance(value, list) or any(not isinstance(s, str) or s not in SCOPES.values() for s in value)
            or len(value) != len(set(value))):
        raise ValueError('invalid advertised scopes')
    return sorted(value)


def advertised_scopes_from_env():
    if 'GPTOPIA_ADVERTISED_SCOPES' not in os.environ:
        return advertised_scope_list()
    value = json.loads(os.environ['GPTOPIA_ADVERTISED_SCOPES'])
    if value is None:
        raise ValueError('invalid advertised scopes')
    return advertised_scope_list(value)


def create_app(db_path, resource=None, issuer=None, verifier=None, admissions=None, deadline=0, advertised_scopes=None):
    """No verifier/deadline means all application routes deny, health stays live."""
    advertised_scopes = advertised_scope_list(advertised_scopes)
    admissions = validate_admissions({} if admissions is None else admissions)
    if resource is not None:
        resource_origin(resource)
    if issuer is not None:
        https_url(issuer)
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ValueError('invalid pilot deadline')
    if deadline and (not time.time() < deadline <= time.time() + 7*86400):
        raise ValueError('pilot deadline must be within seven days')
    kernel = Kernel(db_path, max_mutations=100, max_objects=10, allow_fixture=False)
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with kernel.connection() as db:
        initialize_schema(db)
        register_admissions(db, admissions)
        db.execute('CREATE TABLE IF NOT EXISTS request_budget (id INTEGER PRIMARY KEY CHECK(id=1), used INTEGER NOT NULL)')
        db.execute('INSERT OR IGNORE INTO request_budget VALUES (1,0)')
        db.commit()
    lock = asyncio.Lock()
    auth_window = [time.monotonic(), 0]

    def reply(status, code):
        headers = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'}
        if status == 401:
            headers['WWW-Authenticate'] = 'Bearer' + (f' resource_metadata="{resource}/.well-known/oauth-protected-resource"' if resource else '')
        return JSONResponse({'ok': False, 'error': {'code': code}}, status_code=status, headers=headers)

    async def dispatch(request: Request):
        if request.url.path == '/healthz' and request.method == 'GET':
            return JSONResponse({'status': 'ok'}, headers={'Cache-Control': 'no-store'})
        if request.url.path == '/.well-known/oauth-protected-resource' and request.method == 'GET' and resource and issuer:
            return JSONResponse({'resource': resource, 'authorization_servers': [issuer], 'scopes_supported': advertised_scopes})
        # Closed pilots do not perform token verification or outbound JWKS work.
        if deadline and not time.time() < deadline:
            return reply(403, 'pilot_closed')
        # Authenticate before path routing, payload read or database writes.
        if request.headers.get('origin') or request.headers.get('x-test-actor'):
            return reply(401, 'unauthenticated')
        if resource and request.headers.get('host') != urlsplit(resource).netloc:
            return reply(400, 'invalid_host')
        # Global bounded verification budget: prevents attacker-controlled JWKS
        # refresh storms. Pilot throughput deliberately tiny; no per-IP trust.
        if time.monotonic() - auth_window[0] >= 60:
            auth_window[:] = [time.monotonic(), 0]
        auth_window[1] += 1
        if auth_window[1] > 60:
            return reply(429, 'rate_limited')
        auth = request.headers.getlist('authorization')
        if not verifier or len(auth) != 1 or not auth[0].startswith('Bearer ') or len(auth[0]) > 8192:
            return reply(401, 'unauthenticated')
        try:
            principal = await asyncio.to_thread(verifier, auth[0][7:])
            if not isinstance(principal, Principal) or principal.assurance != 'verified':
                raise AuthenticationError()
            principal = replace(principal, expires_at=min(principal.expires_at, deadline))
        except Exception:
            return reply(401, 'unauthenticated')
        if not time.time() < deadline:
            return reply(403, 'pilot_closed')
        if request.url.path != '/v1' or request.method != 'POST':
            return reply(404, 'not_found')
        if request.headers.get('content-type', '').split(';')[0] != 'application/json':
            return reply(415, 'json_required')
        try:
            body = bytearray()
            async with asyncio.timeout(5):
                async for chunk in request.stream():
                    body.extend(chunk)
                    if len(body) > MAX_BODY:
                        return reply(413, 'body_too_large')
            payload = json.loads(body, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (ValueError, UnicodeError, RecursionError, TimeoutError):
            return reply(400, 'invalid')
        def execute():
            # Streaming a body or waiting for the execution lock can cross the
            # cutoff after authentication. Do not start application work then.
            if not time.time() < deadline:
                return {'ok': False, 'error': {'code': 'pilot_closed', 'message': 'pilot closed'}}
            with kernel.connection() as db:
                changed = db.execute('UPDATE request_budget SET used=used+1 WHERE id=1 AND used<10000').rowcount
                db.commit()
            if not changed:
                return {'ok': False, 'error': {'code': 'quota'}}
            return kernel.request(principal, payload)
        try:
            async with lock:
                result = await asyncio.to_thread(execute)
        except sqlite3.Error:
            return reply(503, 'unavailable')
        status = 200 if result['ok'] else {'unauthenticated':401, 'forbidden':403, 'pilot_closed':403, 'not_found':404, 'conflict':409, 'quota':429}.get(result['error']['code'],400)
        return JSONResponse(result, status_code=status, headers={'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff'})

    return Starlette(routes=[Route('/{path:path}', dispatch, methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'])])


def from_env():
    advertised_scopes = advertised_scopes_from_env()
    resource, issuer = os.getenv('GPTOPIA_RESOURCE'), os.getenv('GPTOPIA_ISSUER')
    grants = json.loads(os.getenv('GPTOPIA_ADMISSIONS', '{}'))
    deadline = float(os.getenv('GPTOPIA_DEADLINE', '0'))
    verifier = None
    if os.getenv('GPTOPIA_JWKS_URL'):
        if not resource or not issuer or not grants or not deadline:
            raise ValueError('incomplete authentication configuration')
        verifier = JWTVerifier(issuer, resource, os.environ['GPTOPIA_JWKS_URL'], grants)
    return create_app(os.getenv('GPTOPIA_DB', '/data/world.sqlite3'), resource, issuer, verifier, grants, deadline,
                      advertised_scopes)
