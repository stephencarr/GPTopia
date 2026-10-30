"""Deny-by-default HTTPS resource boundary. Not an MCP implementation or OAuth issuer."""
import asyncio
import json
import os
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlsplit

import jwt
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from identity import AUDIENCE, AuthenticationError, Principal, SCOPES
from kernel import Kernel, MAX_BODY, SCHEMA


def https_url(value):
    p = urlsplit(value)
    if p.scheme != 'https' or not p.hostname or p.username or p.password or p.query or p.fragment:
        raise ValueError('canonical HTTPS URL required')
    return value


class JWTVerifier:
    """Only approved issuer keys and operator-maintained admission grant trusted.

    No token issuance, dynamic issuer discovery, payload-selected URLs, fixture
    credentials or custom cryptography. Revocation: remove admission/redeploy;
    access token lifetime capped at one hour; grant expiry capped externally.
    """
    def __init__(self, issuer, resource, jwks_url, admissions, client_claim='azp', key_client=None):
        self.issuer, self.resource = https_url(issuer), https_url(resource)
        self.client_claim = client_claim
        self.admissions = admissions
        self.keys = key_client or jwt.PyJWKClient(https_url(jwks_url), cache_keys=False, lifespan=60, timeout=3)

    def __call__(self, token):
        try:
            key = self.keys.get_signing_key_from_jwt(token).key
            c = jwt.decode(token, key, algorithms=['RS256'], audience=self.resource, issuer=self.issuer,
                           options={'require': ['exp', 'iat', 'iss', 'sub', 'aud']})
            now = time.time()
            if not isinstance(c['iat'], (int, float)) or not isinstance(c['exp'], (int, float)) or c['exp'] - c['iat'] > 3600:
                raise ValueError('token lifetime')
            if not isinstance(c.get('scope'), str):
                raise ValueError('scope')
            grant = self.admissions.get(c['sub'])
            if not grant or c.get(self.client_claim) != grant['client_id'] or not now < grant['expires_at']:
                raise ValueError('not admitted')
            return Principal(grant['actor'], self.issuer, c['sub'], grant['control_domain'],
                             frozenset(grant['spaces']), frozenset(c['scope'].split()) & frozenset(grant['scopes']),
                             AUDIENCE, min(c['exp'], grant['expires_at']), assurance='verified')
        except Exception:
            raise AuthenticationError('invalid credentials') from None


def create_app(db_path, resource=None, issuer=None, verifier=None, admissions=None, deadline=0):
    """No verifier/deadline means all application routes deny, health stays live."""
    admissions = admissions or {}
    if resource:
        https_url(resource)
    if issuer:
        https_url(issuer)
    if deadline and (not time.time() < deadline <= time.time() + 7*86400):
        raise ValueError('pilot deadline must be within seven days')
    kernel = Kernel(db_path, max_mutations=100, max_objects=10, allow_fixture=False)
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with kernel.connection() as db:
        db.executescript(SCHEMA)
        db.execute('CREATE TABLE IF NOT EXISTS request_budget (id INTEGER PRIMARY KEY CHECK(id=1), used INTEGER NOT NULL)')
        db.execute('INSERT OR IGNORE INTO request_budget VALUES (1,0)')
        for grant in admissions.values():
            # Admission is operator configuration, never client JSON.
            from kernel import name
            actor = name(grant['actor'], 'actor')
            db.execute('INSERT OR IGNORE INTO identities VALUES (?,?)', (actor, '[]'))
            for space in grant['spaces']:
                db.execute('INSERT OR IGNORE INTO members VALUES (?,?)', (name(space, 'space'), actor))
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
            return JSONResponse({'resource': resource, 'authorization_servers': [issuer], 'scopes_supported': sorted(set(SCOPES.values()))})
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
        status = 200 if result['ok'] else {'unauthenticated':401, 'forbidden':403, 'not_found':404, 'conflict':409, 'quota':429}.get(result['error']['code'],400)
        return JSONResponse(result, status_code=status, headers={'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff'})

    return Starlette(routes=[Route('/{path:path}', dispatch, methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'])])


def from_env():
    resource, issuer = os.getenv('GPTOPIA_RESOURCE'), os.getenv('GPTOPIA_ISSUER')
    grants = json.loads(os.getenv('GPTOPIA_ADMISSIONS', '{}'))
    deadline = float(os.getenv('GPTOPIA_DEADLINE', '0'))
    verifier = None
    if os.getenv('GPTOPIA_JWKS_URL'):
        if not resource or not issuer or not grants or not deadline:
            raise ValueError('incomplete authentication configuration')
        verifier = JWTVerifier(issuer, resource, os.environ['GPTOPIA_JWKS_URL'], grants)
    return create_app(os.getenv('GPTOPIA_DB', '/data/world.sqlite3'), resource, issuer, verifier, grants, deadline)
