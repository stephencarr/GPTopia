"""Private stdio boundary: never bind a socket, log tokens, or accept principal JSON.

The only production entry uses the existing provider-backed JWT verifier. Tests
inject generated RSA keys in-process; no fixture credential mode exists here.
"""
import json
import os
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from identity import Principal
from kernel import Kernel, SCHEMA, name
from production import JWTVerifier, validate_admissions


class Boundary:
    def __init__(self, db_path, verifier=None, admissions=None, deadline=0):
        admissions = validate_admissions({} if admissions is None else admissions)
        self.verifier, self.deadline = verifier, deadline
        if deadline and not time.time() < deadline <= time.time() + 7 * 86400:
            raise ValueError('pilot deadline must be within seven days')
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.kernel = Kernel(db_path, max_mutations=100, max_objects=10, allow_fixture=False)
        with self.kernel.connection() as db:
            db.executescript(SCHEMA)
            db.execute('CREATE TABLE IF NOT EXISTS request_budget (id INTEGER PRIMARY KEY CHECK(id=1), used INTEGER NOT NULL)')
            db.execute('INSERT OR IGNORE INTO request_budget VALUES (1,0)')
            for grant in (admissions or {}).values():
                actor = name(grant['actor'], 'actor')
                db.execute('INSERT OR IGNORE INTO identities VALUES (?,?)', (actor, '[]'))
                for space in grant['spaces']:
                    db.execute('INSERT OR IGNORE INTO members VALUES (?,?)', (name(space, 'space'), actor))
            db.commit()

    def handle(self, message):
        if message.get('action') == 'health':
            return {'status': 200}
        if not self.verifier:
            return {'status': 401}
        if not time.time() < self.deadline:
            return {'status': 403}
        try:
            token = message['token']
            if not isinstance(token, str) or not 0 < len(token) <= 8192:
                return {'status': 401}
            principal = self.verifier(token)
            if not isinstance(principal, Principal) or principal.assurance != 'verified':
                return {'status': 401}
        except Exception:
            return {'status': 401}
        if message.get('action') == 'authenticate':
            return {'status': 200, 'scopes': sorted(principal.scopes)}
        if message.get('action') != 'call':
            return {'status': 400}
        with self.kernel.connection() as db:
            changed = db.execute('UPDATE request_budget SET used=used+1 WHERE id=1 AND used<10000').rowcount
            db.commit()
        if not changed:
            return {'status': 429}
        return {'status': 200, 'result': self.kernel.request(principal, message.get('payload'))}


def from_env():
    resource, issuer = os.getenv('GPTOPIA_RESOURCE'), os.getenv('GPTOPIA_ISSUER')
    grants = json.loads(os.getenv('GPTOPIA_ADMISSIONS', '{}'))
    deadline = float(os.getenv('GPTOPIA_DEADLINE', '0'))
    verifier = None
    if os.getenv('GPTOPIA_JWKS_URL'):
        if not resource or not issuer or not grants or not deadline:
            raise ValueError('incomplete authentication configuration')
        verifier = JWTVerifier(issuer, resource, os.environ['GPTOPIA_JWKS_URL'], grants)
    return Boundary(os.getenv('GPTOPIA_DB', '/tmp/gptopia-mcp/world.sqlite3'), verifier, grants, deadline)


def serve(boundary):
    for line in sys.stdin:
        try:
            if len(line.encode('utf-8')) > 65536:
                response = {'status': 413}
            else:
                response = boundary.handle(json.loads(line))
        except Exception:
            response = {'status': 503}
        print(json.dumps(response, ensure_ascii=True), flush=True)


if __name__ == '__main__':
    serve(from_env())
