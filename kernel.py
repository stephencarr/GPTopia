"""GPTopia kernel proof: local, deterministic, no participant code execution."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_BODY = 32768
MAX_CONTENT = 8192
DEFAULT_MUTATIONS = 1000
DEFAULT_OBJECTS = 100
IDENT = re.compile(r'^[a-zA-Z0-9_.:-]{1,80}$')
MUTATIONS = {'create', 'update', 'send'}

class Fault(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(message)

def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)

def name(value, field):
    if not isinstance(value, str) or not IDENT.fullmatch(value):
        raise Fault('invalid', f'{field} must be 1–80 identifier characters')
    return value

def content(value):
    try:
        valid = isinstance(value, str) and len(value.encode('utf-8')) <= MAX_CONTENT
    except UnicodeError:
        valid = False
    if not valid:
        raise Fault('invalid', f'content must be valid UTF-8 text of at most {MAX_CONTENT} bytes')
    return value

SCHEMA = '''
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS identities(id TEXT PRIMARY KEY, capabilities TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS members(space TEXT NOT NULL, actor TEXT NOT NULL REFERENCES identities(id), PRIMARY KEY(space,actor));
CREATE TABLE IF NOT EXISTS objects(id TEXT PRIMARY KEY, space TEXT NOT NULL, owner TEXT NOT NULL, version INTEGER NOT NULL, content TEXT NOT NULL, readers TEXT NOT NULL, writers TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS versions(object_id TEXT NOT NULL, version INTEGER NOT NULL, author TEXT NOT NULL, content TEXT NOT NULL, readers TEXT NOT NULL, writers TEXT NOT NULL, created REAL NOT NULL, PRIMARY KEY(object_id,version));
CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY, space TEXT NOT NULL, sender TEXT NOT NULL, recipient TEXT NOT NULL, content TEXT NOT NULL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, space TEXT NOT NULL, kind TEXT NOT NULL, actor TEXT NOT NULL, subject TEXT NOT NULL, version INTEGER, audience TEXT NOT NULL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS retries(actor TEXT NOT NULL, key TEXT NOT NULL, digest TEXT NOT NULL, response TEXT NOT NULL, PRIMARY KEY(actor,key));
CREATE TABLE IF NOT EXISTS usage(actor TEXT PRIMARY KEY, mutations INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, op TEXT, outcome TEXT NOT NULL, created REAL NOT NULL);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'append-only events'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'append-only events'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
'''

class Kernel:
    def __init__(self, path, max_mutations=DEFAULT_MUTATIONS, max_objects=DEFAULT_OBJECTS):
        self.path = str(path)
        self.max_mutations, self.max_objects = max_mutations, max_objects

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            yield db
        finally:
            db.close()

    def initialize(self):
        with self.connection() as db:
            db.executescript(SCHEMA)
            for actor, caps in [('alice', ['design']), ('bob', ['review']), ('eve', ['observe'])]:
                db.execute('INSERT OR IGNORE INTO identities VALUES (?,?)', (actor, encode(caps)))
            for space, actor in [('plaza', 'alice'), ('plaza', 'bob'), ('garden', 'alice'), ('outside', 'eve')]:
                db.execute('INSERT OR IGNORE INTO members VALUES (?,?)', (space, actor))
            db.commit()

    def member(self, db, space, actor):
        if not db.execute('SELECT 1 FROM members WHERE space=? AND actor=?', (space, actor)).fetchone():
            raise Fault('forbidden', 'space membership required')

    def obj(self, db, space, oid, actor, write=False):
        row = db.execute('SELECT * FROM objects WHERE id=? AND space=?', (oid, space)).fetchone()
        if not row or actor not in json.loads(row['writers' if write else 'readers']):
            raise Fault('not_found', 'object not found or inaccessible')
        return row

    def acl(self, db, space, args, owner):
        readers, writers = args.get('readers'), args.get('writers')
        for field, values in [('readers', readers), ('writers', writers)]:
            if not isinstance(values, list) or len(values) > 100 or any(not isinstance(x, str) for x in values):
                raise Fault('invalid', f'{field} must be an array of at most 100 identity IDs')
            for actor in values:
                self.member(db, space, name(actor, field))
        if owner not in writers or not set(writers) <= set(readers):
            raise Fault('invalid', 'owner must retain write access; writers must also be readers')
        return sorted(set(readers)), sorted(set(writers))

    def event(self, db, space, kind, actor, subject, audience, version=None):
        cur = db.execute('INSERT INTO events(space,kind,actor,subject,version,audience,created) VALUES (?,?,?,?,?,?,?)',
                         (space, kind, actor, subject, version, encode(audience), time.time()))
        return cur.lastrowid

    def record(self, row):
        result = dict(row)
        for key in ('readers', 'writers', 'capabilities'):
            if key in result:
                result[key] = json.loads(result[key])
        return result

    def request(self, actor, request):
        op = request.get('op') if isinstance(request, dict) else None
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                name(actor, 'actor')
                if not db.execute('SELECT 1 FROM identities WHERE id=?', (actor,)).fetchone():
                    raise Fault('forbidden', 'unknown test identity')
                if not isinstance(request, dict) or set(request) - {'op', 'args', 'idempotency_key'}:
                    raise Fault('invalid', 'request fields are op, args, idempotency_key')
                args = request.get('args', {})
                if not isinstance(args, dict):
                    raise Fault('invalid', 'args must be an object')
                if not isinstance(op, str) or op not in {'discover', 'get', 'history', 'events', 'inbox'} | MUTATIONS:
                    raise Fault('invalid', 'unknown operation')
                space = name(args.get('space'), 'space')
                self.member(db, space, actor)
                key = digest = None
                if op in MUTATIONS:
                    key = name(request.get('idempotency_key'), 'idempotency_key')
                    try:
                        digest = hashlib.sha256(encode(request).encode('utf-8')).hexdigest()
                    except (ValueError, TypeError, UnicodeError, RecursionError):
                        raise Fault('invalid', 'request must contain valid finite UTF-8 JSON')
                    prior = db.execute('SELECT * FROM retries WHERE actor=? AND key=?', (actor, key)).fetchone()
                    if prior:
                        if prior['digest'] != digest:
                            raise Fault('conflict', 'idempotency key reused with different request')
                        # Replays require current space membership, but return only the original
                        # mutation metadata (never object/message content), even after ACL revocation.
                        result = json.loads(prior['response'])
                        self.audit(db, actor, op, 'replay')
                        db.commit()
                        return result
                    used = db.execute('SELECT mutations FROM usage WHERE actor=?', (actor,)).fetchone()
                    if used and used[0] >= self.max_mutations:
                        raise Fault('quota', 'lifetime mutation quota exceeded')
                result = self.dispatch(db, actor, op, space, args)
                response = {'ok': True, 'result': result}
                if op in MUTATIONS:
                    db.execute('INSERT INTO retries VALUES (?,?,?,?)', (actor, key, digest, encode(response)))
                    db.execute('INSERT INTO usage VALUES (?,1) ON CONFLICT(actor) DO UPDATE SET mutations=mutations+1', (actor,))
                self.audit(db, actor, op, 'ok')
                db.commit()
                return response
            except Fault as exc:
                db.rollback()
                self.audit(db, str(actor)[:80], str(op)[:80], exc.code)
                db.commit()
                return {'ok': False, 'error': {'code': exc.code, 'message': exc.message}}

    def audit(self, db, actor, op, outcome):
        db.execute('INSERT INTO audit(actor,op,outcome,created) VALUES (?,?,?,?)', (actor, op, outcome, time.time()))

    def dispatch(self, db, actor, op, space, a):
        allowed = {
            'discover': {'space'}, 'get': {'space', 'id'}, 'history': {'space', 'id', 'after', 'limit'},
            'events': {'space', 'after', 'limit'}, 'inbox': {'space', 'after', 'limit'},
            'create': {'space', 'content', 'readers', 'writers'},
            'update': {'space', 'id', 'expected_version', 'content', 'readers', 'writers'},
            'send': {'space', 'recipient', 'content'},
        }
        if set(a) - allowed[op]:
            raise Fault('invalid', 'unknown argument')
        if op == 'discover':
            return {'identities': [self.record(r) for r in db.execute('SELECT i.* FROM identities i JOIN members m ON i.id=m.actor WHERE m.space=? ORDER BY i.id', (space,))],
                    'protocol': 'gptopia-kernel/0.1', 'limits': {'content_bytes': MAX_CONTENT, 'mutation_quota': self.max_mutations, 'objects_per_owner': self.max_objects},
                    'operations': sorted(allowed)}
        if op in {'get', 'history', 'update'}:
            row = self.obj(db, space, name(a.get('id'), 'id'), actor, op == 'update')
        if op == 'get':
            result = self.record(row)
            latest = db.execute('SELECT author,created FROM versions WHERE object_id=? AND version=?', (row['id'], row['version'])).fetchone()
            result.update(dict(latest))
            return result
        if op in {'events', 'history', 'inbox'}:
            after, limit = a.get('after', 0), a.get('limit', 50)
            if type(after) is not int or not 0 <= after <= 9223372036854775807 or type(limit) is not int or not 1 <= limit <= 100:
                raise Fault('invalid', 'after must be nonnegative integer; limit must be 1–100')
        if op == 'history':
            # Both current ACL and historical ACL must allow a historical read.
            rows = db.execute('SELECT * FROM versions WHERE object_id=? AND version>? ORDER BY version', (row['id'], after))
            out, cursor = [], after
            for r in rows:
                cursor = r['version']
                if actor in json.loads(r['readers']):
                    out.append(self.record(r))
                if len(out) >= limit:
                    break
            return {'items': out, 'next_cursor': cursor}
        if op == 'events':
            rows = db.execute('SELECT * FROM events WHERE space=? AND seq>? ORDER BY seq', (space, after))
            out, cursor = [], after
            for r in rows:
                cursor = r['seq']
                if actor not in json.loads(r['audience']):
                    continue
                if r['kind'].startswith('object.'):
                    current = db.execute('SELECT readers FROM objects WHERE id=?', (r['subject'],)).fetchone()
                    if not current or actor not in json.loads(current[0]):
                        continue
                item = dict(r)
                del item['audience']
                out.append(item)
                if len(out) >= limit:
                    break
            return {'items': out, 'next_cursor': cursor}
        if op == 'inbox':
            rows = db.execute("SELECT e.seq,m.* FROM events e JOIN messages m ON e.subject=m.id WHERE e.kind='message.sent' AND m.space=? AND m.recipient=? AND e.seq>? ORDER BY e.seq LIMIT ?", (space, actor, after, limit)).fetchall()
            return {'items': [dict(r) for r in rows], 'next_cursor': rows[-1]['seq'] if rows else after}
        if op == 'send':
            recipient = name(a.get('recipient'), 'recipient')
            self.member(db, space, recipient)
            body, mid = content(a.get('content')), 'msg_' + uuid.uuid4().hex
            db.execute('INSERT INTO messages VALUES (?,?,?,?,?,?)', (mid, space, actor, recipient, body, time.time()))
            seq = self.event(db, space, 'message.sent', actor, mid, sorted({actor, recipient}))
            return {'id': mid, 'event': seq}
        if op == 'create':
            if db.execute('SELECT COUNT(*) FROM objects WHERE owner=?', (actor,)).fetchone()[0] >= self.max_objects:
                raise Fault('quota', 'object quota exceeded')
            oid, version, owner = 'obj_' + uuid.uuid4().hex, 1, actor
            readers, writers = self.acl(db, space, a, owner)
        elif op == 'update':
            if type(a.get('expected_version')) is not int or a['expected_version'] != row['version']:
                raise Fault('conflict', 'expected_version does not match current version')
            oid, version, owner = row['id'], row['version'] + 1, row['owner']
            readers, writers = json.loads(row['readers']), json.loads(row['writers'])
            if 'readers' in a or 'writers' in a:
                if actor != owner:
                    raise Fault('forbidden', 'only owner can change ACL')
                readers, writers = self.acl(db, space, a, owner)
        body = content(a.get('content'))
        db.execute('INSERT INTO objects VALUES (?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET version=excluded.version,content=excluded.content,readers=excluded.readers,writers=excluded.writers',
                   (oid, space, owner, version, body, encode(readers), encode(writers)))
        db.execute('INSERT INTO versions VALUES (?,?,?,?,?,?,?)', (oid, version, actor, body, encode(readers), encode(writers), time.time()))
        seq = self.event(db, space, 'object.' + ('created' if op == 'create' else 'updated'), actor, oid, readers, version)
        return {'id': oid, 'version': version, 'event': seq, 'owner': owner, 'author': actor}

class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    def __init__(self, address, kernel):
        if address[0] != '127.0.0.1':
            raise ValueError('test kernel can bind only to 127.0.0.1')
        self.kernel = kernel
        super().__init__(address, Handler)

class Handler(BaseHTTPRequestHandler):
    server_version = 'GPTopiaTestKernel/0.1'
    def log_message(self, *args):
        pass
    def setup(self):
        super().setup()
        self.connection.settimeout(5)
    def do_POST(self):
        if self.path != '/v1':
            return self.reply(404, {'ok': False, 'error': {'code': 'not_found', 'message': 'use POST /v1'}})
        # This is an explicit insecure test harness, not authentication.
        if (self.headers.get('Origin') or self.headers.get('Content-Type') != 'application/json'
                or self.headers.get('Host') not in {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
                or self.headers.get('Transfer-Encoding')):
            return self.reply(403, {'ok': False, 'error': {'code': 'forbidden', 'message': 'browser-origin requests and non-JSON requests rejected'}})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= MAX_BODY:
                raise ValueError('body size')
            request = json.loads(self.rfile.read(length), parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
            result = self.server.kernel.request(self.headers.get('X-Test-Actor'), request)
            status = 200 if result['ok'] else {'forbidden': 403, 'not_found': 404, 'conflict': 409, 'quota': 429}.get(result['error']['code'], 400)
            self.reply(status, result)
        except (ValueError, UnicodeError, RecursionError):
            self.reply(400, {'ok': False, 'error': {'code': 'invalid', 'message': 'invalid JSON or body size'}})
        except sqlite3.OperationalError:
            self.reply(503, {'ok': False, 'error': {'code': 'unavailable', 'message': 'database busy or unavailable; retry same idempotency key'}})
    def reply(self, status, value):
        payload = encode(value).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(payload)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['init', 'serve', 'inspect'])
    parser.add_argument('--db', default='world.sqlite3')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--allow-insecure-test-identities', action='store_true')
    args = parser.parse_args()
    kernel = Kernel(args.db)
    if args.command in {'init', 'serve'} and not args.allow_insecure_test_identities:
        parser.error('this fixture harness requires --allow-insecure-test-identities; never expose publicly')
    if args.command == 'init':
        kernel.initialize()
        print(encode({'database': args.db, 'fixture_identities': ['alice', 'bob', 'eve'], 'security': 'INSECURE TEST DOUBLE'}))
    elif args.command == 'serve':
        if not Path(args.db).is_file():
            parser.error('initialize the fixture database first')
        server = Server(('127.0.0.1', args.port), kernel)
        print(encode({'listening': f'http://127.0.0.1:{server.server_port}/v1', 'security': 'INSECURE TEST DOUBLE'}), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    else:
        if not Path(args.db).is_file():
            parser.error('database not found')
        with sqlite3.connect(f'file:{Path(args.db).resolve()}?mode=ro', uri=True) as db:
            db.row_factory = sqlite3.Row
            print(encode({table: [dict(r) for r in db.execute(f'SELECT * FROM {table}')] for table in ['identities', 'members', 'objects', 'versions', 'messages', 'events', 'usage', 'audit']}))

if __name__ == '__main__':
    main()
