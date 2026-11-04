"""Offline cutoff regression tests. No host, issuer, network, or deployment.

Synthetic injected Principals and clocks test resource control flow, not JWT
verification or independent-agent interoperability. Denial audits/request-budget
writes are distinguished from world mutations. No hard real-time guarantee.
"""
import asyncio
from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT), str(ROOT / 'mcp_adapter')]
from identity import AUDIENCE, Principal, SCOPES
from kernel import Kernel
from production import create_app
from starlette.requests import Request
from worker import Boundary

T = 1793967840.0
TABLES = ('objects', 'versions', 'events', 'messages', 'acceptances', 'retries', 'usage', 'audit')
WORLD_TABLES = TABLES[:-1]


class CutoffBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = T - 10
        self.clock_patch = patch('time.time', side_effect=lambda: self.now)
        self.clock_patch.start()
        self.addCleanup(self.clock_patch.stop)
        self.seq = 0
        self.calls = 0

    def path(self):
        self.seq += 1
        return str(Path(self.tmp.name) / f'test-{self.seq}.db')

    def principal(self, expiry=T + 300):
        return Principal('test-agent', 'https://issuer.example/', 'test-owner',
                         'test-host', frozenset({'pilot'}), frozenset(SCOPES.values()),
                         AUDIENCE, expiry, assurance='verified',
                         client_id='test-client', grant_id='test-grant')

    def admissions(self, expiry=T + 300):
        return {'test-grant': dict(issuer='https://issuer.example/', subject='test-owner',
            actor='test-agent', control_domain='test-host', client_id='test-client',
            spaces=['pilot'], scopes=sorted(set(SCOPES.values())), expires_at=expiry)}

    def verifier(self, _):
        self.calls += 1
        return self.principal()

    def boundary(self, verifier=None):
        path = self.path()
        return Boundary(path, verifier or self.verifier, self.admissions(), T), path

    def app(self, verifier=None):
        path = self.path()
        return create_app(path, verifier=verifier or self.verifier,
                          admissions=self.admissions(), deadline=T), path

    def create(self, key='test-create'):
        return dict(op='create', idempotency_key=key, args=dict(space='pilot',
            content='synthetic local draft', readers=['test-agent'], writers=['test-agent']))

    def snapshot(self, path):
        with sqlite3.connect(path) as db:
            result = {t: db.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0] for t in TABLES}
            result['world_rows'] = {t: sorted(db.execute(f'SELECT * FROM {t}').fetchall(), key=repr)
                                    for t in WORLD_TABLES}
            result['budget'] = db.execute('SELECT used FROM request_budget WHERE id=1').fetchone()[0]
            return result

    def no_world_changes(self, before, after):
        self.assertEqual({t: before[t] for t in WORLD_TABLES}, {t: after[t] for t in WORLD_TABLES})
        self.assertEqual(before['world_rows'], after['world_rows'])

    async def http(self, app, payload=None, before_body=None, path='/v1'):
        body = json.dumps(self.create() if payload is None else payload).encode()
        consumed = False
        async def receive():
            nonlocal consumed
            if consumed:
                return {'type': 'http.disconnect'}
            consumed = True
            if before_body:
                before_body()
            return {'type': 'http.request', 'body': body, 'more_body': False}
        request = Request(dict(type='http', http_version='1.1', method='POST',
            path=path, raw_path=path.encode(), scheme='http', query_string=b'',
            headers=[(b'authorization', b'Bearer synthetic'), (b'content-type', b'application/json')],
            server=('test.invalid', 80), client=('127.0.0.1', 1)), receive)
        return await app.routes[0].endpoint(request)

    def test_worker_exact_entry_cutoff_skips_verifier_and_persistence(self):
        boundary, path = self.boundary()
        for moment in (T, T + 0.001):
            self.now = moment
            for action in ('authenticate', 'call'):
                before = self.snapshot(path)
                response = boundary.handle(dict(action=action, token='synthetic', payload=self.create()))
                self.assertEqual(response, {'status': 403})
                self.assertEqual(before, self.snapshot(path))
        self.assertEqual(self.calls, 0)
        self.assertEqual(boundary.handle({'action': 'health'}), {'status': 200})

    def test_http_exact_entry_cutoff_skips_verifier_and_persistence(self):
        app, path = self.app()
        for moment in (T, T + 0.001):
            self.now = moment
            before = self.snapshot(path)
            response = asyncio.run(self.http(app))
            self.assertEqual(response.status_code, 403)
            self.assertEqual(json.loads(response.body)['error']['code'], 'pilot_closed')
            self.assertEqual(before, self.snapshot(path))
        self.assertEqual(self.calls, 0)

    def test_both_boundaries_work_immediately_before_cutoff(self):
        boundary, _ = self.boundary()
        app, _ = self.app()
        self.now = T - 0.001
        self.assertTrue(boundary.handle(dict(action='call', token='synthetic', payload=self.create()))['result']['ok'])
        self.assertEqual(asyncio.run(self.http(app)).status_code, 200)

    def test_worker_verification_crossing_cutoff_denies_authentication_and_call(self):
        def delayed(_):
            principal = self.principal()
            self.now = T
            return principal
        boundary, path = self.boundary(delayed)
        for action in ('authenticate', 'call'):
            self.now = T - 0.001
            before = self.snapshot(path)
            self.assertEqual(boundary.handle(dict(action=action, token='synthetic', payload=self.create())), {'status': 403})
            self.assertEqual(before, self.snapshot(path))

    def test_http_verification_crossing_cutoff_has_no_persistence(self):
        def delayed(_):
            principal = self.principal()
            self.now = T
            return principal
        app, path = self.app(delayed)
        before = self.snapshot(path)
        self.assertEqual(asyncio.run(self.http(app)).status_code, 403)
        self.assertEqual(before, self.snapshot(path))

    def test_http_body_crossing_cutoff_has_no_persistence(self):
        for expiry in (T, T + 300):
            with self.subTest(principal_expiry=expiry):
                self.now = T - 10
                app, path = self.app(lambda _: self.principal(expiry))
                before = self.snapshot(path)
                response = asyncio.run(self.http(app, before_body=lambda: setattr(self, 'now', T)))
                self.assertEqual(response.status_code, 403)
                self.assertEqual(before, self.snapshot(path))

    def test_http_execution_queue_crossing_cutoff_denies_both_mutations(self):
        entered = threading.Event()
        release = threading.Event()
        queued = threading.Event()
        class ObservedLock:
            def __init__(inner):
                inner.lock = asyncio.Lock()
            async def __aenter__(inner):
                if inner.lock.locked():
                    queued.set()
                await inner.lock.acquire()
                return inner
            async def __aexit__(inner, *args):
                inner.lock.release()
        observed = ObservedLock()
        with patch('production.asyncio.Lock', return_value=observed):
            app, path = self.app()
        original = Kernel.request
        def delayed(kernel, principal, payload):
            entered.set()
            if not release.wait(5):
                raise AssertionError('test barrier was not released')
            return original(kernel, principal, payload)
        async def exercise():
            first = asyncio.create_task(self.http(app, self.create('first')))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 5))
                second = asyncio.create_task(self.http(app, self.create('second')))
                # This signal comes from lock acquisition, after verification
                # and body parsing, so the test cannot pass at an earlier gate.
                self.assertTrue(await asyncio.to_thread(queued.wait, 5))
                self.now = T
                release.set()
                return await asyncio.gather(first, second)
            finally:
                release.set()
        before = self.snapshot(path)
        with patch.object(Kernel, 'request', delayed):
            responses = asyncio.run(exercise())
        self.assertEqual([r.status_code for r in responses], [401, 403])
        after = self.snapshot(path)
        self.no_world_changes(before, after)
        self.assertEqual(after['budget'] - before['budget'], 1)
        self.assertEqual(after['audit'] - before['audit'], 1)

    def test_worker_passes_shorter_of_principal_and_pilot_expiry(self):
        for expiry in (T - 1, T + 300):
            with self.subTest(principal_expiry=expiry):
                boundary, _ = self.boundary(lambda _: self.principal(expiry))
                with patch.object(boundary.kernel, 'request', return_value={'ok': True, 'result': {}}) as call:
                    boundary.handle(dict(action='call', token='synthetic', payload=self.create()))
                self.assertEqual(call.call_args.args[0].expires_at, min(expiry, T))

    def test_http_passes_shorter_of_principal_and_pilot_expiry(self):
        for expiry in (T - 1, T + 300):
            with self.subTest(principal_expiry=expiry):
                app, _ = self.app(lambda _: self.principal(expiry))
                with patch.object(Kernel, 'request', return_value={'ok': True, 'result': {}}) as call:
                    asyncio.run(self.http(app))
                self.assertEqual(call.call_args.args[0].expires_at, min(expiry, T))

    def test_kernel_dispatch_crossing_cutoff_rolls_back_world_mutation(self):
        boundary, path = self.boundary()
        original = boundary.kernel.dispatch
        def delayed(*args):
            result = original(*args)
            self.now = T
            return result
        before = self.snapshot(path)
        with patch.object(boundary.kernel, 'dispatch', delayed):
            response = boundary.handle(dict(action='call', token='synthetic', payload=self.create()))
        self.assertFalse(response['result']['ok'])
        self.assertEqual(response['result']['error']['code'], 'unauthenticated')
        after = self.snapshot(path)
        self.no_world_changes(before, after)
        self.assertEqual(after['budget'] - before['budget'], 1)
        self.assertEqual(after['audit'] - before['audit'], 1)

    def test_kernel_retry_crossing_cutoff_does_not_return_success_receipt(self):
        boundary, path = self.boundary()
        message = dict(action='call', token='synthetic', payload=self.create())
        self.assertTrue(boundary.handle(message)['result']['ok'])
        before = self.snapshot(path)
        original = boundary.kernel.audit
        def delayed(db, actor, op, outcome):
            original(db, actor, op, outcome)
            if outcome == 'replay':
                self.now = T
        with patch.object(boundary.kernel, 'audit', delayed):
            response = boundary.handle(message)
        self.assertFalse(response['result']['ok'])
        self.assertEqual(response['result']['error']['code'], 'unauthenticated')
        after = self.snapshot(path)
        self.no_world_changes(before, after)
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute('SELECT outcome FROM audit ORDER BY rowid DESC LIMIT 1').fetchone()[0], 'unauthenticated')

    def test_kernel_update_and_accept_crossing_cutoff_roll_back_exact_state(self):
        for op in ('update', 'accept'):
            with self.subTest(op=op):
                self.now = T - 10
                boundary, path = self.boundary()
                created = boundary.handle(dict(action='call', token='synthetic', payload=self.create()))['result']['result']
                args = dict(space='pilot', id=created['id'])
                if op == 'update':
                    args.update(expected_version=1, content='changed synthetic text')
                else:
                    args.update(version=1, content_sha256=created['content_sha256'])
                original = boundary.kernel.dispatch
                def delayed(*args):
                    result = original(*args)
                    self.now = T
                    return result
                before = self.snapshot(path)
                with patch.object(boundary.kernel, 'dispatch', delayed):
                    response = boundary.handle(dict(action='call', token='synthetic', payload=dict(
                        op=op, args=args, idempotency_key='late-' + op)))
                self.assertFalse(response['result']['ok'])
                self.assertEqual(response['result']['error']['code'], 'unauthenticated')
                self.no_world_changes(before, self.snapshot(path))

    def test_kernel_read_crossing_cutoff_does_not_return_content(self):
        boundary, path = self.boundary()
        created = boundary.handle(dict(action='call', token='synthetic', payload=self.create()))['result']['result']
        original = boundary.kernel.dispatch
        def delayed(*args):
            result = original(*args)
            self.now = T
            return result
        before = self.snapshot(path)
        with patch.object(boundary.kernel, 'dispatch', delayed):
            response = boundary.handle(dict(action='call', token='synthetic', payload=dict(
                op='get', args=dict(space='pilot', id=created['id']))))
        self.assertFalse(response['result']['ok'])
        self.assertNotIn('content', response['result'])
        self.assertNotIn('result', response['result'])
        self.no_world_changes(before, self.snapshot(path))

    def test_kernel_database_wait_crossing_cutoff_denies_before_dispatch(self):
        boundary, path = self.boundary()
        original = boundary.kernel.connection
        class Connection:
            def __init__(self, db): self.db = db
            def __getattr__(self, key): return getattr(self.db, key)
            def execute(inner, sql, *args):
                result = inner.db.execute(sql, *args)
                if sql == 'BEGIN IMMEDIATE':
                    self.now = T
                return result
        @contextmanager
        def delayed_connection():
            with original() as db:
                yield Connection(db)
        before = self.snapshot(path)
        with patch.object(boundary.kernel, 'connection', delayed_connection), patch.object(boundary.kernel, 'dispatch', side_effect=AssertionError('expired dispatch')):
            response = boundary.handle(dict(action='call', token='synthetic', payload=self.create()))
        self.assertFalse(response['result']['ok'])
        self.no_world_changes(before, self.snapshot(path))


if __name__ == '__main__':
    unittest.main(verbosity=2)
