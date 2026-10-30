"""Synthetic identity/acceptance tests; no tokens, keys, real auth, or agent autonomy.

Even assurance='verified' below is fabricated in-process solely to test a predicate.
Passing these tests does NOT demonstrate authenticated independent agents.
"""
import concurrent.futures
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from identity import AUDIENCE, SCOPES, AuthenticationError, Principal, fixture
from kernel import Kernel, Server


def synthetic(actor='alice', **overrides):
    return replace(Principal(actor=actor, issuer='unit-test-synthetic-issuer',
        subject='synthetic-subject-' + actor, control_domain='synthetic-control-' + actor,
        spaces=frozenset({'plaza'}), scopes=frozenset(SCOPES.values()),
        audience=AUDIENCE, expires_at=time.time() + 300, assurance='synthetic',
        client_id='synthetic-client-' + actor, grant_id='synthetic-grant-' + actor), **overrides)


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'world.sqlite3'
        self.kernel = Kernel(self.path)
        self.kernel.initialize()
        self.n = 0

    def call(self, op, principal=None, key=None, **args):
        self.n += 1
        request = {'op': op, 'args': {'space': 'plaza', **args}}
        if op in {'create', 'update', 'send', 'accept'}:
            request['idempotency_key'] = key or f'synthetic-{self.n}'
        return self.kernel.request(principal or synthetic(), request)

    def ok(self, response):
        self.assertTrue(response['ok'], response)
        return response['result']

    def error(self, response, code):
        self.assertFalse(response['ok'], response)
        self.assertEqual(response['error']['code'], code, response)

    def create(self, **args):
        return self.ok(self.call('create', content='A shared design', readers=['alice', 'bob'], writers=['alice', 'bob'], **args))

    def accept(self, artifact, principal=None, **extra):
        return self.call('accept', principal=principal, id=artifact['id'], version=artifact['version'], content_sha256=artifact['content_sha256'], **extra)

    def test_default_raw_string_and_fixture_principal_are_denied(self):
        req = {'op': 'discover', 'args': {'space': 'plaza'}}
        self.error(self.kernel.request('alice', req), 'unauthenticated')
        self.error(self.kernel.request(fixture('alice'), req), 'unauthenticated')
        self.ok(Kernel(self.path, allow_fixture=True).request('alice', req))

    def test_invalid_expired_revoked_audience_and_scopes(self):
        for principal in [synthetic(expires_at=time.time()-1), synthetic(revoked=True),
                          synthetic(expires_at=float('inf')), synthetic(expires_at=float('nan')),
                          synthetic(audience='another-audience'), synthetic(scopes=frozenset()),
                          synthetic(spaces=frozenset({'garden'})), synthetic(issuer=''),
                          *[synthetic(revoked=v) for v in [None, 0, '', [], {}]],
                          synthetic(assurance='self-asserted'), synthetic(scopes=None), synthetic(spaces=None)]:
            with self.subTest(principal=principal):
                self.error(self.call('discover', principal=principal), 'forbidden' if principal.scopes == frozenset() or principal.spaces == frozenset({'garden'}) else 'unauthenticated')

    def test_operation_scope_is_not_interchangeable(self):
        read_only = synthetic(scopes=frozenset({'world:discover', 'objects:read'}))
        self.ok(self.call('discover', principal=read_only))
        self.error(self.call('send', principal=read_only, recipient='bob', content='x'), 'forbidden')
        artifact = self.create()
        self.ok(self.call('get', principal=read_only, id=artifact['id']))
        self.error(self.accept(artifact, principal=read_only), 'forbidden')

    def test_json_sender_spoof_cannot_override_trusted_principal(self):
        self.error(self.call('send', principal=synthetic('bob'), recipient='alice', content='x', sender='alice'), 'invalid')
        self.ok(self.call('send', principal=synthetic('bob'), recipient='alice', content='real sender is bob'))
        inbox = self.ok(self.call('inbox'))['items']
        self.assertEqual(inbox[0]['sender'], 'bob')
        self.assertEqual(len(inbox), 1)

    def test_hash_and_acceptance_bind_exact_current_revision(self):
        artifact = self.create()
        expected = hashlib.sha256(b'A shared design').hexdigest()
        self.assertEqual(artifact['content_sha256'], expected)
        fetched = self.ok(self.call('get', id=artifact['id']))
        self.assertEqual(fetched['content_sha256'], expected)
        self.assertEqual(fetched['acceptance']['records'], [])
        self.error(self.call('accept', id=artifact['id'], version=1, content_sha256='0'*64), 'conflict')
        self.error(self.call('accept', id=artifact['id'], version=True, content_sha256=expected), 'conflict')
        self.error(self.call('accept', id=artifact['id'], version=2, content_sha256=expected), 'conflict')
        accepted = self.ok(self.accept(artifact))
        record = accepted['acceptance']['records'][0]
        self.assertEqual((record['actor'], record['issuer'], record['subject'], record['control_domain']),
                         ('alice', 'unit-test-synthetic-issuer', 'synthetic-subject-alice', 'synthetic-control-alice'))
        self.assertEqual(record['assurance'], 'synthetic')
        self.assertFalse(accepted['acceptance']['multi_party_attested'])
        self.assertFalse(accepted['acceptance']['test_multi_party_attested'])

    def test_synthetic_pair_is_only_test_multi_party_attested(self):
        artifact = self.create()
        self.ok(self.accept(artifact))
        status = self.ok(self.accept(artifact, synthetic('bob')))['acceptance']
        self.assertFalse(status['multi_party_attested'])
        self.assertTrue(status['test_multi_party_attested'])
        self.assertEqual(len(status['records']), 2)
        self.assertEqual(status['evidence_basis'], 'claims_at_acceptance_time_not_live_revocation')

    def test_unit_only_verified_marker_requires_distinct_attribution_and_control(self):
        # These are synthetic test-issued claims, NOT a working identity verifier.
        for same_subject, same_control, expected in [(False,False,True), (True,False,True), (False,True,False), (True,True,False)]:
            with self.subTest(same_subject=same_subject, same_control=same_control):
                artifact = self.create()
                alice = synthetic(assurance='verified')
                bob = synthetic('bob', assurance='verified',
                    subject=alice.subject if same_subject else 'synthetic-subject-bob',
                    control_domain=alice.control_domain if same_control else 'synthetic-control-bob')
                self.ok(self.accept(artifact, alice))
                status = self.ok(self.accept(artifact, bob))['acceptance']
                self.assertEqual(status['multi_party_attested'], expected)
                self.assertFalse(status['test_multi_party_attested'])
        artifact = self.create()
        self.ok(self.accept(artifact, synthetic(assurance='verified')))
        mixed = self.ok(self.accept(artifact, synthetic('bob')))['acceptance']
        self.assertFalse(mixed['multi_party_attested'])
        self.assertTrue(mixed['test_multi_party_attested'])

    def test_acceptance_is_immutable_and_edit_does_not_carry_it_forward(self):
        artifact = self.create()
        original = self.ok(self.accept(artifact, key='original-accept'))
        self.ok(self.accept(artifact, synthetic('bob')))
        updated = self.ok(self.call('update', id=artifact['id'], expected_version=1, content='Edited design'))
        fetched = self.ok(self.call('get', id=artifact['id']))
        self.assertEqual(fetched['version'], 2)
        self.assertEqual(fetched['acceptance']['records'], [])
        self.assertFalse(fetched['acceptance']['multi_party_attested'])
        history = self.ok(self.call('history', id=artifact['id']))['items']
        self.assertEqual(history[0]['content_sha256'], artifact['content_sha256'])
        self.assertEqual(len(history[0]['acceptance']['records']), 2)
        self.assertTrue(history[0]['acceptance']['test_multi_party_attested'])
        self.assertEqual(history[1]['acceptance']['records'], [])
        self.error(self.accept(artifact), 'conflict')
        # Same retry key is a receipt replay, not fresh acceptance of latest version.
        self.assertEqual(self.ok(self.accept(artifact, key='original-accept')), original)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM acceptances WHERE version=1').fetchone()[0], 2)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM acceptances WHERE version=2').fetchone()[0], 0)
            for sql in ['DELETE FROM acceptances', 'UPDATE acceptances SET version=2']:
                with self.assertRaises(sqlite3.IntegrityError):
                    db.execute(sql)
        self.ok(self.accept(updated))

    def test_acceptance_deduplication_and_new_key_conflict(self):
        artifact = self.create()
        first = self.accept(artifact, key='same-accept')
        self.ok(first)
        self.assertEqual(self.accept(artifact, key='same-accept'), first)
        self.error(self.accept(artifact, key='different-key'), 'conflict')
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE kind='object.accepted'").fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT mutations FROM usage WHERE actor="alice"').fetchone()[0], 2)

    def test_acceptance_authorization_and_quota(self):
        artifact = self.ok(self.call('create', content='private', readers=['alice'], writers=['alice']))
        self.error(self.accept(artifact, synthetic('bob')), 'not_found')
        self.error(self.call('accept', id=artifact['id'], version=1, content_sha256=artifact['content_sha256'], space='garden'), 'forbidden')
        self.kernel = Kernel(self.path, max_mutations=1)
        self.error(self.accept(artifact), 'quota')
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0], 0)

    def test_concurrent_accept_and_edit_cannot_accept_wrong_revision(self):
        artifact = self.create()
        barrier = threading.Barrier(2)
        def accept():
            barrier.wait()
            return self.accept(artifact, synthetic('bob'), key='racing-accept')
        def edit():
            barrier.wait()
            return self.call('update', id=artifact['id'], expected_version=1, content='Concurrent revision', key='racing-edit')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            accepting, editing = pool.submit(accept), pool.submit(edit)
            accepted, edited = accepting.result(), editing.result()
        self.ok(edited)
        if accepted['ok']:
            self.assertEqual(accepted['result']['version'], 1)
        else:
            self.error(accepted, 'conflict')
        latest = self.ok(self.call('get', id=artifact['id']))
        self.assertEqual(latest['version'], 2)
        self.assertEqual(latest['acceptance']['records'], [])
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM acceptances WHERE version != 1').fetchone()[0], 0)

    def test_migration_from_pre_acceptance_schema(self):
        artifact = self.create()
        # Reproduce pre-acceptance schema by removing only the new empty table.
        with sqlite3.connect(self.path) as db:
            db.execute('DROP TABLE acceptances')
            db.commit()
        self.kernel.initialize()
        self.assertEqual(self.ok(self.call('get', id=artifact['id']))['content'], 'A shared design')
        self.ok(self.accept(artifact))
        self.kernel = Kernel(self.path)
        self.assertEqual(len(self.ok(self.call('get', id=artifact['id']))['acceptance']['records']), 1)


class SyntheticVerifierHTTPTests(unittest.TestCase):
    """Header cases feed fabricated in-process principals; not token authentication."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.kernel = Kernel(Path(self.tmp.name) / 'world.sqlite3')
        self.kernel.initialize()
        self.cases = {'valid': synthetic(), 'expired': synthetic(expires_at=0),
                      'revoked': synthetic(revoked=True), 'audience': synthetic(audience='wrong'),
                      'scope': synthetic(scopes=frozenset()), 'none': None, 'invalid-type': {}}
        def synthetic_verifier(headers):
            case = headers.get('X-Synthetic-Case')
            if case == 'crash':
                raise RuntimeError('synthetic verifier secret detail')
            if case not in self.cases:
                raise AuthenticationError('missing or invalid synthetic test case')
            return self.cases[case]
        self.server = Server(('127.0.0.1', 0), self.kernel, verifier=synthetic_verifier)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)
        self.url = f'http://127.0.0.1:{self.server.server_port}/v1'

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def rpc(self, headers):
        req = urllib.request.Request(self.url, json.dumps({'op':'discover','args':{'space':'plaza'}}).encode(), {'Content-Type':'application/json', **headers})
        try:
            response = urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.load(response)

    def test_missing_invalid_expired_revoked_audience_scope_and_spoof(self):
        for case in [None, 'unrecognized', 'expired', 'revoked', 'audience', 'scope', 'none', 'invalid-type', 'crash']:
            with self.subTest(case=case):
                status, body = self.rpc({'X-Synthetic-Case':case} if case else {})
                self.assertEqual(status, 403 if case == 'scope' else 401, body)
                self.assertEqual(body['error']['code'], 'forbidden' if case == 'scope' else 'unauthenticated')
                self.assertNotIn('secret detail', json.dumps(body))
        self.assertEqual(self.rpc({'X-Synthetic-Case':'valid'})[0], 200)
        self.assertEqual(self.rpc({'X-Synthetic-Case':'valid','X-Test-Actor':'bob'})[0], 401)

    def test_server_requires_verifier_and_disallows_mixed_fixture_mode(self):
        with self.assertRaises(ValueError):
            Server(('127.0.0.1', 0), self.kernel)
        with self.assertRaises(ValueError):
            Server(('127.0.0.1', 0), Kernel(self.kernel.path, allow_fixture=True), verifier=lambda _: synthetic())
        with self.assertRaises(ValueError):
            Server(('0.0.0.0', 0), self.kernel, verifier=lambda _: synthetic())


if __name__ == '__main__':
    unittest.main()
