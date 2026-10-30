"""Durable admission lifecycle tests using ephemeral synthetic RSA claims only.

No real provider, credentials, user consent UI, or runtime independence is tested.
"""
import copy
import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from identity import AuthenticationError, SCOPES
from kernel import Kernel, initialize_schema
from onboarding import AdmissionDenied, AdmissionStore
from production import JWTVerifier, register_admissions, create_app
from mcp_adapter.worker import Boundary
from starlette.testclient import TestClient

ISSUER = 'https://synthetic-owner.example/'
RESOURCE = 'https://synthetic-world.example'
OWNER = 'synthetic-human-owner'


class OnboardingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.keys = SimpleNamespace(get_signing_key_from_jwt=lambda _: SimpleNamespace(key=cls.private.public_key()))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'world.db')
        self.now = time.time()
        self.deadline = self.now + 600
        self.store = self.open_store()
        self.grant = dict(issuer=ISSUER, subject=OWNER, client_id='pip-client',
            actor='pip', control_domain='pip-host', spaces=['pilot'],
            scopes=sorted(set(SCOPES.values())), expires_at=self.now+500)
        self.verify = self.verifier(self.store)
        self.kernel = Kernel(self.path, allow_fixture=False)

    def open_store(self, **changes):
        options = dict(owner_issuer=ISSUER, owner_subject=OWNER,
                       roots=frozenset({'pilot'}), deadline=self.deadline)
        options.update(changes)
        return AdmissionStore(self.path, **options)

    def verifier(self, store):
        return JWTVerifier(ISSUER, RESOURCE, ISSUER+'jwks', {},
                           key_client=self.keys, admission_store=store)

    def token(self, **changes):
        claims = dict(iss=ISSUER, sub=OWNER, azp='pip-client', aud=RESOURCE,
                      iat=self.now, exp=self.now+300, scope=' '.join(SCOPES.values()))
        claims.update(changes)
        return jwt.encode(claims, self.private, algorithm='RS256')

    def approve(self):
        return self.store.approve('grant-pip', self.grant)

    def discover(self, principal, space='pilot'):
        return self.kernel.request(principal, {'op':'discover', 'args':{'space':space}})

    def test_approval_does_not_activate_until_verified_claim_and_duplicate_is_idempotent(self):
        self.assertEqual(self.approve()['state'], 'approved')
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM identities').fetchone()[0], 0)
        first = self.verify(self.token())
        second = self.verify(self.token())
        self.assertEqual(first, second)
        self.assertEqual(self.store.inspect('grant-pip')['state'], 'active')
        self.assertTrue(self.discover(first)['ok'])
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM identities').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT action FROM admission_audit ORDER BY seq').fetchall()[0][0], 'approved')
            self.assertEqual(db.execute("SELECT COUNT(*) FROM admission_audit WHERE action='activated'").fetchone()[0], 1)

    def test_no_self_enrollment_or_wrong_owner_client_issuer(self):
        with self.assertRaises(AdmissionDenied) as missing:
            self.verify(self.token())
        self.assertEqual(missing.exception.code, 'admission_required')
        self.approve()
        for changes in [dict(sub='another-human'), dict(azp='another-client'), dict(iss='https://wrong.example/')]:
            with self.subTest(changes=changes), self.assertRaises(AuthenticationError):
                self.verify(self.token(**changes))
        self.assertEqual(self.store.inspect('grant-pip')['state'], 'approved')

    def test_invalid_signature_and_wrong_audience_never_claim_invitation(self):
        self.approve()
        wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        claims = jwt.decode(self.token(), options={'verify_signature':False})
        for token in [jwt.encode(claims, wrong, algorithm='RS256'), self.token(aud='wrong'), self.token(azp=None)]:
            with self.assertRaises(AuthenticationError):
                self.verify(token)
        self.assertEqual(self.store.inspect('grant-pip')['state'], 'approved')

    def test_restart_preserves_exact_binding_deadline_and_activation(self):
        self.approve()
        before = self.verify(self.token())
        restarted = self.open_store()
        after = self.verifier(restarted)(self.token())
        self.assertEqual(before, after)
        self.assertTrue(self.discover(after)['ok'])
        for changes in [dict(deadline=self.deadline+1), dict(owner_subject='replacement'), dict(roots=frozenset({'pilot','other'}))]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.open_store(**changes)

    def test_approved_invitation_revocation_is_terminal_and_idempotent(self):
        self.approve()
        self.assertTrue(self.store.revoke('grant-pip'))
        self.assertFalse(self.store.revoke('grant-pip'))
        with self.assertRaises(AdmissionDenied) as denied:
            self.verify(self.token())
        self.assertEqual(denied.exception.code, 'admission_revoked')
        with self.assertRaises(ValueError):
            self.approve()
        self.assertEqual(self.open_store().inspect('grant-pip')['effective_state'], 'revoked')
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM identities').fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM admission_audit WHERE action='revoked'").fetchone()[0], 1)

    def test_active_revocation_rejects_fresh_and_cached_principal_without_restart(self):
        self.approve()
        stale = self.verify(self.token())
        self.assertTrue(self.discover(stale)['ok'])
        self.store.revoke('grant-pip')
        with self.assertRaises(AdmissionDenied):
            self.verify(self.token())
        result = self.discover(stale)
        self.assertFalse(result['ok'])
        self.assertEqual(result['error']['code'], 'forbidden')
        write = self.kernel.request(stale, {'op':'create','args':{'space':'pilot', 'content':'must not persist','readers':['pip'],'writers':['pip']},'idempotency_key':'after-revoke'})
        self.assertFalse(write['ok'])
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM objects').fetchone()[0], 0)

    def test_expiry_denies_claim_and_cached_principal(self):
        self.grant['expires_at'] = self.now+100
        self.approve()
        principal = self.verify(self.token())
        with patch('onboarding.time.time', return_value=self.now+101):
            with self.assertRaises(AdmissionDenied) as denied:
                self.verify(self.token())
            self.assertEqual(denied.exception.code, 'admission_expired')
            self.assertEqual(self.store.inspect('grant-pip')['effective_state'], 'expired')
            self.assertFalse(self.discover(principal)['ok'])

    def test_owner_root_scope_and_deadline_approval_ceilings(self):
        for changes in [dict(subject='another-human'), dict(issuer='https://other.example/'),
                        dict(spaces=['other']), dict(scopes=['admin:all']), dict(expires_at=self.deadline+1)]:
            grant = self.grant | changes
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.store.approve('grant-pip', grant)
        self.assertIsNone(self.store.inspect('grant-pip'))

    def test_scope_intersection_and_space_denial(self):
        self.grant['scopes'] = ['world:discover']
        self.approve()
        principal = self.verify(self.token(scope='world:discover objects:write admin:all'))
        self.assertEqual(principal.scopes, frozenset({'world:discover'}))
        self.assertTrue(self.discover(principal)['ok'])
        self.assertFalse(self.discover(principal, 'other')['ok'])
        result = self.kernel.request(principal, {'op':'create','args':{'space':'pilot','content':'no','readers':['pip'],'writers':['pip']},'idempotency_key':'no-write'})
        self.assertFalse(result['ok'])
        # A stale or buggy trusted adapter cannot broaden the persisted grant.
        inflated = replace(principal, scopes=frozenset(SCOPES.values()), spaces=frozenset({'pilot','other'}))
        self.assertFalse(self.discover(inflated, 'other')['ok'])
        result = self.kernel.request(inflated, {'op':'create','args':{'space':'pilot','content':'no','readers':['pip'],'writers':['pip']},'idempotency_key':'still-no-write'})
        self.assertFalse(result['ok'])

    def test_same_human_two_clients_distinct_stable_actors(self):
        self.approve()
        muse = self.grant | dict(actor='muse',client_id='muse-client',control_domain='muse-host')
        self.store.approve('grant-muse', muse)
        pip = self.verify(self.token())
        muse = self.verify(self.token(azp='muse-client'))
        self.assertEqual(pip.subject, muse.subject)
        self.assertNotEqual(pip.actor, muse.actor)
        self.assertNotEqual(pip.grant_id, muse.grant_id)
        self.assertNotEqual(pip.client_id, muse.client_id)
        self.assertTrue(self.discover(muse)['ok'])

    def test_duplicate_approval_and_binding_uniqueness(self):
        first = self.approve()
        self.assertEqual(first, self.approve())
        for changes in [dict(actor='other-actor'), dict(control_domain='other-host'), dict(expires_at=self.now+400)]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.store.approve('grant-pip', self.grant | changes)
        for grant in [self.grant | dict(actor='other-actor'), self.grant | dict(client_id='other-client')]:
            with self.assertRaises((ValueError, sqlite3.IntegrityError)):
                self.store.approve('other-grant', grant)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM durable_admissions').fetchone()[0], 1)

    def test_concurrent_duplicate_claims_activate_once(self):
        self.approve()
        token = self.token()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(self.verify, [token]*8))
        self.assertTrue(all(principal == results[0] for principal in results))
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM admission_audit WHERE action='activated'").fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM admission_bindings').fetchone()[0], 1)

    def test_existing_binding_requires_explicit_approval_not_silent_import(self):
        with self.kernel.connection() as db:
            initialize_schema(db)
            register_admissions(db, {'grant-pip':self.grant})
        static = JWTVerifier(ISSUER, RESOURCE, ISSUER+'jwks', {'grant-pip':self.grant}, key_client=self.keys)
        self.assertFalse(self.discover(static(self.token()))['ok'])
        with self.assertRaises(AdmissionDenied):
            self.verify(self.token())
        self.approve()
        principal = self.verify(self.token())
        self.assertTrue(self.discover(principal)['ok'])
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM identities').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM admission_bindings').fetchone()[0], 1)

    def test_historical_binding_cannot_be_reassigned(self):
        with self.kernel.connection() as db:
            initialize_schema(db)
            register_admissions(db, {'grant-pip':self.grant})
        for gid, changes in [('new-grant', {}), ('grant-pip', dict(client_id='other-client')),
                             ('grant-pip', dict(control_domain='other-host'))]:
            with self.subTest(gid=gid,changes=changes), self.assertRaises(ValueError):
                self.store.approve(gid, self.grant | changes)
        self.assertIsNone(self.store.inspect('grant-pip'))

    def test_unbound_legacy_actor_fails_closed_on_activation(self):
        with self.store.connect() as db:
            db.execute('INSERT INTO identities VALUES (?,?)',('pip','[]'))
        self.approve()
        with self.assertRaises(AdmissionDenied):
            self.verify(self.token())
        self.assertEqual(self.store.inspect('grant-pip')['state'], 'approved')
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM members').fetchone()[0], 0)

    def test_durable_and_static_authority_cannot_be_combined(self):
        with self.assertRaises(ValueError):
            JWTVerifier(ISSUER, RESOURCE, ISSUER+'jwks', {'grant-pip':self.grant}, key_client=self.keys, admission_store=self.store)


    def test_diagnostic_ready_exposes_only_own_permissions_never_token(self):
        self.approve()
        token = self.token()
        result = self.store.self_test(self.verify, token, requested_scopes=['world:discover'])
        self.assertTrue(result['ready'])
        self.assertEqual(result['code'], 'ready')
        self.assertEqual(result['actor'], 'pip')
        self.assertEqual(result['authorized_spaces'], ['pilot'])
        self.assertEqual(set(result['effective_scopes']), set(SCOPES.values()))
        self.assertEqual(set(result['available_operations']), set(SCOPES))
        self.assertNotIn(token, repr(result))
        self.assertNotIn(OWNER, repr(result))
        self.assertEqual(self.store.inspect('grant-pip')['state'], 'active')

    def test_diagnostic_missing_scope_does_not_request_repeated_login(self):
        self.grant['scopes'] = ['world:discover']
        self.approve()
        result = self.store.self_test(self.verify, self.token(), requested_scopes=['world:discover','objects:write'])
        self.assertFalse(result['ready'])
        self.assertEqual(result['code'], 'permission_missing')
        self.assertEqual(result['missing_requested_scopes'], ['objects:write'])
        self.assertEqual(result['next_action'], 'request_scope_review_not_repeated_login')
        self.assertEqual(result['available_operations'], ['discover'])

    def test_diagnostic_admission_required_revoked_and_expired_are_distinct(self):
        result = self.store.self_test(self.verify, self.token())
        self.assertEqual(result['code'], 'admission_required')
        self.assertNotIn('actor', result)
        self.grant['expires_at'] = self.now+100
        self.approve()
        self.verify(self.token())
        with patch('onboarding.time.time', return_value=self.now+101):
            result = self.store.self_test(self.verify, self.token())
            self.assertEqual(result['code'], 'admission_expired')
            self.assertNotIn('actor', result)
        self.store.revoke('grant-pip')
        result = self.store.self_test(self.verify, self.token())
        self.assertEqual(result['code'], 'admission_revoked')
        self.assertNotIn('actor', result)

    def test_diagnostic_invalid_credentials_and_wrong_verifier_fail_closed(self):
        self.approve()
        result = self.store.self_test(self.verify, 'not-a-jwt')
        self.assertEqual(result, {'ready':False, 'code':'invalid_credentials', 'next_action':'use_host_oauth_login'})
        self.assertEqual(self.store.inspect('grant-pip')['state'], 'approved')
        with self.assertRaises(ValueError):
            self.store.self_test(lambda token: self.verify(token), self.token())
        with self.assertRaises(ValueError):
            self.store.self_test(self.verifier(self.open_store()), self.token())
        with self.assertRaises(ValueError):
            self.store.self_test(self.verify, self.token(), requested_scopes=['admin:all'])


    def test_http_and_worker_reject_split_database_before_target_creation(self):
        for name, factory in [
            ('http', lambda path: create_app(path, RESOURCE, ISSUER, self.verify, {}, self.deadline)),
            ('worker', lambda path: Boundary(path, self.verify, {}, self.deadline)),
        ]:
            target = Path(self.tmp.name) / (name+'-missing') / 'world.db'
            with self.subTest(boundary=name), self.assertRaises(ValueError):
                factory(str(target))
            self.assertFalse(target.exists())
            self.assertFalse(target.parent.exists())

    def test_http_and_worker_reject_static_import_mixing(self):
        for factory in [
            lambda: create_app(self.path, RESOURCE, ISSUER, self.verify, {'grant-pip':self.grant}, self.deadline),
            lambda: Boundary(self.path, self.verify, {'grant-pip':self.grant}, self.deadline),
        ]:
            with self.assertRaises(ValueError):
                factory()
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM identities').fetchone()[0], 0)
            self.assertIsNone(db.execute("SELECT 1 FROM sqlite_master WHERE name='request_budget'").fetchone())

    def test_http_and_worker_accept_matching_store_without_static_import(self):
        self.approve()
        payload = {'op':'discover','args':{'space':'pilot'}}
        app = create_app(self.path, RESOURCE, ISSUER, self.verify, {}, self.deadline)
        with TestClient(app, base_url=RESOURCE) as client:
            response = client.post('/v1', headers={'Authorization':'Bearer '+self.token()}, json=payload)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(response.json()['ok'])
        boundary = Boundary(self.path, self.verify, {}, self.deadline)
        response = boundary.handle({'action':'call','token':self.token(),'payload':payload})
        self.assertEqual(response['status'], 200)
        self.assertTrue(response['result']['ok'])
        self.store.revoke('grant-pip')
        self.assertNotEqual(boundary.handle({'action':'authenticate','token':self.token()})['status'], 200)

    def test_copied_legacy_database_explicit_adoption_preserves_content_and_source(self):
        source = Path(self.tmp.name) / 'legacy.db'
        destination = Path(self.tmp.name) / 'copied.db'
        legacy = Kernel(str(source), allow_fixture=False)
        with legacy.connection() as db:
            initialize_schema(db)
            register_admissions(db, {'grant-pip':self.grant})
        static = JWTVerifier(ISSUER, RESOURCE, ISSUER+'jwks', {'grant-pip':self.grant}, key_client=self.keys)
        principal = static(self.token())
        request = {'op':'create','args':{'space':'pilot','content':'Persistent legacy draft',
                   'readers':['pip'],'writers':['pip']},'idempotency_key':'legacy-create'}
        created = legacy.request(principal, request)
        self.assertTrue(created['ok'])
        oid = created['result']['id']
        protected_tables = ['objects','versions','events','retries','usage','members','identities','admission_bindings']
        with sqlite3.connect(source) as old, sqlite3.connect(destination) as new:
            old.backup(new)
            snapshots = {table:old.execute('SELECT * FROM '+table).fetchall() for table in protected_tables}
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        copied = AdmissionStore(str(destination), owner_issuer=ISSUER, owner_subject=OWNER,
                                roots=frozenset({'pilot'}), deadline=self.deadline)
        copied_kernel = Kernel(str(destination), allow_fixture=False)
        read = {'op':'get','args':{'space':'pilot','id':oid}}
        self.assertFalse(copied_kernel.request(principal, read)['ok'])
        copied.approve('grant-pip', self.grant)
        activated = self.verifier(copied)(self.token())
        result = copied_kernel.request(activated, read)
        self.assertTrue(result['ok'])
        self.assertEqual(result['result']['content'], 'Persistent legacy draft')
        self.assertEqual(result['result']['content_sha256'], created['result']['content_sha256'])
        with copied.connect() as db:
            for table, expected in snapshots.items():
                self.assertEqual([tuple(row) for row in db.execute('SELECT * FROM '+table)], expected, table)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_hash)


    def test_diagnostic_default_requires_discovery_even_after_admission(self):
        self.approve()
        token = self.token(scope='')
        result = self.store.self_test(self.verify, token)
        self.assertFalse(result['ready'])
        self.assertEqual(result['code'], 'permission_missing')
        self.assertEqual(result['missing_requested_scopes'], ['world:discover'])
        self.assertEqual(result['effective_scopes'], [])
        self.assertEqual(result['available_operations'], [])
        admission_only = self.store.self_test(self.verify, token, requested_scopes=[])
        self.assertTrue(admission_only['ready'])
        self.assertEqual(admission_only['effective_scopes'], [])


if __name__ == '__main__':
    unittest.main()
