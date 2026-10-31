"""Synthetic local V2 seam tests. Not production/provider-runtime integration."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from dataclasses import replace
import tempfile
import time
import unittest
from types import SimpleNamespace
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from identity import AuthenticationError
from kernel import Kernel
from grant_bridge import ProviderGrant, ApplicationAdmission, ProofBoundary

class V2BridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cls.keys=SimpleNamespace(get_signing_key_from_jwt=lambda _:SimpleNamespace(key=cls.key.public_key()))
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.now=time.time();self.issuer='https://test-issuer.example/';self.resource='https://test-world.example'
        self.kernel=Kernel(str(Path(self.tmp.name)/'world.db'),allow_fixture=False)
        self.boundary=ProofBoundary(self.kernel,issuer=self.issuer,resource=self.resource,key_client=self.keys)
        self.pairs=[]
        for actor in ('alpha','beta'):
            g=ProviderGrant(self.issuer,'oauth-'+actor,'owner','shared-client',frozenset({'world:discover','objects:read','objects:write'}),True,self.now+200)
            a=ApplicationAdmission('admission-'+actor,self.issuer,g.oauth_grant_id,g.owner,g.client_id,
                actor,'same-host',frozenset({'pilot'}),frozenset({'world:discover','objects:read','objects:write'}),True,self.now+200)
            self.pairs.append((g,a))
        self.boundary.initialize_fresh_registry(self.pairs)
    def token(self,agent='alpha',**changes):
        c=dict(iss=self.issuer,aud=self.resource,sub='owner',client_id='shared-client',gptopia_grant_id='oauth-'+agent,
            iat=self.now,exp=self.now+120,scope='world:discover objects:read objects:write objects:accept admin:all')
        c.update(changes);return jwt.encode(c,self.key,algorithm='RS256')
    def test_distinct_same_owner_client_actors_make_real_kernel_revisions(self):
        a=self.boundary.verifier(self.token());b=self.boundary.verifier(self.token('beta'))
        self.assertEqual((a.subject,a.client_id,a.control_domain),(b.subject,b.client_id,b.control_domain))
        self.assertNotEqual(a.actor,b.actor);self.assertNotEqual(a.grant_id,b.grant_id)
        obj=self.boundary.request(self.token(),{'op':'create','idempotency_key':'create-one','args':dict(space='pilot',content='alpha',readers=['alpha','beta'],writers=['alpha','beta'])})
        self.assertTrue(obj['ok'],obj);oid=obj['result']['id']
        updated=self.boundary.request(self.token('beta'),{'op':'update','idempotency_key':'edit-one','args':dict(space='pilot',id=oid,expected_version=1,content='beta')})
        self.assertTrue(updated['ok'],updated);self.assertEqual(updated['result']['author'],'beta')
        self.assertEqual(updated['result']['owner'],'alpha')
    def test_revocation_between_operations_denies_previously_valid_token(self):
        token=self.token();r={'op':'discover','args':{'space':'pilot'}}
        self.assertTrue(self.boundary.request(token,r)['ok'])
        self.boundary.revoke(self.issuer,'oauth-alpha')
        with self.assertRaises(AuthenticationError):self.boundary.request(token,r)
    def test_unknown_and_wrong_binding_claims_deny(self):
        for change in ({'gptopia_grant_id':'unknown'},{'sub':'other-owner'},{'client_id':'other-client'},
                       {'iss':'https://other.example/'},{'aud':'https://other.example'},{'scope':[]},{'exp':self.now-1}):
            with self.subTest(change=change),self.assertRaises(AuthenticationError):self.boundary.verifier(self.token(**change))
    def test_actor_claim_is_inert_and_registry_mismatch_fails_kernel(self):
        p=self.boundary.verifier(self.token(actor='beta'))
        self.assertEqual(p.actor,'alpha')
        key=(self.issuer,'oauth-alpha');old=self.boundary._admissions[key]
        self.boundary._admissions[key]=replace(old,actor='beta')
        result=self.boundary.request(self.token(),{'op':'discover','args':{'space':'pilot'}})
        self.assertFalse(result['ok']);self.assertEqual(result['error']['code'],'unauthenticated')
    def test_unavailable_provider_or_admission_denies(self):
        def unavailable(*_):raise OSError('state unavailable')
        for field in ('grant','admission'):
            original=getattr(self.boundary.verifier,field);setattr(self.boundary.verifier,field,unavailable)
            with self.assertRaises(AuthenticationError):self.boundary.verifier(self.token())
            setattr(self.boundary.verifier,field,original)
    def test_scope_intersection_prevents_escalation(self):
        p=self.boundary.verifier(self.token());self.assertNotIn('admin:all',p.scopes);self.assertNotIn('objects:accept',p.scopes)
        p=self.boundary.verifier(self.token(scope='objects:read'));self.assertEqual(p.scopes,frozenset({'objects:read'}))
    def test_current_admission_inactive_or_mismatched_denies(self):
        key=(self.issuer,'oauth-alpha');old=self.boundary._admissions[key]
        for change in ({'active':False},{'owner':'other'},{'client_id':'other'},{'oauth_grant_id':'other'},{'issuer':'https://other.example/'},{'expires_at':self.now-1}):
            self.boundary._admissions[key]=replace(old,**change)
            with self.subTest(change=change),self.assertRaises(AuthenticationError):self.boundary.verifier(self.token())
    def test_provider_scope_narrowing_applies_to_existing_token(self):
        key=(self.issuer,'oauth-alpha');token=self.token()
        self.assertIn('objects:write',self.boundary.verifier(token).scopes)
        self.boundary._grants[key]=replace(self.boundary._grants[key],scopes=frozenset({'objects:read'}))
        self.assertEqual(self.boundary.verifier(token).scopes,frozenset({'objects:read'}))
    def test_missing_provider_or_admission_denies(self):
        key=(self.issuer,'oauth-alpha')
        for attr in ('_grants','_admissions'):
            mapping=getattr(self.boundary,attr);old=mapping.pop(key)
            with self.subTest(attr=attr),self.assertRaises(AuthenticationError):self.boundary.verifier(self.token())
            mapping[key]=old
    def test_provider_binding_expiry_and_malformed_scope_deny(self):
        key=(self.issuer,'oauth-alpha');old=self.boundary._grants[key]
        for change in ({'owner':'other'},{'client_id':'other'},{'oauth_grant_id':'other'},
                       {'issuer':'https://other.example/'},{'expires_at':self.now-1},{'scopes':['objects:write']}):
            self.boundary._grants[key]=replace(old,**change)
            with self.subTest(change=change),self.assertRaises(AuthenticationError):self.boundary.verifier(self.token())
    def test_duplicate_actor_setup_rolls_back_all_identity_rows(self):
        kernel=Kernel(str(Path(self.tmp.name)/'rollback.db'),allow_fixture=False)
        boundary=ProofBoundary(kernel,issuer=self.issuer,resource=self.resource,key_client=self.keys)
        first=self.pairs[0];g,a=self.pairs[1]
        with self.assertRaises(Exception):boundary.initialize_fresh_registry([first,(g,replace(a,actor=first[1].actor))])
        with kernel.connection() as db:
            for table in ('identities','members','admission_bindings'):
                self.assertEqual(db.execute('SELECT count(*) FROM '+table).fetchone()[0],0)
        self.assertEqual(boundary._grants,{})
        self.assertEqual(boundary._admissions,{})
    def test_request_and_revoke_are_serialized_with_single_process_lock(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor
        entered=threading.Event();release=threading.Event();revoker_started=threading.Event()
        original=self.kernel.request
        def blocked_operation(principal,request):
            entered.set()
            if not release.wait(5):raise TimeoutError('test release missing')
            return original(principal,request)
        self.kernel.request=blocked_operation
        token=self.token();request={'op':'discover','args':{'space':'pilot'}}
        def revoke():
            revoker_started.set();self.boundary.revoke(self.issuer,'oauth-alpha')
        with ThreadPoolExecutor(max_workers=2) as pool:
            operation=pool.submit(self.boundary.request,token,request)
            try:
                self.assertTrue(entered.wait(5))
                # The operation owns the shared lock before provider-state mutation.
                acquired=self.boundary.lock.acquire(blocking=False)
                if acquired:self.boundary.lock.release()
                self.assertFalse(acquired)
                revocation=pool.submit(revoke);self.assertTrue(revoker_started.wait(5))
                self.assertFalse(revocation.done())
            finally:release.set()
            self.assertTrue(operation.result(timeout=5)['ok']);revocation.result(timeout=5)
        self.kernel.request=original
        with self.assertRaises(AuthenticationError):self.boundary.request(token,request)
    def test_registry_reinitialization_refuses_legacy_or_existing_data(self):
        with self.assertRaisesRegex(ValueError,'fresh proof'):self.boundary.initialize_fresh_registry(self.pairs)

if __name__=='__main__':unittest.main(verbosity=2)
