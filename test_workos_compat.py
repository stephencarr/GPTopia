"""Synthetic RSA compatibility tests only; no WorkOS/network/host calls.

Reissued test JWTs model token replacement, not a tested provider renewal flow.
"""
from dataclasses import replace
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from identity import Principal
from workos_compat import ApprovedBinding, Denied, WorkOSCompatibility


class WorkOSCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.now = time.time()
        self.issuer = 'https://auth.example.test'
        self.audience = 'https://world.example.test/mcp'
        self.status = True
        self.status_calls = []
        self.key_client = SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=self.key.public_key()))
        self.claims = dict(iss=self.issuer, aud=self.audience, sub='user_owner',
                           client_id='client_pip', sid='consent_one', org_id='org_one',
                           scope='world:discover objects:read objects:write',
                           jti='token_one', iat=self.now-1, exp=self.now+299)
        self.approval = ApprovedBinding(
            ('connect_user',self.issuer,'org_one','user_owner','client_pip'),
            'pip','grant_pip','pip_host',frozenset({'pilot'}),
            frozenset({'world:discover','objects:read'}),self.now+600)
        self.adapter = self.make()

    def status_checker(self, token, identity):
        self.status_calls.append((token, identity.binding))
        return self.status

    def make(self, **overrides):
        args=dict(profile='connect_user',issuer=self.issuer,audience=self.audience,
                  key_client=self.key_client,status_checker=self.status_checker,approval=self.approval)
        return WorkOSCompatibility(**(args|overrides))

    def token(self, changes=None, *, omitted=(), key=None):
        claims=self.claims | (changes or {})
        for field in omitted: claims.pop(field,None)
        return jwt.encode(claims,key or self.key,algorithm='RS256')

    def agent(self):
        approval=replace(self.approval,binding=('agent_registration',self.issuer,'org_one','user_owner','agent_reg_muse'),actor='muse',grant_id='grant_muse',control_domain='muse_host')
        adapter=self.make(profile='agent_registration',approval=approval)
        token=self.token({'sub':'agent_reg_muse','act':{'sub':'user_owner'}},omitted=('sid','client_id'))
        return adapter,token

    def test_connect_identity_keeps_owner_client_separate(self):
        result=self.adapter.authorize(self.token(),operation='discover',space='pilot')
        self.assertEqual(result.actor,'pip')
        self.assertEqual(result.identity.owner_subject,'user_owner')
        self.assertEqual(result.identity.oauth_client_id,'client_pip')
        self.assertIsNone(result.identity.agent_registration_id)
        self.assertEqual(result.effective_scopes,frozenset({'world:discover','objects:read'}))
        self.assertNotIsInstance(result,Principal)

    def test_agent_identity_keeps_registration_owner_separate(self):
        adapter,token=self.agent()
        result=adapter.authorize(token,operation='discover',space='pilot')
        self.assertEqual(result.actor,'muse')
        self.assertEqual(result.identity.owner_subject,'user_owner')
        self.assertEqual(result.identity.agent_registration_id,'agent_reg_muse')
        self.assertIsNone(result.identity.oauth_client_id)
        self.assertNotEqual(result.identity.binding,self.adapter.verify(self.token()).binding)

    def test_wrong_verified_binding_issuer_audience_and_signature(self):
        for changes in [dict(sub='user_other'),dict(client_id='client_other'),dict(org_id='org_other'),dict(iss='https://evil.example.test'),dict(aud='https://other.example.test/mcp'),dict(aud=[self.audience]),dict(aud='environment_client_id')]:
            with self.subTest(changes=changes),self.assertRaises(Denied):self.adapter.verify(self.token(changes))
        with self.assertRaises(Denied):self.adapter.verify(self.token(key=self.other_key))
        self.assertEqual(self.status_calls,[])

    def test_required_claims_and_malformed_fields(self):
        for field in ('iss','aud','sub','org_id','scope','jti','iat','exp','client_id','sid'):
            with self.subTest(field=field),self.assertRaises(Denied):self.adapter.verify(self.token(omitted=(field,)))
        for changes in [dict(scope=[]),dict(scope='x'*4097),dict(sub=''),dict(org_id=1),dict(jti=''),dict(client_id=None),dict(sid=''),dict(exp=True),dict(iat=False),dict(exp=float('inf'))]:
            with self.subTest(changes=changes),self.assertRaises(Denied):self.adapter.verify(self.token(changes))

    def test_profiles_are_not_auto_detected_or_interchangeable(self):
        adapter,agent_token=self.agent()
        with self.assertRaises(Denied):self.adapter.verify(agent_token)
        with self.assertRaises(Denied):adapter.verify(self.token())
        for changes in [dict(act={'sub':'user_owner'}),dict(sub='agent_reg_muse')]:
            with self.assertRaises(Denied):self.adapter.verify(self.token(changes))
        # M2M lacks a user consent ID; not accepted as human authorization.
        with self.assertRaises(Denied):self.adapter.verify(self.token({'sub':'client_pip'},omitted=('sid',)))

    def test_agent_missing_owner_anonymous_nested_delegation_denied(self):
        adapter,_=self.agent()
        for act in (None,{},'user_owner',{'sub':'user_other'},{'sub':'user_owner','act':{'sub':'nested'}}):
            with self.subTest(act=act),self.assertRaises(Denied):
                adapter.verify(self.token({'sub':'agent_reg_muse','act':act},omitted=('client_id','sid')))
        with self.assertRaises(Denied):adapter.verify(self.token({'sub':'agent_reg_other','act':{'sub':'user_owner'}},omitted=('client_id','sid')))

    def test_untrusted_spoof_claims_do_not_change_attribution(self):
        result=self.adapter.authorize(self.token({'actor':'muse','grant_id':'grant_muse','control_domain':'other','azp':'other'}),operation='discover',space='pilot')
        self.assertEqual((result.actor,result.grant_id,result.control_domain),('pip','grant_pip','pip_host'))
        with self.assertRaises(Denied):self.adapter.verify(self.token({'azp':'client_pip'},omitted=('client_id',)))

    def test_scope_intersection_and_space_ceiling(self):
        token=self.token()
        for operation,space in [('create','pilot'),('discover','outside'),('admin','pilot')]:
            with self.subTest(operation=operation,space=space),self.assertRaisesRegex(Denied,'permission_missing'):
                self.adapter.authorize(token,operation=operation,space=space)
        with self.assertRaisesRegex(Denied,'permission_missing'):
            self.adapter.authorize(self.token({'scope':'openid profile'}),operation='discover',space='pilot')
        result=self.adapter.authorize(self.token({'scope':'world:discover admin:all'}),operation='discover',space='pilot')
        self.assertEqual(result.effective_scopes,frozenset({'world:discover'}))

    def test_status_rechecked_no_positive_cache_and_strict_bool(self):
        token=self.token()
        self.adapter.authorize(token,operation='discover',space='pilot')
        for status in (False,None,1,0,'verified',[],{}, {'active':True}):
            self.status=status
            with self.subTest(status=status),self.assertRaises(Denied):self.adapter.authorize(token,operation='discover',space='pilot')
        self.assertEqual(len(self.status_calls),9)
        def unavailable(token,identity):raise TimeoutError('synthetic status service unavailable')
        with self.assertRaises(Denied):self.make(status_checker=unavailable).verify(token)

    def test_token_and_approval_expiry_and_lifetime(self):
        for changes in [dict(exp=self.now-1),dict(exp=self.now+7200),dict(iat=self.now+60),dict(nbf=self.now+60)]:
            with self.subTest(changes=changes),self.assertRaises(Denied):self.adapter.verify(self.token(changes))
        expired=self.make(approval=replace(self.approval,expires_at=self.now-1))
        with self.assertRaises(Denied):expired.verify(self.token())
        near=self.make(approval=replace(self.approval,expires_at=self.now+10))
        self.assertEqual(near.authorize(self.token(),operation='discover',space='pilot').expires_at,self.now+10)

    def test_synthetic_reissuance_retains_identity_but_not_expired_credentials(self):
        first=self.adapter.authorize(self.token(),operation='discover',space='pilot')
        # This signs a synthetic replacement, NOT a call to WorkOS refresh.
        next_token=self.token({'jti':'token_two','exp':self.now+500})
        second=self.adapter.authorize(next_token,operation='discover',space='pilot')
        self.assertEqual((first.actor,first.grant_id,first.identity.binding),(second.actor,second.grant_id,second.identity.binding))
        self.assertNotEqual(first.identity.token_id,second.identity.token_id)
        with self.assertRaises(Denied):self.adapter.verify(self.token({'jti':'token_three','client_id':'other'}))
        self.status=False
        with self.assertRaises(Denied):self.adapter.verify(next_token)

    def test_synthetic_agent_reissuance_preserves_registration(self):
        adapter,token=self.agent()
        first=adapter.verify(token)
        renewed=self.token({'sub':'agent_reg_muse','act':{'sub':'user_owner'},'jti':'renewed_agent'},omitted=('sid','client_id'))
        self.assertEqual(first.binding,adapter.verify(renewed).binding)
        with self.assertRaises(Denied):adapter.verify(self.token({'sub':'agent_reg_new','act':{'sub':'user_owner'},'jti':'renewed_agent'},omitted=('sid','client_id')))

    def test_no_token_algorithm_or_format_fallback(self):
        bad_tokens=(None,'','x'*8193,'not.a.jwt',jwt.encode(self.claims,'synthetic-shared-secret-not-real',algorithm='HS256'))
        for token in bad_tokens:
            with self.subTest(token_type=type(token).__name__),self.assertRaises(Denied):self.adapter.verify(token)

    def test_constructor_requires_explicit_fail_closed_dependencies(self):
        for changes in [dict(profile='auto'),dict(issuer='http://issuer.test'),dict(audience='environment_client'),dict(key_client=None),dict(status_checker=None),dict(max_token_lifetime=True),dict(max_token_lifetime=3601),dict(max_token_lifetime=0)]:
            with self.subTest(changes=changes),self.assertRaises(ValueError):self.make(**changes)
        for approval in [replace(self.approval,binding=('connect_user',self.issuer,'org_other')),replace(self.approval,spaces=frozenset()),replace(self.approval,scopes=frozenset({'admin:all'})),replace(self.approval,expires_at=float('nan')),replace(self.approval,actor=''),replace(self.approval,spaces={'pilot'})]:
            with self.subTest(approval=approval),self.assertRaises(ValueError):self.make(approval=approval)


if __name__=='__main__': unittest.main()
