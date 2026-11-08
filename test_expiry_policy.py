"""Explicit pilot retirement must retain token expiry and admission revocation."""
import io
import os
import sqlite3
import unittest
from contextlib import redirect_stderr
from types import SimpleNamespace
from unittest.mock import patch
from starlette.testclient import TestClient
import test_production as fixtures
from identity import AuthenticationError
from production import JWTVerifier, create_app, validate_admissions, validate_deadline, deadline_from_env
from mcp_adapter.worker import Boundary, main


class ExpiryPolicyTests(unittest.TestCase):
    setUp = fixtures.ProductionTests.setUp
    tearDown = fixtures.ProductionTests.tearDown
    token = fixtures.ProductionTests.token

    def verifier(self, grants=None):
        return JWTVerifier('https://issuer.example/', 'https://world.example',
            'https://issuer.example/jwks', self.grants if grants is None else grants,
            key_client=SimpleNamespace(get_signing_key_from_jwt=lambda _: SimpleNamespace(key=self.private.public_key())))

    def test_explicit_no_admission_expiry_retains_token_bounds_and_identity(self):
        self.grants['grant-pip']['expires_at'] = None
        verify = self.verifier()
        principal = verify(self.token())
        self.assertEqual(principal.expires_at, self.claims['exp'])
        self.assertEqual(principal.actor, 'pip')
        self.assertEqual(principal.grant_id, 'grant-pip')
        for changes in [dict(exp=self.now-1), dict(exp=self.now+7200), dict(azp='wrong')]:
            with self.assertRaises(AuthenticationError): verify(self.token(**changes))
        with self.assertRaises(AuthenticationError): self.verifier({})(self.token())

    def test_dated_admissions_still_expire_and_long_lived_dates_are_supported(self):
        self.grants['grant-pip']['expires_at'] = self.now + 30*86400
        self.assertEqual(self.verifier()(self.token()).expires_at, self.claims['exp'])
        self.grants['grant-pip']['expires_at'] = self.now + 1
        verify = self.verifier()
        with patch('production.time.time',return_value=self.now+2):
            with self.assertRaises(AuthenticationError): verify(self.token())
        for value in [True, 'none', float('inf'), self.now-1]:
            self.grants['grant-pip']['expires_at'] = value
            with self.assertRaises(ValueError): validate_admissions(self.grants)
        del self.grants['grant-pip']['expires_at']
        with self.assertRaises(ValueError): validate_admissions(self.grants)

    def test_deadline_removal_requires_explicit_selection(self):
        with patch.dict(os.environ,{},clear=True):
            self.assertEqual(deadline_from_env(),0)
            os.environ['GPTOPIA_DEADLINE']='none'
            self.assertIsNone(deadline_from_env())
            os.environ['GPTOPIA_DEADLINE']='secret-invalid-value'
            with self.assertRaisesRegex(ValueError,'^invalid service deadline$'): deadline_from_env()
        for value in [None, 0, self.now+30*86400]: validate_deadline(value)
        for value in [True, float('nan'), float('inf'), -1, self.now-1, 'none']:
            with self.assertRaises(ValueError): validate_deadline(value)

    def test_no_service_cutoff_http_and_worker_keep_authentication_and_scope_checks(self):
        self.grants['grant-pip']['expires_at'] = None
        verify = self.verifier()
        boundary = Boundary(self.db,verify,self.grants,deadline=None)
        message = dict(action='call',token=self.token(),payload={'op':'discover','args':{'space':'pilot'}})
        self.assertTrue(boundary.handle(message)['result']['ok'])
        self.assertEqual(boundary.handle(message | {'token':self.token(exp=self.now-1)})['status'],401)
        denied = boundary.handle(message | {'token':self.token(scope='objects:read')})
        self.assertFalse(denied['result']['ok'])
        with TestClient(create_app(self.db,'https://world.example','https://issuer.example/',verify,self.grants,None),base_url='https://world.example') as client:
            self.assertEqual(client.post('/v1',json=message['payload']).status_code,401)
            self.assertEqual(client.post('/v1',json=message['payload'],headers={'Authorization':'Bearer '+self.token()}).status_code,200)
            self.assertEqual(client.post('/v1',json=message['payload'],headers={'Authorization':'Bearer '+self.token(exp=self.now-1)}).status_code,401)
        self.assertEqual(Boundary(self.db,verify,self.grants).handle(message)['status'],403)
        self.assertEqual(Boundary(self.db,deadline=None).handle(message)['status'],401)

    def test_token_expiry_during_dispatch_rolls_back_without_service_cutoff(self):
        self.grants['grant-pip']['expires_at'] = None
        boundary = Boundary(self.db,self.verifier(),self.grants,None)
        token = self.token()
        dispatch = boundary.kernel.dispatch
        def expire(*args):
            result = dispatch(*args)
            clock.return_value = self.claims['exp']
            return result
        with patch('time.time',return_value=self.now) as clock, patch.object(boundary.kernel,'dispatch',expire):
            result = boundary.handle(dict(action='call',token=token,payload={'op':'create','idempotency_key':'expiry','args':{'space':'pilot','content':'test','readers':['pip'],'writers':['pip']}}))
        self.assertFalse(result['result']['ok'])
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM objects').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM retries').fetchone()[0],0)

    def test_retirement_preserves_binding_and_reopens_existing_database(self):
        Boundary(self.db,self.verify,self.grants,self.now+600)
        with sqlite3.connect(self.db) as db:
            before=db.execute('SELECT * FROM admission_bindings').fetchall()
        self.grants['grant-pip']['expires_at']=None
        Boundary(self.db,self.verifier(),self.grants,None)
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute('SELECT * FROM admission_bindings').fetchall(),before)

    def test_startup_diagnostics_contain_only_fixed_reason_codes(self):
        for exc, code in [(ValueError('invalid admission expiry'),'admission_expiry_invalid'),
                          (ValueError('invalid service deadline'),'service_deadline_invalid'),
                          (ValueError('SECRET_CONFIG'),'configuration_invalid'),
                          (sqlite3.OperationalError('SECRET_PATH'),'storage_unavailable'),
                          (RuntimeError('SECRET_TOKEN'),'unexpected_startup_failure')]:
            stderr=io.StringIO()
            with patch('mcp_adapter.worker.from_env',side_effect=exc), redirect_stderr(stderr):
                self.assertEqual(main(),1)
            self.assertEqual(stderr.getvalue(),'GPTOPIA_WORKER_STARTUP_ERROR:'+code+'\n')
