"""Synthetic-only tests; generated keys never leave this process."""
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient
from identity import AuthenticationError, Principal, AUDIENCE, SCOPES
from production import create_app, JWTVerifier

class ProductionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.temp.name) / 'world.db')
        self.now = time.time()
        self.grants = {'subject-pip': {'actor':'pip','control_domain':'pip-runtime','client_id':'pip-client','spaces':['pilot'], 'scopes':list(SCOPES.values()),'expires_at':self.now+600}}
        self.private = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        keyclient = SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=self.private.public_key()))
        self.verify = JWTVerifier('https://issuer.example/','https://world.example','https://issuer.example/jwks',self.grants,key_client=keyclient)
        self.claims = dict(iss='https://issuer.example/', aud='https://world.example',sub='subject-pip',azp='pip-client',exp=self.now+300,iat=self.now,scope=' '.join(SCOPES.values()))
    def tearDown(self): self.temp.cleanup()
    def token(self, **changes): return jwt.encode(self.claims | changes, self.private, algorithm='RS256')
    def client(self, verifier=True):
        return TestClient(create_app(self.db,'https://world.example','https://issuer.example/',self.verify if verifier else None,self.grants,self.now+600),base_url='https://world.example')
    def test_deny_default_all_routes(self):
        with self.client(False) as c:
            self.assertEqual(c.get('/healthz').status_code,200)
            self.assertEqual(c.get('/.well-known/oauth-protected-resource').status_code,200)
            for path in ['/v1','/mcp','/unknown']:
                self.assertEqual(c.post(path,json={}).status_code,401)
    def test_signature_claims_and_admission(self):
        self.assertEqual(self.verify(self.token()).actor,'pip')
        for changes in [dict(aud='wrong'),dict(iss='https://evil.example/'),dict(exp=self.now-10),dict(nbf=self.now+100),dict(sub='unknown'),dict(azp='muse-client'),dict(exp=self.now+7200),dict(scope=[]),dict(iat=self.now+100)]:
            with self.assertRaises(AuthenticationError): self.verify(self.token(**changes))
        wrong = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        with self.assertRaises(AuthenticationError): self.verify(jwt.encode(self.claims,wrong,algorithm='RS256'))
        self.grants['subject-pip']['expires_at'] = self.now-1
        with self.assertRaises(AuthenticationError): self.verify(self.token())
    def test_authenticated_and_spoof_denial(self):
        with self.client() as c:
            h={'Authorization':'Bearer '+self.token()}
            response=c.post('/v1',headers=h,json={'op':'discover','args':{'space':'pilot'}})
            self.assertEqual(response.status_code,200, response.text)
            self.assertEqual(c.post('/v1',headers=h|{'X-Test-Actor':'bob'},json={}).status_code,401)
            self.assertEqual(c.post('/v1',headers=h|{'Origin':'https://world.example'},json={}).status_code,401)
            self.assertEqual(c.post('/v1',headers=h,json={'op':'discover','actor':'bob','args':{'space':'pilot'}}).status_code,400)
            self.assertEqual(c.post('/v1',headers=h,json={'op':'discover','args':{'space':'other'}}).status_code,401)
            self.assertEqual(c.post('/v1',headers=h|{'Content-Type':'application/json'},content='x'*32769).status_code,413)
    def test_no_fixture_admission(self):
        with self.client() as c:
            import sqlite3
            with sqlite3.connect(self.db) as db:
                self.assertEqual(db.execute('SELECT id FROM identities').fetchall(),[('pip',)])
    def test_scope_intersection(self):
        self.assertEqual(self.verify(self.token(scope='objects:read admin:all')).scopes,frozenset({'objects:read'}))
    def test_synthetic_verifier_refused(self):
        def fixture(_):return Principal('pip','issuer','sub','controller',frozenset({'pilot'}),frozenset(SCOPES.values()),AUDIENCE,self.now+600,assurance='synthetic')
        with TestClient(create_app(self.db,verifier=fixture,deadline=self.now+600)) as c:
            self.assertEqual(c.post('/v1',headers={'Authorization':'Bearer synthetic'},json={}).status_code,401)

if __name__=='__main__':unittest.main()
