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
        self.grants = {'grant-pip': {'issuer':'https://issuer.example/','subject':'subject-pip','actor':'pip','control_domain':'pip-runtime','client_id':'pip-client','spaces':['pilot'], 'scopes':sorted(set(SCOPES.values())),'expires_at':self.now+600}}
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
        from unittest.mock import patch
        with patch('production.time.time', return_value=self.now+601), self.assertRaises(AuthenticationError):
            self.verify(self.token())
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

    def test_malformed_admissions_fail_at_startup(self):
        import copy
        from production import validate_admissions
        for field, value in [('client_id',None),('client_id',''),('actor',''),('control_domain',None),('spaces','pilot'),('spaces',[]),('scopes',['admin:all']),('expires_at',True),('expires_at',float('inf')),('expires_at',self.now-1)]:
            grants=copy.deepcopy(self.grants)
            grants['grant-pip'][field]=value
            with self.subTest(field=field,value=value), self.assertRaises(ValueError):
                create_app(str(Path(self.temp.name)/'must-not-exist.db'),admissions=grants)
            self.assertFalse(Path(self.temp.name,'must-not-exist.db').exists())
        with self.assertRaises(ValueError):validate_admissions({'':self.grants['grant-pip']})
        with self.assertRaises(ValueError):validate_admissions([])

    def test_missing_client_claim_never_matches_null(self):
        claims=dict(self.claims)
        claims.pop('azp')
        self.grants['grant-pip']['client_id']=None
        with self.assertRaises(AuthenticationError):
            self.verify(jwt.encode(claims,self.private,algorithm='RS256'))

    def test_resource_and_url_validation(self):
        from production import resource_origin, https_url
        for url in ['https://world.example/', 'https://world.example/api', 'http://world.example', 'https://world.example?x=1', 'https://world.example/#x', 'https://user@world.example', 'https://world.example\\evil', 'https://world.example\n']:
            with self.subTest(url=url), self.assertRaises(ValueError):resource_origin(url)
        for url in [None,'', 'https://world.example:bad', 'https://world.example:0']:
            with self.assertRaises(ValueError):https_url(url)
        with self.client(False) as c:
            response=c.post('/v1',json={})
            url=response.headers['www-authenticate'].split('"')[1]
            self.assertEqual(c.get(url).status_code,200)

    def test_closed_pilot_skips_verification(self):
        from unittest.mock import patch
        def forbidden(_):raise AssertionError('must not verify after deadline')
        app=create_app(self.db,verifier=forbidden,deadline=self.now+600)
        with TestClient(app) as c, patch('production.time.time',return_value=self.now+601):
            response=c.post('/v1',headers={'Authorization':'Bearer synthetic'},json={})
            self.assertEqual(response.status_code,403)
            self.assertEqual(response.json()['error']['code'],'pilot_closed')
            self.assertEqual(c.get('/healthz').status_code,200)

    def test_advertised_scopes_metadata_only(self):
        from production import READ_ONLY_SCOPES, from_env
        from unittest.mock import patch
        import json
        for selected in [None, [], ['objects:read'], ['objects:write']]:
            env = {'GPTOPIA_DB':self.db, 'GPTOPIA_RESOURCE':'https://world.example', 'GPTOPIA_ISSUER':'https://issuer.example/'}
            if selected is not None:
                env['GPTOPIA_ADVERTISED_SCOPES'] = json.dumps(selected)
            with patch.dict('os.environ', env, clear=True), patch('production.JWTVerifier', side_effect=AssertionError('must not construct verifier')):
                with TestClient(from_env(), base_url='https://world.example') as c:
                    self.assertEqual(c.get('/.well-known/oauth-protected-resource').json()['scopes_supported'], list(READ_ONLY_SCOPES) if selected is None else selected)
                    for path in ['/v1','/mcp']:
                        self.assertEqual(c.post(path, headers={'Authorization':'Bearer synthetic'}, content='malformed').status_code, 401)

    def test_advertised_scope_invalid_config_fails_before_db(self):
        from production import advertised_scopes_from_env
        from unittest.mock import patch
        for raw in ['null','"world:discover"','["unknown"]','[1]','{}','["objects:read","objects:read"]','broken']:
            with self.subTest(raw=raw), patch.dict('os.environ', {'GPTOPIA_ADVERTISED_SCOPES':raw}), self.assertRaises(ValueError):
                advertised_scopes_from_env()
        path=str(Path(self.temp.name)/'not-created.db')
        with self.assertRaises(ValueError):
            create_app(path, advertised_scopes=['unknown'])
        self.assertFalse(Path(path).exists())

if __name__=='__main__':unittest.main()
