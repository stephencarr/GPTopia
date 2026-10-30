"""Local synthetic RSA/ASGI tests only: no provider contact or runtime attestation."""
import copy
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
from starlette.testclient import TestClient
from identity import AuthenticationError, SCOPES, validate
from kernel import Kernel, initialize_schema
from production import JWTVerifier, create_app, register_admissions, validate_admissions

ISSUER = 'https://synthetic-issuer.example/'
RESOURCE = 'https://synthetic-world.example'
OWNER = 'same-human-owner-subject'

class AgentBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ephemeral test key, not a real credential; never serialized or transmitted.
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.keys = SimpleNamespace(get_signing_key_from_jwt=lambda _: SimpleNamespace(key=cls.private.public_key()))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'world.db')
        self.now = time.time()
        self.grants = {f'grant-{actor}': dict(issuer=ISSUER, subject=OWNER,
            client_id=f'{actor}-client', actor=actor, control_domain=f'{actor}-controller',
            spaces=['pilot'], scopes=sorted(set(SCOPES.values())), expires_at=self.now+600)
            for actor in ['pip','muse']}
        self.verifier = self.verifier_for(self.grants)
        self.seq = 0

    def verifier_for(self, grants):
        return JWTVerifier(ISSUER, RESOURCE, ISSUER+'jwks', grants, key_client=self.keys)

    def token(self, actor='pip', omit=(), **changes):
        claims = dict(iss=ISSUER, aud=RESOURCE, sub=OWNER, azp=actor+'-client',
                      iat=self.now, exp=self.now+300, scope=' '.join(SCOPES.values()))
        claims.update(changes)
        for key in omit:
            claims.pop(key, None)
        return jwt.encode(claims, self.private, algorithm='RS256')

    def client(self, grants=None, verifier=None):
        return TestClient(create_app(self.path, RESOURCE, ISSUER,
            verifier or self.verifier, self.grants if grants is None else grants,
            self.now+600), base_url=RESOURCE)

    def call(self, client, actor, op, **args):
        self.seq += 1
        body = {'op':op, 'args':{'space':'pilot', **args}}
        if op in {'create','update','send','accept'}:
            body['idempotency_key'] = f'request-{self.seq}'
        response = client.post('/v1', headers={'Authorization':'Bearer '+self.token(actor)}, json=body)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()['result']

    def test_same_owner_two_signed_clients_create_update_and_accept(self):
        pip, muse = self.verifier(self.token()), self.verifier(self.token('muse'))
        self.assertEqual((pip.issuer,pip.subject), (muse.issuer,muse.subject))
        self.assertNotEqual(pip.client_id, muse.client_id)
        self.assertNotEqual(pip.grant_id, muse.grant_id)
        with self.client() as client:
            artifact = self.call(client, 'pip', 'create', content='Draft', readers=['pip','muse'], writers=['pip','muse'])
            artifact = self.call(client, 'muse', 'update', id=artifact['id'], expected_version=1, content='Shared draft')
            self.assertEqual(artifact['owner'], 'pip')
            self.assertEqual(artifact['author'], 'muse')
            args = {k:artifact[k] for k in ['id','version','content_sha256']}
            first = self.call(client, 'pip', 'accept', **args)
            self.assertFalse(first['acceptance']['multi_party_attested'])
            final = self.call(client, 'muse', 'accept', **args)
            self.assertTrue(final['acceptance']['multi_party_attested'])
            self.assertFalse(final['acceptance']['test_multi_party_attested'])
            rows = final['acceptance']['records']
            self.assertEqual({r['subject'] for r in rows}, {OWNER})
            self.assertEqual({r['client_id'] for r in rows}, {'pip-client','muse-client'})
            self.assertEqual({r['grant_id'] for r in rows}, {'grant-pip','grant-muse'})
        with self.client() as restarted:
            current = self.call(restarted, 'pip', 'get', id=artifact['id'])
            self.assertEqual(current['owner'], 'pip')
            self.assertTrue(current['acceptance']['multi_party_attested'])

    def test_azp_required_no_client_id_fallback_and_malformed_claims(self):
        for changes in [dict(azp=None),dict(azp=[]),dict(azp={}),dict(azp=''),dict(azp='pip client'),dict(azp='unadmitted'),
                        dict(sub='different-owner'),dict(iss='https://other.example/'),dict(scope=[]),dict(aud='wrong')]:
            with self.subTest(changes=changes), self.assertRaises(AuthenticationError):
                self.verifier(self.token(**changes))
        for changes in [{}, {'client_id':'pip-client'}]:
            with self.assertRaises(AuthenticationError):
                self.verifier(self.token(omit=('azp',), **changes))
        for claim in ['client_id', '', None]:
            with self.assertRaises(ValueError):
                JWTVerifier(ISSUER,RESOURCE,ISSUER+'jwks',self.grants,client_claim=claim,key_client=self.keys)

    def test_wrong_client_signature_and_scopes(self):
        wrong = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        claims = jwt.decode(self.token(),options={'verify_signature':False})
        with self.assertRaises(AuthenticationError):
            self.verifier(jwt.encode(claims,wrong,algorithm='RS256'))
        principal = self.verifier(self.token(scope='objects:read admin:all'))
        self.assertEqual(principal.scopes, frozenset({'objects:read'}))
        with self.assertRaises(AuthenticationError):
            validate(principal, 'create', 'pilot')
        for field in ['client_id','grant_id']:
            with self.assertRaises(AuthenticationError):
                validate(replace(principal, **{field:None}), 'get', 'pilot')

    def test_grants_require_unique_actor_and_exact_tuple(self):
        for field, value in [('actor','pip'),('client_id','pip-client')]:
            grants = copy.deepcopy(self.grants)
            grants['grant-muse'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_admissions(grants)
        for field in ['issuer','subject','client_id']:
            grants = copy.deepcopy(self.grants)
            grants['grant-pip'].pop(field)
            with self.assertRaises(ValueError):
                validate_admissions(grants)
        grants = copy.deepcopy(self.grants)
        grants['grant-pip']['issuer'] = 'https://different.example/'
        with self.assertRaises(ValueError):
            self.verifier_for(grants)
        self.assertEqual(len(validate_admissions(self.grants)), 2)

    def test_verifier_configuration_is_frozen_detached_snapshot(self):
        self.grants['grant-pip']['client_id'] = 'attacker-client'
        self.grants['grant-pip']['spaces'].append('other')
        self.grants['grant-pip']['expires_at'] = self.now-1
        principal = self.verifier(self.token())
        self.assertEqual(principal.client_id, 'pip-client')
        self.assertEqual(principal.spaces, frozenset({'pilot'}))
        with self.assertRaises(TypeError):
            self.verifier.admissions['grant-pip']['actor'] = 'other'
        with self.assertRaises(TypeError):
            self.verifier.admissions['new-grant'] = {}

    def test_expiry_and_removed_active_grant_revocation(self):
        with self.assertRaises(AuthenticationError):
            self.verifier(self.token(exp=self.now-1))
        # Grant expiry is checked every call, independently of a still-valid token.
        grants = copy.deepcopy(self.grants)
        grants['grant-pip']['expires_at'] = self.now+30
        short = self.verifier_for(grants)
        with patch('production.time.time', return_value=self.now+31), self.assertRaises(AuthenticationError):
            short(self.token())
        reduced = {'grant-muse': copy.deepcopy(self.grants['grant-muse'])}
        replacement = self.verifier_for(reduced)
        with self.assertRaises(AuthenticationError):
            replacement(self.token())
        self.assertEqual(replacement(self.token('muse')).actor, 'muse')
        with self.client():
            pass
        with self.client(reduced,replacement) as restarted:
            denied = restarted.post('/v1',headers={'Authorization':'Bearer '+self.token()},json={'op':'discover','args':{'space':'pilot'}})
            self.assertEqual(denied.status_code,401)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM admission_bindings').fetchone()[0],2)

    def test_immutable_binding_rejects_startup_reassignment(self):
        with self.client():
            pass
        for field,value in [('actor','replacement'),('issuer','https://other.example/'),('subject','other-owner'),('client_id','other-client'),('control_domain','other-controller')]:
            changed = copy.deepcopy(self.grants)
            changed['grant-pip'][field] = value
            with self.subTest(field=field), self.assertRaises((ValueError, sqlite3.IntegrityError)):
                with sqlite3.connect(self.path) as db:
                    register_admissions(db, changed)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT subject,client_id,control_domain FROM admission_bindings WHERE grant_id='grant-pip'").fetchone(), (OWNER,'pip-client','pip-controller'))
            for statement in ['DELETE FROM admission_bindings','UPDATE admission_bindings SET subject="replacement"']:
                with self.assertRaises(sqlite3.IntegrityError):
                    db.execute(statement)

    def test_removed_binding_cannot_be_reused_as_new_grant_or_actor(self):
        with self.client():
            pass
        reduced = {'grant-muse': self.grants['grant-muse']}
        with sqlite3.connect(self.path) as db:
            register_admissions(db,reduced)
        for newactor in ['pip','other-actor']:
            grants = {'new-grant':dict(self.grants['grant-pip'],actor=newactor)}
            with self.subTest(actor=newactor), self.assertRaises((ValueError,sqlite3.IntegrityError)):
                with sqlite3.connect(self.path) as db:
                    register_admissions(db,grants)
        with sqlite3.connect(self.path) as db:
            self.assertIsNone(db.execute("SELECT 1 FROM admission_bindings WHERE grant_id='new-grant'").fetchone())

    def test_existing_unbound_actor_is_not_silently_claimed(self):
        with sqlite3.connect(self.path) as db:
            initialize_schema(db)
            db.execute('INSERT INTO identities VALUES (?,?)',('pip','[]'))
            db.commit()
            with self.assertRaises(ValueError):
                register_admissions(db,self.grants)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM admission_bindings').fetchone()[0],0)

    def test_predicate_rejects_shared_client_grant_or_controller(self):
        # Direct fixture insertion isolates the predicate; never represents admitted agents.
        kernel = Kernel(self.path)
        with kernel.connection() as db:
            initialize_schema(db)
            for i, (field,value) in enumerate([('client_id','pip-client'),('grant_id','grant-pip'),('control_domain','pip-controller'),('actor','pip')]):
                oid=f'predicate-{i}'
                first=dict(object_id=oid,version=1,content_sha256='hash',actor='pip',issuer=ISSUER,subject=OWNER,control_domain='pip-controller',assurance='verified',created=self.now,client_id='pip-client',grant_id='grant-pip')
                second=first|dict(actor='muse',client_id='muse-client',grant_id='grant-muse',control_domain='muse-controller')|{field:value}
                db.execute('INSERT INTO acceptances ('+','.join(first)+') VALUES ('+','.join('?' for _ in first)+')',tuple(first.values()))
                if field=='actor':
                    with self.assertRaises(sqlite3.IntegrityError):
                        db.execute('INSERT INTO acceptances ('+','.join(second)+') VALUES ('+','.join('?' for _ in second)+')',tuple(second.values()))
                else:
                    db.execute('INSERT INTO acceptances ('+','.join(second)+') VALUES ('+','.join('?' for _ in second)+')',tuple(second.values()))
                self.assertFalse(kernel.acceptance_status(db,oid,1,'hash')['multi_party_attested'])
            db.commit()

    def test_legacy_acceptance_retry_cannot_replay_old_threshold(self):
        import json
        with self.client() as client:
            artifact = self.call(client, 'pip', 'create', content='Draft', readers=['pip','muse'], writers=['pip','muse'])
            request = {'op':'accept','args':{'space':'pilot','id':artifact['id'],'version':1,'content_sha256':artifact['content_sha256']},'idempotency_key':'legacy-retry'}
            headers = {'Authorization':'Bearer '+self.token()}
            first = client.post('/v1',headers=headers,json=request)
            self.assertEqual(first.status_code,200)
            self.assertEqual(client.post('/v1',headers=headers,json=request).json(),first.json())
            legacy = first.json()
            for record in legacy['result']['acceptance']['records']:
                record.pop('client_id'); record.pop('grant_id')
            legacy['result']['acceptance']['multi_party_attested'] = True
            with sqlite3.connect(self.path) as db:
                db.execute('UPDATE retries SET response=? WHERE actor=? AND key=?', (json.dumps(legacy),'pip','legacy-retry'))
                db.commit()
            replay = client.post('/v1',headers=headers,json=request)
            self.assertEqual(replay.status_code,409)
            self.assertFalse(replay.json()['ok'])
            with sqlite3.connect(self.path) as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0],1)

    def test_kernel_crosschecks_principal_against_immutable_registry(self):
        with self.client():
            pass
        kernel = Kernel(self.path)
        principal = self.verifier(self.token())
        request = {'op':'discover', 'args':{'space':'pilot'}}
        self.assertTrue(kernel.request(principal,request)['ok'])
        for field,value in [('client_id','muse-client'),('grant_id','grant-muse'),
                            ('grant_id','unknown-grant'),('subject','other-human'),
                            ('control_domain','other-controller'),('issuer','https://other.example/'),
                            ('actor','muse')]:
            with self.subTest(field=field,value=value):
                result = kernel.request(replace(principal,**{field:value}),request)
                self.assertFalse(result['ok'])
                self.assertEqual(result['error']['code'],'unauthenticated')
        # Even a trusted injected verifier cannot accidentally map a mismatched
        # client to an already registered actor at the HTTP boundary.
        inconsistent = replace(principal,client_id='muse-client')
        with self.client(verifier=lambda _: inconsistent) as client:
            response=client.post('/v1',headers={'Authorization':'Bearer synthetic-local-only'},json=request)
            self.assertEqual(response.status_code,401)
        with self.client() as client:
            self.call(client,'pip','discover')

    def test_legacy_acceptance_migration_preserves_unbound_nonqualifying_rows(self):
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE acceptances (object_id TEXT NOT NULL,version INTEGER NOT NULL,content_sha256 TEXT NOT NULL,actor TEXT NOT NULL,issuer TEXT NOT NULL,subject TEXT NOT NULL,control_domain TEXT NOT NULL,assurance TEXT NOT NULL,created REAL NOT NULL,PRIMARY KEY(object_id,version,actor))')
            for actor in ['pip','muse']:
                db.execute('INSERT INTO acceptances VALUES (?,?,?,?,?,?,?,?,?)',('legacy',1,'hash',actor,ISSUER,OWNER,actor+'-controller','verified',self.now))
            db.commit()
            initialize_schema(db)
            rows=db.execute('SELECT actor,client_id,grant_id FROM acceptances ORDER BY actor').fetchall()
            self.assertEqual(rows,[('muse',None,None),('pip',None,None)])
            initialize_schema(db)
        kernel=Kernel(self.path)
        with kernel.connection() as db:
            status=kernel.acceptance_status(db,'legacy',1,'hash')
            self.assertEqual(len(status['records']),2)
            self.assertFalse(status['multi_party_attested'])
            self.assertFalse(status['test_multi_party_attested'])
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE acceptances SET client_id='invented'")

if __name__=='__main__': unittest.main()
