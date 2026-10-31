"""Characterization tests for an UNIMPLEMENTED issuer migration, local only.

All claims and RSA keys are synthetic. No tokens leave this process. A passing
negative characterization is NOT a passing production bridge implementation.
"""
import copy
from dataclasses import replace
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from identity import AuthenticationError
from kernel import Kernel, initialize_schema
from production import JWTVerifier, register_admissions, validate_admissions


class BridgeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.key_client = SimpleNamespace(get_signing_key_from_jwt=lambda _:
            SimpleNamespace(key=cls.key.public_key()))

    def setUp(self):
        self.now = time.time()
        self.issuer = 'https://synthetic-bridge.example/'
        self.resource = 'https://synthetic-world.example'
        self.admission = dict(issuer=self.issuer, subject='test-owner',
            client_id='test-host-client', actor='test-agent',
            control_domain='synthetic-host', spaces=['pilot'],
            scopes=['world:discover'], expires_at=self.now + 300)
        self.admissions = {'operator-admission': self.admission}
        self.verifier = JWTVerifier(self.issuer, self.resource,
            self.issuer + 'jwks', self.admissions, key_client=self.key_client)

    def token(self, grant, alias=False):
        claims = dict(iss=self.issuer, aud=self.resource, sub='test-owner',
            client_id='test-host-client', gptopia_grant_id=grant,
            iat=self.now, exp=self.now + 120, scope='world:discover')
        if alias:
            claims['azp'] = claims['client_id']
        return jwt.encode(claims, self.key, algorithm='RS256')

    def test_portable_claim_profile_is_rejected_without_explicit_bridge(self):
        # The 0.3 verifier intentionally requires the Auth0 azp profile.
        with self.assertRaises(AuthenticationError):
            self.verifier(self.token('oauth-grant-A'))

    def test_naive_client_alias_collapses_distinct_oauth_grants(self):
        first = self.verifier(self.token('oauth-grant-A', alias=True))
        second = self.verifier(self.token('oauth-grant-B', alias=True))
        self.assertEqual(first, second)
        self.assertEqual(first.grant_id, 'operator-admission')
        self.assertNotEqual(first.grant_id, 'oauth-grant-A')

    def test_unrecognized_oauth_grant_is_not_a_legacy_denial_signal(self):
        # 0.3 has no provider Grant lookup. Changing only the signed OAuth grant
        # claim cannot express active/revoked state to this verifier.
        active = self.verifier(self.token('oauth-grant-A', alias=True))
        unknown = self.verifier(self.token('unknown-or-revoked', alias=True))
        self.assertEqual(active, unknown)

    def test_two_actors_for_same_owner_client_are_rejected_by_old_registry(self):
        admissions = copy.deepcopy(self.admissions)
        admissions['another-admission'] = dict(self.admission, actor='another-agent')
        with self.assertRaisesRegex(ValueError, 'duplicate issuer/subject/client'):
            validate_admissions(admissions)

    def test_replacing_principal_grant_without_registry_migration_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            kernel = Kernel(str(Path(folder) / 'world.db'), allow_fixture=False)
            with kernel.connection() as db:
                initialize_schema(db)
                register_admissions(db, self.admissions)
            principal = self.verifier(self.token('oauth-grant-A', alias=True))
            request = {'op': 'discover', 'args': {'space': 'pilot'}}
            self.assertTrue(kernel.request(principal, request)['ok'])
            changed = replace(principal, grant_id='oauth-grant-A')
            result = kernel.request(changed, request)
            self.assertFalse(result['ok'])
            self.assertEqual(result['error']['code'], 'unauthenticated')


if __name__ == '__main__':
    unittest.main(verbosity=2)
