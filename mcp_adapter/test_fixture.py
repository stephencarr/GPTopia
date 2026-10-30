"""TEST ONLY. Scripted identities and generated RSA keys, NOT Pip or Muse.
No network/JWKS server and no credentials are stored. Never a production entry.
"""
import json
import tempfile
import time
from types import SimpleNamespace
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from worker import Boundary, JWTVerifier, serve
from identity import SCOPES

with tempfile.TemporaryDirectory() as tmp:
    now=time.time()
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    grants={actor:{'actor':actor,'control_domain':'synthetic-'+actor,'client_id':actor+'-client','spaces':['pilot'],'scopes':sorted(set(SCOPES.values())),'expires_at':now+600} for actor in ['test-a','test-b']}
    verifier=JWTVerifier('https://issuer.example','https://world.example','https://issuer.example/jwks',grants,key_client=SimpleNamespace(get_signing_key_from_jwt=lambda _:SimpleNamespace(key=key.public_key())))
    boundary=Boundary(tmp+'/world.db',verifier,grants,now+600)
    def token(actor='test-a',**changes):
        return jwt.encode(dict(iss='https://issuer.example',aud='https://world.example',sub=actor,azp=actor+'-client',iat=now,exp=now+300,scope=' '.join(SCOPES.values()))|changes,key,algorithm='RS256')
    original=boundary.handle
    def handle(m):
        if m.get('action')=='test_restart':
            boundary.kernel = Boundary(tmp+'/world.db',verifier,grants,now+600).kernel
            return {'status':200}
        if m.get('action')=='test_setup':
            return dict(a=token(),b=token('test-b'),wrong=token(aud='wrong'),expired=token(exp=now-1),unknown=token('unknown'),read=token(scope='objects:read'),badIssuer=token(iss='https://evil.example'))
        return original(m)
    boundary.handle=handle
    serve(boundary)
