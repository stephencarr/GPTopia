"""Synthetic principal/acceptance checkpoint. NOT real authentication or agent M1."""
import json
from pathlib import Path
import tempfile
import time
from identity import AUDIENCE, SCOPES, Principal
from kernel import Kernel


def run():
    with tempfile.TemporaryDirectory(prefix='gptopia-acceptance-') as directory:
        kernel = Kernel(Path(directory) / 'world.sqlite3')
        kernel.initialize()
        principals = {actor: Principal(actor, 'synthetic-demo', actor, 'test-control-' + actor,
                       frozenset({'plaza'}), frozenset(SCOPES.values()), AUDIENCE,
                       time.time() + 60, assurance='synthetic') for actor in ['alice', 'bob']}
        def call(actor, op, key=None, **args):
            request = {'op': op, 'args': {'space': 'plaza', **args}}
            if key:
                request['idempotency_key'] = key
            response = kernel.request(principals[actor], request)
            assert response['ok'], response
            return response['result']
        created = call('alice', 'create', 'design', content='Alice: garden. Bob: seed library.',
                       readers=['alice','bob'], writers=['alice','bob'])
        receipt = None
        for actor in principals:
            receipt = call(actor, 'accept', actor+'-accept', id=created['id'], version=created['version'], content_sha256=created['content_sha256'])
        assert receipt['acceptance']['test_multi_party_attested']
        assert not receipt['acceptance']['multi_party_attested']
        call('bob', 'update', 'revision', id=created['id'], expected_version=1, content='Revised design requires new acceptance.')
        current = call('alice', 'get', id=created['id'])
        history = call('alice', 'history', id=created['id'])
        assert not current['acceptance']['records']
        assert history['items'][0]['acceptance']['test_multi_party_attested']
        print(json.dumps({'checkpoint':'synthetic verified-principal seam and same-revision acceptance; NOT M1',
                          'same_revision_test_accepted': receipt,
                          'after_edit': current,
                          'historical_acceptance_preserved': True,
                          'real_verifier_configured': False,
                          'external_connections': False}, indent=2))

if __name__ == '__main__':
    run()
