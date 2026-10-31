"""Local synthetic regression of Muse's reported path; no live calls or credentials."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import unittest
import test_identity_acceptance as support

class DemoHandoffTests(unittest.TestCase):
    def setUp(self):
        self.f = support.AcceptanceTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def test_identical_acl_denial_does_not_burn_key_and_omission_preserves_acl(self):
        f = self.f
        obj = f.create()
        args = dict(id=obj['id'], expected_version=1, content='Owner contribution\nPeer contribution')
        f.error(f.call('update', principal=support.synthetic('bob'), key='peer-edit',
                       readers=['alice', 'bob'], writers=['alice', 'bob'], **args), 'forbidden')
        unchanged = f.ok(f.call('get', id=obj['id']))
        self.assertEqual(unchanged['version'], 1)
        edited = f.ok(f.call('update', principal=support.synthetic('bob'), key='peer-edit', **args))
        replay = f.ok(f.call('update', principal=support.synthetic('bob'), key='peer-edit', **args))
        self.assertEqual(edited, replay)
        readback = f.ok(f.call('get', id=obj['id']))
        self.assertEqual(readback['version'], 2)
        self.assertEqual(readback['author'], 'bob')
        self.assertEqual(readback['owner'], 'alice')
        self.assertEqual(sorted(readback['readers']), ['alice', 'bob'])
        self.assertEqual(sorted(readback['writers']), ['alice', 'bob'])
        self.assertEqual(readback['acceptance']['records'], [])

    def test_readback_revision_change_blocks_prior_acceptance_without_auto_accept(self):
        f = self.f
        obj = f.create()
        seen = f.ok(f.call('get', id=obj['id']))
        f.ok(f.call('update', principal=support.synthetic('bob'), id=obj['id'],
                    expected_version=seen['version'], content='Changed after read'))
        f.error(f.accept(seen, key='owner-accept-stale'), 'conflict')
        current = f.ok(f.call('get', id=obj['id']))
        self.assertEqual(current['acceptance']['records'], [])

    def test_wrong_hash_cannot_be_accepted(self):
        f = self.f
        obj = f.create()
        f.error(f.call('accept', id=obj['id'], version=1, content_sha256='0'*64,
                       key='wrong-hash'), 'conflict')
        self.assertEqual(f.ok(f.call('get', id=obj['id']))['acceptance']['records'], [])

if __name__ == '__main__':
    unittest.main()
