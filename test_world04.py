"""Local 0.4 tests. Synthetic fixtures only; no live database, provider or external network."""
import concurrent.futures
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from identity import fixture
from kernel import Kernel, MUTATIONS, SCHEMA, initialize_schema

class World04Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'world.db'
        self.k=Kernel(self.path,allow_fixture=True,max_mutations=5000,max_objects=2000)
        self.k.initialize(); self.n=0
        with self.k.connection() as db:
            db.execute("INSERT INTO members VALUES ('plaza','eve')");db.commit()
    def call(self,op,who='alice',key=None,**args):
        self.n+=1
        request={'op':op,'args':args if op=='roots' else {'space':'plaza',**args}}
        if op in MUTATIONS:request['idempotency_key']=key or f'key-{self.n}'
        return self.k.request(who,request)
    def ok(self,r):self.assertTrue(r['ok'],r);return r['result']
    def err(self,r,code):self.assertFalse(r['ok'],r);self.assertEqual(r['error']['code'],code,r)
    def child(self):return self.ok(self.call('space_create',title='Workshop'))['id']
    def info(self,s):return self.ok(self.call('space_get',space=s))
    def invite(self,s,actor='bob'):
        return self.ok(self.call('space_invite',space=s,actor=actor,expected_version=self.info(s)['version']))
    def join(self,s,actor='bob'):
        inv=self.invite(s,actor)
        return self.ok(self.call('space_accept',who=actor,space=s,invite_id=inv['id']))
    def remove(self,s,actor='bob'):
        return self.ok(self.call('space_remove',space=s,actor=actor,expected_version=self.info(s)['version']))
    def artifact(self,s,**overrides):
        return self.ok(self.call('create',**(dict(space=s,content='shared',readers=['alice','bob'],writers=['alice'],title='Design',tags=['design'])|overrides)))

    def test_roots_bootstrap_and_scope_ceiling(self):
        roots=self.ok(self.call('roots'))['items']
        self.assertEqual(roots,[{'id':'garden'},{'id':'plaza'}])
        principal=replace(fixture('alice'),scopes=frozenset({'world:discover'}))
        result=self.ok(self.call('discover',who=principal))
        self.assertEqual(result['effective_scopes'],['world:discover'])
        self.assertNotIn('space_create',result['operations'])
        for op,args in [('space_create',{'title':'blocked'}),('catalog',{}),('post',{'content':'blocked'})]:
            self.err(self.call(op,who=principal,**args),'forbidden')
        self.assertEqual(self.ok(self.call('roots',who=replace(principal,spaces=frozenset({'garden'}))))['items'],[{'id':'garden'}])

    def test_invitation_target_privacy_and_membership_lifecycle(self):
        s=self.child(); self.err(self.call('space_get',who='bob',space=s),'forbidden')
        inv=self.invite(s)
        pending=self.ok(self.call('space_get',who='bob',space=s))
        self.assertEqual(pending['members'],[]);self.assertEqual(pending['invitation']['id'],inv['id'])
        self.assertEqual(self.ok(self.call('spaces',who='eve'))['items'],[])
        self.err(self.call('space_accept',who='eve',space=s,invite_id=inv['id']),'not_found')
        self.ok(self.call('space_accept',who='bob',space=s,invite_id=inv['id']))
        self.assertEqual({m['actor'] for m in self.info(s)['members']},{'alice','bob'})
        discovered=self.ok(self.call('discover',space=s))
        self.assertEqual({r['id'] for r in discovered['identities']},{'alice','bob'})
        self.err(self.call('space_invite',who='bob',space=s,expected_version=self.info(s)['version'],actor='eve'),'forbidden')

    def test_owner_cannot_leave_or_be_removed_and_member_can_leave(self):
        s=self.child();self.join(s)
        self.err(self.call('space_leave',space=s),'forbidden')
        self.err(self.call('space_remove',space=s,actor='alice',expected_version=self.info(s)['version']),'forbidden')
        self.ok(self.call('space_leave',who='bob',space=s))
        self.err(self.call('entries',who='bob',space=s),'forbidden')
        self.assertEqual(self.join(s)['epoch'],2)
        self.err(self.call('space_create',space=s,title='nested'),'invalid')

    def test_invitation_cas_expiry_malformed_and_replay(self):
        s=self.child();version=self.info(s)['version']; inv=self.invite(s)
        self.err(self.call('space_invite',space=s,actor='eve',expected_version=version),'conflict')
        for invalid in [[],{},None]:
            self.err(self.call('space_accept',who='bob',space=s,invite_id=invalid),'invalid')
        first=self.call('space_accept',who='bob',space=s,invite_id=inv['id'],key='join-once');self.ok(first)
        self.assertEqual(first,self.call('space_accept',who='bob',space=s,invite_id=inv['id'],key='join-once'))
        self.remove(s)
        self.err(self.call('space_accept',who='bob',space=s,invite_id=inv['id'],key='join-once'),'conflict')
        replacement=self.invite(s)
        with self.k.connection() as db:db.execute('UPDATE space_invites SET expires=? WHERE id=?',(time.time()-1,replacement['id']));db.commit()
        self.err(self.call('space_accept',who='bob',space=s,invite_id=replacement['id']),'conflict')
        self.assertEqual(self.ok(self.call('spaces',who='bob'))['items'],[])

    def test_posts_are_multiparty_author_readable_immutable_and_idempotent(self):
        s=self.child();self.join(s);self.join(s,'eve')
        first=self.call('post',space=s,content='Hello all',key='post-once');self.ok(first)
        self.assertEqual(first,self.call('post',space=s,content='Hello all',key='post-once'))
        self.ok(self.call('post',who='bob',space=s,content='Reply'))
        for actor in ['alice','bob','eve']:
            entries=self.ok(self.call('entries',who=actor,space=s))['items']
            self.assertEqual([r['content'] for r in entries],['Hello all','Reply'])
            self.assertEqual([r['author'] for r in entries],['alice','bob'])
        with self.k.connection() as db:
            for sql in ['DELETE FROM entries','UPDATE entries SET content="changed"']:
                with self.assertRaises(sqlite3.IntegrityError):db.execute(sql)

    def test_removed_rejoined_member_cannot_recover_old_content(self):
        s=self.child();self.join(s);oldpost=self.ok(self.call('post',space=s,content='old epoch'))
        obj=self.artifact(s);self.ok(self.call('send',space=s,recipient='bob',content='old DM'));self.remove(s)
        for op,args in [('entries',{}),('events',{}),('get',{'id':obj['id']}),('history',{'id':obj['id']}),('catalog',{})]:
            self.err(self.call(op,who='bob',space=s,**args),'forbidden')
        self.assertEqual(self.join(s)['epoch'],2)
        self.assertEqual(self.ok(self.call('entries',who='bob',space=s))['items'],[])
        self.assertEqual(self.ok(self.call('inbox',who='bob',space=s))['items'],[])
        events=self.ok(self.call('events',who='bob',space=s))['items']
        self.assertNotIn(oldpost['event'],[r['seq'] for r in events])
        for op in ['get','history']:self.err(self.call(op,who='bob',space=s,id=obj['id']),'not_found')
        self.assertEqual(self.ok(self.call('catalog',who='bob',space=s))['items'],[])
        self.ok(self.call('update',space=s,id=obj['id'],expected_version=1,content='new epoch revision',readers=['alice','bob'],writers=['alice']))
        history=self.ok(self.call('history',who='bob',space=s,id=obj['id']))['items']
        self.assertEqual([r['version'] for r in history],[2])
        self.assertEqual(len(self.ok(self.call('catalog',who='bob',space=s))['items']),1)

    def test_catalog_filters_private_metadata_before_tags_and_updates_snapshot(self):
        s=self.child();self.join(s)
        private=self.artifact(s,readers=['alice'],title='Secret title',tags=['secret'])
        shared=self.artifact(s,title='Public title',tags=['public'])
        self.assertEqual(self.ok(self.call('catalog',who='bob',space=s,tag='secret'))['items'],[])
        rows=self.ok(self.call('catalog',who='bob',space=s))['items']
        self.assertEqual([r['id'] for r in rows],[shared['id']]);self.assertNotIn('Secret',json.dumps(rows))
        self.ok(self.call('update',space=s,id=shared['id'],expected_version=1,content='revision'))
        current=self.ok(self.call('get',space=s,id=shared['id']))
        self.assertEqual((current['title'],current['tags']),('Public title',['public']))
        self.ok(self.call('update',space=s,id=private['id'],expected_version=1,content='new share',readers=['alice','bob'],writers=['alice'],title='Shared title',tags=[]))
        history=self.ok(self.call('history',who='bob',space=s,id=private['id']))['items']
        self.assertEqual([r['version'] for r in history],[2]);self.assertEqual(history[0]['title'],'Shared title')
        for extra in [{'title':'é'*61},{'tags':['a']*2},{'tags':['x'*33]},{'tags':['x']*9}]:
            self.err(self.call('create',space=s,content='bad',readers=['alice'],writers=['alice'],**extra),'invalid')

    def test_sparse_catalog_events_entries_and_history_bounded_to_500(self):
        s=self.child();self.join(s)
        # Bulk local fixtures isolate paging without spending 500 protocol writes.
        with self.k.connection() as db:
            for i in range(501):
                oid=f'private-{i}'
                db.execute('INSERT INTO objects(id,space,owner,version,content,readers,writers,title,tags) VALUES (?,?,?,?,?,?,?,?,?)',(oid,'plaza','alice',1,'private','["alice"]','["alice"]','private','[]'))
                db.execute('INSERT INTO versions(object_id,version,author,content,readers,writers,created) VALUES (?,?,?,?,?,?,?)',(oid,1,'alice','private','["alice"]','["alice"]',time.time()))
                seq=self.k.event(db,s,'entry.posted','alice',f'entry-{i}',['alice'])
                db.execute('INSERT INTO entries VALUES (?,?,?,?,?,?,?)',(f'entry-{i}',s,'alice','hidden',time.time(),seq,'{"alice":1}'))
            db.commit()
        page=self.ok(self.call('catalog',who='bob'))
        self.assertEqual(page['items'],[]);self.assertEqual(page['scanned'],500);self.assertTrue(page['has_more'])
        second=self.ok(self.call('catalog',who='bob',after=page['next_cursor']))
        self.assertEqual(second['scanned'],1);self.assertFalse(second['has_more'])
        page=self.ok(self.call('entries',who='bob',space=s))
        self.assertEqual(page['items'],[]);self.assertEqual(page['scanned'],500);self.assertTrue(page['has_more'])
        events=self.ok(self.call('events',who='bob',space=s,after=2))
        self.assertLessEqual(events['next_cursor']-2,501)
        obj=self.artifact(s,readers=['alice'])
        with self.k.connection() as db:
            for version in range(2,502):
                db.execute('INSERT INTO versions(object_id,version,author,content,readers,writers,created) VALUES (?,?,?,?,?,?,?)',(obj['id'],version,'alice','hidden','["alice"]','["alice"]',time.time()))
            db.execute('UPDATE objects SET version=501 WHERE id=?',(obj['id'],));self.k.world.snapshot_object(db,s,obj['id'],501,['alice'],explicit_grant=True);db.commit()
        self.ok(self.call('update',space=s,id=obj['id'],expected_version=501,content='visible',readers=['alice','bob'],writers=['alice']))
        page=self.ok(self.call('history',who='bob',space=s,id=obj['id']))
        self.assertEqual(page['items'],[]);self.assertEqual(page['next_cursor'],500)
        page=self.ok(self.call('history',who='bob',space=s,id=obj['id'],after=500))
        self.assertEqual([r['version'] for r in page['items']],[502])

    def test_root_quota_audit_and_disk_guard(self):
        for _ in range(10):self.child()
        self.err(self.call('space_create',title='eleventh'),'quota')
        with self.k.connection() as db:
            before=db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
            size=self.k.database_bytes(db)
        self.k.max_audit=before+1
        self.ok(self.call('roots'));self.err(self.call('roots'),'quota')
        with self.k.connection() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0],before+1)
        self.k.max_audit=20000;self.k.max_database_bytes=size-1
        self.err(self.call('space_create',title='disk blocked'),'quota')
        with self.k.connection() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM child_spaces').fetchone()[0],10)

    def test_transaction_rollback_and_cas_race(self):
        s=self.child();version=self.info(s)['version']
        with self.k.connection() as db:before=db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        self.err(self.call('space_invite',space=s,actor='unknown',expected_version=version),'forbidden')
        with self.k.connection() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],before)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM space_invites').fetchone()[0],0)
        barrier=threading.Barrier(2)
        def invite(target):
            barrier.wait()
            return self.call('space_invite',space=s,actor=target,expected_version=version,key='race-'+target)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(invite,['bob','eve']))
        self.assertEqual(sum(r['ok'] for r in results),1)
        self.assertEqual([r['error']['code'] for r in results if not r['ok']],['conflict'])

    def test_ten_targets_membership_quota_and_pending_invite_revocation(self):
        s=self.child()
        with self.k.connection() as db:
            for i in range(10):
                actor=f'guest{i}'
                db.execute('INSERT INTO identities VALUES (?,?)',(actor,'[]'))
                db.execute('INSERT INTO members VALUES (?,?)',('plaza',actor))
            db.commit()
        for i in range(9):self.invite(s,f'guest{i}')
        self.err(self.call('space_invite',space=s,actor='guest9',expected_version=self.info(s)['version']),'quota')
        self.remove(s,'guest0')
        self.invite(s,'guest9')
        self.assertEqual(self.ok(self.call('spaces',who='guest0'))['items'],[])
        with self.k.connection() as db:
            self.assertEqual(db.execute("SELECT state FROM space_invites WHERE actor='guest0'").fetchone()[0],'revoked')

    def test_page_limit100_and_transactional_disk_overflow_rolls_back(self):
        s=self.child();self.join(s)
        with self.k.connection() as db:
            for i in range(101):
                seq=self.k.event(db,s,'entry.posted','alice',f'p{i}',['alice','bob'])
                db.execute('INSERT INTO entries VALUES (?,?,?,?,?,?,?)',(f'p{i}',s,'alice','text',time.time(),seq,'{"alice":1,"bob":1}'))
            db.commit()
        first=self.ok(self.call('entries',who='bob',space=s,limit=100))
        self.assertEqual(len(first['items']),100);self.assertEqual(first['scanned'],100);self.assertTrue(first['has_more'])
        second=self.ok(self.call('entries',who='bob',space=s,limit=100,after=first['next_cursor']))
        self.assertEqual(len(second['items']),1);self.assertFalse(second['has_more'])
        self.err(self.call('entries',space=s,limit=101),'invalid')
        with self.k.connection() as db:
            before={table:db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in ['entries','events','retries','usage']}
        # Simulate one-page growth inside transaction using a tiny100-byte guard;
        # asserts storage denial cannot leave content/event/retry side effects.
        self.k.max_database_bytes=100
        with patch.object(self.k,'database_bytes',side_effect=[1,101,1]):
            self.err(self.call('post',space=s,content='must roll back',key='overflow'),'quota')
        with self.k.connection() as db:
            after={table:db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in before}
        self.assertEqual(after,before)
        self.k.max_database_bytes=32*1024*1024
        self.ok(self.call('post',space=s,content='must roll back',key='overflow'))

    def test_content_only_owner_and_nonowner_edits_cannot_regrant_old_epoch(self):
        s=self.child();self.join(s);self.join(s,'eve')
        obj=self.artifact(s,readers=['alice','bob','eve'],writers=['alice','bob','eve'])
        oldpost=self.ok(self.call('post',space=s,content='before removal'))
        receipt_args={k:obj[k] for k in ['id','version','content_sha256']}
        self.ok(self.call('accept',who='bob',space=s,key='old-accept',**receipt_args))
        self.remove(s);self.join(s)
        self.err(self.call('accept',who='bob',space=s,key='old-accept',**receipt_args),'not_found')
        version=1
        hidden_events=[obj['event'],oldpost['event']]
        for editor in ['alice','eve']:
            revision=self.ok(self.call('update',who=editor,space=s,id=obj['id'],expected_version=version,content='content-only '+editor))
            version=revision['version'];hidden_events.append(revision['event'])
            for op in ['get','history']:
                self.err(self.call(op,who='bob',space=s,id=obj['id']),'not_found')
            self.assertEqual(self.ok(self.call('catalog',who='bob',space=s))['items'],[])
            self.err(self.call('update',who='bob',space=s,id=obj['id'],expected_version=version,content='unauthorized edit'),'not_found')
            self.assertEqual(self.ok(self.call('entries',who='bob',space=s))['items'],[])
            visible={r['seq'] for r in self.ok(self.call('events',who='bob',space=s))['items']}
            self.assertTrue(set(hidden_events).isdisjoint(visible))
        granted=self.ok(self.call('update',space=s,id=obj['id'],expected_version=version,content='explicit owner grant',readers=['alice','bob','eve'],writers=['alice','bob','eve']))
        self.ok(self.call('get',who='bob',space=s,id=obj['id']))
        history=self.ok(self.call('history',who='bob',space=s,id=obj['id']))['items']
        self.assertEqual([r['version'] for r in history],[granted['version']])
        visible={r['seq'] for r in self.ok(self.call('events',who='bob',space=s))['items']}
        self.assertIn(granted['event'],visible);self.assertTrue(set(hidden_events).isdisjoint(visible))
        # Current visibility restored, but old cached acceptance remains inaccessible.
        self.err(self.call('accept',who='bob',space=s,key='old-accept',**receipt_args),'forbidden')
        self.ok(self.call('update',who='bob',space=s,id=obj['id'],expected_version=granted['version'],content='new authorized edit'))

    def test_actual_database_page_growth_rolls_back_atomically(self):
        s=self.child()
        with self.k.connection() as db:
            start=self.k.database_bytes(db)
            page=db.execute('PRAGMA page_size').fetchone()[0]
            before={table:db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in ['entries','events','retries']}
            usage=db.execute('SELECT SUM(mutations) FROM usage').fetchone()[0]
        self.k.max_database_bytes=start+page
        self.err(self.call('post',space=s,content='x'*8192,key='real-overflow'),'quota')
        with self.k.connection() as db:
            self.assertEqual({table:db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in before},before)
            self.assertEqual(db.execute('SELECT SUM(mutations) FROM usage').fetchone()[0],usage)
            self.assertLessEqual(self.k.database_bytes(db),self.k.max_database_bytes)
        self.k.max_database_bytes=32*1024*1024
        self.ok(self.call('post',space=s,content='x'*8192,key='real-overflow'))

    def test_packaged_python_runtime_includes_world_module(self):
        import shutil
        import subprocess
        import sys
        root=Path(__file__).resolve().parent
        docker=(root/'Dockerfile').read_text()
        self.assertTrue(any(line.startswith('COPY ') and 'kernel.py' in line.split() and 'world04.py' in line.split() for line in docker.splitlines()))
        self.assertIn('!world04.py',(root/'.dockerignore').read_text().splitlines())
        runtime=Path(self.tmp.name)/'runtime';runtime.mkdir()
        for name in ['kernel.py','world04.py','identity.py','production.py']:
            shutil.copy2(root/name,runtime/name)
        (runtime/'mcp_adapter').mkdir()
        shutil.copy2(root/'mcp_adapter/worker.py',runtime/'mcp_adapter/worker.py')
        script="import sys;sys.path.insert(0,sys.argv[1]);import kernel,world04,production;import mcp_adapter.worker;assert world04.SCAN==500"
        result=subprocess.run([sys.executable,'-I','-c',script,str(runtime)],cwd=runtime,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        sid=self.child();self.ok(self.call('post',space=sid,content='human inspection fixture'))
        with self.k.connection() as db:count=db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
        inspected=json.loads(subprocess.check_output([sys.executable,str(root/'kernel.py'),'inspect','--db',str(self.path)],text=True))
        self.assertEqual(inspected['child_spaces'][0]['id'],sid)
        self.assertEqual(inspected['entries'][0]['content'],'human inspection fixture')
        with self.k.connection() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0],count)

    def test_copy_old_schema_migration_preserves_rows_and_old_operations(self):
        source=Path(self.tmp.name)/'synthetic-03.db';copy=Path(self.tmp.name)/'copied-03.db'
        with sqlite3.connect(source) as db:
            db.executescript(SCHEMA)
            db.execute('INSERT INTO identities VALUES (?,?)',('alice','[]'));db.execute('INSERT INTO members VALUES (?,?)',('plaza','alice'))
            db.execute('INSERT INTO objects VALUES (?,?,?,?,?,?,?)',('old','plaza','alice',1,'old content','["alice"]','["alice"]'))
            db.execute('INSERT INTO versions VALUES (?,?,?,?,?,?,?)',('old',1,'alice','old content','["alice"]','["alice"]',1))
            db.commit()
            with sqlite3.connect(copy) as target:db.backup(target)
        migrated=Kernel(copy,allow_fixture=True)
        with migrated.connection() as db:initialize_schema(db)
        self.k=migrated
        old=self.ok(self.call('get',id='old'));self.assertEqual(old['content'],'old content');self.assertEqual(old['tags'],[])
        self.ok(self.call('update',id='old',expected_version=1,content='updated old'))
        self.assertEqual(len(self.ok(self.call('history',id='old'))['items']),2)
        self.ok(self.call('send',recipient='alice',content='legacy DM'))
        self.assertEqual(self.ok(self.call('inbox'))['items'][0]['content'],'legacy DM')
        # Restart the actual fixture HTTP process twice against the migrated copy.
        # The original synthetic 0.3 source is never served or modified.
        import subprocess, sys, urllib.request
        for _ in range(2):
            process=subprocess.Popen([sys.executable,str(Path(__file__).with_name('kernel.py')),'serve','--db',str(copy),'--port','0','--allow-insecure-test-identities'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                url=json.loads(process.stdout.readline())['listening']
                request=urllib.request.Request(url,data=json.dumps({'op':'get','args':{'space':'plaza','id':'old'}}).encode(),headers={'Content-Type':'application/json','X-Test-Actor':'alice'})
                with urllib.request.urlopen(request,timeout=5) as response:
                    value=json.load(response)
                self.assertTrue(value['ok']);self.assertEqual(value['result']['version'],2)
                self.assertEqual(value['result']['content'],'updated old')
            finally:
                process.terminate();process.wait(timeout=5);process.stdout.close();process.stderr.close()
        with sqlite3.connect(source) as db:self.assertEqual(db.execute('SELECT content FROM objects').fetchone()[0],'old content')

if __name__=='__main__':unittest.main()
