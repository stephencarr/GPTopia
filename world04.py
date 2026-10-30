"""Bounded child venues. No external admission, inference, scheduling, or execution."""
import json
import time
import uuid

READS = {'roots', 'spaces', 'space_get', 'entries', 'catalog'}
WRITES = {'space_create', 'space_invite', 'space_accept', 'space_remove', 'space_leave', 'post'}
OPS = READS | WRITES
SCAN = 500
SCHEMA = '''
CREATE TABLE IF NOT EXISTS child_spaces(id TEXT UNIQUE NOT NULL,root TEXT NOT NULL,owner TEXT NOT NULL,title TEXT NOT NULL,version INTEGER NOT NULL,created REAL NOT NULL);
CREATE INDEX IF NOT EXISTS children_root ON child_spaces(root);
CREATE TABLE IF NOT EXISTS child_members(space TEXT NOT NULL,actor TEXT NOT NULL,epoch INTEGER NOT NULL,active INTEGER NOT NULL,PRIMARY KEY(space,actor));
CREATE TABLE IF NOT EXISTS space_invites(id TEXT PRIMARY KEY,space TEXT NOT NULL,actor TEXT NOT NULL,expires REAL NOT NULL,state TEXT NOT NULL,accepted_epoch INTEGER);
CREATE INDEX IF NOT EXISTS invites_target ON space_invites(space,actor,state);
CREATE TABLE IF NOT EXISTS entries(id TEXT UNIQUE NOT NULL,space TEXT NOT NULL,author TEXT NOT NULL,content TEXT NOT NULL,created REAL NOT NULL,event INTEGER NOT NULL,audience TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS entries_page ON entries(space,event);
CREATE TABLE IF NOT EXISTS object_epochs(object_id TEXT NOT NULL,version INTEGER NOT NULL,actor TEXT NOT NULL,epoch INTEGER NOT NULL,PRIMARY KEY(object_id,version,actor));
CREATE TABLE IF NOT EXISTS event_epochs(seq INTEGER NOT NULL,actor TEXT NOT NULL,epoch INTEGER NOT NULL,PRIMARY KEY(seq,actor));
CREATE INDEX IF NOT EXISTS objects_page ON objects(space);
CREATE INDEX IF NOT EXISTS events_page ON events(space,seq);
CREATE INDEX IF NOT EXISTS inbox_page ON messages(space,recipient);
CREATE TRIGGER IF NOT EXISTS entries_no_update BEFORE UPDATE ON entries BEGIN SELECT RAISE(ABORT,'immutable entry'); END;
CREATE TRIGGER IF NOT EXISTS entries_no_delete BEFORE DELETE ON entries BEGIN SELECT RAISE(ABORT,'immutable entry'); END;
'''


def fail(code, message):
    from kernel import Fault
    raise Fault(code, message)


def text(value, maximum, field, empty=False):
    try:
        good = isinstance(value, str) and (empty or bool(value)) and len(value.encode('utf-8')) <= maximum
    except UnicodeError:
        good = False
    if not good:
        fail('invalid', f'{field} must be UTF-8 text of at most {maximum} bytes')
    return value


def metadata(args, old=None):
    title = text(args.get('title', old['title'] if old else ''), 120, 'title', True)
    tags = args.get('tags', json.loads(old['tags']) if old else [])
    if not isinstance(tags, list) or len(tags) > 8:
        fail('invalid', 'tags must contain at most eight strings')
    for tag in tags:
        text(tag, 32, 'tag')
    if len(set(tags)) != len(tags):
        fail('invalid', 'tags must be unique')
    return title, tags


class World:
    def __init__(self, kernel):
        self.k = kernel

    def child(self, db, space):
        return db.execute('SELECT * FROM child_spaces WHERE id=?', (space,)).fetchone()

    def epoch(self, db, space, actor):
        r = db.execute('SELECT epoch FROM child_members WHERE space=? AND actor=? AND active=1', (space, actor)).fetchone()
        return r[0] if r else None

    def audience(self, db, space):
        return {r['actor']: r['epoch'] for r in db.execute('SELECT actor,epoch FROM child_members WHERE space=? AND active=1', (space,))}

    def invite(self, db, space, actor):
        return db.execute("SELECT * FROM space_invites WHERE space=? AND actor=? AND state='pending' AND expires>? ORDER BY rowid DESC LIMIT 1", (space, actor, time.time())).fetchone()

    def authorize(self, db, actor, op, space, a):
        child = self.child(db, space)
        if op == 'roots':
            return
        if child:
            epoch = self.epoch(db, space, actor)
            if op == 'space_accept':
                from kernel import name
                name(a.get('invite_id'), 'invite_id')
                inv = db.execute('SELECT * FROM space_invites WHERE id=? AND space=? AND actor=?', (a.get('invite_id'), space, actor)).fetchone()
                if not inv or inv['state'] == 'revoked':
                    fail('not_found', 'invitation unavailable')
                if inv['state'] == 'pending' and inv['expires'] <= time.time():
                    fail('conflict', 'invitation expired')
                if inv['state'] == 'accepted' and epoch != inv['accepted_epoch']:
                    fail('conflict', 'membership changed; old acceptance cannot be replayed')
            elif not epoch and not (op == 'space_get' and self.invite(db, space, actor)):
                fail('forbidden', 'current child membership required')
            if op in {'space_invite', 'space_remove'} and actor != child['owner']:
                fail('forbidden', 'space owner permission required')
            if op in {'spaces', 'space_create'}:
                fail('invalid', 'operation requires an admitted root; nested spaces are unsupported')
        elif op in {'space_get', 'space_invite', 'space_accept', 'space_remove', 'space_leave', 'post', 'entries'}:
            fail('not_found', 'child space unavailable')

    def object_visible(self, db, space, oid, version, actor):
        if not self.child(db, space):
            return True
        epoch = self.epoch(db, space, actor)
        return bool(epoch and db.execute('SELECT 1 FROM object_epochs WHERE object_id=? AND version=? AND actor=? AND epoch=?', (oid, version, actor, epoch)).fetchone())

    def snapshot_object(self, db, space, oid, version, readers, explicit_grant=False):
        if self.child(db, space):
            audience = self.audience(db, space)
            prior = {r['actor']:r['epoch'] for r in db.execute('SELECT actor,epoch FROM object_epochs WHERE object_id=? AND version=?',(oid,version-1))}
            for actor in readers:
                if actor in audience and (version == 1 or explicit_grant or prior.get(actor) == audience[actor]):
                    db.execute('INSERT INTO object_epochs VALUES (?,?,?,?)', (oid, version, actor, audience[actor]))

    def snapshot_event(self, db, space, seq, audience):
        if self.child(db, space):
            members = self.audience(db, space)
            for actor in audience:
                if actor in members:
                    db.execute('INSERT INTO event_epochs VALUES (?,?,?)', (seq, actor, members[actor]))

    def event_visible(self, db, space, seq, actor):
        if not self.child(db, space):
            return True
        epoch = self.epoch(db, space, actor)
        return bool(epoch and db.execute('SELECT 1 FROM event_epochs WHERE seq=? AND actor=? AND epoch=?', (seq, actor, epoch)).fetchone())

    def info(self, db, row, actor):
        invite = self.invite(db, row['id'], actor)
        members = []
        if self.epoch(db, row['id'], actor):
            members = [dict(r) for r in db.execute('SELECT actor,epoch FROM child_members WHERE space=? AND active=1 ORDER BY actor', (row['id'],))]
        return dict(row) | {'members': members, 'invitation': {'id': invite['id'], 'expires_at': invite['expires']} if invite else None}

    def page_args(self, a):
        after, limit = a.get('after', 0), a.get('limit', 50)
        if type(after) is not int or not 0 <= after <= 9223372036854775807 or type(limit) is not int or not 1 <= limit <= 100:
            fail('invalid', 'after must be nonnegative integer; limit must be 1–100')
        return after, limit

    def page(self, rows, after, limit, select):
        items, cursor, scanned = [], after, 0
        # Fetch one lookahead row. Never scan arbitrarily many private records.
        consumed = 0
        for r in rows[:SCAN]:
            scanned += 1; consumed += 1; cursor = r['cursor']
            item = select(r)
            if item is not None:
                items.append(item)
            if len(items) == limit:
                break
        return {'items': items, 'next_cursor': cursor, 'scanned': scanned, 'has_more': consumed < len(rows)}

    def dispatch(self, db, actor, op, space, a, principal):
        from kernel import name, content, encode
        allowed = {
            'roots': set(), 'spaces': {'space','after','limit'}, 'space_get': {'space'},
            'space_create': {'space','title'}, 'space_invite': {'space','actor','expected_version'},
            'space_accept': {'space','invite_id'}, 'space_remove': {'space','actor','expected_version'},
            'space_leave': {'space'}, 'post': {'space','content'},
            'entries': {'space','after','limit'}, 'catalog': {'space','after','limit','tag'},
        }
        if set(a) - allowed[op]:
            fail('invalid', 'unknown argument')
        if op == 'roots':
            roots = [r['space'] for r in db.execute('SELECT space FROM members WHERE actor=? ORDER BY space', (actor,)) if r['space'] in principal.spaces and not self.child(db, r['space'])]
            return {'items': [{'id': root} for root in roots]}
        row = self.child(db, space)
        if op == 'space_get':
            return self.info(db, row, actor)
        if op in {'spaces','entries','catalog'}:
            after, limit = self.page_args(a)
        if op == 'spaces':
            rows = db.execute('SELECT rowid AS cursor,* FROM child_spaces WHERE root=? AND rowid>? ORDER BY rowid LIMIT ?', (space, after, SCAN+1)).fetchall()
            def select(r):
                if not self.epoch(db, r['id'], actor) and not self.invite(db, r['id'], actor):
                    return None
                value = self.info(db, r, actor); value.pop('cursor'); return value
            return self.page(rows, after, limit, select)
        if op == 'catalog':
            tag = text(a['tag'],32,'tag') if 'tag' in a else None
            rows = db.execute('SELECT rowid AS cursor,* FROM objects WHERE space=? AND rowid>? ORDER BY rowid LIMIT ?', (space, after, SCAN+1)).fetchall()
            def select(r):
                if actor not in json.loads(r['readers']) or not self.object_visible(db, space, r['id'], r['version'], actor):
                    return None
                tags = json.loads(r['tags'])
                if tag is not None and tag not in tags:
                    return None
                v = db.execute('SELECT author,created FROM versions WHERE object_id=? AND version=?', (r['id'],r['version'])).fetchone()
                return {k:r[k] for k in ['id','space','owner','version','title']} | {'tags':tags,'content_sha256':self.k.content_hash(r['content']),**dict(v)}
            return self.page(rows, after, limit, select)
        if op == 'entries':
            epoch = self.epoch(db, space, actor)
            rows = db.execute('SELECT event AS cursor,* FROM entries WHERE space=? AND event>? ORDER BY event LIMIT ?', (space, after, SCAN+1)).fetchall()
            def select(r):
                if json.loads(r['audience']).get(actor) != epoch:
                    return None
                return {k:r[k] for k in ['id','space','author','content','created']} | {'seq':r['event']}
            return self.page(rows, after, limit, select)
        if op == 'space_create':
            title = text(a.get('title'),120,'title')
            if db.execute('SELECT COUNT(*) FROM child_spaces WHERE root=?', (space,)).fetchone()[0] >= 10:
                fail('quota', 'root child-space quota exceeded')
            sid = 'space_' + uuid.uuid4().hex
            db.execute('INSERT INTO child_spaces VALUES (?,?,?,?,?,?)', (sid,space,actor,title,1,time.time()))
            db.execute('INSERT INTO child_members VALUES (?,?,1,1)', (sid,actor))
            seq = self.k.event(db,space,'space.created',actor,sid,[actor],1)
            return {'id':sid,'root':space,'version':1,'event':seq}
        if op == 'post':
            body = content(a.get('content')); eid = 'entry_' + uuid.uuid4().hex
            audience = self.audience(db,space)
            seq = self.k.event(db,space,'entry.posted',actor,eid,sorted(audience))
            db.execute('INSERT INTO entries VALUES (?,?,?,?,?,?,?)', (eid,space,actor,body,time.time(),seq,encode(audience)))
            return {'id':eid,'event':seq}
        if op in {'space_invite','space_remove'}:
            target = name(a.get('actor'),'actor')
            if type(a.get('expected_version')) is not int or a['expected_version'] != row['version']:
                fail('conflict','space version changed')
            if target == row['owner']:
                fail('forbidden','space owner membership cannot be changed')
        if op == 'space_invite':
            self.k.member(db,row['root'],target)
            if self.epoch(db,space,target):
                fail('conflict','actor already a member')
            if self.invite(db,space,target):
                fail('conflict','actor already has a live invitation')
            active = set(self.audience(db,space))
            pending = {r[0] for r in db.execute("SELECT actor FROM space_invites WHERE space=? AND state='pending' AND expires>?",(space,time.time()))}
            if len(active | pending | {target}) > 10:
                fail('quota','child membership quota exceeded')
            iid, expiry = 'invite_' + uuid.uuid4().hex, time.time()+86400
            db.execute("INSERT INTO space_invites VALUES (?,?,?,?,'pending',NULL)",(iid,space,target,expiry))
            db.execute('UPDATE child_spaces SET version=version+1 WHERE id=?',(space,))
            seq = self.k.event(db,row['root'],'space.invited',actor,space,sorted({actor,target}),row['version']+1)
            return {'space':space,'id':iid,'actor':target,'expires_at':expiry,'version':row['version']+1,'event':seq}
        if op == 'space_accept':
            iid = name(a.get('invite_id'),'invite_id')
            inv = db.execute('SELECT * FROM space_invites WHERE id=? AND space=? AND actor=?',(iid,space,actor)).fetchone()
            if not inv or inv['state'] != 'pending' or inv['expires'] <= time.time() or self.epoch(db,space,actor):
                fail('conflict','invitation is not currently acceptable')
            old = db.execute('SELECT epoch FROM child_members WHERE space=? AND actor=?',(space,actor)).fetchone()
            epoch = old[0]+1 if old else 1
            db.execute('INSERT INTO child_members VALUES (?,?,?,1) ON CONFLICT(space,actor) DO UPDATE SET epoch=excluded.epoch,active=1',(space,actor,epoch))
            db.execute("UPDATE space_invites SET state='accepted',accepted_epoch=? WHERE id=?",(epoch,iid))
            db.execute('UPDATE child_spaces SET version=version+1 WHERE id=?',(space,))
            seq = self.k.event(db,space,'space.joined',actor,space,sorted(self.audience(db,space)),row['version']+1)
            return {'space':space,'actor':actor,'epoch':epoch,'version':row['version']+1,'event':seq}
        target = actor if op == 'space_leave' else target
        if target == row['owner']:
            fail('forbidden','space owner cannot leave')
        if not self.epoch(db,space,target) and not self.invite(db,space,target):
            fail('not_found','membership or invitation unavailable')
        db.execute('UPDATE child_members SET active=0 WHERE space=? AND actor=?',(space,target))
        db.execute("UPDATE space_invites SET state='revoked' WHERE space=? AND actor=? AND state='pending'",(space,target))
        db.execute('UPDATE child_spaces SET version=version+1 WHERE id=?',(space,))
        seq = self.k.event(db,space,'space.left',actor,space,sorted(self.audience(db,space)),row['version']+1)
        return {'space':space,'actor':target,'active':False,'version':row['version']+1,'event':seq}
