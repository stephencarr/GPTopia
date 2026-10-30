"""Deterministic subprocess protocol smoke test; NOT real-agent interoperability."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent


def call(url, actor, op, args, key=None):
    payload = {'op': op, 'args': args}
    if key:
        payload['idempotency_key'] = key
    request = urllib.request.Request(url, json.dumps(payload).encode(),
                                    {'Content-Type': 'application/json', 'X-Test-Actor': actor})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        result = json.load(exc)
    if not result['ok']:
        raise RuntimeError(result)
    return result['result']


def worker(role, url, oid):
    peers = call(url, role, 'discover', {'space': 'plaza'})['identities']
    assert {p['id'] for p in peers} == {'alice', 'bob'}
    if role == 'alice':
        obj = call(url, role, 'create', {'space': 'plaza', 'content': '# City charter\nAlice: build a public garden.',
                                        'readers': ['alice', 'bob'], 'writers': ['alice', 'bob']}, 'alice-create')
        call(url, role, 'send', {'space': 'plaza', 'recipient': 'bob', 'content': obj['id']}, 'alice-invite')
        print(json.dumps({'process': os.getpid(), 'role': role, 'object': obj['id'], 'version': obj['version']}))
    else:
        inbox = call(url, role, 'inbox', {'space': 'plaza'})['items']
        assert any(m['sender'] == 'alice' and m['content'] == oid for m in inbox)
        obj = call(url, role, 'get', {'space': 'plaza', 'id': oid})
        update_args = {'space': 'plaza', 'id': oid, 'expected_version': obj['version'],
                       'content': obj['content'] + '\nBob: add a shared seed library.'}
        updated = call(url, role, 'update', update_args, 'bob-update')
        assert updated == call(url, role, 'update', update_args, 'bob-update')
        call(url, role, 'send', {'space': 'plaza', 'recipient': 'alice', 'content': 'Charter extended; seed library added.'}, 'bob-ack')
        print(json.dumps({'process': os.getpid(), 'role': role, 'object': oid, 'version': updated['version'], 'idempotent_retry': True}))


def start(db):
    proc = subprocess.Popen([sys.executable, str(ROOT / 'kernel.py'), 'serve', '--db', str(db), '--port', '0',
                             '--allow-insecure-test-identities'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError(proc.stderr.read())
    return proc, json.loads(line)['listening']


def stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    proc.stdout.close()
    proc.stderr.close()


def demo(db):
    # Refuse to touch an existing database: demo data is always fresh/reversible.
    if db.exists():
        raise SystemExit('Refusing existing database; choose a fresh --db path')
    subprocess.run([sys.executable, str(ROOT / 'kernel.py'), 'init', '--db', str(db),
                    '--allow-insecure-test-identities'], check=True, capture_output=True, text=True)
    proc, url = start(db)
    try:
        alice = json.loads(subprocess.check_output([sys.executable, __file__, '--worker', 'alice', '--url', url], text=True))
        bob = json.loads(subprocess.check_output([sys.executable, __file__, '--worker', 'bob', '--url', url,
                                                '--object', alice['object']], text=True))
        assert alice['process'] != bob['process']
        pages, cursor = [], 0
        while True:
            page = call(url, 'alice', 'events', {'space': 'plaza', 'after': cursor, 'limit': 1})
            if not page['items']:
                break
            pages += page['items']
            cursor = page['next_cursor']
        assert len(pages) == 4
    finally:
        stop(proc)
    proc, url = start(db)
    try:
        obj = call(url, 'alice', 'get', {'space': 'plaza', 'id': alice['object']})
        history = call(url, 'alice', 'history', {'space': 'plaza', 'id': alice['object']})['items']
        assert obj['version'] == 2 and [v['author'] for v in history] == ['alice', 'bob']
        assert len(call(url, 'alice', 'inbox', {'space': 'plaza'})['items']) == 1
        print(json.dumps({'milestone': 'deterministic two-process protocol proof; NOT real-agent interoperability',
                          'clients': [alice, bob], 'persisted_after_server_restart': True, 'events': len(pages),
                          'history_authors': [v['author'] for v in history], 'database': str(db),
                          'shared_artifact': obj}, indent=2))
    finally:
        stop(proc)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path)
    parser.add_argument('--worker', choices=['alice', 'bob'])
    parser.add_argument('--url')
    parser.add_argument('--object')
    args = parser.parse_args()
    if args.worker:
        worker(args.worker, args.url, args.object)
    elif args.db:
        demo(args.db)
    else:
        with tempfile.TemporaryDirectory(prefix='gptopia-demo-') as directory:
            demo(Path(directory) / 'world.sqlite3')
