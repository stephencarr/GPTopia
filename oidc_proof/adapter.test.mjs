import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createAdapter } from './adapter.mjs';

function fixture(t, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'gptopia-oidc-adapter-'));
  const path = join(dir, 'test.sqlite');
  const storage = createAdapter(path, options);
  t.after(() => { storage.close(); rmSync(dir, { recursive: true, force: true }); });
  return { ...storage, path };
}

test('restart, model separation, consumed flag, indexes and expiry', async (t) => {
  let now = 100000;
  const s = fixture(t, { now: () => now });
  const session = new s.Adapter('Session');
  const device = new s.Adapter('DeviceCode');
  await session.upsert('same', { uid: 'u1', data: 'synthetic' }, 10);
  await device.upsert('same', { userCode: 'c1', grantId: 'g' }, 10);
  assert.equal((await session.findByUid('u1')).data, 'synthetic');
  assert.equal((await device.findByUserCode('c1')).grantId, 'g');
  await device.consume('same');
  await device.upsert('same', { userCode: 'c2', grantId: 'g' }, 10);
  assert.equal(await device.findByUserCode('c1'), undefined);
  assert.ok((await device.find('same')).consumed);
  s.close();
  const restarted = createAdapter(s.path, { now: () => now });
  try {
    assert.ok((await new restarted.Adapter('DeviceCode').find('same')).consumed);
    assert.equal((await new restarted.Adapter('Session').findByUid('u1')).data, 'synthetic');
    now += 11000;
    assert.equal(await new restarted.Adapter('DeviceCode').findByUserCode('c2'), undefined);
    assert.equal(await new restarted.Adapter('Session').find('same'), undefined);
  } finally { restarted.close(); }
  assert.equal(statSync(s.path).mode & 0o777, 0o600);
});

test('replay insertion rejects unexpired duplicate and permits expired replacement', async (t) => {
  let now = 100000;
  const s = fixture(t, { now: () => now });
  const a = new s.Adapter('ReplayDetection');
  await a.upsert('r', { jti: 'r' }, 2);
  await assert.rejects(a.upsert('r', { jti: 'r' }, 2), /invalid_grant/);
  now += 3000;
  await a.upsert('r', { jti: 'r' }, 2);
  assert.equal((await a.find('r')).jti, 'r');
});

test('grant revocation and tombstone survive restart; unrelated grants remain', async (t) => {
  const s = fixture(t);
  for (const name of ['AccessToken', 'AuthorizationCode', 'RefreshToken']) {
    await new s.Adapter(name).upsert(name, { grantId: 'g1' }, 100);
    await new s.Adapter(name).upsert(`${name}-other`, { grantId: 'g2' }, 100);
  }
  const refresh = new s.Adapter('RefreshToken');
  await refresh.revokeByGrantId('g1');
  s.close();
  const restarted = createAdapter(s.path);
  try {
    for (const name of ['AccessToken', 'AuthorizationCode', 'RefreshToken']) {
      const a = new restarted.Adapter(name);
      assert.equal(await a.find(name), undefined);
      assert.ok(await a.find(`${name}-other`));
      await assert.rejects(a.upsert('late-successor', { grantId: 'g1' }, 100), /invalid_grant/);
    }
    await assert.rejects(new restarted.Adapter('Grant').upsert('g1', {}, 100), /invalid_grant/);
  } finally { restarted.close(); }
});

test('concurrent consumed replay revokes chain and prevents late successor', async (t) => {
  const s = fixture(t);
  const a = new s.Adapter('RefreshToken');
  await a.upsert('r', { grantId: 'g' }, 100);
  const results = await Promise.allSettled([a.consume('r'), a.consume('r')]);
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  assert.equal(await a.find('r'), undefined);
  await assert.rejects(a.upsert('successor', { grantId: 'g' }, 100), /invalid_grant/);
});

async function race(path, action) {
  const url = new URL('./adapter.mjs', import.meta.url).href;
  const code = `import { createAdapter } from ${JSON.stringify(url)};
    const s=createAdapter(process.argv[1]); const a=new s.Adapter(${JSON.stringify(action === 'consume' ? 'RefreshToken' : 'ReplayDetection')});
    process.stdout.write('READY\\n');
    process.stdin.once('data',async()=>{try{await ${action === 'consume' ? "a.consume('r')" : "a.upsert('r',{jti:'r'},100)"};process.stdout.write('SUCCESS\\n');}
      catch{process.stdout.write('DENIED\\n');}finally{s.close();process.stdin.destroy();}});`;
  const children = [0, 1].map(() => spawn(process.execPath, ['--input-type=module', '-e', code, path], { stdio: ['pipe', 'pipe', 'pipe'] }));
  const buffers = ['', ''];
  const exits = children.map((child) => once(child, 'exit'));
  await Promise.all(children.map((child, i) => new Promise((resolve, reject) => {
    child.on('error', reject);
    child.stdout.on('data', (data) => { buffers[i] += data; if (buffers[i].includes('READY')) resolve(); });
    child.on('exit', () => { if (!buffers[i].includes('READY')) reject(new Error('worker failed before readiness')); });
  })));
  for (const child of children) child.stdin.end('go');
  const codes = await Promise.all(exits);
  assert.ok(codes.every(([code]) => code === 0));
  return buffers;
}

test('two independent OS processes cannot both insert a replay key or consume token', async (t) => {
  const s = fixture(t);
  const replayResults = await race(s.path, 'insert');
  assert.equal(replayResults.filter((x) => x.includes('SUCCESS')).length, 1);
  const a = new s.Adapter('RefreshToken');
  await a.upsert('r', { grantId: 'g' }, 100);
  const consumedResults = await race(s.path, 'consume');
  assert.equal(consumedResults.filter((x) => x.includes('SUCCESS')).length, 1);
  await assert.rejects(a.upsert('late', { grantId: 'g' }, 100), /invalid_grant/);
});

test('row and payload ceilings fail closed, revocation works at row capacity', async (t) => {
  const s = fixture(t, { maxRows: 2, maxPayloadBytes: 100 });
  const a = new s.Adapter('RefreshToken');
  await a.upsert('one', { grantId: 'g' }, 100);
  await a.upsert('two', { grantId: 'g' }, 100);
  await assert.rejects(a.upsert('three', {}, 100), /row quota/);
  await assert.rejects(a.upsert('one', { text: 'x'.repeat(200) }, 100), /payload quota/);
  assert.equal((await a.find('one')).grantId, 'g');
  await a.revokeByGrantId('g');
  assert.equal(await a.find('one'), undefined);
  assert.equal(s.stats().revokedGrants, 1);
  await a.destroy('missing');
  assert.ok(s.stats().databaseBytes < 32 * 1024 * 1024);
});

test('real SQLite page ceiling rejects growth atomically', async (t) => {
  const s = fixture(t, { maxBytes: 65536, maxPayloadBytes: 40000 });
  const a = new s.Adapter('Client');
  await a.upsert('small', { note: 'must survive failed write' });
  const before = s.stats().rows;
  let denied = false;
  for (let i = 0; i < 10; i += 1) {
    try { await a.upsert(`large-${i}`, { data: 'x'.repeat(30000) }); }
    catch (error) { assert.match(error.message, /full/); denied = true; break; }
  }
  assert.ok(denied);
  assert.equal((await a.find('small')).note, 'must survive failed write');
  assert.ok(s.stats().databaseBytes <= 65536);
  assert.ok(s.stats().rows >= before);
});
