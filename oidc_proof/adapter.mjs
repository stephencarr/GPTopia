/** Bounded LOCAL TEST adapter for oidc-provider 9.13.3, not a production claim.
 * Contract: official example/my_adapter.js. Credentials are plaintext SQLite
 * test artifacts; callers MUST use temporary storage and delete it after proof.
 */
import { DatabaseSync } from 'node:sqlite';
import { chmodSync } from 'node:fs';
import { errors } from 'oidc-provider';

const grantable = new Set(['AccessToken', 'AuthorizationCode', 'RefreshToken',
  'DeviceCode', 'BackchannelAuthenticationRequest', 'PreAuthorizedCode']);

export function createAdapter(path, { now = Date.now, maxRows = 5000,
  maxPayloadBytes = 65536, maxBytes = 32 * 1024 * 1024 } = {}) {
  if (typeof path !== 'string' || !path || ![maxRows, maxPayloadBytes, maxBytes].every(
    (n) => Number.isSafeInteger(n) && n > 0)) throw new TypeError('bounded storage configuration required');
  const db = new DatabaseSync(path);
  if (path !== ':memory:') chmodSync(path, 0o600);
  db.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;');
  const pageSize = Number(db.prepare('PRAGMA page_size').get().page_size);
  if (maxBytes < pageSize * 16) { db.close(); throw new RangeError('storage ceiling too small'); }
  db.exec(`PRAGMA max_page_count=${Math.floor(maxBytes / pageSize)};`);
  db.exec(`CREATE TABLE IF NOT EXISTS oidc_models (
    model TEXT NOT NULL, id TEXT NOT NULL, payload TEXT NOT NULL,
    expires_at INTEGER, consumed INTEGER, grant_id TEXT, uid TEXT, user_code TEXT,
    PRIMARY KEY(model,id));
    CREATE INDEX IF NOT EXISTS oidc_expiry ON oidc_models(expires_at);
    CREATE INDEX IF NOT EXISTS oidc_grant ON oidc_models(grant_id);
    CREATE UNIQUE INDEX IF NOT EXISTS oidc_uid ON oidc_models(model,uid) WHERE uid IS NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS oidc_user_code ON oidc_models(model,user_code) WHERE user_code IS NOT NULL;
    CREATE TABLE IF NOT EXISTS oidc_revoked_grants (id TEXT PRIMARY KEY, revoked_at INTEGER NOT NULL);`);
  let closed = false;
  const clock = () => Math.floor(now() / 1000);
  const transaction = (fn) => {
    db.exec('BEGIN IMMEDIATE');
    try { const value = fn(); db.exec('COMMIT'); return value; }
    catch (error) {
      // SQLITE_FULL may already have rolled back the transaction. Preserve the
      // original failure rather than replacing it with a second rollback error.
      try { db.exec('ROLLBACK'); } catch { /* transaction already rolled back */ }
      throw error;
    }
  };
  const unpack = (row) => {
    if (!row) return undefined;
    const value = JSON.parse(row.payload);
    if (row.consumed !== null) value.consumed = row.consumed;
    return value;
  };
  const assertId = (id) => {
    if (typeof id !== 'string' || !id || Buffer.byteLength(id) > 2048) throw new TypeError('invalid storage identifier');
  };
  const live = '(expires_at IS NULL OR expires_at > ?)';
  const revoked = (grantId) => grantId && db.prepare('SELECT 1 FROM oidc_revoked_grants WHERE id=?').get(grantId);
  const count = () => Number(db.prepare('SELECT (SELECT count(*) FROM oidc_models)+(SELECT count(*) FROM oidc_revoked_grants) AS n').get().n);
  const revoke = (grantId) => {
    // Durable tombstone prevents successor-token writes racing revocation.
    db.prepare('DELETE FROM oidc_models WHERE grant_id=? OR (model=\'Grant\' AND id=?)').run(grantId, grantId);
    if (!revoked(grantId) && count() >= maxRows) throw new Error('storage row quota');
    db.prepare('INSERT OR IGNORE INTO oidc_revoked_grants VALUES (?,?)').run(grantId, clock());
  };
  class Adapter {
    constructor(model) { assertId(model); this.model = model; }
    async upsert(id, payload, expiresIn) {
      assertId(id);
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new TypeError('object payload required');
      if (expiresIn !== undefined && (!Number.isFinite(expiresIn) || expiresIn < 0)) throw new TypeError('invalid expiry');
      const encoded = JSON.stringify(payload);
      if (Buffer.byteLength(encoded) > maxPayloadBytes) throw new Error('storage payload quota');
      const expiresAt = expiresIn === undefined ? null : Math.ceil(now() / 1000 + expiresIn);
      const gid = grantable.has(this.model) ? payload.grantId ?? null : null;
      const uid = this.model === 'Session' ? payload.uid ?? null : null;
      const userCode = payload.userCode ?? null;
      for (const value of [gid, uid, userCode]) if (value !== null) assertId(value);
      return transaction(() => {
        db.prepare('DELETE FROM oidc_models WHERE expires_at IS NOT NULL AND expires_at<=?').run(clock());
        if (revoked(gid) || (this.model === 'Grant' && revoked(id))) throw new errors.InvalidGrant('grant revoked');
        const previous = db.prepare('SELECT consumed FROM oidc_models WHERE model=? AND id=?').get(this.model, id);
        if (this.model === 'ReplayDetection' && previous) throw new errors.InvalidGrant('replay detected');
        if (!previous && count() >= maxRows) throw new Error('storage row quota');
        const consumed = previous?.consumed ?? (payload.consumed ? clock() || 1 : null);
        db.prepare(`INSERT INTO oidc_models VALUES (?,?,?,?,?,?,?,?)
          ON CONFLICT(model,id) DO UPDATE SET payload=excluded.payload,expires_at=excluded.expires_at,
          consumed=excluded.consumed,grant_id=excluded.grant_id,uid=excluded.uid,user_code=excluded.user_code`)
          .run(this.model, id, encoded, expiresAt, consumed, gid, uid, userCode);
      });
    }
    async find(id) { assertId(id); return unpack(db.prepare(`SELECT * FROM oidc_models WHERE model=? AND id=? AND ${live}`).get(this.model, id, clock())); }
    async findByUid(uid) { assertId(uid); return unpack(db.prepare(`SELECT * FROM oidc_models WHERE model=? AND uid=? AND ${live}`).get(this.model, uid, clock())); }
    async findByUserCode(code) { assertId(code); return unpack(db.prepare(`SELECT * FROM oidc_models WHERE model=? AND user_code=? AND ${live}`).get(this.model, code, clock())); }
    async consume(id) {
      assertId(id);
      let denied = false;
      transaction(() => {
        const row = db.prepare(`SELECT * FROM oidc_models WHERE model=? AND id=? AND ${live}`).get(this.model, id, clock());
        if (!row) { denied = true; return; }
        if (row.consumed !== null) {
          // Concurrent refresh replay takes the same conservative grant-wide
          // outcome as provider's sequential consumed-token replay path.
          if (row.grant_id) revoke(row.grant_id);
          denied = true;
          return;
        }
        db.prepare('UPDATE oidc_models SET consumed=? WHERE model=? AND id=? AND consumed IS NULL').run(clock() || 1, this.model, id);
      });
      if (denied) throw new errors.InvalidGrant('token unavailable or already consumed');
    }
    async destroy(id) { assertId(id); db.prepare('DELETE FROM oidc_models WHERE model=? AND id=?').run(this.model, id); }
    async revokeByGrantId(grantId) { assertId(grantId); return transaction(() => revoke(grantId)); }
  }
  return {
    Adapter,
    close() { if (!closed) { db.close(); closed = true; } },
    stats() {
      return { rows: count(), pages: Number(db.prepare('PRAGMA page_count').get().page_count), pageSize,
        databaseBytes: Number(db.prepare('PRAGMA page_count').get().page_count) * pageSize,
        revokedGrants: Number(db.prepare('SELECT count(*) AS n FROM oidc_revoked_grants').get().n) };
    },
  };
}
