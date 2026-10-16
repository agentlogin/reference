import { DatabaseSync } from 'node:sqlite';

export type CallbackClaim = 'claimed' | 'duplicate' | 'missing';

/**
 * Shared, durable one-use state for every replica serving the same RP. Keys are opaque digests, never cookies or
 * PKCE verifiers. Registration must not overwrite an existing record; claiming must atomically mark an unexpired
 * record used, and only one caller may win. Keep used records until their original expiry. Missing records must
 * fail closed, including after storage loss. Never release a claim after an exchange or application failure.
 */
export interface CallbackStateStore {
  /** Register a fresh sign-in until this Unix time in milliseconds. False means the key already exists. */
  register(key: string, expiresAt: number): Promise<boolean>;
  /** Atomically claim a previously registered, unexpired sign-in, before contacting the Issuer. */
  claim(key: string): Promise<CallbackClaim>;
}

/** Single-process development store. Share one instance across handlers; use durable shared storage in production. */
export class MemoryCallbackStateStore implements CallbackStateStore {
  private readonly records = new Map<string, { expiresAt: number; used: boolean }>();
  private readonly now: () => number;
  private readonly maxEntries: number;

  constructor(o: { now?: () => number; maxEntries?: number } = {}) {
    this.now = o.now ?? Date.now;
    this.maxEntries = o.maxEntries ?? 10_000;
    if (!Number.isSafeInteger(this.maxEntries) || this.maxEntries < 1) throw new Error('maxEntries must be a positive integer');
  }

  private sweep(): void {
    const now = this.now();
    for (const [key, record] of this.records) if (record.expiresAt <= now) this.records.delete(key);
  }

  async register(key: string, expiresAt: number): Promise<boolean> {
    checkRegistration(key, expiresAt, this.now());
    this.sweep();
    if (this.records.has(key)) return false;
    // Capacity pressure must never make a previously consumed callback replayable.
    if (this.records.size >= this.maxEntries) throw new Error('callback state store is full');
    this.records.set(key, { expiresAt, used: false });
    return true;
  }

  async claim(key: string): Promise<CallbackClaim> {
    this.sweep();
    const record = this.records.get(key);
    if (!record) return 'missing';
    if (record.used) return 'duplicate';
    record.used = true;
    return 'claimed';
  }
}

/**
 * Persistent store for processes sharing a SQLite database on one host. SQLite serializes claims across separate
 * connections/processes. Use a database service adapter for replicas on different hosts; do not put this file on
 * a network filesystem. Protect its directory with application-only permissions.
 */
export class SqliteCallbackStateStore implements CallbackStateStore {
  private readonly db: DatabaseSync;
  private readonly now: () => number;

  constructor(filename: string, o: { now?: () => number; busyTimeoutMs?: number } = {}) {
    this.now = o.now ?? Date.now;
    const timeout = o.busyTimeoutMs ?? 5_000;
    if (!Number.isSafeInteger(timeout) || timeout < 0 || timeout > 60_000) throw new Error('busyTimeoutMs must be an integer from 0 to 60000');
    this.db = new DatabaseSync(filename);
    this.db.exec(`PRAGMA busy_timeout = ${timeout}`);
    this.db.exec('PRAGMA journal_mode = WAL');
    this.db.exec('PRAGMA synchronous = FULL');
    this.db.exec(`CREATE TABLE IF NOT EXISTS agentlogin_rp_callbacks (
      key TEXT PRIMARY KEY NOT NULL,
      expires_at INTEGER NOT NULL,
      used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0, 1))
    )`);
    this.db.exec('CREATE INDEX IF NOT EXISTS agentlogin_rp_callbacks_expiry ON agentlogin_rp_callbacks(expires_at)');
  }

  async register(key: string, expiresAt: number): Promise<boolean> {
    return this.write(() => {
      const now = this.now();
      checkRegistration(key, expiresAt, now);
      this.db.prepare('DELETE FROM agentlogin_rp_callbacks WHERE expires_at <= ?').run(now);
      const result = this.db.prepare('INSERT INTO agentlogin_rp_callbacks (key, expires_at) VALUES (?, ?) ON CONFLICT(key) DO NOTHING').run(key, expiresAt);
      return result.changes === 1;
    });
  }

  async claim(key: string): Promise<CallbackClaim> {
    return this.write(() => {
      const now = this.now();
      const result = this.db.prepare('UPDATE agentlogin_rp_callbacks SET used = 1 WHERE key = ? AND used = 0 AND expires_at > ?').run(key, now);
      if (result.changes === 1) return 'claimed';
      const row = this.db.prepare('SELECT used FROM agentlogin_rp_callbacks WHERE key = ? AND expires_at > ?').get(key, now);
      return row ? 'duplicate' : 'missing';
    });
  }

  private write<T>(operation: () => T): T {
    // Wait for other writers before sampling expiry time, even if their transaction changes no rows.
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = operation();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      try { this.db.exec('ROLLBACK'); } catch { /* Preserve the original failure. */ }
      throw error;
    }
  }

  close(): void { this.db.close(); }
}

function checkRegistration(key: string, expiresAt: number, now: number): void {
  if (!key || !Number.isSafeInteger(expiresAt) || expiresAt <= now) throw new Error('invalid callback state registration');
}
