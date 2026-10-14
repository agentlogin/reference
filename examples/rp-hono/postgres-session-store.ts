import { Pool, type PoolClient } from 'pg';
import type { AgentIdentity } from '@agentlogin/rp';
import { SessionProtection, cleanupLimit, validSid, validateSession, type NewSession, type Session, type SessionStore } from './session-store.js';

type Operation = 'create' | 'get' | 'revoke' | 'cleanup' | 'migrate' | 'verifySchema';
export interface ApplicationSessionCheckpoint {
  operation: Operation;
  phase: 'after-lock' | 'before-commit' | 'after-commit';
  client: PoolClient;
}
export interface PostgresSessionStoreOptions {
  /** Exactly one connection source, connected to the authoritative primary. */
  connectionString?: string;
  /** The owner of an external pool configures its connection limits and acquisition timeout. */
  pool?: Pool;
  schema?: string;
  sessionSecret: string;
  namespace: string;
  maxConnections?: number;
  connectionTimeoutMs?: number;
  statementTimeoutMs?: number;
  lockTimeoutMs?: number;
  idleTransactionTimeoutMs?: number;
  /** Scheduling and failure injection only. Never perform application work or log values here. */
  onCheckpoint?: (event: ApplicationSessionCheckpoint) => Promise<void> | void;
  /** Raw driver errors can contain sensitive values; callers must redact before reporting. */
  onPoolError?: (error: Error) => void;
}

export class ApplicationSessionUncertainCommitError extends Error {
  constructor(readonly operation: Operation, cause: unknown) {
    super(`The application session ${operation} commit outcome is uncertain; do not repeat the operation automatically`, { cause });
    this.name = 'ApplicationSessionUncertainCommitError';
  }
}

interface StoredSession {
  key: string;
  account_key: string;
  agent: AgentIdentity;
  expires_at: string;
  live_expires_at: string | null;
  live_ciphertext: Buffer | null;
  first_seen: string;
}

const VERSION = 1;
const MAX_TIME = Number.MAX_SAFE_INTEGER;
const quote = (identifier: string): string => `"${identifier}"`;
function integer(value: number | undefined, fallback: number, name: string, max = 2_147_483_647): number {
  const actual = value ?? fallback;
  if (!Number.isSafeInteger(actual) || actual < 1 || actual > max) throw new RangeError(`${name} must be an integer from 1 to ${max}`);
  return actual;
}
function sqlState(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' ? error.code : undefined;
}

/** Example application sessions, separate from protocol callback state and issuer storage. */
export class PostgresSessionStore implements SessionStore {
  readonly schema: string;
  private readonly pool: Pool;
  private readonly ownedPool: boolean;
  private readonly protection: SessionProtection;
  private readonly statementTimeoutMs: number;
  private readonly lockTimeoutMs: number;
  private readonly idleTransactionTimeoutMs: number;
  private readonly hook?: PostgresSessionStoreOptions['onCheckpoint'];
  private readonly poolErrorHandler: (error: Error) => void;
  private closed = false;

  constructor(options: PostgresSessionStoreOptions) {
    if (!options || (!!options.pool === (options.connectionString !== undefined))) throw new TypeError('Supply exactly one of pool or connectionString');
    if (options.connectionString !== undefined && (typeof options.connectionString !== 'string' || !options.connectionString.trim())) throw new TypeError('connectionString must be nonempty');
    this.schema = options.schema ?? 'agentlogin_app';
    if (typeof this.schema !== 'string' || !/^[a-z_][a-z0-9_]{0,62}$/.test(this.schema) || this.schema.startsWith('pg_')) throw new TypeError('PostgreSQL schema must be a lowercase SQL identifier of at most 63 characters, outside pg_*');
    this.protection = new SessionProtection(options.sessionSecret, options.namespace);
    this.statementTimeoutMs = integer(options.statementTimeoutMs, 10_000, 'statementTimeoutMs');
    this.lockTimeoutMs = integer(options.lockTimeoutMs, 5_000, 'lockTimeoutMs');
    this.idleTransactionTimeoutMs = integer(options.idleTransactionTimeoutMs, 30_000, 'idleTransactionTimeoutMs');
    const max = integer(options.maxConnections, 10, 'maxConnections', 1000);
    const connectionTimeoutMillis = integer(options.connectionTimeoutMs, 5_000, 'connectionTimeoutMs');
    this.ownedPool = !options.pool;
    this.pool = options.pool ?? new Pool({ connectionString: options.connectionString, max, connectionTimeoutMillis, idleTimeoutMillis: 30_000 });
    this.hook = options.onCheckpoint;
    this.poolErrorHandler = (error) => { options.onPoolError?.(error); };
    this.pool.on('error', this.poolErrorHandler);
  }

  private name(name: 'app_accounts' | 'app_sessions' | 'app_schema_migrations' | 'app_now'): string {
    return `${quote(this.schema)}.${quote(name)}`;
  }
  private async checkpoint(client: PoolClient, operation: Operation, phase: ApplicationSessionCheckpoint['phase']): Promise<void> {
    await this.hook?.({ client, operation, phase });
  }
  private async now(client: PoolClient): Promise<number> {
    const result = await client.query<{ now: string }>(`SELECT ${this.name('app_now')}() AS now`);
    const value = result.rows[0]?.now;
    const now = value === null || value === undefined ? NaN : Number(value);
    if (!Number.isSafeInteger(now) || now < 0) throw new Error('app_now() must return nonnegative safe integer Unix seconds');
    return now;
  }

  private async transaction<T>(operation: Operation, action: (client: PoolClient) => Promise<T>, options: {
    readOnly?: boolean;
    finalize?: (client: PoolClient, result: T) => Promise<T>;
  } = {}): Promise<T> {
    if (this.closed) throw new Error('PostgreSQL application session store is closed');
    const client = await this.pool.connect();
    let committing = false;
    let committed = false;
    let discard = false;
    let connectionError: Error | undefined;
    const onClientError = (error: Error): void => { connectionError = error; discard = true; };
    client.on('error', onClientError);
    try {
      await client.query(`BEGIN ISOLATION LEVEL READ COMMITTED ${options.readOnly ? 'READ ONLY' : 'READ WRITE'}`);
      await client.query(`SELECT set_config('statement_timeout', $1, true), set_config('lock_timeout', $2, true),
        set_config('idle_in_transaction_session_timeout', $3, true), set_config('search_path', 'pg_catalog', true),
        set_config('synchronous_commit', 'on', true)`, [String(this.statementTimeoutMs), String(this.lockTimeoutMs), String(this.idleTransactionTimeoutMs)]);
      let result = await action(client);
      await this.checkpoint(client, operation, 'before-commit');
      if (options.finalize) result = await options.finalize(client, result);
      if (connectionError) throw connectionError;
      committing = true;
      const commit = await client.query('COMMIT');
      if (commit.command !== 'COMMIT') {
        committing = false;
        throw new Error('PostgreSQL rolled back the application session transaction instead of committing');
      }
      committed = true;
      await this.checkpoint(client, operation, 'after-commit');
      if (connectionError) throw connectionError;
      return result;
    } catch (error) {
      if (committed || committing) {
        discard = true;
        throw new ApplicationSessionUncertainCommitError(operation, error);
      }
      try { await client.query('ROLLBACK'); } catch { discard = true; }
      throw error;
    } finally {
      try { client.release(discard); }
      finally { client.removeListener('error', onClientError); }
    }
  }

  async create(sid: string, value: NewSession, previousSid?: string): Promise<Session> {
    validateSession(sid, value);
    if (previousSid === sid) throw new Error('A new application session requires a new cookie');
    const session = structuredClone(value);
    const key = this.protection.key(sid);
    const accountKey = this.protection.accountKey(session.agent);
    const encrypted = session.live ? this.protection.encrypt(key, session.live) : null;
    return this.transaction('create', async (client) => {
      await client.query(`INSERT INTO ${this.name('app_accounts')} (account_key, first_seen)
        VALUES ($1, ${this.name('app_now')}()) ON CONFLICT (account_key) DO NOTHING`, [accountKey]);
      const account = await client.query<{ first_seen: string }>(`SELECT first_seen FROM ${this.name('app_accounts')} WHERE account_key = $1`, [accountKey]);
      if (!account.rows[0]) throw new Error('Application account is missing');
      const live = session.live && session.live.accessTokenExpiresAt > await this.now(client) ? session.live : undefined;
      await client.query(`INSERT INTO ${this.name('app_sessions')} (key, account_key, agent, expires_at, live_expires_at, live_ciphertext)
        VALUES ($1, $2, $3, $4, $5, $6)`, [key, accountKey, session.agent, session.expiresAt, live?.accessTokenExpiresAt ?? null, live ? encrypted : null]);
      if (validSid(previousSid)) await client.query(`DELETE FROM ${this.name('app_sessions')} WHERE key = $1`, [this.protection.key(previousSid)]);
      await this.checkpoint(client, 'create', 'after-lock');
      return { ...session, live, firstSeen: new Date(Number(account.rows[0].first_seen) * 1000).toISOString() };
    }, { finalize: async (client, result) => {
      // All uniqueness, account and previous-session waits have completed. No caller timestamp authorizes expiry.
      const now = await this.now(client);
      if (result.expiresAt <= now) throw new Error('Application session has expired before creation');
      if (result.live && result.live.accessTokenExpiresAt <= now) {
        await client.query(`UPDATE ${this.name('app_sessions')} SET live_expires_at = NULL, live_ciphertext = NULL WHERE key = $1`, [key]);
        delete result.live;
      }
      return result;
    } });
  }

  private async read(client: PoolClient, key: string): Promise<StoredSession | undefined> {
    const result = await client.query<StoredSession>(`SELECT s.key, s.account_key, s.agent, s.expires_at, s.live_expires_at, s.live_ciphertext, a.first_seen
      FROM ${this.name('app_sessions')} s JOIN ${this.name('app_accounts')} a USING (account_key) WHERE s.key = $1`, [key]);
    return result.rows[0];
  }
  private session(row: StoredSession | undefined, now: number): Session | undefined {
    if (!row || Number(row.expires_at) <= now) return undefined;
    if (this.protection.accountKey(row.agent) !== row.account_key) throw new Error('Invalid stored application account');
    const result: Session = { agent: row.agent, expiresAt: Number(row.expires_at), firstSeen: new Date(Number(row.first_seen) * 1000).toISOString() };
    if (row.live_ciphertext && row.live_expires_at !== null && Number(row.live_expires_at) > now) {
      result.live = this.protection.decrypt(row.key, Number(row.live_expires_at), row.live_ciphertext);
      if (result.live.issuer !== row.agent.iss || result.live.sub !== row.agent.sub) throw new Error('Stored live check does not match application account');
    }
    return result;
  }
  async get(sid: string): Promise<Session | undefined> {
    if (!validSid(sid)) return undefined;
    const key = this.protection.key(sid);
    return this.transaction('get', async (client) => ({ row: await this.read(client, key), now: 0 }), { finalize: async (client, original) => {
      let row = original.row;
      let now = await this.now(client);
      if (row?.live_expires_at !== null && row?.live_expires_at !== undefined && Number(row.live_expires_at) <= now) {
        // Only expired credentials cause a write. This is never an upsert: a simultaneous logout stays deleted.
        await client.query(`UPDATE ${this.name('app_sessions')} SET live_expires_at = NULL, live_ciphertext = NULL
          WHERE key = $1 AND live_expires_at <= $2`, [key, now]);
        await this.checkpoint(client, 'get', 'after-lock');
        row = await this.read(client, key);
        now = await this.now(client);
      }
      return { row, now };
    } }).then(({ row, now }) => this.session(row, now));
  }

  async revoke(sid: string): Promise<void> {
    if (!validSid(sid)) return;
    await this.transaction('revoke', async (client) => {
      await client.query(`DELETE FROM ${this.name('app_sessions')} WHERE key = $1`, [this.protection.key(sid)]);
      await this.checkpoint(client, 'revoke', 'after-lock');
    });
  }

  /** Bounded expiry work, safe to run concurrently on multiple hosts. Account first-seen records are retained. */
  async cleanup(limit = 1000): Promise<number> {
    cleanupLimit(limit);
    return this.transaction('cleanup', async (client) => {
      await client.query(`LOCK TABLE ${this.name('app_sessions')} IN ROW EXCLUSIVE MODE`);
      const initialNow = await this.now(client);
      const expired = await client.query<{ key: string }>(`SELECT key FROM ${this.name('app_sessions')} WHERE expires_at <= $1
        ORDER BY expires_at, key LIMIT $2 FOR UPDATE SKIP LOCKED`, [initialNow, limit]);
      const credentials = expired.rows.length === limit ? { rows: [] as { key: string }[] } : await client.query<{ key: string }>(
        `SELECT key FROM ${this.name('app_sessions')} WHERE live_expires_at <= $1 AND expires_at > $1
         ORDER BY live_expires_at, key LIMIT $2 FOR UPDATE SKIP LOCKED`, [initialNow, limit - expired.rows.length]);
      await this.checkpoint(client, 'cleanup', 'after-lock');
      const now = await this.now(client);
      const removed = expired.rows.length ? await client.query(`DELETE FROM ${this.name('app_sessions')}
        WHERE key = ANY($1::text[]) AND expires_at <= $2`, [expired.rows.map((row) => row.key), now]) : undefined;
      const erased = credentials.rows.length ? await client.query(`UPDATE ${this.name('app_sessions')} SET live_expires_at = NULL, live_ciphertext = NULL
        WHERE key = ANY($1::text[]) AND live_expires_at <= $2`, [credentials.rows.map((row) => row.key), now]) : undefined;
      return (removed?.rowCount ?? 0) + (erased?.rowCount ?? 0);
    });
  }

  /** Explicit DDL operation. Neither normal requests nor startup verification migrate storage. */
  async migrate(): Promise<void> {
    await this.transaction('migrate', async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`agentlogin-example-app-sessions:${this.schema}`]);
      await this.checkpoint(client, 'migrate', 'after-lock');
      await client.query(`CREATE SCHEMA IF NOT EXISTS ${quote(this.schema)}`);
      await client.query(`CREATE TABLE IF NOT EXISTS ${this.name('app_schema_migrations')} (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`);
      const result = await client.query<{ version: number }>(`SELECT version FROM ${this.name('app_schema_migrations')} ORDER BY version DESC LIMIT 1`);
      const version = result.rows[0]?.version ?? 0;
      if (version === VERSION) return;
      if (version !== 0) throw new Error('Unsupported PostgreSQL application session schema version');
      await client.query(`CREATE FUNCTION ${this.name('app_now')}() RETURNS bigint LANGUAGE sql VOLATILE SET search_path = pg_catalog
          AS 'SELECT floor(extract(epoch FROM clock_timestamp()))::bigint';
        CREATE TABLE ${this.name('app_accounts')} (
          account_key text PRIMARY KEY CHECK (account_key ~ '^[0-9a-f]{64}$'),
          first_seen bigint NOT NULL CHECK (first_seen BETWEEN 0 AND ${MAX_TIME})
        );
        CREATE TABLE ${this.name('app_sessions')} (
          key text PRIMARY KEY CHECK (key ~ '^[0-9a-f]{64}$'),
          account_key text NOT NULL REFERENCES ${this.name('app_accounts')} (account_key),
          agent jsonb NOT NULL CHECK (jsonb_typeof(agent) = 'object'),
          expires_at bigint NOT NULL CHECK (expires_at BETWEEN 1 AND ${MAX_TIME}),
          live_expires_at bigint CHECK (live_expires_at BETWEEN 1 AND ${MAX_TIME}),
          live_ciphertext bytea,
          CHECK ((live_expires_at IS NULL) = (live_ciphertext IS NULL)),
          CHECK (live_ciphertext IS NULL OR octet_length(live_ciphertext) >= 29)
        );
        CREATE INDEX app_sessions_expiry ON ${this.name('app_sessions')} (expires_at, key);
        CREATE INDEX app_sessions_live_expiry ON ${this.name('app_sessions')} (live_expires_at, key) WHERE live_expires_at IS NOT NULL;
        INSERT INTO ${this.name('app_schema_migrations')} (version) VALUES (${VERSION});`);
    });
  }

  async verifySchema(): Promise<void> {
    try {
      await this.transaction('verifySchema', async (client) => {
        const result = await client.query<{ version: number }>(`SELECT version FROM ${this.name('app_schema_migrations')} ORDER BY version DESC LIMIT 1`);
        if (result.rows[0]?.version !== VERSION) throw new Error('Unsupported PostgreSQL application session schema version');
        await client.query(`SELECT s.key, s.agent, s.expires_at, s.live_expires_at, s.live_ciphertext, a.first_seen
          FROM ${this.name('app_sessions')} s JOIN ${this.name('app_accounts')} a USING (account_key) LIMIT 0`);
        await this.now(client);
      }, { readOnly: true });
    } catch (error) {
      if (['42P01', '3F000', '42883'].includes(sqlState(error) ?? '')) throw new Error('PostgreSQL application session schema is not initialized. Run npm run example:migrate before serving requests.', { cause: error });
      throw error;
    }
  }

  /** Drain requests first. An external pool remains under its owner's control. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try { if (this.ownedPool) await this.pool.end(); }
    finally { this.pool.removeListener('error', this.poolErrorHandler); }
  }
}
