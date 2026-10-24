import type { CallbackClaim, CallbackStateStore } from '@agentlogin/rp';
import { Pool, type PoolClient } from 'pg';

type Operation = 'register' | 'claim' | 'cleanup' | 'migrate' | 'verifySchema';

export interface CallbackStoreCheckpoint {
  operation: Operation;
  phase: 'after-lock' | 'before-commit' | 'after-commit';
  client: PoolClient;
}

export interface PostgresCallbackStateStoreOptions {
  /** Supply exactly one connection source, connected to the authoritative primary. */
  connectionString?: string;
  /** Externally managed pool: its owner controls pool limits and connection acquisition timeouts. */
  pool?: Pool;
  schema?: string;
  maxConnections?: number;
  connectionTimeoutMs?: number;
  statementTimeoutMs?: number;
  lockTimeoutMs?: number;
  idleTransactionTimeoutMs?: number;
  /** Fault injection / scheduling only. Never log query values or perform application work here. */
  onCheckpoint?: (event: CallbackStoreCheckpoint) => Promise<void> | void;
  /** Optional reporting for idle pool errors. Raw driver errors may contain sensitive data. */
  onPoolError?: (error: Error) => void;
}

/** The callback must fail closed. A second attempt cannot establish ownership of an earlier claim. */
export class UncertainCommitError extends Error {
  readonly operation: Operation;
  constructor(operation: Operation, cause: unknown) {
    super(`The commit outcome for ${operation} is uncertain; abandon this sign-in instead of repeating the operation`, { cause });
    this.name = 'UncertainCommitError';
    this.operation = operation;
  }
}

const SCHEMA_VERSION = 1;
const MAX_KEY_BYTES = 1024;
const MAX_SAFE_TIME = Number.MAX_SAFE_INTEGER;
const quote = (identifier: string): string => `"${identifier}"`;

function integer(value: number | undefined, fallback: number, name: string, max = 2_147_483_647): number {
  const actual = value ?? fallback;
  if (!Number.isSafeInteger(actual) || actual < 1 || actual > max) throw new RangeError(`${name} must be an integer from 1 to ${max}`);
  return actual;
}

function validateKey(key: string): void {
  if (typeof key !== 'string' || key.length === 0 || key.includes('\0') || Buffer.byteLength(key, 'utf8') > MAX_KEY_BYTES) {
    throw new TypeError('Callback state key must be nonempty UTF-8 text of at most 1024 bytes, without NUL');
  }
}

function sqlState(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' ? error.code : undefined;
}

/**
 * Durable one-use callbacks shared across RP instances. Each operation uses one connection and one transaction.
 * No application, network, or token exchange work belongs inside these transactions. Claims are never released.
 */
export class PostgresCallbackStateStore implements CallbackStateStore {
  readonly schema: string;
  private readonly pool: Pool;
  private readonly ownedPool: boolean;
  private readonly statementTimeoutMs: number;
  private readonly lockTimeoutMs: number;
  private readonly idleTransactionTimeoutMs: number;
  private readonly hook?: PostgresCallbackStateStoreOptions['onCheckpoint'];
  private readonly poolErrorHandler: (error: Error) => void;
  private closed = false;

  constructor(options: PostgresCallbackStateStoreOptions) {
    if (!options || (!!options.pool === (options.connectionString !== undefined))) {
      throw new TypeError('Supply exactly one of pool or connectionString');
    }
    if (options.connectionString !== undefined && (typeof options.connectionString !== 'string' || options.connectionString.trim() === '')) {
      throw new TypeError('connectionString must be nonempty');
    }
    this.schema = options.schema ?? 'agentlogin_rp';
    if (typeof this.schema !== 'string' || !/^[a-z_][a-z0-9_]{0,62}$/.test(this.schema) || this.schema.startsWith('pg_')) {
      throw new TypeError('PostgreSQL schema must be a lowercase SQL identifier of at most 63 characters, outside pg_*');
    }
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

  private name(name: 'callback_states' | 'schema_migrations' | 'app_now_ms'): string {
    return `${quote(this.schema)}.${quote(name)}`;
  }

  private async checkpoint(client: PoolClient, operation: Operation, phase: CallbackStoreCheckpoint['phase']): Promise<void> {
    await this.hook?.({ client, operation, phase });
  }

  private async now(client: PoolClient): Promise<number> {
    const result = await client.query<{ now: string }>(`SELECT ${this.name('app_now_ms')}() AS now`);
    const raw = result.rows[0]?.now;
    const now = raw === null || raw === undefined ? NaN : Number(raw);
    if (!Number.isSafeInteger(now) || now < 0) throw new Error('app_now_ms() must return a nonnegative safe integer Unix time in milliseconds');
    return now;
  }

  private async transaction<T>(operation: Operation, action: (client: PoolClient) => Promise<T>, readOnly = false): Promise<T> {
    if (this.closed) throw new Error('PostgreSQL callback store is closed');
    const client = await this.pool.connect();
    let committing = false;
    let committed = false;
    let discard = false;
    let connectionError: Error | undefined;
    // pg-pool handles idle connections only. A checked-out client emits errors independently of query rejection.
    const onClientError = (error: Error): void => { connectionError = error; discard = true; };
    client.on('error', onClientError);
    try {
      await client.query(`BEGIN ISOLATION LEVEL READ COMMITTED ${readOnly ? 'READ ONLY' : 'READ WRITE'}`);
      await client.query(`SELECT
        set_config('statement_timeout', $1, true),
        set_config('lock_timeout', $2, true),
        set_config('idle_in_transaction_session_timeout', $3, true),
        set_config('search_path', 'pg_catalog', true),
        set_config('synchronous_commit', 'on', true)`, [
        String(this.statementTimeoutMs), String(this.lockTimeoutMs), String(this.idleTransactionTimeoutMs),
      ]);
      const result = await action(client);
      await this.checkpoint(client, operation, 'before-commit');
      if (connectionError) throw connectionError;
      committing = true;
      const commit = await client.query('COMMIT');
      if (commit.command !== 'COMMIT') {
        committing = false;
        throw new Error('PostgreSQL rolled back the callback transaction instead of committing');
      }
      committed = true;
      await this.checkpoint(client, operation, 'after-commit');
      if (connectionError) throw connectionError;
      return result;
    } catch (error) {
      // Never replay a mutation whose commit may have reached PostgreSQL. In particular, used=true is not proof
      // that this caller won. A hook after COMMIT models a lost acknowledgement after a durable claim.
      if (committed || committing) {
        discard = true;
        throw new UncertainCommitError(operation, error);
      }
      try { await client.query('ROLLBACK'); } catch { discard = true; }
      throw error;
    } finally {
      try { client.release(discard); }
      finally { client.removeListener('error', onClientError); }
    }
  }

  async register(key: string, expiresAt: number): Promise<boolean> {
    validateKey(key);
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0) throw new TypeError('Callback expiry must be a positive safe integer Unix time in milliseconds');
    return this.transaction('register', async (client) => {
      const inserted = await client.query(
        `INSERT INTO ${this.name('callback_states')} (key, expires_at) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`,
        [key, expiresAt],
      );
      await this.checkpoint(client, 'register', 'after-lock');
      // Uniqueness checks can wait on another transaction. An expiry sampled before that wait is insufficient.
      if (expiresAt <= await this.now(client)) throw new Error('Callback state registration has expired');
      return inserted.rowCount === 1;
    });
  }

  async claim(key: string): Promise<CallbackClaim> {
    validateKey(key);
    return this.transaction('claim', async (client) => {
      // Acquire the UPDATE's table lock before sampling time. It is compatible with other ordinary readers and
      // writers, but prevents a later lock upgrade waiting behind maintenance after the expiry decision.
      await client.query(`LOCK TABLE ${this.name('callback_states')} IN ROW EXCLUSIVE MODE`);
      // Do not put expiry in this predicate: a lock-only blocker can outlast expiry without changing the row.
      const found = await client.query<{ expires_at: string; used: boolean }>(
        `SELECT expires_at, used FROM ${this.name('callback_states')} WHERE key = $1 FOR UPDATE`, [key],
      );
      await this.checkpoint(client, 'claim', 'after-lock');
      const now = await this.now(client);
      const row = found.rows[0];
      if (!row || Number(row.expires_at) <= now) return 'missing';
      if (row.used) return 'duplicate';
      await client.query(`UPDATE ${this.name('callback_states')} SET used = true WHERE key = $1`, [key]);
      return 'claimed';
    });
  }

  /** Remove only expired rows in a bounded indexed batch. Schedule separately from login and callback requests. */
  async cleanup(limit = 1000): Promise<number> {
    if (typeof limit !== 'number') throw new TypeError('cleanup limit must be a number');
    integer(limit, 1000, 'cleanup limit', 10_000);
    return this.transaction('cleanup', async (client) => {
      const now = await this.now(client);
      const selected = await client.query<{ key: string }>(
        `SELECT key FROM ${this.name('callback_states')} WHERE expires_at <= $1
         ORDER BY expires_at, key LIMIT $2 FOR UPDATE SKIP LOCKED`, [now, limit],
      );
      await this.checkpoint(client, 'cleanup', 'after-lock');
      if (!selected.rows.length) return 0;
      const deleted = await client.query(
        `DELETE FROM ${this.name('callback_states')} WHERE key = ANY($1::text[]) AND expires_at <= $2`,
        [selected.rows.map((row) => row.key), await this.now(client)],
      );
      return deleted.rowCount ?? 0;
    });
  }

  /** Deployment operation using a DDL-capable role; ordinary requests never create database objects. */
  async migrate(): Promise<void> {
    await this.transaction('migrate', async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`agentlogin-rp-store-postgres:${this.schema}`]);
      await this.checkpoint(client, 'migrate', 'after-lock');
      await client.query(`CREATE SCHEMA IF NOT EXISTS ${quote(this.schema)}`);
      await client.query(`CREATE TABLE IF NOT EXISTS ${this.name('schema_migrations')} (
        version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
      )`);
      const found = await client.query<{ version: number }>(`SELECT version FROM ${this.name('schema_migrations')} ORDER BY version DESC LIMIT 1`);
      const version = found.rows[0]?.version ?? 0;
      if (version === SCHEMA_VERSION) return;
      if (version !== 0) throw new Error('PostgreSQL callback schema version is not supported by this adapter');
      await client.query(`
        CREATE FUNCTION ${this.name('app_now_ms')}() RETURNS bigint LANGUAGE sql VOLATILE
          SET search_path = pg_catalog
          AS 'SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint';
        CREATE TABLE ${this.name('callback_states')} (
          key text PRIMARY KEY CHECK (octet_length(key) BETWEEN 1 AND ${MAX_KEY_BYTES}),
          expires_at bigint NOT NULL CHECK (expires_at BETWEEN 1 AND ${MAX_SAFE_TIME}),
          used boolean NOT NULL DEFAULT false
        );
        CREATE INDEX callback_states_expiry ON ${this.name('callback_states')} (expires_at, key);
        INSERT INTO ${this.name('schema_migrations')} (version) VALUES (${SCHEMA_VERSION});
      `);
    });
  }

  /** Startup check: requires schema usage, function execute, callback-table DML and migration-version SELECT. */
  async verifySchema(): Promise<void> {
    try {
      await this.transaction('verifySchema', async (client) => {
        const found = await client.query<{ version: number }>(`SELECT version FROM ${this.name('schema_migrations')} ORDER BY version DESC LIMIT 1`);
        if (found.rows[0]?.version !== SCHEMA_VERSION) throw new Error('PostgreSQL callback schema version is not supported by this adapter');
        await client.query(`SELECT key, expires_at, used FROM ${this.name('callback_states')} LIMIT 0`);
        await this.now(client);
      }, true);
    } catch (error) {
      if (['42P01', '3F000', '42883'].includes(sqlState(error) ?? '')) {
        throw new Error('PostgreSQL callback schema is not initialized. Run agentlogin-rp-migrate before serving callbacks.', { cause: error });
      }
      throw error;
    }
  }

  /** Drain application requests before closing. An external pool retains its owner-controlled lifecycle. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try { if (this.ownedPool) await this.pool.end(); }
    finally { this.pool.removeListener('error', this.poolErrorHandler); }
  }
}
