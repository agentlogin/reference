import { LEGACY_SIGNING_OVERLAP_SECONDS, ownerAddressKey } from '@agentlogin/issuer';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool, type PoolClient, type QueryResult, type QueryResultRow } from 'pg';
import { identifier, schemaV1, schemaV2, schemaV3, SCHEMA_VERSION, TABLES, type TableName, validateSchema } from './schema.js';

export interface PgCheckpoint {
  operation: string;
  phase: string;
  /** Zero-based whole-transaction attempt, never a statement retry. */
  attempt: number;
  client: PoolClient;
}
export interface PgOptions {
  connectionString?: string;
  /** An externally managed pool. close() does not end it. Must connect to the authoritative primary. */
  pool?: Pool;
  schema?: string;
  maxConnections?: number;
  connectionTimeoutMs?: number;
  statementTimeoutMs?: number;
  lockTimeoutMs?: number;
  idleTransactionTimeoutMs?: number;
  maxRetries?: number;
  retryBaseMs?: number;
  /** Fault injection / scheduling for tests; no hooks are installed by default. Never log query values here. */
  onCheckpoint?: (event: PgCheckpoint) => Promise<void> | void;
  /** Optional reporting for idle connection errors, which also cause the pool to discard the connection. */
  onPoolError?: (error: Error) => void;
}
export type Reconciliation<T> = { resolved: true; value: T } | { resolved: false };

export class UncertainCommitError extends Error {
  readonly operation: string;
  constructor(operation: string, cause: unknown) {
    super(`The commit outcome for ${operation} could not be established; do not blindly repeat this operation`, { cause });
    this.name = 'UncertainCommitError';
    this.operation = operation;
  }
}

function boundedInteger(value: number | undefined, fallback: number, name: string, min: number, max = 2_147_483_647): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < min || result > max) throw new RangeError(`${name} must be an integer from ${min} to ${max}`);
  return result;
}
function sqlState(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' ? error.code : undefined;
}
const retryable = (error: unknown): boolean => ['40001', '40P01'].includes(sqlState(error) ?? '');

/** Pool error handlers cover idle clients only; checked-out clients emit socket failures independently. */
function watchConnection(client: PoolClient) {
  let failure: Error | undefined;
  const onError = (error: Error): void => { failure = error; };
  client.on('error', onError);
  return {
    failed: () => failure !== undefined,
    check: (): void => { if (failure) throw failure; },
    release: (poisoned: boolean): void => {
      // release restores the pool's idle listener. Remove ours afterwards so no event has an unhandled gap.
      try { client.release(poisoned || failure !== undefined); }
      finally { client.removeListener('error', onError); }
    },
  };
}

/** One checked-out connection. Every query in an atomic operation uses this session. */
export class PgSession {
  constructor(
    readonly client: PoolClient,
    private readonly database: PgDatabase,
    readonly operation: string,
    readonly attempt: number,
  ) {}
  table(name: TableName | string): string { return this.database.table(name); }
  query<Row extends QueryResultRow = QueryResultRow>(text: string, values?: readonly unknown[]): Promise<QueryResult<Row>> {
    return this.client.query<Row>(text, values === undefined ? undefined : [...values]);
  }
  /** Must be called after quota waits and before the security-sensitive decision. Do not cache across waits. */
  async now(): Promise<number> {
    const result = await this.query<{ now: number }>(`SELECT ${identifier(this.database.schema)}.app_now() AS now`);
    const now = Number(result.rows[0]?.now);
    if (!Number.isSafeInteger(now)) throw new Error('app_now() must return a finite integer number of epoch seconds');
    return now;
  }
  async checkpoint(phase: string): Promise<void> {
    await this.database.checkpoint({ operation: this.operation, phase, attempt: this.attempt, client: this.client });
  }
}

/** Async PostgreSQL transactions with complete rollback retries and conservative uncertain-commit recovery. */
export class PgDatabase {
  readonly pool: Pool;
  readonly schema: string;
  private readonly ownedPool: boolean;
  private readonly options: Required<Pick<PgOptions, 'statementTimeoutMs' | 'lockTimeoutMs' | 'idleTransactionTimeoutMs' | 'maxRetries' | 'retryBaseMs'>>;
  private readonly hook?: PgOptions['onCheckpoint'];
  private readonly poolErrorHandler: (error: Error) => void;
  private closed = false;

  constructor(options: PgOptions = {}) {
    if (options.pool && options.connectionString) throw new TypeError('Supply pool or connectionString, not both');
    this.schema = validateSchema(options.schema ?? 'agentlogin');
    this.options = {
      statementTimeoutMs: boundedInteger(options.statementTimeoutMs, 10_000, 'statementTimeoutMs', 1),
      lockTimeoutMs: boundedInteger(options.lockTimeoutMs, 5_000, 'lockTimeoutMs', 1),
      idleTransactionTimeoutMs: boundedInteger(options.idleTransactionTimeoutMs, 30_000, 'idleTransactionTimeoutMs', 1),
      maxRetries: boundedInteger(options.maxRetries, 3, 'maxRetries', 0, 20),
      retryBaseMs: boundedInteger(options.retryBaseMs, 5, 'retryBaseMs', 0, 10_000),
    };
    this.ownedPool = !options.pool;
    this.pool = options.pool ?? new Pool({
      connectionString: options.connectionString,
      max: boundedInteger(options.maxConnections, 10, 'maxConnections', 1, 1000),
      connectionTimeoutMillis: boundedInteger(options.connectionTimeoutMs, 5_000, 'connectionTimeoutMs', 1),
      idleTimeoutMillis: 30_000,
    });
    this.hook = options.onCheckpoint;
    this.poolErrorHandler = (error: Error) => { options.onPoolError?.(error); };
    this.pool.on('error', this.poolErrorHandler);
  }

  table(name: TableName | string): string {
    if (!(TABLES as readonly string[]).includes(name)) throw new TypeError(`Unknown issuer table: ${name}`);
    return `${identifier(this.schema)}.${identifier(name)}`;
  }
  async checkpoint(event: PgCheckpoint): Promise<void> { await this.hook?.(event); }
  private async connect(): Promise<PoolClient> {
    if (this.closed) throw new Error('PostgreSQL store is closed');
    return this.pool.connect();
  }
  private async configure(client: PoolClient): Promise<void> {
    await client.query(`SELECT
      set_config('statement_timeout', $1, true),
      set_config('lock_timeout', $2, true),
      set_config('idle_in_transaction_session_timeout', $3, true),
      set_config('search_path', 'pg_catalog', true),
      set_config('synchronous_commit', 'on', true)`, [
      String(this.options.statementTimeoutMs), String(this.options.lockTimeoutMs), String(this.options.idleTransactionTimeoutMs),
    ]);
  }

  /** Polling and ordinary lookups cannot mutate the database. */
  async read<T>(fn: (session: PgSession) => Promise<T>): Promise<T> {
    const client = await this.connect();
    const connection = watchConnection(client);
    let poisoned = false;
    try {
      await client.query('BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY');
      await this.configure(client);
      const result = await fn(new PgSession(client, this, 'read', 0));
      connection.check();
      const commit = await client.query('COMMIT');
      if (commit.command !== 'COMMIT') throw new Error('PostgreSQL rolled back the transaction instead of committing');
      connection.check();
      return result;
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch { poisoned = true; }
      throw error;
    } finally { connection.release(poisoned); }
  }

  async mutate<T>(
    operation: string,
    fn: (session: PgSession) => Promise<T>,
    reconcile?: (session: PgSession) => Promise<Reconciliation<T>>,
  ): Promise<T> {
    for (let attempt = 0; ; attempt += 1) {
      const client = await this.connect();
      const connection = watchConnection(client);
      let committing = false;
      let committed = false;
      let poisoned = false;
      let released = false;
      try {
        await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE READ WRITE');
        await this.configure(client);
        const session = new PgSession(client, this, operation, attempt);
        await session.checkpoint('afterBegin');
        connection.check();
        const result = await fn(session);
        await session.checkpoint('beforeCommit');
        connection.check();
        committing = true;
        const commit = await client.query('COMMIT');
        if (commit.command !== 'COMMIT') {
          // PostgreSQL answers COMMIT with ROLLBACK when the callback swallowed an earlier SQL error.
          committing = false;
          throw new Error('PostgreSQL rolled back the transaction instead of committing');
        }
        committed = true;
        // Throwing here deliberately models a committed write whose acknowledgement never reached its caller.
        await session.checkpoint('afterCommit');
        connection.check();
        return result;
      } catch (error) {
        if (committed || (committing && (!retryable(error) || connection.failed()))) {
          poisoned = true;
          connection.release(true);
          released = true;
          if (reconcile) {
            try {
              const resolution = await this.read(reconcile);
              if (resolution.resolved) return resolution.value;
            } catch { /* Failed or inconclusive reconciliation must never repeat an uncertain mutation. */ }
          }
          throw new UncertainCommitError(operation, error);
        }
        try { await client.query('ROLLBACK'); } catch { poisoned = true; }
        if (connection.failed() || !retryable(error) || attempt >= this.options.maxRetries) throw error;
      } finally { if (!released) connection.release(poisoned); }
      // Bounded exponential delay with jitter. This delay holds no database connection or lock.
      const cap = Math.min(this.options.retryBaseMs * 2 ** attempt, 1_000);
      if (cap > 0) await delay(Math.floor(cap / 2 + Math.random() * cap / 2));
    }
  }

  /** Startup check for a DML-only service role. This never performs a migration. */
  async verifySchema(): Promise<void> {
    let version: number | undefined;
    try {
      version = await this.read(async (s) => (await s.query<{ version: number }>(
        `SELECT version FROM ${identifier(this.schema)}.schema_migrations ORDER BY version DESC LIMIT 1`,
      )).rows[0]?.version);
    } catch (error) {
      if (sqlState(error) !== '42P01' && sqlState(error) !== '3F000') throw error;
      throw new Error(`PostgreSQL schema ${this.schema} is not initialized. Run agentlogin-migrate with DATABASE_URL and DATABASE_SCHEMA before starting the issuer.`);
    }
    if (version !== SCHEMA_VERSION) {
      throw new Error(`PostgreSQL schema ${this.schema} has version ${version ?? 'none'}; this adapter requires ${SCHEMA_VERSION}. Run the matching agentlogin-migrate deployment command, or install an adapter compatible with the database version.`);
    }
  }

  /** Explicit versioned migration. The advisory lock is used only for DDL, never for issuer operations. */
  async migrate(): Promise<void> {
    const client = await this.connect();
    const connection = watchConnection(client);
    let poisoned = false;
    let committing = false;
    try {
      await client.query('BEGIN');
      await this.configure(client);
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`agentlogin-store-postgres:${this.schema}`]);
      await client.query(`CREATE SCHEMA IF NOT EXISTS ${identifier(this.schema)}`);
      const migrations = `${identifier(this.schema)}.schema_migrations`;
      await client.query(`CREATE TABLE IF NOT EXISTS ${migrations} (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`);
      const found = await client.query<{ version: number }>(`SELECT version FROM ${migrations} ORDER BY version DESC LIMIT 1`);
      let version = found.rows[0]?.version ?? 0;
      const upgradingExistingSchema = version > 0;
      if (version > SCHEMA_VERSION) throw new Error(`Database schema ${version} is newer than supported schema ${SCHEMA_VERSION}`);
      if (version === 0) {
        await client.query(schemaV1(this.schema));
        await client.query(`INSERT INTO ${migrations} (version) VALUES (1)`);
        version = 1;
      }
      if (version === 1) {
        await client.query(schemaV2(this.schema));
        await client.query(`INSERT INTO ${migrations} (version) VALUES (2)`);
        version = 2;
      }
      if (version === 2) {
        await client.query(schemaV3(this.schema,upgradingExistingSchema ? LEGACY_SIGNING_OVERLAP_SECONDS : 0));
        const owners = await client.query<{ id: string; data: { email: string } }>(`SELECT id,data FROM ${this.table('owners')}`);
        for (const owner of owners.rows) await client.query(`UPDATE ${this.table('owners')} SET address_key=$1 WHERE id=$2`, [ownerAddressKey(owner.data.email),owner.id]);
        await client.query(`INSERT INTO ${this.table('signup_events')}(owner_id,client_id,event_id)
          SELECT target.id,e.client_id,e.event_id FROM ${this.table('owners')} target JOIN ${this.table('owners')} source ON source.address_key=target.address_key
          JOIN ${this.table('signup_events')} e ON e.owner_id=source.id
          WHERE (target.data->>'emailVerified')::boolean AND (source.data->>'emailVerified')::boolean ON CONFLICT DO NOTHING`);
        await client.query(`ALTER TABLE ${this.table('owners')} ALTER COLUMN address_key DROP DEFAULT`);
        await client.query(`INSERT INTO ${migrations} (version) VALUES (3)`);
      }
      connection.check();
      committing = true;
      const commit = await client.query('COMMIT');
      if (commit.command !== 'COMMIT') {
        committing = false;
        throw new Error('PostgreSQL rolled back the migration instead of committing');
      }
      connection.check();
    } catch (error) {
      if (committing) {
        poisoned = true;
        throw new UncertainCommitError('migrate', error);
      }
      try { await client.query('ROLLBACK'); } catch { poisoned = true; }
      throw error;
    } finally { connection.release(poisoned); }
  }

  /** Drain issuer requests before closing. Caller-supplied pools retain their owner-controlled lifecycle. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    if (this.ownedPool) await this.pool.end();
    this.pool.removeListener('error', this.poolErrorHandler);
  }
}
