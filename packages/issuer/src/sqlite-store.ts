// Durable reference adapter. Mutations use one write transaction; reads never acquire the writer lock.
import { DatabaseSync, type StatementSync } from 'node:sqlite';
import { READ_METHODS, STORE_METHODS, StoreState, type Store } from './store.js';

export interface SQLiteStoreOptions {
  /** How long a competing process may hold the write lock before this operation fails (default: 5000 ms). */
  busyTimeoutMs?: number;
}

export interface SQLiteStore extends Store {}
/**
 * A deliberately coarse reference adapter: the complete state is one versioned JSON row, and every method executes
 * under BEGIN IMMEDIATE for mutations or a read transaction for queries. No state survives between calls, and no
 * await occurs while a transaction owns the lock. Reads still parse the complete snapshot.
 * Separate connections and processes therefore see every preceding committed change. Use a local filesystem;
 * WAL databases must not be shared over a network filesystem. This design favors auditable guarantees over scale.
 */
export class SQLiteStore {
  private readonly database: DatabaseSync;
  private readonly read: StatementSync;
  private readonly write: StatementSync;
  private closed = false;

  constructor(path: string, options: SQLiteStoreOptions = {}) {
    const timeout = options.busyTimeoutMs ?? 5000;
    if (!Number.isSafeInteger(timeout) || timeout < 0 || timeout > 2_147_483_647) throw new RangeError('busyTimeoutMs must be a nonnegative 32-bit integer');
    this.database = new DatabaseSync(path, { enableDoubleQuotedStringLiterals: false, allowExtension: false });
    try {
      // PRAGMA works on every supported Node 22 release; DatabaseSync's timeout option arrived later.
      this.database.exec(`PRAGMA busy_timeout = ${timeout}`);
      this.database.exec('PRAGMA journal_mode = WAL');
      this.database.exec('PRAGMA synchronous = FULL');
      this.database.exec('CREATE TABLE IF NOT EXISTS agentlogin_state (id INTEGER PRIMARY KEY CHECK (id = 1), snapshot TEXT NOT NULL)');
      this.database.prepare('INSERT OR IGNORE INTO agentlogin_state (id, snapshot) VALUES (1, ?)').run(new StoreState().exportSnapshot());
      this.read = this.database.prepare('SELECT snapshot FROM agentlogin_state WHERE id = 1');
      this.write = this.database.prepare('UPDATE agentlogin_state SET snapshot = ? WHERE id = 1');
    } catch (error) {
      this.database.close();
      throw error;
    }

    return new Proxy(this, {
      get: (target, property) => {
        const method = Object.getOwnPropertyDescriptor(StoreState.prototype, property)?.value as unknown;
        if (typeof method === 'function' && STORE_METHODS.includes(property as keyof Store)) {
          return async (...args: unknown[]) => target.perform(method as (...args: unknown[]) => unknown, args, READ_METHODS.has(property as keyof Store));
        }
        const value = Reflect.get(target, property, target) as unknown;
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
  }

  private perform(method: (...args: unknown[]) => unknown, args: unknown[], readOnly: boolean): unknown {
    if (this.closed) throw new Error('SQLiteStore is closed');
    this.database.exec(readOnly ? 'BEGIN' : 'BEGIN IMMEDIATE');
    try {
      const snapshot = this.read.get()?.snapshot;
      if (typeof snapshot !== 'string') throw new Error('Missing issuer store snapshot');
      const state = new StoreState(snapshot);
      const result = Reflect.apply(method, state, args);
      // Enforce the adapter contract if a future StoreState change accidentally introduces an asynchronous method.
      if (result && typeof (result as { then?: unknown }).then === 'function') throw new Error('StoreState operations must be synchronous');
      if (!readOnly) this.write.run(state.exportSnapshot());
      this.database.exec('COMMIT');
      return result;
    } catch (error) {
      // Certain SQLite failures already roll the transaction back. A failed ROLLBACK must not hide the cause.
      try { this.database.exec('ROLLBACK'); } catch { /* already rolled back or unusable connection */ }
      throw error;
    }
  }

  /** Close this connection after requests have drained. Safe to call more than once. */
  close(): void {
    if (this.closed) return;
    this.database.close();
    this.closed = true;
  }
}
