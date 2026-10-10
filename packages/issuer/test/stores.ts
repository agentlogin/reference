// Store wrappers that give the in-memory store the timing and copy semantics of a database, for tests.
import type { Store } from '../src/index.js';

/**
 * Database semantics: every read returns a copy taken at the time of the query, every write stores a copy, and each
 * operation completes on a later turn of the event loop. The in-memory store answers within the same turn and hands
 * out the stored objects themselves, which hides races between concurrent requests: with it a handler is never
 * interrupted between two store operations, and a change made by one request is visible to another at once.
 */
export function snapshotting(store: Store): Store {
  const copy = <T>(v: T): T => (v === undefined ? v : structuredClone(v));
  return new Proxy(store, {
    get(target, prop, receiver) {
      const v = Reflect.get(target, prop, receiver) as unknown;
      if (typeof v !== 'function') return v;
      return async (...args: unknown[]) => {
        const result = await (v as (...a: unknown[]) => unknown).apply(target, args.map(copy));
        await new Promise((r) => setImmediate(r));
        return copy(result);
      };
    },
  });
}
