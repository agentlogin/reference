// Store wrappers for tests: database timing and copy semantics, and hooks that place one request inside another.
import type { Store } from '../src/index.js';

const copy = <T>(v: T): T => (v === undefined ? v : structuredClone(v));

/**
 * Database semantics: a read returns a copy taken at the time of the query, a write stores a copy, and each operation
 * completes on a later turn of the event loop. The copy is taken before the turn is yielded, so a change that another
 * request makes in between is not visible in the result, exactly as with a query that has already been answered.
 */
export function snapshotting(store: Store): Store {
  return new Proxy(store, {
    get(target, prop, receiver) {
      const v = Reflect.get(target, prop, receiver) as unknown;
      if (typeof v !== 'function') return v;
      return async (...args: unknown[]) => {
        const result = copy(await (v as (...a: unknown[]) => unknown).apply(target, args.map(copy)));
        await new Promise((r) => setImmediate(r));
        return result;
      };
    },
  });
}

/**
 * Runs `hook` once, right after the next call of `method` has been answered and before its caller continues: the
 * place where another request can slip in between two store operations of one handler.
 */
export function hookable(store: Store): { store: Store; after: (method: keyof Store, hook: () => Promise<void>) => void } {
  const hooks = new Map<string, () => Promise<void>>();
  const proxy = new Proxy(store, {
    get(target, prop, receiver) {
      const v = Reflect.get(target, prop, receiver) as unknown;
      if (typeof v !== 'function') return v;
      return async (...args: unknown[]) => {
        const result = await (v as (...a: unknown[]) => unknown).apply(target, args);
        const hook = hooks.get(String(prop));
        if (hook) {
          hooks.delete(String(prop));
          await hook();
        }
        return result;
      };
    },
  });
  return { store: proxy, after: (method, hook) => { hooks.set(String(method), hook); } };
}
