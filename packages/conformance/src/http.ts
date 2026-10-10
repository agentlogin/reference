// Minimal HTTP helper: never follows redirects, captures status, headers and parsed body.
import { AsyncLocalStorage } from 'node:async_hooks';

export interface Res {
  status: number;
  headers: Headers;
  text: string;
  json: unknown;
}
/** One request and its response, as reported to the run that made it. */
export interface Exchange { method: string; url: string; res: Res }
/**
 * Per-run context of `call`: `seen` receives every exchange of the run, including those of the Agent Client, so that a
 * check can audit response headers across the whole run (I-49); `headers` are added to every request that does not set
 * them itself.
 */
export interface CallContext { seen?: (x: Exchange) => void; headers?: Record<string, string> }
export const callContext = new AsyncLocalStorage<CallContext>();

export async function call(url: string, init: RequestInit & { json?: unknown; form?: Record<string, string> } = {}): Promise<Res> {
  const cx = callContext.getStore();
  const headers = new Headers(init.headers);
  let body = init.body;
  if (init.json !== undefined) {
    headers.set('content-type', 'application/json');
    body = JSON.stringify(init.json);
  }
  if (init.form) {
    headers.set('content-type', 'application/x-www-form-urlencoded');
    body = new URLSearchParams(init.form).toString();
  }
  if (!headers.has('accept')) headers.set('accept', 'application/json');
  for (const [k, v] of Object.entries(cx?.headers ?? {})) if (!headers.has(k)) headers.set(k, v);
  const r = await fetch(url, { ...init, headers, body, redirect: 'manual' });
  const text = await r.text();
  let json: unknown = undefined;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  const res: Res = { status: r.status, headers: r.headers, text, json };
  cx?.seen?.({ method: (init.method ?? 'GET').toUpperCase(), url, res });
  return res;
}
export const obj = (v: unknown): Record<string, any> => (typeof v === 'object' && v !== null ? (v as Record<string, any>) : {});
