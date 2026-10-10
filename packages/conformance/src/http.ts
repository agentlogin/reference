// Minimal HTTP helper: never follows redirects, captures status, headers and parsed body.
export interface Res {
  status: number;
  headers: Headers;
  text: string;
  json: unknown;
}
export async function call(url: string, init: RequestInit & { json?: unknown; form?: Record<string, string> } = {}): Promise<Res> {
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
  const r = await fetch(url, { ...init, headers, body, redirect: 'manual' });
  const text = await r.text();
  let json: unknown = undefined;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  return { status: r.status, headers: r.headers, text, json };
}
export const obj = (v: unknown): Record<string, any> => (typeof v === 'object' && v !== null ? (v as Record<string, any>) : {});
