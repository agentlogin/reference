import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';
import { workspaceView } from '../workspace-view.js';

type NoteInput = { id: string; text: string };
type Handler = (event: { preventDefault(): void }) => unknown;

/** Only the DOM surface used by the emitted script; requests and their timing remain observable. */
class Element {
  value = '';
  textContent = '';
  hidden = false;
  disabled = false;
  children: Element[] = [];
  handlers = new Map<string, Handler>();
  addEventListener(name: string, handler: Handler) { this.handlers.set(name, handler); }
  replaceChildren() { this.children = []; }
  append(...children: Element[]) { this.children.push(...children); }
  get childElementCount() { return this.children.length; }
}

async function browser(options: {
  post: (input: NoteInput, attempt: number) => Response | Promise<Response>;
  list?: (request: number, path: string) => Response | Promise<Response>;
}) {
  const elements = new Map<string, Element>();
  const element = (selector: string) => {
    if (!elements.has(selector)) elements.set(selector, new Element());
    return elements.get(selector)!;
  };
  const writes: NoteInput[] = [];
  let ids = 0, reads = 0;
  const fetch = async (path: string, init: RequestInit = {}) => {
    if (path === '/me') return Response.json({ handle: 'alice@example.com' });
    if (path === '/notes' && init.method === 'POST') {
      const input = JSON.parse(String(init.body)) as NoteInput;
      writes.push(input);
      return options.post(input, writes.length);
    }
    if (path === '/notes' || path.startsWith('/notes?')) return options.list?.(++reads, path) ?? Response.json({ notes: [] });
    throw new Error(`Unexpected browser request: ${path}`);
  };
  const script = workspaceView('test').match(/<script nonce="test">([\s\S]*?)<\/script>/)?.[1];
  assert.ok(script, 'execute the actual script returned to browsers');
  runInNewContext(script, {
    document: { querySelector: element, createElement: () => new Element() },
    fetch, TextEncoder,
    crypto: { randomUUID: () => `note-request-1234567890-${++ids}` },
    location: { assign() { throw new Error('Unexpected navigation'); } },
  });
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.match(element('#identity').textContent, /^Signed in as /);
  return {
    text: element('#text'), status: element('#status'), save: element('#save'), more: element('#more'), writes,
    noteTexts: () => element('#notes').children.map((item) => item.children[1]!.textContent),
    submit: async () => { await element('#form').handlers.get('submit')!({ preventDefault() {} }); },
    loadOlder: async () => { await element('#more').handlers.get('click')!({ preventDefault() {} }); },
  };
}

test('a delayed save preserves a draft edited during the request and ignores overlapping submissions', async () => {
  let acknowledge!: (response: Response) => void;
  const response = new Promise<Response>((resolve) => { acknowledge = resolve; });
  const b = await browser({ post: () => response });
  b.text.value = 'The submitted note';
  const saving = b.submit();
  assert.equal(b.save.disabled, true);
  b.text.value = 'An unsaved draft typed while the request is pending';
  await b.submit();
  assert.equal(b.writes.length, 1, 'only the original submission reaches the application');
  acknowledge(Response.json({ saved: true }));
  await saving;
  assert.equal(b.writes[0]?.text, 'The submitted note');
  assert.equal(b.text.value, 'An unsaved draft typed while the request is pending');
  assert.equal(b.status.textContent, 'Note saved.');
  assert.equal(b.save.disabled, false);
});

test('an acknowledged save remains successful when refreshing the notes fails', async () => {
  const b = await browser({
    post: () => Response.json({ saved: true }),
    list: (request) => request === 1 ? Response.json({ notes: [] }) : Response.json({ error: 'session_store_failed' }, { status: 503 }),
  });
  b.text.value = 'Confirmed saved note';
  await b.submit();
  assert.equal(b.writes.length, 1);
  assert.equal(b.text.value, '');
  assert.match(b.status.textContent, /^Note saved\./);
  assert.match(b.status.textContent, /could not be refreshed/);
  assert.doesNotMatch(b.status.textContent, /retry|not confirmed|may.*succeeded/i);
  assert.equal(b.save.disabled, false);
  b.text.value = 'A different note after the confirmed write';
  await b.submit();
  assert.equal(b.writes.length, 2, 'refresh failure leaves the next deliberate save usable');
  assert.notEqual(b.writes[0]?.id, b.writes[1]?.id);
});

for (const staleResult of ['success', 'failure'] as const) {
  test(`a stale older-page ${staleResult} cannot change a refreshed list, cursor or save status`, async () => {
    const note = (index: number) => ({
      id: `note-request-${String(index).padStart(4, '0')}`,
      text: String(index).padStart(2, '0') + 'x'.repeat(4094),
      createdAt: 1000 - index,
    });
    let notes = Array.from({ length: 23 }, (_, index) => note(index + 1));
    let release!: () => void;
    let requested!: () => void;
    const olderRequested = new Promise<void>((resolve) => { requested = resolve; });
    const paths: string[] = [];
    const b = await browser({
      post: () => { notes = [note(0), ...notes]; return Response.json({ saved: true }); },
      list: (request, path) => {
        paths.push(path);
        const before = new URL(path, 'https://notes.example').searchParams.get('before');
        const beforeId = before ? JSON.parse(Buffer.from(before, 'base64url').toString('utf8'))[1] : undefined;
        const start = beforeId ? notes.findIndex((item) => item.id === beforeId) + 1 : 0;
        // Eleven 4 KiB notes fit within the application's bounded page response.
        const page = notes.slice(start, start + 11), last = page.at(-1)!;
        const value = { notes: page, ...(start + 11 < notes.length
          ? { next_cursor: Buffer.from(JSON.stringify([last.createdAt, last.id])).toString('base64url') } : {}) };
        if (request === 2) {
          requested();
          return new Promise<Response>((resolve) => { release = () => resolve(staleResult === 'success'
            ? Response.json(value)
            : Response.json({ error: 'session_store_failed' }, { status: 503 })); });
        }
        return Response.json(value);
      },
    });
    const rendered = () => b.noteTexts().map((text) => Number(text.slice(0, 2)));
    assert.deepEqual(rendered(), Array.from({ length: 11 }, (_, index) => index + 1));
    const older = b.loadOlder();
    await olderRequested;
    b.text.value = note(0).text;
    await b.submit();
    assert.deepEqual(rendered(), Array.from({ length: 11 }, (_, index) => index));
    assert.equal(b.status.textContent, 'Note saved.');
    release();
    await older;
    assert.deepEqual(rendered(), Array.from({ length: 11 }, (_, index) => index), 'stale page does not append to the refreshed list');
    assert.equal(b.status.textContent, 'Note saved.', 'stale failure does not replace the acknowledged save status');
    assert.equal(b.more.hidden, false);
    assert.equal(b.more.disabled, false);
    await b.loadOlder();
    assert.notEqual(paths[1], paths[3], 'continuation uses the refreshed cursor');
    await b.loadOlder();
    assert.deepEqual(rendered(), Array.from({ length: 24 }, (_, index) => index), 'every saved note appears exactly once');
    assert.equal(b.more.hidden, true);
  });
}

for (const failure of ['lost acknowledgement', 'unavailable service'] as const) {
  test(`an uncertain save from ${failure} retains its ID for an explicit retry`, async () => {
    const b = await browser({ post: (_input, attempt) => {
      if (attempt > 1) return Response.json({ saved: true });
      if (failure === 'lost acknowledgement') throw new Error('Connection interrupted');
      return Response.json({ error: 'session_store_failed' }, { status: 503 });
    } });
    b.text.value = 'The same note must keep the same request ID';
    await b.submit();
    assert.equal(b.writes.length, 1, 'no automatic write retry');
    assert.equal(b.text.value, b.writes[0]?.text);
    assert.match(b.status.textContent, /Retry the original note/);
    assert.equal(b.save.disabled, false);
    b.text.value = 'Different text must not reuse an uncertain request ID';
    await b.submit();
    assert.equal(b.writes.length, 1);
    b.text.value = b.writes[0]!.text;
    await b.submit();
    assert.deepEqual(b.writes[1], b.writes[0]);
    assert.equal(b.text.value, '');
    assert.equal(b.status.textContent, 'Note saved.');
  });
}

test('local validation and confirmed server rejection allow the note to be corrected', async () => {
  const b = await browser({ post: (_input, attempt) => attempt === 1
    ? Response.json({ error: 'invalid_note' }, { status: 400 })
    : Response.json({ saved: true }) });
  b.text.value = '   ';
  await b.submit();
  assert.equal(b.writes.length, 0);
  assert.match(b.status.textContent, /Write a note/);
  b.text.value = 'Rejected note';
  await b.submit();
  assert.equal(b.text.value, 'Rejected note');
  assert.doesNotMatch(b.status.textContent, /may already have succeeded/);
  b.text.value = 'Corrected note';
  await b.submit();
  assert.equal(b.writes.length, 2);
  assert.notEqual(b.writes[0]?.id, b.writes[1]?.id);
  assert.equal(b.writes[1]?.text, 'Corrected note');
  assert.equal(b.text.value, '');
  assert.equal(b.status.textContent, 'Note saved.');
});
