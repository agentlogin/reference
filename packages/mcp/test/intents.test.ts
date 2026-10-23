import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AgentLoginError, MemoryCookieJar, type SignInAtOptions, type TransactionView } from 'agentlogin';
import { LoginRuntime } from '../src/runtime.js';

const day = 86_400_000;
function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'agentlogin-sign-in-intents-'));
  const config = { version: 1, stateDirectory: dir, signInTimeoutSeconds: 10,
    identities: { scout: { handle: 'scout@example.com', ownerPortal: 'https://issuer.example/identity', ownerApprovalPath: '/identity/transactions/{transaction_id}' } },
    applications: { notes: { name: 'Notes', origin: 'https://notes.example', loginPath: '/login', sessionCheck: { path: '/me', handlePointer: '/handle', issuerPointer: '/iss', subjectPointer: '/sub' } } } };
  const state = { now: Date.now(), issuer: 'https://issuer.example', attempts: 0, discoveries: 0, signIn: async (_options: SignInAtOptions) => {} };
  const runtime = (ownConfig: unknown = config) => new LoginRuntime(ownConfig, {
    now: () => state.now, jarFactory: () => new MemoryCookieJar(),
    clientFactory: (identity) => ({
      async discover() { state.discoveries += 1; return { issuer: state.issuer }; },
      async signInAt(_url, options) {
        state.attempts += 1; await state.signIn(options);
        return { handle: identity.handle, issuer: state.issuer, client: { client_id: 'notes', client_type: 'open', redirect_host: 'notes.example' }, scopes: ['openid'], redirectUrl: 'https://notes.example/callback?code=PRIVATE_CODE' } as any;
      },
      async fetch(url) {
        if (new URL(url).pathname === '/me') return Response.json({ handle: identity.handle, iss: state.issuer, sub: 'immutable-scout' });
        return new Response('PRIVATE_CALLBACK_HTML', { status: 200 });
      },
    }),
  });
  const saved = () => JSON.parse(readFileSync(join(dir, 'sign-in-intents', readdirSync(join(dir, 'sign-in-intents'))[0]!), 'utf8'));
  return { dir, config, state, runtime, saved, close: () => rmSync(dir, { recursive: true, force: true }) };
}
const timeout = () => { throw new AgentLoginError('synthetic private timeout', 'timeout'); };

async function until(test: () => boolean) {
  const deadline = Date.now() + 5000;
  while (!test()) { if (Date.now() >= deadline) throw new Error('test condition timed out'); await new Promise((resolve) => setTimeout(resolve, 5)); }
}

test('sign-in task survives local timeout and restart, then resumes six days later with a fresh operation and fixed decision deadline', async () => {
  const f = fixture();
  try {
    f.state.signIn = async (o) => { o.onOwnerApproval!({ transaction_id: 'old_transaction_private' } as TransactionView); f.state.now += 10_000; timeout(); };
    const first = f.runtime(); const started = first.start('scout', 'notes');
    const paused = await first.settled(started.operation);
    assert.equal(paused.status, 'paused'); assert.equal(paused.resumable, true);
    assert.equal(paused.ownerApprovalUrl, undefined); assert.equal(paused.transactionId, undefined); assert.equal(paused.ownerPortal, undefined);
    assert.equal(paused.decisionExpiresAt, f.saved().createdAt + 7 * day);
    assert.equal(statSync(join(f.dir, 'sign-in-intents')).mode & 0o777, 0o700);
    const file = join(f.dir, 'sign-in-intents', readdirSync(join(f.dir, 'sign-in-intents'))[0]!);
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.doesNotMatch(readFileSync(file, 'utf8'), /old_transaction|PRIVATE_|cookie|assertion|challenge|disclosure|policy_uri/);
    f.state.now += 6 * day;
    const restarted = f.runtime();
    assert.equal(restarted.status(started.operation).status, 'paused');
    assert.equal(f.state.attempts, 1, 'reading durable progress cannot restart network work');
    f.state.signIn = async () => {};
    const resumed = restarted.start('scout', 'notes');
    assert.equal(resumed.intent, started.intent); assert.notEqual(resumed.operation, started.operation);
    assert.equal(resumed.decisionExpiresAt, paused.decisionExpiresAt);
    assert.equal((await restarted.settled(resumed.operation)).status, 'authenticated');
    assert.equal(f.state.attempts, 2);
    assert.equal(readdirSync(join(f.dir, 'sign-in-intents')).length, 1, 'only the current task for a pair is retained on disk');
  } finally { f.close(); }
});

test('an approved old disclosure cannot authorize a changed disclosure after resuming', async () => {
  const f = fixture();
  try {
    let policy = 'policy-a'; const accepted: string[] = [];
    f.state.signIn = async (o) => {
      const decision = await o.onReview!({ transaction_id: policy, requested_scopes: ['openid', 'owner_email'], client: { client_id: 'notes', client_type: 'open', redirect_host: 'notes.example', policy_uri: `https://notes.example/${policy}` }, disclosure: [{ scope: 'owner_email', title: 'Owner email', description: policy }], consent_reason: 'material_change' } as TransactionView);
      assert.equal(decision, 'allow'); accepted.push(policy);
      if (policy === 'policy-a') { f.state.now += 10_000; timeout(); }
    };
    const first = f.runtime(); const started = first.start('scout', 'notes');
    await until(() => first.status(started.operation).status === 'awaiting_consent');
    first.review(started.operation, 'allow');
    assert.equal((await first.settled(started.operation)).status, 'paused');
    policy = 'policy-b'; f.state.now += day;
    const resumed = first.start('scout', 'notes');
    await until(() => first.status(resumed.operation).status === 'awaiting_consent');
    assert.equal(first.status(resumed.operation).client?.policy_uri, 'https://notes.example/policy-b');
    assert.throws(() => first.review(started.operation, 'allow'), /no live disclosure/);
    assert.deepEqual(accepted, ['policy-a']);
    first.review(resumed.operation, 'allow');
    assert.equal((await first.settled(resumed.operation)).status, 'authenticated');
    assert.deepEqual(accepted, ['policy-a', 'policy-b']);
  } finally { f.close(); }
});

test('decision expiry is fixed; a later explicitly requested sign-in creates a new intent', async () => {
  const f = fixture();
  try {
    f.state.signIn = async () => { f.state.now += 10_000; timeout(); };
    const first = f.runtime(); const started = first.start('scout', 'notes'); await first.settled(started.operation);
    f.state.now = started.decisionExpiresAt;
    const restarted = f.runtime();
    const expired = restarted.status(started.operation);
    assert.equal(expired.status, 'expired'); assert.equal(expired.resumable, false); assert.equal(f.state.attempts, 1);
    const another = restarted.start('scout', 'notes');
    assert.notEqual(another.intent, started.intent); assert.equal(another.decisionExpiresAt, f.state.now + 7 * day);
    await restarted.settled(another.operation);
  } finally { f.close(); }
});

test('changed configuration refuses a saved task before discovery or network use', async () => {
  const f = fixture();
  try {
    f.state.signIn = async () => { f.state.now += 10_000; timeout(); };
    const first = f.runtime(); const started = first.start('scout', 'notes'); await first.settled(started.operation);
    const before = f.state.discoveries;
    const changed = structuredClone(f.config); changed.applications.notes.origin = 'https://attacker.example';
    const restarted = f.runtime(changed);
    assert.throws(() => restarted.start('scout', 'notes'), /no longer matches/);
    assert.throws(() => restarted.status(started.operation), /no longer matches/);
    assert.equal(f.state.discoveries, before); assert.equal(f.state.attempts, 1);
  } finally { f.close(); }
});

for (const restart of [false, true]) test(`changed discovered issuer cannot inherit a pending sign-in task ${restart ? 'after restart' : 'in the same process'}`, async () => {
  const f = fixture();
  try {
    f.state.signIn = async () => { f.state.now += 10_000; timeout(); };
    const first = f.runtime(); const started = first.start('scout', 'notes'); await first.settled(started.operation);
    f.state.issuer = 'https://replacement.example';
    const restarted = restart ? f.runtime() : first; const resumed = restarted.start('scout', 'notes');
    const result = await restarted.settled(resumed.operation);
    assert.equal(result.status, 'failed'); assert.equal(result.error, 'intent_mismatch'); assert.equal(f.state.attempts, 1);
  } finally { f.close(); }
});

test('a process restart cannot restore live review or old Owner approval authority', async () => {
  const f = fixture();
  try {
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    f.state.signIn = async (o) => { o.onOwnerApproval!({ transaction_id: 'old_owner_approval' } as TransactionView); await blocked; f.state.now += 10_000; timeout(); };
    const first = f.runtime(); const started = first.start('scout', 'notes');
    await until(() => first.status(started.operation).status === 'awaiting_owner');
    const restarted = f.runtime();
    const restored = restarted.status(started.operation);
    assert.equal(restored.status, 'paused'); assert.equal(restored.ownerApprovalUrl, undefined); assert.equal(restored.transactionId, undefined);
    assert.throws(() => restarted.review(started.operation, 'allow'), /no live disclosure/);
    assert.equal(f.state.attempts, 1);
    release(); await first.settled(started.operation);
  } finally { f.close(); }
});

for (const code of ['expired', 'transaction_expired', 'login_required']) test(`Core ${code} preserves the saved task without reusing the protocol transaction`, async () => {
  const f = fixture();
  try {
    f.state.signIn = async (o) => {
      o.onOwnerApproval!({ transaction_id: 'expired_owner_transaction' } as TransactionView);
      throw new AgentLoginError('The issuer transaction expired', code);
    };
    const runtime = f.runtime(); const started = runtime.start('scout', 'notes');
    const paused = await runtime.settled(started.operation);
    assert.equal(paused.status, 'paused'); assert.equal(paused.resumable, true);
    assert.equal(f.saved().state, 'pending'); assert.equal(f.saved().intent, started.intent);
    assert.equal(paused.ownerApprovalUrl, undefined); assert.equal(paused.transactionId, undefined);
    f.state.now += day; f.state.signIn = async () => {};
    const resumed = runtime.start('scout', 'notes');
    assert.equal(resumed.intent, started.intent); assert.notEqual(resumed.operation, started.operation);
    assert.equal(resumed.decisionExpiresAt, started.decisionExpiresAt);
    assert.equal((await runtime.settled(resumed.operation)).status, 'authenticated');
  } finally { f.close(); }
});
