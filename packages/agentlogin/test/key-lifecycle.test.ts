import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { serve } from '@hono/node-server';
import { createIssuer, MemoryStore, type Store } from '../../issuer/src/index.js';
import { AgentLogin, AgentLoginError, MemoryCookieJar, MemoryKeystore } from '../src/index.js';

const rnd = (n = 16) => randomBytes(n).toString('base64url');

test('the SDK distinguishes interrupted Agent authority from explicit key revocation', async (t) => {
  const reservation = http.createServer();
  await new Promise<void>((resolve, reject) => {
    reservation.once('error', reject);
    reservation.listen(0, '127.0.0.1', resolve);
  });
  const port = (reservation.address() as AddressInfo).port;
  await new Promise<void>((resolve) => reservation.close(() => resolve()));
  const issuer = `http://127.0.0.1:${port}`;
  const backing = new MemoryStore();
  let cycleNextAssertion = false;
  let interruptedTransaction: string | undefined;
  let cycles = 0;
  const store = new Proxy(backing, {
    get(target, property, receiver) {
      if (property !== 'updateTransaction') return Reflect.get(target, property, receiver);
      return async (...args: Parameters<Store['updateTransaction']>) => {
        const [next, , effects] = args;
        if (cycleNextAssertion && next.kid) {
          cycleNextAssertion = false;
          interruptedTransaction = next.id;
          cycles += 1;
          const agent = await backing.getAgent(next.handle!);
          assert.ok(agent);
          // Interrupt between the issuer's subject read and its atomic assertion acceptance. The key itself
          // stays active, but the assertion's captured Agent version is now obsolete.
          await backing.setAgentEnabled(agent.handle, false, agent.sub, effects.now);
          await backing.setAgentEnabled(agent.handle, true, agent.sub, effects.now);
        }
        return backing.updateTransaction(...args);
      };
    },
  });
  const { app } = await createIssuer({ issuer, handleDomains: ['example.com'], store, allowInsecureClients: true, adminToken: 'admin' });
  const server = serve({ fetch: app.fetch, port, hostname: '127.0.0.1' });
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const post = async (path: string, body: unknown) => {
    const response = await fetch(`${issuer}${path}`, {
      method: 'POST', headers: { authorization: 'Bearer admin', 'content-type': 'application/json' }, body: JSON.stringify(body),
    });
    assert.equal(response.status, 201);
    return response.json() as Promise<Record<string, string>>;
  };
  const owner = await post('/admin/owners', { email: 'owner@example.com', session_auth: 'passkey' });
  const client = await post('/register', {
    redirect_uris: ['https://rp.example/callback'], client_name: 'Lifecycle test',
    tos_uri: 'https://rp.example/terms', policy_uri: 'https://rp.example/privacy', token_endpoint_auth_method: 'client_secret_basic',
  });
  const authorizationUrl = () => `${issuer}/authorize?${new URLSearchParams({
    response_type: 'code', client_id: client.client_id!, redirect_uri: 'https://rp.example/callback', scope: 'openid email',
    state: rnd(), nonce: rnd(), code_challenge: createHash('sha256').update(rnd(32)).digest('base64url'), code_challenge_method: 'S256',
  })}`;
  const newAgent = async (handle: string) => {
    await post('/admin/agents', { handle, owner_id: owner.owner_id });
    const keystore = new MemoryKeystore();
    const al = new AgentLogin({ handle, issuer, allowInsecure: true, keystore, cookies: new MemoryCookieJar() });
    const key = await al.enroll({ credential: owner.credential! });
    return { al, key, keystore };
  };

  await t.test('unknown_key after disable/re-enable keeps the same key usable for a new request', async () => {
    const { al, key, keystore } = await newAgent('scout@example.com');
    cycleNextAssertion = true;
    await assert.rejects(al.signIn({ authorizationUrl: authorizationUrl(), expectedHost: 'rp.example' }),
      (error: unknown) => error instanceof AgentLoginError && error.code === 'unknown_key' && error.status === 401);
    assert.equal(cycles, 1);
    assert.equal((await backing.getAgent(al.handle))?.enabled, true);
    assert.equal((await backing.getKey(key.kid))?.status, 'active', 'disable/re-enable did not revoke the enrollment');
    assert.equal((await backing.getTransaction(interruptedTransaction!))?.status, 'awaiting_agent', 'the obsolete assertion was not accepted');
    assert.equal((await keystore.get(key.kid))?.status, 'active', 'unknown_key is not evidence that the key was revoked');

    const result = await al.signIn({ authorizationUrl: authorizationUrl(), expectedHost: 'rp.example' });
    assert.ok(new URL(result.redirectUrl).searchParams.get('code'));
    assert.equal((await al.activeKey()).kid, key.kid, 'retry uses the original SDK instance and enrollment');
    assert.equal((await keystore.list(al.handle)).length, 1, 'no replacement enrollment was needed');
  });

  await t.test('a server-side key revocation still marks the local key revoked', async () => {
    const { al, key, keystore } = await newAgent('revoked@example.com');
    const revoked = await fetch(`${issuer}/agents/${encodeURIComponent(al.handle)}/keys/${encodeURIComponent(key.kid)}`, {
      method: 'DELETE', headers: { authorization: `Bearer ${owner.credential}` },
    });
    assert.equal(revoked.status, 204);
    assert.equal((await keystore.get(key.kid))?.status, 'active', 'remote revocation has not yet reached the SDK');
    await assert.rejects(al.signIn({ authorizationUrl: authorizationUrl(), expectedHost: 'rp.example' }),
      (error: unknown) => error instanceof AgentLoginError && error.code === 'key_revoked' && error.status === 401);
    assert.equal((await keystore.get(key.kid))?.status, 'revoked');
    await assert.rejects(al.activeKey(), (error: unknown) => error instanceof AgentLoginError && error.code === 'no_key');
  });
});
