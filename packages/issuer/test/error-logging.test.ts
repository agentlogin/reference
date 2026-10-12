import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createIssuer, MemoryStore } from '../src/index.js';

test('storage errors do not expose private database row contents in HTTP responses or logs', async (t) => {
  const secret = 'private-continue-secret';
  const email = 'private-owner@example.test';
  const error = Object.assign(new Error(`Failing row contains (${secret}, ${email})`), {code:'23514',detail:secret,cause:new Error(email)});
  const store = new Proxy(new MemoryStore(), { get(target, prop, receiver) {
    if (prop === 'putOwner') return async () => { throw error; };
    return Reflect.get(target, prop, receiver);
  } });
  const captured: unknown[] = [];
  t.mock.method(console,'error',(...args:unknown[]) => { captured.push(args); });
  const { app } = await createIssuer({issuer:'https://issuer.test',handleDomains:['example.test'],adminToken:'admin',store});
  const response = await app.request('https://issuer.test/admin/owners',{method:'POST',headers:{authorization:'Bearer admin','content-type':'application/json'},body:JSON.stringify({email})});
  assert.equal(response.status,500);
  const output = JSON.stringify(captured) + await response.text();
  assert.ok(output.includes('23514'));
  assert.ok(!output.includes(secret));
  assert.ok(!output.includes(email));
});
