import { test } from 'node:test';
import assert from 'node:assert/strict';
import { registerStoreContract } from '../../issuer/test/store-contract.js';
import { connectionString, fixture, required } from './helpers.js';

if (connectionString) {
  registerStoreContract('PostgreSQL', async (t) => fixture(t));
} else {
  test('PostgreSQL store contracts require an explicitly configured database', { skip: !required }, () => {
    assert.fail('REQUIRE_POSTGRES_TESTS=1 requires AGENTLOGIN_TEST_POSTGRES_URL');
  });
}
