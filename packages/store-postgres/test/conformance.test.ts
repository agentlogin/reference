import { test } from 'node:test';
import { conformanceRun } from '../../issuer/test/conformance-fixtures.js';
import { fixture, skipPostgres } from './helpers.js';

test('reference issuer passes the complete HTTP conformance harness with PostgreSQL', { skip: skipPostgres, timeout: 120_000 }, async (t) => {
  const { store } = await fixture(t, { realClock: true });
  await conformanceRun(store);
});
