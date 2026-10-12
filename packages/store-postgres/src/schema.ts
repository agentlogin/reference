/** Versioned normalized schema. JSONB contains one protocol record, never the entire issuer database.
 * Critical lookup/lifecycle fields are stored generated columns, so indexed values cannot drift from payloads.
 * Historical authorizations intentionally do not cascade from live identities; revocation/replay evidence survives.
 */
export const SCHEMA_VERSION = 1;
export const TABLES = [
  'owners', 'agents', 'credentials', 'owner_codes', 'keys', 'revoked_keys', 'clients',
  'transactions', 'codes', 'access_tokens', 'accounts', 'consents', 'quotas', 'reservations',
] as const;
export type TableName = typeof TABLES[number];

export function validateSchema(schema: string): string {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(schema) || schema.startsWith('pg_')) {
    throw new TypeError('PostgreSQL schema must be a lowercase SQL identifier of at most 63 characters, outside pg_*');
  }
  return schema;
}
export const identifier = (name: string): string => `"${name.replaceAll('"', '""')}"`;

export function schemaV1(schema: string): string {
  const q = (name: string) => `${identifier(schema)}.${identifier(name)}`;
  const text = (column: string, field = column) => `${column} text GENERATED ALWAYS AS (data->>'${field}') STORED`;
  const num = (column: string, field = column) => `${column} bigint GENERATED ALWAYS AS ((data->>'${field}')::bigint) STORED`;
  const bool = (column: string, field = column, fallback?: boolean) => `${column} boolean GENERATED ALWAYS AS (${fallback === undefined ? `(data->>'${field}')::boolean` : `COALESCE((data->>'${field}')::boolean, ${fallback})`}) STORED`;
  const subject = `
    ${text('handle')} NOT NULL,
    ${text('client_id', 'clientId')} NOT NULL,
    ${text('kid')} NOT NULL,
    ${text('key_enrollment', 'keyEnrollment')} NOT NULL,
    ${text('agent_sub', 'agentSub')} NOT NULL,
    ${num('agent_version', 'agentVersion')} NOT NULL CHECK (agent_version >= 0),
    ${num('account_version', 'accountVersion')} NOT NULL CHECK (account_version >= 0)`;
  return `
CREATE FUNCTION ${q('app_now')}() RETURNS double precision LANGUAGE sql VOLATILE
  AS 'SELECT floor(extract(epoch FROM clock_timestamp()))::double precision';
CREATE TABLE ${q('owners')} (
  data jsonb NOT NULL CHECK (jsonb_typeof(data) = 'object'),
  ${text('id')} PRIMARY KEY,
  ${text('owner_sub', 'ownerSub')} NOT NULL UNIQUE,
  email_lower text GENERATED ALWAYS AS (lower(data->>'email')) STORED NOT NULL,
  ${num('created_at', 'createdAt')} NOT NULL
);
CREATE INDEX owners_email ON ${q('owners')} (email_lower, created_at DESC);
CREATE FUNCTION ${q('guard_owner_identity')}() RETURNS trigger LANGUAGE plpgsql
  SET search_path = pg_catalog AS $$
BEGIN
  IF (NEW.data->>'id') IS DISTINCT FROM (OLD.data->>'id')
    OR (NEW.data->>'ownerSub') IS DISTINCT FROM (OLD.data->>'ownerSub') THEN
    RAISE EXCEPTION 'Owner identity is immutable' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER owners_immutable_identity BEFORE UPDATE ON ${q('owners')}
  FOR EACH ROW EXECUTE FUNCTION ${q('guard_owner_identity')}();
CREATE TABLE ${q('owner_codes')} (
  data jsonb NOT NULL,
  ${text('owner_id', 'ownerId')} PRIMARY KEY,
  ${num('expires_at', 'expiresAt')} NOT NULL
);
CREATE INDEX owner_codes_expiry ON ${q('owner_codes')} (expires_at);
CREATE TABLE ${q('agents')} (
  data jsonb NOT NULL,
  ${text('handle')} PRIMARY KEY,
  ${text('sub')} NOT NULL UNIQUE,
  ${text('owner_id', 'ownerId')} NOT NULL,
  ${bool('enabled')} NOT NULL,
  ${num('authorization_version', 'authorizationVersion')} NOT NULL CHECK (authorization_version >= 0)
);
CREATE INDEX agents_owner ON ${q('agents')} (owner_id);
CREATE FUNCTION ${q('guard_agent_identity')}() RETURNS trigger LANGUAGE plpgsql
  SET search_path = pg_catalog AS $$
BEGIN
  IF (NEW.data->>'handle') IS DISTINCT FROM (OLD.data->>'handle')
    OR (NEW.data->>'sub') IS DISTINCT FROM (OLD.data->>'sub')
    OR (NEW.data->>'ownerId') IS DISTINCT FROM (OLD.data->>'ownerId') THEN
    RAISE EXCEPTION 'Agent identity and ownership are immutable' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER agents_immutable_identity BEFORE UPDATE ON ${q('agents')}
  FOR EACH ROW EXECUTE FUNCTION ${q('guard_agent_identity')}();
CREATE TABLE ${q('credentials')} (
  data jsonb NOT NULL,
  ${text('hash')} PRIMARY KEY,
  ${text('owner_id', 'ownerId')} NOT NULL,
  ${text('handle')},
  ${text('kind')} NOT NULL CHECK (kind IN ('owner', 'delegated')),
  CHECK (kind <> 'delegated' OR handle IS NOT NULL)
);
CREATE INDEX credentials_owner ON ${q('credentials')} (owner_id);
CREATE INDEX credentials_handle ON ${q('credentials')} (handle) WHERE handle IS NOT NULL;
CREATE TABLE ${q('keys')} (
  data jsonb NOT NULL,
  ${text('kid')} PRIMARY KEY,
  ${text('enrollment')} NOT NULL UNIQUE,
  ${text('handle')} NOT NULL,
  ${text('agent_sub', 'agentSub')} NOT NULL,
  ${text('status')} NOT NULL CHECK (status IN ('pending', 'active', 'expired', 'revoked')),
  ${num('expires_at', 'expiresAt')} NOT NULL,
  challenge_expires_at bigint GENERATED ALWAYS AS ((data->'challenge'->>'expiresAt')::bigint) STORED
);
CREATE INDEX keys_handle ON ${q('keys')} (handle);
CREATE INDEX keys_expiry ON ${q('keys')} (expires_at);
CREATE TABLE ${q('revoked_keys')} (
  handle text NOT NULL,
  kid text NOT NULL,
  PRIMARY KEY (handle, kid)
);
CREATE TABLE ${q('clients')} (
  data jsonb NOT NULL,
  ${text('client_id', 'clientId')} PRIMARY KEY
);
CREATE TABLE ${q('transactions')} (
  data jsonb NOT NULL,
  ${text('id')} PRIMARY KEY,
  ${num('version')} NOT NULL CHECK (version >= 0),
  ${text('client_id', 'clientId')} NOT NULL,
  ${text('status')} NOT NULL CHECK (status IN ('awaiting_agent', 'awaiting_owner', 'awaiting_consent', 'ready', 'completed', 'denied', 'expired')),
  ${num('expires_at', 'expiresAt')} NOT NULL,
  ${num('terminal_at', 'terminalAt')},
  ${text('agent_sub', 'agentSub')},
  ${num('agent_version', 'agentVersion')} CHECK (agent_version >= 0),
  ${num('account_version', 'accountVersion')} CHECK (account_version >= 0),
  ${text('owner_id', 'ownerId')},
  ${text('handle')},
  ${text('kid')},
  ${text('key_enrollment', 'keyEnrollment')},
  ${text('transaction_token_hash', 'transactionTokenHash')} UNIQUE,
  ${text('session_secret_hash', 'sessionSecretHash')} UNIQUE
);
CREATE INDEX transactions_open_handle ON ${q('transactions')} (handle, client_id) WHERE status NOT IN ('completed', 'denied', 'expired');
CREATE INDEX transactions_open_key ON ${q('transactions')} (kid, key_enrollment) WHERE status NOT IN ('completed', 'denied', 'expired');
CREATE INDEX transactions_open_owner ON ${q('transactions')} (owner_id, client_id) WHERE status NOT IN ('completed', 'denied', 'expired');
CREATE INDEX transactions_expiry ON ${q('transactions')} (expires_at);
CREATE INDEX transactions_retention ON ${q('transactions')} (terminal_at) WHERE terminal_at IS NOT NULL;
CREATE TABLE ${q('codes')} (
  data jsonb NOT NULL,
  ${text('hash')} PRIMARY KEY,
  ${text('txn_id', 'txnId')} NOT NULL UNIQUE,
  ${subject},
  ${num('expires_at', 'expiresAt')} NOT NULL,
  ${bool('used')} NOT NULL,
  ${bool('voided')} NOT NULL,
  ${bool('replayed', 'replayed', false)} NOT NULL,
  redemption_attempt text,
  redeemed_at bigint,
  issuance_until bigint,
  CHECK (redemption_attempt IS NULL OR (used AND redeemed_at IS NOT NULL AND issuance_until IS NOT NULL))
);
CREATE INDEX codes_handle ON ${q('codes')} (handle, client_id);
CREATE INDEX codes_key ON ${q('codes')} (kid, key_enrollment);
CREATE INDEX codes_expiry ON ${q('codes')} (expires_at);
CREATE TABLE ${q('access_tokens')} (
  data jsonb NOT NULL,
  ${text('hash')} PRIMARY KEY,
  ${text('txn_id', 'txnId')} NOT NULL UNIQUE REFERENCES ${q('codes')} (txn_id),
  ${subject},
  ${num('expires_at', 'expiresAt')} NOT NULL,
  ${num('issued_at', 'issuedAt')},
  ${bool('revoked')} NOT NULL
);
CREATE INDEX access_tokens_handle ON ${q('access_tokens')} (handle, client_id);
CREATE INDEX access_tokens_key ON ${q('access_tokens')} (kid, key_enrollment);
CREATE INDEX access_tokens_expiry ON ${q('access_tokens')} (expires_at);
CREATE TABLE ${q('accounts')} (
  data jsonb NOT NULL,
  agent_sub text NOT NULL,
  ${text('handle')} NOT NULL,
  ${text('client_id', 'clientId')} NOT NULL,
  ${text('status')} NOT NULL CHECK (status IN ('enabled', 'disabled')),
  ${num('authorization_version', 'authorizationVersion')} NOT NULL CHECK (authorization_version >= 0),
  PRIMARY KEY (agent_sub, client_id),
  UNIQUE (handle, client_id)
);
CREATE TABLE ${q('consents')} (
  data jsonb NOT NULL,
  agent_sub text NOT NULL,
  ${text('handle')} NOT NULL,
  ${text('client_id', 'clientId')} NOT NULL,
  ${num('last_used_at', 'lastUsedAt')} NOT NULL,
  PRIMARY KEY (agent_sub, client_id),
  UNIQUE (handle, client_id)
);
CREATE INDEX consents_expiry ON ${q('consents')} (last_used_at);
CREATE TABLE ${q('quotas')} (
  owner_id text NOT NULL,
  client_id text NOT NULL,
  count bigint NOT NULL DEFAULT 0 CHECK (count >= 0),
  PRIMARY KEY (owner_id, client_id)
);
CREATE TABLE ${q('reservations')} (
  txn_id text PRIMARY KEY,
  owner_id text NOT NULL,
  client_id text NOT NULL,
  agent_sub text NOT NULL,
  expires_at bigint NOT NULL,
  FOREIGN KEY (owner_id, client_id) REFERENCES ${q('quotas')} (owner_id, client_id)
);
CREATE INDEX reservations_quota ON ${q('reservations')} (owner_id, client_id, expires_at, agent_sub);
CREATE INDEX reservations_expiry ON ${q('reservations')} (expires_at);
`;
}
