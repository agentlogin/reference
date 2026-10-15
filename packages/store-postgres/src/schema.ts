/** Versioned normalized schema. JSONB contains one protocol record, never the entire issuer database.
 * Critical lookup/lifecycle fields are stored generated columns, so indexed values cannot drift from payloads.
 * Historical authorizations intentionally do not cascade from live identities; revocation/replay evidence survives.
 */
export const SCHEMA_VERSION = 3;
export const TABLES = [
  'owners', 'agents', 'credentials', 'owner_codes', 'keys', 'revoked_keys', 'clients',
  'transactions', 'codes', 'access_tokens', 'accounts', 'consents', 'quotas', 'reservations', 'signup_events', 'owner_tombstones', 'address_quotas', 'signing_keys', 'signing_state',
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

/** Pending challenges are scoped to an Agent. Only a proved, active key is exclusive. */
export function schemaV2(schema: string): string {
  const keys = `${identifier(schema)}.keys`;
  return `
ALTER TABLE ${keys} DROP CONSTRAINT keys_pkey;
ALTER TABLE ${keys} ADD PRIMARY KEY (handle, kid);
CREATE INDEX keys_kid ON ${keys} (kid);
CREATE UNIQUE INDEX keys_active_kid ON ${keys} (kid) WHERE status = 'active';
`;
}

/** Durable quota provenance and issuer signing-key lifecycle. */
export function schemaV3(schema: string, legacySigningOverlapSeconds = 0): string {
  if (!Number.isSafeInteger(legacySigningOverlapSeconds) || legacySigningOverlapSeconds < 0) throw new TypeError('Invalid legacy signing overlap');
  const q = (name: string) => `${identifier(schema)}.${identifier(name)}`;
  return `
CREATE INDEX transactions_legacy_presentation ON ${q('transactions')} (id)
  WHERE status NOT IN ('completed','denied','expired') AND NOT (data ? 'clientPresentation');
ALTER TABLE ${q('owners')} ADD COLUMN address_key text NOT NULL DEFAULT '';
CREATE INDEX owners_address ON ${q('owners')} (address_key, created_at DESC);
CREATE TABLE ${q('owner_tombstones')} (
  owner_id text PRIMARY KEY, owner_sub text NOT NULL UNIQUE,
  address_key text, expires_at bigint,
  CHECK ((address_key IS NULL) = (expires_at IS NULL))
);
CREATE INDEX owner_tombstones_address ON ${q('owner_tombstones')} (address_key, expires_at) WHERE address_key IS NOT NULL;
CREATE INDEX owner_tombstones_expiry ON ${q('owner_tombstones')} (expires_at) WHERE expires_at IS NOT NULL;
CREATE TABLE ${q('signup_events')} (
  owner_id text NOT NULL, client_id text NOT NULL, event_id text NOT NULL,
  PRIMARY KEY (owner_id, client_id, event_id)
);
INSERT INTO ${q('signup_events')}(owner_id,client_id,event_id)
  SELECT owner_id,client_id,jsonb_build_array(agent_sub,client_id)::text FROM (
    SELECT owner_id,client_id,agent_sub FROM ${q('transactions')} WHERE status='completed' AND owner_id IS NOT NULL
    UNION SELECT a.owner_id,ac.client_id,ac.agent_sub FROM ${q('accounts')} ac JOIN ${q('agents')} a ON a.sub=ac.agent_sub
  ) known ON CONFLICT DO NOTHING;
INSERT INTO ${q('signup_events')}(owner_id,client_id,event_id)
  SELECT q.owner_id,q.client_id,'legacy:' || jsonb_build_array(q.owner_id,q.client_id,n)::text
  FROM ${q('quotas')} q, LATERAL generate_series(1,GREATEST(0,q.count-(SELECT count(*) FROM ${q('signup_events')} e WHERE e.owner_id=q.owner_id AND e.client_id=q.client_id))) n;
CREATE TABLE ${q('address_quotas')} (
  address_key text NOT NULL, client_id text NOT NULL,
  PRIMARY KEY (address_key, client_id)
);
CREATE TABLE ${q('signing_keys')} (kid text PRIMARY KEY, data jsonb NOT NULL);
CREATE TABLE ${q('signing_state')} (singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), active_kid text REFERENCES ${q('signing_keys')}(kid), legacy_retire_not_before bigint);
INSERT INTO ${q('signing_state')}(singleton,legacy_retire_not_before) VALUES(true,${legacySigningOverlapSeconds ? `${q('app_now')}()::bigint + ${legacySigningOverlapSeconds}` : 'NULL'});
CREATE FUNCTION ${q('invalidate_agent')}(p_handle text, p_sub text, p_now bigint) RETURNS boolean LANGUAGE plpgsql
SET search_path=pg_catalog AS $$
BEGIN
  UPDATE ${q('agents')} SET data=data || jsonb_build_object('enabled',false,'authorizationVersion',authorization_version+1)
    WHERE handle=p_handle AND sub=p_sub;
  IF NOT FOUND THEN RETURN false; END IF;
  -- The Agent update can wait for an in-flight authorization's shared row lock.
  -- Expiry and terminal retention use the authoritative time after that wait.
  p_now := ${q('app_now')}()::bigint;
  WITH affected AS (
    SELECT t.id,t.expires_at,COALESCE(k.expires_at,9223372036854775807) AS key_expiry
    FROM ${q('transactions')} t LEFT JOIN ${q('keys')} k ON k.kid=t.kid AND k.enrollment=t.key_enrollment AND k.agent_sub=t.agent_sub AND k.status<>'pending'
    WHERE t.agent_sub=p_sub AND t.status NOT IN ('completed','denied','expired'))
  UPDATE ${q('transactions')} t SET data=(t.data-'challenge'-'reason') || jsonb_build_object(
    'status',CASE WHEN x.expires_at<=p_now AND x.expires_at<=x.key_expiry THEN 'expired' ELSE 'denied' END,
    'terminalAt',LEAST(x.expires_at,x.key_expiry,p_now),'version',t.version+1) ||
    CASE WHEN x.expires_at<=p_now AND x.expires_at<=x.key_expiry THEN '{}'::jsonb
    ELSE jsonb_build_object('reason',CASE WHEN x.key_expiry<=p_now THEN 'key_revoked' ELSE 'access_denied' END) END
    FROM affected x WHERE t.id=x.id;
  DELETE FROM ${q('reservations')} WHERE agent_sub=p_sub;
  UPDATE ${q('codes')} SET data=data || '{"voided":true}'::jsonb WHERE agent_sub=p_sub AND NOT used AND NOT voided;
  UPDATE ${q('access_tokens')} SET data=data || '{"revoked":true}'::jsonb WHERE agent_sub=p_sub AND NOT revoked;
  RETURN true;
END;
$$;
CREATE FUNCTION ${q('retire_agent')}(p_handle text, p_sub text, p_now bigint) RETURNS boolean LANGUAGE plpgsql
SET search_path=pg_catalog AS $$
BEGIN
  IF NOT ${q('invalidate_agent')}(p_handle,p_sub,p_now) THEN RETURN false; END IF;
  UPDATE ${q('transactions')} t SET data=(t.data-'transactionTokenHash') || jsonb_build_object('version',t.version+1)
    WHERE t.data ? 'transactionTokenHash' AND EXISTS(SELECT 1 FROM ${q('keys')} k WHERE k.agent_sub=p_sub AND k.status='revoked' AND k.kid=t.kid AND k.enrollment=t.key_enrollment);
  INSERT INTO ${q('revoked_keys')}(handle,kid) SELECT handle,kid FROM ${q('keys')} WHERE agent_sub=p_sub ON CONFLICT DO NOTHING;
  DELETE FROM ${q('keys')} WHERE agent_sub=p_sub;
  DELETE FROM ${q('accounts')} WHERE agent_sub=p_sub;
  DELETE FROM ${q('consents')} WHERE agent_sub=p_sub;
  DELETE FROM ${q('credentials')} WHERE handle=p_handle AND kind='delegated';
  DELETE FROM ${q('agents')} WHERE handle=p_handle AND sub=p_sub;
  RETURN true;
END;
$$;
`;
}
