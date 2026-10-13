import { randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import {
  AssertionWindowError, KeyActivationConflictError, TERMINAL, sameConsentMetadata, consentRecordReason,
  type Store, type Owner, type OwnerCode, type Agent, type AgentKey, type Credential, type Client,
  type Transaction, type Code, type AccessToken, type Account, type Consent, type SubjectFilter,
  type ManagementAuthorization, type TransitionEffects, type InsertKeyResult, type RedeemResult,
  type DenyReason,
} from '@agentlogin/issuer';
import type { TableName } from './schema.js';
import { PgDatabase, type PgOptions, type PgSession } from './runtime.js';

export interface PostgresStoreOptions extends PgOptions {
  /** A redeemed code can issue its token only within this bounded interval (default 60 seconds). */
  issuanceWindowSeconds?: number;
}
type Subject = Pick<Code, 'handle' | 'clientId' | 'kid' | 'keyEnrollment' | 'agentSub' | 'agentVersion' | 'accountVersion'>;
type DataRow<T> = { data: T };
const clone = <T>(value: T): T => structuredClone(value);
const sameRecord = (a: unknown, b: unknown): boolean => a !== undefined && isDeepStrictEqual(a, JSON.parse(JSON.stringify(b)));
const unknown = { resolved: false as const };
class WindowElapsed extends Error { constructor(readonly result: 'expired' | 'void') { super('Authorization expired while waiting for a database write'); } }

/** Indexed record storage. Every mutation runs as one retriable SERIALIZABLE database transaction. */
export class PostgresStore implements Store {
  readonly db: PgDatabase;
  private readonly issuanceWindow: number;
  constructor(options: PostgresStoreOptions = {}) {
    this.db = new PgDatabase(options);
    this.issuanceWindow = options.issuanceWindowSeconds ?? 60;
    if (!Number.isSafeInteger(this.issuanceWindow) || this.issuanceWindow < 1 || this.issuanceWindow > 600) throw new RangeError('issuanceWindowSeconds must be from 1 to 600');
  }
  migrate() { return this.db.migrate(); }
  close() { return this.db.close(); }
  currentTime(_fallbackNow: number) { return this.db.read((s) => s.now()); }

  private async one<T>(s: PgSession, table: TableName, where: string, values: unknown[]): Promise<T | undefined> {
    return (await s.query<DataRow<T>>(`SELECT data FROM ${s.table(table)} WHERE ${where}`, values)).rows[0]?.data;
  }
  private async many<T>(s: PgSession, table: TableName, where: string, values: unknown[] = []): Promise<T[]> {
    return (await s.query<DataRow<T>>(`SELECT data FROM ${s.table(table)} WHERE ${where}`, values)).rows.map((r) => r.data);
  }
  private get<T>(table: TableName, where: string, values: unknown[]) { return this.db.read((s) => this.one<T>(s, table, where, values)); }
  private list<T>(table: TableName, where: string, values: unknown[] = []) { return this.db.read((s) => this.many<T>(s, table, where, values)); }
  private async replace(s: PgSession, table: TableName, key: string, value: unknown, data: unknown) {
    await s.query(`UPDATE ${s.table(table)} SET data=$1::jsonb WHERE ${key}=$2`, [JSON.stringify(data), value]);
  }
  private put<T>(operation: string, table: TableName, key: string, id: string, input: T) {
    const data = clone(input);
    return this.db.mutate(operation, async (s) => {
      await s.query(`INSERT INTO ${s.table(table)}(data) VALUES($1::jsonb) ON CONFLICT (${key}) DO UPDATE SET data=EXCLUDED.data`, [JSON.stringify(data)]);
    }, async (s) => sameRecord(await this.one(s, table, `${key}=$1`, [id]), data) ? { resolved: true, value: undefined } : unknown);
  }
  private filter(f: SubjectFilter, transactions = false, offset = 0, alias = '') {
    const columns: Record<keyof SubjectFilter, string> = { kid: 'kid', keyEnrollment: 'key_enrollment', handle: 'handle', clientId: 'client_id', ownerId: transactions ? 'owner_id' : "data->>'ownerId'", txnId: transactions ? 'id' : 'txn_id' };
    const values: unknown[] = [];
    const clauses = Object.entries(f).filter(([, value]) => value !== undefined).map(([key, value]) => {
      values.push(value);
      return `${alias}${columns[key as keyof SubjectFilter]}=$${offset + values.length}`;
    });
    return { where: clauses.join(' AND ') || 'TRUE', values };
  }

  putOwner(o: Owner) {
    const data = clone(o);
    return this.db.mutate('putOwner', async (s) => {
      const old = await this.one<Owner>(s, 'owners', 'id=$1', [o.id]);
      if (old && old.ownerSub !== data.ownerSub) throw new Error('Owner subject is immutable');
      await s.query(`INSERT INTO ${s.table('owners')}(data) VALUES($1::jsonb) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data`, [JSON.stringify(data)]);
    });
  }
  getOwner(id: string) { return this.get<Owner>('owners', 'id=$1', [id]); }
  getOwnerByEmail(email: string) { return this.get<Owner>('owners', 'email_lower=lower($1) ORDER BY created_at DESC LIMIT 1', [email]); }
  putOwnerCode(c: OwnerCode) { return this.put('putOwnerCode', 'owner_codes', 'owner_id', c.ownerId, c); }
  takeOwnerCode(ownerId: string) {
    // Absence after an uncertain COMMIT cannot identify who consumed the code. Deliberately no reconciliation.
    return this.db.mutate('takeOwnerCode', async (s) => (await s.query<DataRow<OwnerCode>>(`DELETE FROM ${s.table('owner_codes')} WHERE owner_id=$1 RETURNING data`, [ownerId])).rows[0]?.data);
  }
  putAgent(a: Agent) {
    const data = clone(a);
    return this.db.mutate('putAgent', async (s) => {
      if (!await this.one(s, 'owners', 'id=$1', [data.ownerId])) throw new Error('Unknown Owner');
      const result = await s.query(`INSERT INTO ${s.table('agents')}(data) VALUES($1::jsonb) ON CONFLICT DO NOTHING`, [JSON.stringify(data)]);
      return result.rowCount === 1;
    }, async (s) => sameRecord(await this.one(s, 'agents', 'handle=$1 AND sub=$2', [data.handle, data.sub]), data) ? { resolved: true, value: true } : unknown);
  }
  getAgent(handle: string) { return this.get<Agent>('agents', 'handle=$1', [handle]); }
  listAgentsByOwner(ownerId: string) { return this.list<Agent>('agents', 'owner_id=$1', [ownerId]); }
  putCredential(c: Credential) { return this.put('putCredential', 'credentials', 'hash', c.hash, c); }
  getCredential(hash: string) { return this.get<Credential>('credentials', 'hash=$1', [hash]); }
  listCredentials(f: { ownerId?: string; handle?: string; kind?: 'owner' | 'delegated' }) {
    const values: unknown[] = [];
    const columns = { ownerId: 'owner_id', handle: 'handle', kind: 'kind' };
    const where = Object.entries(f).filter(([, v]) => v !== undefined).map(([k, v]) => { values.push(v); return `${columns[k as keyof typeof columns]}=$${values.length}`; }).join(' AND ');
    return this.list<Credential>('credentials', where || 'TRUE', values);
  }
  deleteCredential(hash: string) { return this.db.mutate('deleteCredential', async (s) => { await s.query(`DELETE FROM ${s.table('credentials')} WHERE hash=$1`, [hash]); }); }
  getKey(kid: string, handle?: string) {
    return this.db.read(async (s) => {
      if (handle !== undefined) return this.one<AgentKey>(s, 'keys', 'kid=$1 AND handle=$2', [kid, handle]);
      const keys = await this.many<AgentKey>(s, 'keys', 'kid=$1', [kid]);
      return keys.find((key) => key.status === 'active') ?? (keys.length === 1 ? keys[0] : undefined);
    });
  }
  listKeys(handle: string) { return this.list<AgentKey>('keys', 'handle=$1', [handle]); }
  wasRevoked(handle: string, kid: string) { return this.db.read(async (s) => (await s.query(`SELECT 1 FROM ${s.table('revoked_keys')} WHERE handle=$1 AND kid=$2`, [handle, kid])).rowCount !== 0); }
  putClient(c: Client) { return this.put('putClient', 'clients', 'client_id', c.clientId, c); }
  getClient(clientId: string) { return this.get<Client>('clients', 'client_id=$1', [clientId]); }
  insertTransaction(t: Transaction) {
    const data = clone(t);
    return this.db.mutate('insertTransaction', async (s) => {
      await s.query(`INSERT INTO ${s.table('transactions')}(data) VALUES($1::jsonb)`, [JSON.stringify(data)]);
    }, async (s) => sameRecord(await this.one(s, 'transactions', 'id=$1', [data.id]), data) ? { resolved: true, value: undefined } : unknown);
  }
  getTransaction(id: string) { return this.get<Transaction>('transactions', 'id=$1', [id]); }
  listOpenTransactions(filter: SubjectFilter) {
    const f = this.filter(filter, true);
    return this.list<Transaction>('transactions', `status NOT IN ('completed','denied','expired') AND ${f.where}`, f.values);
  }
  getCode(hash: string) { return this.get<Code>('codes', 'hash=$1', [hash]); }
  getAccessToken(hash: string) { return this.get<AccessToken>('access_tokens', 'hash=$1', [hash]); }
  getAccount(handle: string, clientId: string) { return this.get<Account>('accounts', 'handle=$1 AND client_id=$2', [handle, clientId]); }
  listAccounts(handle: string) { return this.list<Account>('accounts', 'handle=$1', [handle]); }
  getConsent(handle: string, clientId: string) { return this.get<Consent>('consents', 'handle=$1 AND client_id=$2', [handle, clientId]); }
  listConsents(handle: string) { return this.list<Consent>('consents', 'handle=$1', [handle]); }
  signupsEver(ownerId: string, clientId: string) { return this.db.read(async (s) => Number((await s.query<{ count: string }>(`SELECT count FROM ${s.table('quotas')} WHERE owner_id=$1 AND client_id=$2`, [ownerId, clientId])).rows[0]?.count ?? 0)); }

  /** The quota is the sole explicit coordination row. SSI still detects stale snapshots after lock waits. */
  private async quota(s: PgSession, ownerId: string, clientId: string) {
    await s.query(`INSERT INTO ${s.table('quotas')}(owner_id,client_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, [ownerId, clientId]);
    await s.query(`SELECT count FROM ${s.table('quotas')} WHERE owner_id=$1 AND client_id=$2 FOR UPDATE`, [ownerId, clientId]);
    await s.checkpoint('quota_locked');
  }
  private async subjectQuotas(s: PgSession, filter: SubjectFilter) {
    const f = this.filter(filter, true, 0, 't.');
    const pairs = await s.query<{ owner_id: string; client_id: string }>(`SELECT DISTINCT r.owner_id,r.client_id FROM ${s.table('reservations')} r JOIN ${s.table('transactions')} t ON t.id=r.txn_id WHERE ${f.where} ORDER BY r.owner_id,r.client_id`, f.values);
    for (const p of pairs.rows) await this.quota(s, p.owner_id, p.client_id);
  }
  private async authorized(s: PgSession, handle: string, auth: ManagementAuthorization) {
    const a = await this.one<Agent>(s, 'agents', 'handle=$1', [handle]);
    const c = await this.one<Credential>(s, 'credentials', 'hash=$1', [auth.hash]);
    return a?.sub === auth.agentSub && a.ownerId === auth.ownerId && c?.ownerId === auth.ownerId && c.kind === auth.kind && (c.kind === 'owner' || c.handle === handle);
  }
  private async subject(s: PgSession, t: Partial<Subject>, now: number): Promise<'key_revoked' | 'access_denied' | undefined> {
    const k = t.kid ? await this.one<AgentKey>(s, 'keys', 'kid=$1 AND enrollment=$2 AND handle=$3', [t.kid,t.keyEnrollment,t.handle]) : undefined;
    if (!k || k.handle !== t.handle || k.enrollment !== t.keyEnrollment || k.agentSub !== t.agentSub || k.status !== 'active' || now >= k.expiresAt) return 'key_revoked';
    const a = await this.one<Agent>(s, 'agents', 'handle=$1', [t.handle]);
    if (!a || a.sub !== t.agentSub || !a.enabled || a.authorizationVersion !== t.agentVersion) return 'access_denied';
    const account = await this.one<Account>(s, 'accounts', 'agent_sub=$1 AND client_id=$2', [t.agentSub, t.clientId]);
    if (account?.status === 'disabled' || (account?.authorizationVersion ?? 0) !== t.accountVersion) return 'access_denied';
    return undefined;
  }
  private async invalidate(s: PgSession, filter: SubjectFilter, reason: DenyReason, now: number) {
    const f = this.filter(filter, true, 2, 't.');
    await s.query(`WITH affected AS (
      SELECT t.id,t.expires_at,COALESCE(k.expires_at,9223372036854775807) AS key_expiry
      FROM ${s.table('transactions')} t LEFT JOIN ${s.table('keys')} k
        ON k.kid=t.kid AND k.enrollment=t.key_enrollment AND k.handle=t.handle AND k.agent_sub=t.agent_sub AND k.status<>'pending'
      WHERE t.status NOT IN ('completed','denied','expired') AND ${f.where})
      UPDATE ${s.table('transactions')} t SET data=(t.data-'challenge'-'reason') || jsonb_build_object(
        'status',CASE WHEN x.expires_at<=$1::bigint AND x.expires_at<=x.key_expiry THEN 'expired' ELSE 'denied' END,
        'terminalAt',LEAST(x.expires_at,x.key_expiry,$1::bigint),'version',t.version+1) ||
        CASE WHEN x.expires_at<=$1::bigint AND x.expires_at<=x.key_expiry THEN '{}'::jsonb
             ELSE jsonb_build_object('reason',CASE WHEN x.key_expiry<=$1::bigint THEN 'key_revoked' ELSE $2::text END) END
      FROM affected x WHERE t.id=x.id`, [now, reason, ...f.values]);
    const select = this.filter(filter, true);
    await s.query(`DELETE FROM ${s.table('reservations')} WHERE txn_id IN (SELECT id FROM ${s.table('transactions')} WHERE ${select.where})`, select.values);
    await this.voidMatching(s, filter);
    await this.revokeMatching(s, filter);
  }
  private async voidMatching(s: PgSession, filter: SubjectFilter) {
    const f = this.filter(filter);
    await s.query(`UPDATE ${s.table('codes')} SET data=data || '{"voided":true}'::jsonb WHERE NOT used AND NOT voided AND ${f.where}`, f.values);
  }
  private async revokeMatching(s: PgSession, filter: SubjectFilter) {
    const f = this.filter(filter);
    await s.query(`UPDATE ${s.table('access_tokens')} SET data=data || '{"revoked":true}'::jsonb WHERE NOT revoked AND ${f.where}`, f.values);
  }
  setAgentEnabled(handle: string, enabled: boolean, agentSub: string, _now: number) {
    return this.db.mutate('setAgentEnabled', async (s) => {
      await this.subjectQuotas(s, { handle });
      const a = await this.one<Agent>(s, 'agents', 'handle=$1 AND sub=$2', [handle, agentSub]);
      if (!a) return undefined;
      a.enabled = enabled;
      if (!enabled) a.authorizationVersion += 1;
      await this.replace(s, 'agents', 'handle', handle, a);
      if (!enabled) await this.invalidate(s, { handle }, 'access_denied', await s.now());
      return a;
    });
  }
  deleteAgent(handle: string, agentSub: string, _now: number) {
    return this.db.mutate('deleteAgent', async (s) => {
      await this.subjectQuotas(s, { handle });
      if (!await this.one(s, 'agents', 'handle=$1 AND sub=$2', [handle, agentSub])) return false;
      await this.invalidate(s, { handle }, 'access_denied', await s.now());
      await s.query(`INSERT INTO ${s.table('revoked_keys')}(handle,kid) SELECT handle,kid FROM ${s.table('keys')} WHERE agent_sub=$1 ON CONFLICT DO NOTHING`, [agentSub]);
      for (const table of ['keys','accounts','consents'] as const) await s.query(`DELETE FROM ${s.table(table)} WHERE agent_sub=$1`, [agentSub]);
      await s.query(`DELETE FROM ${s.table('credentials')} WHERE handle=$1 AND kind='delegated'`, [handle]);
      await s.query(`DELETE FROM ${s.table('agents')} WHERE handle=$1 AND sub=$2`, [handle, agentSub]);
      return true;
    });
  }
  insertKey(input: AgentKey, _now: number, authorization: ManagementAuthorization): Promise<InsertKeyResult> {
    const key = clone(input);
    return this.db.mutate('insertKey', async (s) => {
      const old = await this.one<AgentKey>(s, 'keys', 'kid=$1 AND handle=$2', [key.kid,key.handle]);
      if (old) await this.subjectQuotas(s, { kid: old.kid, keyEnrollment: old.enrollment });
      const now = await s.now();
      if (key.status !== 'pending' || key.agentSub !== authorization.agentSub || !await this.authorized(s, key.handle, authorization)) return 'unauthorized';
      if ((await s.query(`SELECT 1 FROM ${s.table('revoked_keys')} WHERE handle=$1 AND kid=$2`, [key.handle, key.kid])).rowCount) return 'revoked';
      if (old && now < old.expiresAt && ((old.status === 'pending' && old.challenge && now < old.challenge.expiresAt) || old.status === 'active')) return 'enrolled';
      if (key.expiresAt <= now || !key.challenge || key.challenge.expiresAt <= now) return 'unauthorized';
      if (await this.one(s, 'keys', 'enrollment=$1', [key.enrollment])) throw new Error('Key enrollment already exists');
      if (old?.status === 'active' && now >= old.expiresAt) await this.invalidate(s, { kid: old.kid, keyEnrollment: old.enrollment }, 'key_revoked', old.expiresAt);
      await s.query(`INSERT INTO ${s.table('keys')}(data) VALUES($1::jsonb) ON CONFLICT(handle,kid) DO UPDATE SET data=EXCLUDED.data`, [JSON.stringify(key)]);
      return 'ok';
    }, async (s) => sameRecord(await this.one(s, 'keys', 'kid=$1 AND enrollment=$2', [key.kid, key.enrollment]), key) ? { resolved: true, value: 'ok' } : unknown);
  }
  activateKey(kid: string, enrollment: string, challenge: string, _now: number, assertionWindow?: {notBefore:number;expiresAt:number}) {
    return this.db.mutate('activateKey', async (s) => {
      // Expiring a previously proved enrollment can invalidate reservations. Take quota
      // coordination first, including when this pending enrollment has no transactions.
      await this.subjectQuotas(s, { kid });
      const key = await this.one<AgentKey>(s, 'keys', 'kid=$1 AND enrollment=$2', [kid, enrollment]);
      const now = await s.now();
      if (assertionWindow && (now < assertionWindow.notBefore || now >= assertionWindow.expiresAt)) throw new AssertionWindowError();
      if (!key || key.status !== 'pending' || key.challenge?.value !== challenge || now >= key.challenge.expiresAt || now >= key.expiresAt) return false;
      if (!await this.one(s, 'agents', 'handle=$1 AND sub=$2', [key.handle, key.agentSub])) return false;
      const active = await this.one<AgentKey>(s, 'keys', "kid=$1 AND status='active'", [kid]);
      if (active) {
        if (now < active.expiresAt) throw new KeyActivationConflictError();
        await this.invalidate(s, { kid, keyEnrollment: active.enrollment }, 'key_revoked', active.expiresAt);
        await this.replace(s, 'keys', 'enrollment', active.enrollment, { ...active, status: 'expired', challenge: undefined });
      }
      await s.checkpoint('activation_checked');
      await this.replace(s, 'keys', 'enrollment', enrollment, { ...key, status: 'active', challenge: undefined });
      const acceptedAt = await s.now();
      if (assertionWindow && (acceptedAt < assertionWindow.notBefore || acceptedAt >= assertionWindow.expiresAt)) throw new AssertionWindowError();
      if (acceptedAt >= key.challenge.expiresAt || acceptedAt >= key.expiresAt) throw new WindowElapsed('expired');
      return true;
    }).catch((error: unknown) => {
      if (error instanceof WindowElapsed) return false;
      // SSI may report a unique violation when concurrent snapshots each saw no
      // active enrollment. Only this exact index denotes an activation conflict;
      // mutate() has already rolled back all changes before this mapping.
      if (error && typeof error === 'object' && 'code' in error && error.code === '23505'
        && 'constraint' in error && error.constraint === 'keys_active_kid') throw new KeyActivationConflictError();
      throw error;
    });
  }
  revokeKey(kid: string, enrollment: string, _now: number) {
    return this.db.mutate('revokeKey', async (s) => {
      await this.subjectQuotas(s, { kid, keyEnrollment: enrollment });
      const key = await this.one<AgentKey>(s, 'keys', 'kid=$1 AND enrollment=$2', [kid, enrollment]);
      if (!key || !['active','pending'].includes(key.status)) return undefined;
      const now = await s.now();
      const revoked: AgentKey = { ...key, status: 'revoked', revokedAt: now, challenge: undefined };
      await this.replace(s, 'keys', 'enrollment', enrollment, revoked);
      await s.query(`INSERT INTO ${s.table('revoked_keys')}(handle,kid) VALUES($1,$2) ON CONFLICT DO NOTHING`, [key.handle,kid]);
      await this.invalidate(s, { kid, keyEnrollment: enrollment }, 'key_revoked', now);
      return revoked;
    });
  }
  revokeAllKeys(handle: string, auth: ManagementAuthorization, _now: number) {
    return this.db.mutate('revokeAllKeys', async (s) => {
      await this.subjectQuotas(s, { handle });
      if (!await this.authorized(s, handle, auth)) return false;
      const now = await s.now();
      const keys = await this.many<AgentKey>(s, 'keys', "handle=$1 AND agent_sub=$2 AND status IN ('pending','active')", [handle,auth.agentSub]);
      for (const key of keys) {
        await this.replace(s, 'keys', 'enrollment', key.enrollment, { ...key,status:'revoked',revokedAt:now,challenge:undefined });
        await s.query(`INSERT INTO ${s.table('revoked_keys')}(handle,kid) VALUES($1,$2) ON CONFLICT DO NOTHING`, [handle,key.kid]);
        await this.invalidate(s, { kid:key.kid,keyEnrollment:key.enrollment }, 'key_revoked', now);
      }
      if (auth.kind === 'owner') await s.query(`DELETE FROM ${s.table('credentials')} WHERE handle=$1 AND kind='delegated'`, [handle]);
      return true;
    });
  }
  patchKey(kid: string, enrollment: string, patch: { name?: string; shareOwner?: boolean }) {
    return this.db.mutate('patchKey', async (s) => {
      const key = await this.one<AgentKey>(s, 'keys', 'kid=$1 AND enrollment=$2', [kid,enrollment]);
      if (!key) return undefined;
      if (patch.name !== undefined) key.name = patch.name;
      if (patch.shareOwner !== undefined) key.permissions.share_owner = patch.shareOwner;
      await this.replace(s, 'keys', 'enrollment', enrollment, key);
      return key;
    });
  }
  deleteKey(kid: string, enrollment?: string, pendingExpiredAt?: number) {
    return this.db.mutate('deleteKey', async (s) => {
      let target = enrollment;
      if (target === undefined) {
        const keys = await this.many<AgentKey>(s, 'keys', 'kid=$1', [kid]);
        target = (keys.find((key) => key.status === 'active') ?? (keys.length === 1 ? keys[0] : undefined))?.enrollment;
      }
      if (target !== undefined) {
        if (pendingExpiredAt === undefined) {
          await s.query(`DELETE FROM ${s.table('keys')} WHERE kid=$1 AND enrollment=$2`, [kid,target]);
        } else {
          const now = await s.now();
          await s.query(`DELETE FROM ${s.table('keys')} WHERE kid=$1 AND enrollment=$2 AND status='pending'
            AND (challenge_expires_at IS NULL OR challenge_expires_at<=$3)`, [kid,target,now]);
        }
      }
    });
  }

  /** One read-only SQL snapshot computes lifecycle status; polling never writes or renews retention. */
  readTransaction(id: string, options: { now: number; retainFor: number }): Promise<Transaction | undefined> {
    return this.db.read(async (s) => {
      const result = await s.query<DataRow<Transaction>>(`WITH clock AS MATERIALIZED (SELECT ${this.db.schema}.app_now()::bigint AS now),
      facts AS (SELECT t.data,t.status,t.expires_at,t.terminal_at,c.now,
        CASE WHEN k.enrollment=t.key_enrollment AND k.agent_sub=t.agent_sub AND k.status<>'pending' THEN k.expires_at ELSE 9223372036854775807 END AS key_expiry,
        CASE WHEN t.kid IS NULL THEN NULL
          WHEN k.kid IS NULL OR k.enrollment<>t.key_enrollment OR k.agent_sub<>t.agent_sub OR k.status<>'active' THEN 'key_revoked'
          WHEN a.sub IS DISTINCT FROM t.agent_sub OR NOT a.enabled OR a.authorization_version<>(t.data->>'agentVersion')::bigint
            OR ac.status='disabled' OR COALESCE(ac.authorization_version,0)<>(t.data->>'accountVersion')::bigint THEN 'access_denied' ELSE NULL END AS dead
        FROM ${s.table('transactions')} t CROSS JOIN clock c LEFT JOIN ${s.table('keys')} k ON k.kid=t.kid AND k.enrollment=t.key_enrollment AND k.handle=t.handle
        LEFT JOIN ${s.table('agents')} a ON a.handle=t.handle
        LEFT JOIN ${s.table('accounts')} ac ON ac.agent_sub=t.agent_sub AND ac.client_id=t.client_id WHERE t.id=$1),
      effective AS (SELECT now, CASE WHEN status IN ('completed','denied','expired') THEN data
        WHEN expires_at<=now AND expires_at<=key_expiry THEN (data-'challenge'-'reason') || jsonb_build_object('status','expired','terminalAt',expires_at)
        WHEN key_expiry<=now THEN (data-'challenge') || jsonb_build_object('status','denied','reason','key_revoked','terminalAt',key_expiry)
        WHEN dead IS NOT NULL THEN (data-'challenge') || jsonb_build_object('status','denied','reason',dead,'terminalAt',now)
        ELSE data END AS data FROM facts)
      SELECT data FROM effective WHERE NOT (data->>'status' IN ('completed','denied','expired') AND data->>'terminalAt' IS NOT NULL AND now>(data->>'terminalAt')::bigint+$2::bigint)`, [id,options.retainFor]);
      return result.rows[0]?.data;
    });
  }
  private async expiration(s: PgSession, tx: Transaction, now: number): Promise<Transaction | undefined> {
    const k = tx.kid ? await this.one<AgentKey>(s, 'keys', 'kid=$1 AND enrollment=$2 AND handle=$3', [tx.kid,tx.keyEnrollment,tx.handle]) : undefined;
    const keyExpiry = k && k.enrollment === tx.keyEnrollment && k.agentSub === tx.agentSub && k.status !== 'pending' ? k.expiresAt : Infinity;
    if (now >= tx.expiresAt && tx.expiresAt <= keyExpiry) return { ...tx,status:'expired',reason:undefined,terminalAt:tx.expiresAt,challenge:undefined };
    if (now >= keyExpiry) return { ...tx,status:'denied',reason:'key_revoked',terminalAt:keyExpiry,challenge:undefined };
    return undefined;
  }
  private async reserve(s: PgSession, tx: Transaction, max: number, now: number): Promise<boolean> {
    // Retire invalid/expired reservations during admission. Polling and garbage collection are not quota authorities.
    await s.query(`DELETE FROM ${s.table('reservations')} r WHERE r.owner_id=$1 AND r.client_id=$2 AND (
      r.expires_at<=$3 OR NOT EXISTS (SELECT 1 FROM ${s.table('transactions')} t
        JOIN ${s.table('keys')} k ON k.kid=t.kid AND k.enrollment=t.key_enrollment AND k.handle=t.handle AND k.agent_sub=t.agent_sub AND k.status='active' AND k.expires_at>$3
        JOIN ${s.table('agents')} a ON a.sub=t.agent_sub AND a.enabled AND a.authorization_version=(t.data->>'agentVersion')::bigint
        LEFT JOIN ${s.table('accounts')} ac ON ac.agent_sub=t.agent_sub AND ac.client_id=t.client_id
        WHERE t.id=r.txn_id AND t.status NOT IN ('completed','denied','expired') AND t.expires_at>$3
        AND COALESCE(ac.status,'enabled')='enabled' AND COALESCE(ac.authorization_version,0)=(t.data->>'accountVersion')::bigint))`, [tx.ownerId,tx.clientId,now]);
    const count = await s.query<{ count: string; others: string }>(`SELECT q.count,
      (SELECT count(DISTINCT r.agent_sub) FROM ${s.table('reservations')} r
       WHERE r.owner_id=q.owner_id AND r.client_id=q.client_id AND r.expires_at>$3 AND r.agent_sub<>$4
       AND NOT EXISTS(SELECT 1 FROM ${s.table('accounts')} a WHERE a.agent_sub=r.agent_sub AND a.client_id=r.client_id)) AS others
      FROM ${s.table('quotas')} q WHERE q.owner_id=$1 AND q.client_id=$2`, [tx.ownerId,tx.clientId,now,tx.agentSub]);
    if (Number(count.rows[0]?.count ?? 0) + Number(count.rows[0]?.others ?? 0) >= max) return false;
    await s.query(`INSERT INTO ${s.table('reservations')}(txn_id,owner_id,client_id,agent_sub,expires_at) VALUES($1,$2,$3,$4,$5)
      ON CONFLICT(txn_id) DO UPDATE SET expires_at=EXCLUDED.expires_at`, [tx.id,tx.ownerId,tx.clientId,tx.agentSub,tx.expiresAt]);
    return true;
  }
  private async consentEffects(s: PgSession, tx: Transaction, effects: TransitionEffects, now: number) {
    const previous = await this.one<Consent>(s, 'consents', 'agent_sub=$1 AND client_id=$2', [tx.agentSub,tx.clientId]);
    const maxAge = effects.expireConsentBefore === undefined ? undefined : effects.now - effects.expireConsentBefore;
    const expired = previous && maxAge !== undefined && now - previous.lastUsedAt > maxAge;
    if (expired) await s.query(`DELETE FROM ${s.table('consents')} WHERE agent_sub=$1 AND client_id=$2`, [tx.agentSub,tx.clientId]);
    if (effects.consent) {
      const cur = !expired && previous && sameConsentMetadata(previous,effects.consent) ? previous : undefined;
      const consent: Consent = { ...effects.consent,scopes:[...new Set([...(cur?.scopes ?? []),...effects.consent.scopes])],createdAt:cur?.createdAt ?? now,lastUsedAt:now };
      await s.query(`INSERT INTO ${s.table('consents')}(agent_sub,data) VALUES($1,$2::jsonb)
        ON CONFLICT(agent_sub,client_id) DO UPDATE SET data=EXCLUDED.data`, [tx.agentSub,JSON.stringify(consent)]);
    } else if (effects.touchConsent && tx.consentRelied && tx.status==='ready' && previous && !expired) {
      await s.query(`UPDATE ${s.table('consents')} SET data=data || jsonb_build_object('lastUsedAt',$3::bigint) WHERE agent_sub=$1 AND client_id=$2`, [tx.agentSub,tx.clientId,now]);
    }
  }
  updateTransaction(input: Transaction, expectedVersion: number, inputEffects: TransitionEffects): Promise<Transaction | undefined> {
    const supplied = clone(input), effects = clone(inputEffects);
    let produced: Transaction | undefined;
    return this.db.mutate('updateTransaction', async (s) => {
      produced = undefined;
      if (supplied.ownerId) await this.quota(s,supplied.ownerId,supplied.clientId);
      const cur = await this.one<Transaction>(s,'transactions','id=$1',[supplied.id]);
      if (!cur || cur.version !== expectedVersion || TERMINAL.has(cur.status) || supplied.status === 'completed') return undefined;
      const now = await s.now();
      if (effects.assertionWindow && (now < effects.assertionWindow.notBefore || now >= effects.assertionWindow.expiresAt)) throw new AssertionWindowError();
      let next = clone(supplied);
      if (next.status === 'denied') next.terminalAt = now;
      const expired = await this.expiration(s,cur,now);
      const dead = next.kid ? await this.subject(s,next,now) : undefined;
      if (expired) next = { ...next,status:expired.status,reason:expired.reason,terminalAt:expired.terminalAt,challenge:undefined };
      else if (dead) next = { ...next,status:'denied',reason:dead,terminalAt:now,challenge:undefined };
      else if (cur.status === 'awaiting_agent' && next.kid) {
        next.assertedAt = now;
        if (!await this.one(s,'accounts','agent_sub=$1 AND client_id=$2',[next.agentSub,next.clientId]) && effects.maxSignups !== undefined) {
          if (await this.reserve(s,next,effects.maxSignups,now)) next.passedCap = true;
          else next = { ...next,status:'denied',reason:'signup_limit_reached',terminalAt:now,challenge:undefined };
        }
      }
      if (!TERMINAL.has(next.status) && effects.touchConsent && !effects.consent) {
        const prior = await this.one<Consent>(s,'consents','agent_sub=$1 AND client_id=$2',[next.agentSub,next.clientId]);
        const expiry = effects.expireConsentBefore === undefined ? undefined : now-(effects.now-effects.expireConsentBefore);
        const reason = consentRecordReason(prior,effects.consentContext ?? {scopes:next.scopes,redirectHost:new URL(next.redirectUri).host},expiry);
        if (reason) {
          next.consentRelied=false; next.reviewOutstanding=true; next.consentReason=reason;
          if (next.prompt==='none') next={...next,status:'denied',reason:'consent_required',terminalAt:now,challenge:undefined};
          else next.status=next.ownerApprovalOutstanding ? 'awaiting_owner' : 'awaiting_consent';
        }
      }
      next.version = expectedVersion + 1;
      // All conflicting mutations run SERIALIZABLE; the version predicate is a second explicit precondition.
      const accepted = await s.query(`UPDATE ${s.table('transactions')} SET data=$1::jsonb WHERE id=$2 AND version=$3`, [JSON.stringify(next),next.id,expectedVersion]);
      if (!accepted.rowCount) return undefined;
      if (TERMINAL.has(next.status)) await s.query(`DELETE FROM ${s.table('reservations')} WHERE txn_id=$1`,[next.id]);
      else {
        if (next.passedCap) await s.query(`UPDATE ${s.table('reservations')} SET expires_at=$2 WHERE txn_id=$1`,[next.id,next.expiresAt]);
        if (next.agentSub) await this.consentEffects(s,next,effects,now);
      }
      const acceptedAt = await s.now();
      if (effects.assertionWindow && (acceptedAt < effects.assertionWindow.notBefore || acceptedAt >= effects.assertionWindow.expiresAt)) throw new AssertionWindowError();
      if (!TERMINAL.has(next.status) && (acceptedAt >= next.expiresAt || await this.subject(s,next,acceptedAt))) throw new WindowElapsed('expired');
      produced = next;
      return next;
    }, async (s) => {
      const stored = await this.one<Transaction>(s,'transactions','id=$1',[supplied.id]);
      return produced && isDeepStrictEqual(stored,JSON.parse(JSON.stringify(produced))) ? {resolved:true,value:stored} : unknown;
    }).catch((error) => { if (error instanceof WindowElapsed) return undefined; throw error; });
  }
  completeTransaction(input: Transaction, expectedVersion: number, inputCode: Code, suppliedNow: number): Promise<Transaction | undefined> {
    const supplied = clone(input), code = clone(inputCode);
    return this.db.mutate('completeTransaction', async (s) => {
      if (supplied.ownerId) await this.quota(s,supplied.ownerId,supplied.clientId);
      const cur = await this.one<Transaction>(s,'transactions','id=$1',[supplied.id]);
      if (!cur || cur.version !== expectedVersion || cur.status !== 'ready') return undefined;
      const now = await s.now();
      const dead = await this.subject(s,cur,now);
      const expired = await this.expiration(s,cur,now);
      const account = await this.one<Account>(s,'accounts','agent_sub=$1 AND client_id=$2',[cur.agentSub,cur.clientId]);
      const reservation = await s.query(`SELECT 1 FROM ${s.table('reservations')} WHERE txn_id=$1 AND agent_sub=$2 AND owner_id=$3 AND client_id=$4 AND expires_at>$5`,[cur.id,cur.agentSub,cur.ownerId,cur.clientId,now]);
      if (dead || expired || (cur.passedCap && !account && !reservation.rowCount)) {
        const next: Transaction = { ...cur,...expired,status:expired?.status ?? 'denied',reason:expired ? expired.reason : dead ?? 'signup_limit_reached',terminalAt:expired?.terminalAt ?? now,challenge:undefined,version:cur.version+1 };
        await this.replace(s,'transactions','id',cur.id,next);
        await s.query(`DELETE FROM ${s.table('reservations')} WHERE txn_id=$1`,[cur.id]);
        return next;
      }
      const ttl = code.expiresAt - suppliedNow;
      if (!Number.isSafeInteger(ttl) || ttl <= 0) throw new Error('Invalid code lifetime');
      const issued: Code = { ...code,txnId:cur.id,clientId:cur.clientId,redirectUri:cur.redirectUri,codeChallenge:cur.codeChallenge,nonce:cur.nonce,scopes:cur.scopes,
        handle:cur.handle!,kid:cur.kid!,keyEnrollment:cur.keyEnrollment!,agentSub:cur.agentSub!,agentVersion:cur.agentVersion!,accountVersion:cur.accountVersion!,
        authTime:cur.assertedAt!,expiresAt:now+ttl,used:false,voided:false,replayed:undefined };
      const next: Transaction = { ...cur,status:'completed',terminalAt:now,challenge:undefined,codeIssued:true,version:cur.version+1 };
      await this.replace(s,'transactions','id',cur.id,next);
      await s.query(`INSERT INTO ${s.table('codes')}(data) VALUES($1::jsonb)`,[JSON.stringify(issued)]);
      const nextAccount: Account = account ? { ...account,lastSignedInAt:now,signInCount:account.signInCount+1 } :
        { handle:cur.handle!,clientId:cur.clientId,status:'enabled',authorizationVersion:0,firstSignedInAt:now,lastSignedInAt:now,signInCount:1 };
      await s.query(`INSERT INTO ${s.table('accounts')}(agent_sub,data) VALUES($1,$2::jsonb) ON CONFLICT(agent_sub,client_id) DO UPDATE SET data=EXCLUDED.data`,[cur.agentSub,JSON.stringify(nextAccount)]);
      if (!account) await s.query(`UPDATE ${s.table('quotas')} SET count=count+1 WHERE owner_id=$1 AND client_id=$2`,[cur.ownerId,cur.clientId]);
      await s.query(`DELETE FROM ${s.table('reservations')} WHERE txn_id=$1`,[cur.id]);
      const acceptedAt = await s.now();
      if (acceptedAt >= cur.expiresAt || await this.subject(s,cur,acceptedAt) || (cur.passedCap && !account && acceptedAt >= cur.expiresAt)) throw new WindowElapsed('expired');
      return next;
    }, async (s) => {
      const c = await this.one<Code>(s,'codes','hash=$1 AND txn_id=$2',[code.hash,supplied.id]);
      const tx = await this.one<Transaction>(s,'transactions','id=$1',[supplied.id]);
      return c && tx?.status === 'completed' && tx.version === expectedVersion+1 && c.agentSub === supplied.agentSub && c.keyEnrollment === supplied.keyEnrollment ? {resolved:true,value:tx} : unknown;
    }).catch((error) => { if (error instanceof WindowElapsed) return undefined; throw error; });
  }
  redeemCode(hash: string, _now: number): Promise<RedeemResult> {
    // Unique to this request, stable only across database retries/reconciliation. A new HTTP replay gets a new ID.
    const attempt = randomUUID();
    return this.db.mutate<RedeemResult>('redeemCode', async (s) => {
      const code = await this.one<Code>(s,'codes','hash=$1',[hash]);
      if (!code) return 'unknown';
      const now = await s.now();
      if (code.used) {
        await this.replace(s,'codes','hash',hash,{...code,replayed:true});
        await this.revokeMatching(s,{txnId:code.txnId});
        return 'used';
      }
      if (code.voided || await this.subject(s,code,now)) return 'void';
      if (now >= code.expiresAt) return 'expired';
      await s.query(`UPDATE ${s.table('codes')} SET data=data || '{"used":true}'::jsonb,redemption_attempt=$2,redeemed_at=$3,issuance_until=$4 WHERE hash=$1`,[hash,attempt,now,now+this.issuanceWindow]);
      const acceptedAt = await s.now();
      if (acceptedAt >= code.expiresAt) throw new WindowElapsed('expired');
      if (await this.subject(s,code,acceptedAt)) throw new WindowElapsed('void');
      return 'ok';
    }, async (s) => {
      const row = (await s.query<{data:Code;redemption_attempt:string;issuance_until:string}>(`SELECT data,redemption_attempt,issuance_until FROM ${s.table('codes')} WHERE hash=$1`,[hash])).rows[0];
      if (!row) return unknown;
      if (row.data.replayed) return {resolved:true,value:'used'};
      const now = await s.now();
      return row.redemption_attempt === attempt && row.data.used && Number(row.issuance_until)>now && !await this.subject(s,row.data,now) ? {resolved:true,value:'ok'} : unknown;
    }).catch((error) => { if (error instanceof WindowElapsed) return error.result; throw error; });
  }
  voidCodes(f: SubjectFilter) { return this.db.mutate('voidCodes',(s) => this.voidMatching(s,f)); }
  revokeAccessTokens(f: SubjectFilter) { return this.db.mutate('revokeAccessTokens',(s) => this.revokeMatching(s,f)); }
  insertAccessToken(input: AccessToken, suppliedNow: number) {
    const token = clone(input);
    return this.db.mutate('insertAccessToken', async (s) => {
      const row = (await s.query<{data:Code;issuance_until:string}>(`SELECT data,issuance_until FROM ${s.table('codes')} WHERE txn_id=$1`,[token.txnId])).rows[0];
      const now = await s.now();
      if (!row || !row.data.used || row.data.replayed || Number(row.issuance_until)<=now || await this.subject(s,token,now)) return false;
      if (await this.subject(s,row.data,now)) return false;
      if ((['handle','kid','agentSub','keyEnrollment','agentVersion','accountVersion','clientId'] as const).some((field)=>row.data[field] !== token[field]) || !isDeepStrictEqual(row.data.scopes,token.scopes)) return false;
      const ttl = token.expiresAt - suppliedNow;
      if (!Number.isSafeInteger(ttl) || ttl <= 0) return false;
      const issued = { ...token,issuedAt:now,expiresAt:now+ttl };
      const result = await s.query(`INSERT INTO ${s.table('access_tokens')}(data) VALUES($1::jsonb) ON CONFLICT DO NOTHING`,[JSON.stringify(issued)]);
      const acceptedAt = await s.now();
      if (Number(row.issuance_until)<=acceptedAt || await this.subject(s,row.data,acceptedAt)) throw new WindowElapsed('expired');
      return result.rowCount === 1;
    }, async (s) => {
      const stored = await this.one<AccessToken>(s,'access_tokens','hash=$1 AND txn_id=$2',[token.hash,token.txnId]);
      if (!stored) return unknown;
      const code = await this.one<Code>(s,'codes','txn_id=$1',[token.txnId]);
      const now = await s.now();
      return {resolved:true,value:stored.expiresAt>now && !stored.revoked && !!code?.used && !code.replayed && stored.agentSub===token.agentSub && stored.keyEnrollment===token.keyEnrollment && !await this.subject(s,stored,now)};
    }).catch((error) => { if (error instanceof WindowElapsed) return false; throw error; });
  }
  deleteConsent(handle: string, clientId: string, auth: ManagementAuthorization) {
    return this.db.mutate('deleteConsent', async (s) => {
      if (!await this.authorized(s,handle,auth)) return false;
      await s.query(`DELETE FROM ${s.table('consents')} WHERE agent_sub=$1 AND client_id=$2`,[auth.agentSub,clientId]);
      return true;
    });
  }
  setAccountStatus(handle: string, clientId: string, status: 'enabled' | 'disabled', auth: ManagementAuthorization, _now: number) {
    return this.db.mutate('setAccountStatus', async (s) => {
      await this.quota(s,auth.ownerId,clientId);
      if (!await this.authorized(s,handle,auth)) return undefined;
      const account = await this.one<Account>(s,'accounts','agent_sub=$1 AND client_id=$2',[auth.agentSub,clientId]);
      if (!account) return undefined;
      account.status = status;
      if (status === 'disabled') account.authorizationVersion += 1;
      await s.query(`UPDATE ${s.table('accounts')} SET data=$3::jsonb WHERE agent_sub=$1 AND client_id=$2`,[auth.agentSub,clientId,JSON.stringify(account)]);
      if (status === 'disabled') await this.invalidate(s,{handle,clientId},'access_denied',await s.now());
      return account;
    });
  }
  deleteAccount(handle: string, clientId: string) {
    return this.db.mutate('deleteAccount', async (s) => {
      const a = await this.one<Agent>(s,'agents','handle=$1',[handle]);
      if (!a) return;
      await this.quota(s,a.ownerId,clientId);
      await s.query(`DELETE FROM ${s.table('accounts')} WHERE agent_sub=$1 AND client_id=$2`,[a.sub,clientId]);
    });
  }

  /** Bounded dependency-aware GC. No lifetime counts or revoked-key tombstones are removed. */
  cleanup(options: {batchSize?:number;retainFor?:number;consentMaxAge?:number} = {}) {
    const batch = options.batchSize ?? 100, retainFor = options.retainFor ?? 300, consentAge = options.consentMaxAge ?? 180*86400;
    for (const [name,n] of Object.entries({batchSize:batch,retainFor,consentMaxAge:consentAge})) if (!Number.isSafeInteger(n) || n<1 || (name==='batchSize' && n>10000)) throw new RangeError(`Invalid ${name}`);
    return this.db.mutate('cleanup', async (s) => {
      const start = await s.now();
      const candidates = await s.query<{txn_id:string;owner_id:string;client_id:string}>(
        `SELECT txn_id,owner_id,client_id FROM ${s.table('reservations')} WHERE expires_at<=$1 ORDER BY expires_at,txn_id LIMIT $2`,[start,batch]);
      const pairs = await s.query<{owner_id:string;client_id:string}>(`SELECT DISTINCT owner_id,client_id FROM ${s.table('reservations')} WHERE txn_id=ANY($1::text[]) ORDER BY owner_id,client_id`,[candidates.rows.map((r)=>r.txn_id)]);
      for (const p of pairs.rows) await this.quota(s,p.owner_id,p.client_id);
      const now = await s.now();
      const remove = async (table: 'access_tokens'|'codes'|'transactions'|'owner_codes'|'consents'|'reservations', key: string, where: string, values: unknown[]) => {
        const result = await s.query(`DELETE FROM ${s.table(table)} WHERE ${key} IN (SELECT ${key} FROM ${s.table(table)} WHERE ${where} LIMIT $${values.length+1})`,[...values,batch]);
        return result.rowCount ?? 0;
      };
      const tokens = await remove('access_tokens','hash','expires_at<=$1',[now]);
      const codes = await remove('codes','hash',`expires_at<=$1 AND (NOT used OR issuance_until<=$1) AND NOT EXISTS(SELECT 1 FROM ${s.table('access_tokens')} a WHERE a.txn_id=${s.table('codes')}.txn_id)`,[now]);
      const transactions = await remove('transactions','id',`COALESCE(terminal_at,LEAST(expires_at,(SELECT k.expires_at FROM ${s.table('keys')} k WHERE k.kid=${s.table('transactions')}.kid AND k.enrollment=${s.table('transactions')}.key_enrollment AND k.status<>'pending')))+$2<$1 AND NOT EXISTS(SELECT 1 FROM ${s.table('codes')} c WHERE c.txn_id=${s.table('transactions')}.id)`,[now,retainFor]);
      const reservations = (await s.query(`DELETE FROM ${s.table('reservations')} WHERE txn_id=ANY($1::text[]) AND expires_at<=$2`,[candidates.rows.map((r)=>r.txn_id),now])).rowCount ?? 0;
      const ownerCodes = await remove('owner_codes','owner_id','expires_at<=$1',[now]);
      // Row-value selection respects each immutable Agent/client pair.
      const consentResult = await s.query(`DELETE FROM ${s.table('consents')} WHERE (agent_sub,client_id) IN (SELECT agent_sub,client_id FROM ${s.table('consents')} WHERE last_used_at<$1 LIMIT $2)`,[now-consentAge,batch]);
      // Keep an expired enrollment until its transaction expiry evidence has been retired. No unbounded invalidation in GC.
      const keys = await s.query(`DELETE FROM ${s.table('keys')} WHERE enrollment IN (SELECT k.enrollment FROM ${s.table('keys')} k WHERE (k.expires_at<=$1 OR (k.status='pending' AND k.challenge_expires_at<$1)) AND NOT EXISTS(SELECT 1 FROM ${s.table('transactions')} t WHERE t.kid=k.kid AND t.key_enrollment=k.enrollment) LIMIT $2)`,[now,batch]);
      return {tokens,codes,transactions,reservations,ownerCodes,consents:consentResult.rowCount ?? 0,keys:keys.rowCount ?? 0};
    });
  }
}
