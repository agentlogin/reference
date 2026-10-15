import { createHash, createHmac, createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { AgentIdentity, LiveCheck } from '@agentlogin/rp';

export interface NewSession { agent: AgentIdentity; expiresAt: number; live?: LiveCheck }
export interface Session extends NewSession { firstSeen: string }
export interface Note { id: string; text: string; createdAt: number }
export interface NoteCursor { id: string; createdAt: number }
export class NoteError extends Error {
  constructor(readonly code: 'session_expired' | 'reauthentication_required' | 'idempotency_conflict' | 'note_limit') { super(code); }
}
export function validateNote(id: string, text: string): void {
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(id) || typeof text !== 'string' || !text.trim() || Buffer.byteLength(text, 'utf8') > 4096 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(text)) throw new TypeError('invalid note');
}

/** Application data, separate from the RP callback claim. Times are Unix seconds. No read renews a deadline. */
export interface SessionStore {
  /** Insert a fresh random session, preserve the account's firstSeen, and revoke the old cookie atomically. */
  create(sid: string, session: NewSession, previousSid?: string): Promise<Session>;
  /** Expiry and revocation are authoritative; expired live-check credentials must not be returned. */
  get(sid: string): Promise<Session | undefined>;
  /** Return only after durable invalidation. A storage failure must not be reported as successful logout. */
  revoke(sid: string): Promise<void>;
  /** Session authorization and note insertion share one transaction. Reuse id only with identical text. */
  saveNote(sid: string, id: string, text: string): Promise<Note>;
  /** Return the newest 100 notes belonging to this authenticated account. */
  listNotes(sid: string, before?: NoteCursor): Promise<Note[] | undefined>;
  /** A bounded batch of expired sessions and/or expired live-check credentials. */
  cleanup(limit?: number): Promise<number>;
  close(): Promise<void>;
}

export const validSid = (sid: unknown): sid is string => typeof sid === 'string' && /^[A-Za-z0-9_-]{43}$/.test(sid);
export function cleanupLimit(limit: number): number {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) throw new TypeError('cleanup limit must be an integer from 1 to 10000');
  return limit;
}
export function validateSession(sid: string, session: NewSession): void {
  if (!validSid(sid) || !Number.isSafeInteger(session.expiresAt) || session.expiresAt <= 0 ||
      !session.agent || typeof session.agent.iss !== 'string' || !session.agent.iss ||
      typeof session.agent.sub !== 'string' || !session.agent.sub || !Array.isArray(session.agent.scopes) ||
      session.agent.key !== `${session.agent.iss} ${session.agent.sub}`) throw new TypeError('invalid application session');
  if (session.live && (session.live.issuer !== session.agent.iss || session.live.sub !== session.agent.sub ||
      !Number.isSafeInteger(session.live.accessTokenExpiresAt) || !session.live.accessToken ||
      typeof session.live.accessToken !== 'string')) throw new TypeError('invalid application live check');
}

/** Purpose-separated keys; rotating the secret invalidates lookup of every previously issued session. */
export class SessionProtection {
  private readonly lookupKey: Buffer;
  private readonly encryptionKey: Buffer;
  constructor(secret: string, readonly namespace: string) {
    if (typeof secret !== 'string' || secret.length < 32) throw new TypeError('sessionSecret must be at least 32 characters');
    if (typeof namespace !== 'string' || !namespace || namespace.length > 2048) throw new TypeError('session namespace is required and must be at most 2048 characters');
    this.lookupKey = createHash('sha256').update(`agentlogin-example-session-lookup-v1|${secret}`).digest();
    this.encryptionKey = createHash('sha256').update(`agentlogin-example-session-encryption-v1|${secret}`).digest();
  }
  key(sid: string): string { return createHmac('sha256', this.lookupKey).update(JSON.stringify([this.namespace, sid])).digest('hex'); }
  accountKey(agent: AgentIdentity): string {
    return createHash('sha256').update(JSON.stringify([this.namespace, agent.iss, agent.sub])).digest('hex');
  }
  private aad(key: string, expiresAt: number): Buffer { return Buffer.from(JSON.stringify(['live-v1', this.namespace, key, expiresAt])); }
  encrypt(key: string, live: LiveCheck): Buffer {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    cipher.setAAD(this.aad(key, live.accessTokenExpiresAt));
    const body = Buffer.concat([cipher.update(JSON.stringify(live), 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), body]);
  }
  decrypt(key: string, expiresAt: number, encrypted: Buffer): LiveCheck {
    if (encrypted.length < 29) throw new Error('invalid stored live check');
    const decipher = createDecipheriv('aes-256-gcm', this.encryptionKey, encrypted.subarray(0, 12));
    decipher.setAuthTag(encrypted.subarray(12, 28));
    decipher.setAAD(this.aad(key, expiresAt));
    const value = JSON.parse(Buffer.concat([decipher.update(encrypted.subarray(28)), decipher.final()]).toString('utf8')) as LiveCheck;
    if (!value || typeof value.issuer !== 'string' || typeof value.sub !== 'string' || typeof value.accessToken !== 'string' || !value.accessToken || value.accessTokenExpiresAt !== expiresAt) throw new Error('invalid stored live check');
    return value;
  }
}

/** Loopback development and tests only. Production replicas use PostgresSessionStore. */
export class MemorySessionStore implements SessionStore {
  private readonly sessions = new Map<string, Session>();
  private readonly accounts = new Map<string, string>();
  private readonly notes = new Map<string, Map<string, Note>>();
  constructor(private readonly now: () => number = () => Math.floor(Date.now() / 1000)) {}
  async create(sid: string, value: NewSession, previousSid?: string): Promise<Session> {
    validateSession(sid, value);
    const now = this.now();
    if (value.expiresAt <= now || this.sessions.has(sid) || previousSid === sid) throw new Error('application session cannot be created');
    const firstSeen = this.accounts.get(value.agent.key) ?? new Date(now * 1000).toISOString();
    const session = structuredClone({ ...value, firstSeen });
    if (session.live && session.live.accessTokenExpiresAt <= now) session.live = undefined;
    this.accounts.set(value.agent.key, firstSeen);
    if (previousSid) this.sessions.delete(previousSid);
    this.sessions.set(sid, session);
    return structuredClone(session);
  }
  async get(sid: string): Promise<Session | undefined> {
    const session = this.sessions.get(sid);
    if (!session) return undefined;
    const now = this.now();
    if (session.expiresAt <= now) { this.sessions.delete(sid); return undefined; }
    if (session.live && session.live.accessTokenExpiresAt <= now) session.live = undefined;
    return structuredClone(session);
  }
  async revoke(sid: string): Promise<void> { this.sessions.delete(sid); }
  async saveNote(sid: string, id: string, text: string): Promise<Note> {
    validateNote(id, text);
    // No await separates authorization from insertion in the in-memory implementation.
    const s = this.sessions.get(sid), now = this.now();
    if (!s || s.expiresAt <= now) throw new NoteError('session_expired');
    if (!s.live || s.live.accessTokenExpiresAt <= now) throw new NoteError('reauthentication_required');
    const notes = this.notes.get(s.agent.key) ?? new Map<string, Note>();
    const previous = notes.get(id);
    if (previous) {
      if (previous.text !== text) throw new NoteError('idempotency_conflict');
      return structuredClone(previous);
    }
    if (notes.size >= 1000) throw new NoteError('note_limit');
    const note = { id, text, createdAt: now };
    notes.set(id, note); this.notes.set(s.agent.key, notes);
    return structuredClone(note);
  }
  async listNotes(sid: string, before?: NoteCursor): Promise<Note[] | undefined> {
    const s = this.sessions.get(sid);
    if (!s || s.expiresAt <= this.now()) return undefined;
    return structuredClone([...(this.notes.get(s.agent.key)?.values() ?? [])]
      .filter((note) => !before || note.createdAt < before.createdAt || (note.createdAt === before.createdAt && note.id > before.id))
      .sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)).slice(0, 100));
  }
  async cleanup(limit = 1000): Promise<number> {
    cleanupLimit(limit);
    const now = this.now();
    let changed = 0;
    for (const [sid, session] of this.sessions) {
      if (changed === limit) break;
      if (session.expiresAt <= now) { this.sessions.delete(sid); changed++; }
      else if (session.live && session.live.accessTokenExpiresAt <= now) { session.live = undefined; changed++; }
    }
    return changed;
  }
  async close(): Promise<void> { this.sessions.clear(); this.accounts.clear(); this.notes.clear(); }
}
