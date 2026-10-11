// How state changes without locks. The issuer holds none: several issuer processes may share one store, so every
// guarantee rests on store operations that are atomic with explicit preconditions (see store.ts). Two patterns
// build on them.
//
// 1. A transaction changes by compare-and-swap. A handler reads it, decides, and writes against the version it
//    read; if another request got there first, the write is refused and the handler reads and decides again.
//
// 2. Where an invariant spans two records (a transaction and the key that asserted it, a code and that key), the
//    change is written first and the other record is read again afterwards. Revocation writes the key first and then
//    ends what the key asserted. Whichever order two requests interleave in, one of them sees the other's write:
//    a revoked key never keeps a live transaction, code or token.
import type { IssuerContext } from './context.js';
import { TERMINAL, type DenyReason, type SubjectFilter, type Transaction } from './store.js';

/** The transaction as it stands now. Expiry is a function of time, not a stored status (Section 6.2). */
export function effective(ctx: IssuerContext, tx: Transaction): Transaction {
  if (!TERMINAL.has(tx.status) && ctx.now() >= tx.expiresAt) return { ...tx, status: 'expired', terminalAt: tx.expiresAt, challenge: undefined };
  return tx;
}

/** A copy of `tx` in a terminal status. */
export function ended(ctx: IssuerContext, tx: Transaction, status: 'completed' | 'denied', reason?: DenyReason): Transaction {
  return { ...tx, status, reason: reason ?? tx.reason, terminalAt: ctx.now(), challenge: undefined };
}

/** Writes `next` if the transaction is still at `expectedVersion`. On success `next.version` is the stored version. */
export async function commit(ctx: IssuerContext, next: Transaction, expectedVersion: number): Promise<boolean> {
  const ok = await ctx.store.updateTransaction(next, expectedVersion);
  if (ok) next.version = expectedVersion + 1;
  return ok;
}

/** Gives up the place a transaction holds under a per-owner cap, if any (Section 7.6). */
export async function releasePlace(ctx: IssuerContext, tx: Transaction): Promise<void> {
  if (tx.passedCap && tx.ownerId) await ctx.store.releaseSignup({ ownerId: tx.ownerId, clientId: tx.clientId, txnId: tx.id });
}

/**
 * Ends a transaction as `denied`, whatever else is happening to it: retried until it is terminal. Returns the
 * transaction as it ended, which may be an outcome another request reached first.
 */
export async function denyTransaction(ctx: IssuerContext, id: string, reason: DenyReason): Promise<Transaction | undefined> {
  for (;;) {
    const stored = await ctx.store.getTransaction(id);
    if (!stored) return undefined;
    const cur = effective(ctx, stored);
    if (TERMINAL.has(cur.status)) return cur;
    const next = ended(ctx, cur, 'denied', reason);
    if (await commit(ctx, next, stored.version)) {
      await releasePlace(ctx, next);
      return next;
    }
  }
}

/** Ends every open transaction that matches; `asserted` limits it to transactions past step 7 of Section 6.3. */
export async function denyOpenTransactions(ctx: IssuerContext, filter: SubjectFilter, reason: DenyReason, asserted = false): Promise<void> {
  for (const t of await ctx.store.listOpenTransactions(filter)) {
    if (!asserted || t.assertedAt !== undefined) await denyTransaction(ctx, t.id, reason);
  }
}

/** What a transaction, code or Access Token is bound to. */
export interface Subject { handle: string; kid: string; keyEnrollment: string; clientId: string }

/**
 * Whether the subject still stands (Sections 3.3, 7.4): the asserting key is the same enrollment, active and
 * unexpired; the Agent exists and is enabled; the Account is not disabled. Otherwise the reason it does not.
 */
export async function subjectState(ctx: IssuerContext, s: Subject): Promise<null | 'key_revoked' | 'access_denied'> {
  const key = await ctx.store.getKey(s.kid);
  if (!key || key.handle !== s.handle || key.enrollment !== s.keyEnrollment || key.status !== 'active' || ctx.now() >= key.expiresAt) return 'key_revoked';
  const agent = await ctx.store.getAgent(s.handle);
  if (!agent || !agent.enabled) return 'access_denied';
  const account = await ctx.store.getAccount(s.handle, s.clientId);
  if (account?.status === 'disabled') return 'access_denied';
  return null;
}
