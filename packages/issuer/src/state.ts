// Transactions use a store compare-and-swap that commits their dependent effects atomically. Immutable Agent
// subjects, key enrollment IDs and monotonic Agent/Account disable versions keep delayed reads and writes from
// becoming valid again after a deletion, re-enrollment, or disable/re-enable cycle.
import type { IssuerContext } from './context.js';
import { isAssertionWindowError, TERMINAL, type DenyReason, type SubjectFilter, type Transaction, type TransitionEffects } from './store.js';
import { OAuthError } from './errors.js';

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
export async function commit(ctx: IssuerContext, next: Transaction, expectedVersion: number, effects: Omit<TransitionEffects, 'now'> = {}): Promise<boolean> {
  let updated;
  try {
    updated = await ctx.store.updateTransaction(next, expectedVersion, { ...effects, now: ctx.now() });
  } catch (error) {
    // An external adapter can load a separate copy of the issuer package (including source vs dist in tests).
    if (isAssertionWindowError(error)) {
      throw new OAuthError(400, 'invalid_assertion', 'assertion expired while awaiting acceptance');
    }
    throw error;
  }
  if (updated) Object.assign(next, updated);
  return updated !== undefined;
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
export interface Subject { handle: string; kid: string; keyEnrollment: string; clientId: string; agentSub: string; agentVersion: number; accountVersion: number }

/**
 * Whether the subject still stands (Sections 3.3, 7.4): the asserting key is the same enrollment, active and
 * unexpired; the Agent exists and is enabled; the Account is not disabled. Otherwise the reason it does not.
 */
export async function subjectState(ctx: IssuerContext, s: Subject): Promise<null | 'key_revoked' | 'access_denied'> {
  const key = await ctx.store.getKey(s.kid);
  if (!key || key.handle !== s.handle || key.enrollment !== s.keyEnrollment || key.agentSub !== s.agentSub || key.status !== 'active' || (await ctx.store.currentTime(ctx.now())) >= key.expiresAt) return 'key_revoked';
  const agent = await ctx.store.getAgent(s.handle);
  if (!agent || agent.sub !== s.agentSub || !agent.enabled || agent.authorizationVersion !== s.agentVersion) return 'access_denied';
  const account = await ctx.store.getAccount(s.handle, s.clientId);
  if (account?.status === 'disabled' || (account?.authorizationVersion ?? 0) !== s.accountVersion) return 'access_denied';
  return null;
}
