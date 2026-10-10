/**
 * A sign-in that did not complete. `code` is stable and safe to branch on:
 *  - OAuth errors returned by the Issuer (Section 5.5): `access_denied`, `signup_limit_reached`, `consent_required`,
 *    `interaction_required`, `invalid_request`, `invalid_scope`, ...
 *  - local validation failures: `invalid_state`, `issuer_mismatch`, `issuer_not_accepted`, `invalid_id_token`,
 *    `handle_binding_failed`, `token_request_failed`, `revoked`, `invalid_handle`, `discovery_failed`.
 * `description` comes from the Issuer and MUST be escaped before it is rendered (Section 9 item 7).
 */
export class RelyingPartyError extends Error {
  constructor(public readonly code: string, message: string, public readonly description?: string) {
    super(message);
    this.name = 'RelyingPartyError';
  }
}
