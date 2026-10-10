/** OAuth error codes an Issuer may return on the redirect (Section 5.5). Anything else is reported as `issuer_error`. */
export const ISSUER_ERROR_CODES = [
  'access_denied', 'signup_limit_reached', 'consent_required', 'interaction_required', 'invalid_request', 'invalid_scope',
  'unauthorized_client', 'unsupported_response_type', 'server_error', 'temporarily_unavailable', 'request_not_supported',
  'request_uri_not_supported',
] as const;
/** Codes the kit itself produces. */
export const LOCAL_ERROR_CODES = [
  'invalid_state', 'issuer_mismatch', 'issuer_not_accepted', 'issuer_error', 'invalid_id_token', 'handle_binding_failed',
  'token_request_failed', 'discovery_failed', 'userinfo_failed', 'revoked', 'reauthentication_required', 'invalid_handle',
  'handle_required', 'configuration_error', 'duplicate_callback',
] as const;
export type RelyingPartyErrorCode = (typeof ISSUER_ERROR_CODES)[number] | (typeof LOCAL_ERROR_CODES)[number];

/**
 * A sign-in that did not complete. `code` is one of a fixed set and safe to branch on and to show. `message` is
 * written by the kit and contains no text from the Issuer. `description` is the Issuer's `error_description`: it is
 * untrusted text and MUST be escaped before it is rendered (Section 9 item 7).
 */
export class RelyingPartyError extends Error {
  constructor(public readonly code: RelyingPartyErrorCode, message: string, public readonly description?: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'RelyingPartyError';
  }
  /** HTTP status a handler should answer with: 502 for upstream failures, 500 for configuration, 400 otherwise. */
  get status(): number {
    if (this.code === 'discovery_failed' || this.code === 'token_request_failed' || this.code === 'userinfo_failed') return 502;
    if (this.code === 'configuration_error') return 500;
    return 400;
  }
}
