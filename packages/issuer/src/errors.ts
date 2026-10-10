/** OAuth / transaction error (Sections 5.5, 6.7). `status` is the HTTP status. */
export class OAuthError extends Error {
  constructor(
    public readonly status: number,
    public readonly error: string,
    public readonly description?: string,
    public readonly headers: Record<string, string> = {},
  ) {
    super(description ? `${error}: ${description}` : error);
  }
}
export const invalidRequest = (d?: string) => new OAuthError(400, 'invalid_request', d);
export const invalidToken = (d?: string) =>
  new OAuthError(401, 'invalid_token', d, { 'WWW-Authenticate': 'Bearer error="invalid_token"' });
