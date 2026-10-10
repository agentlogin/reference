// Section 1.5 constants. Values in seconds unless stated.
export interface Constants {
  T_TXN: number;
  T_OWNER: number;
  T_CODE: number;
  T_TOKEN: number;
  T_ASSERT: number;
  T_SKEW: number;
  T_KEY: number;
  T_KEY_MAX: number;
  T_CONSENT: number;
  T_RETAIN: number;
  T_CACHE: number;
  N_ASSERTION: number; // octets
  N_CIMD: number; // octets
  N_FETCH_BYTES: number;
  N_FETCH_MS: number;
}

export const DEFAULT_CONSTANTS: Constants = {
  T_TXN: 300,
  T_OWNER: 86400,
  T_CODE: 60,
  T_TOKEN: 600,
  T_ASSERT: 300,
  T_SKEW: 60,
  T_KEY: 2592000,
  T_KEY_MAX: 31536000,
  T_CONSENT: 180 * 86400,
  T_RETAIN: 300,
  T_CACHE: 86400,
  N_ASSERTION: 2048,
  N_CIMD: 16 * 1024,
  N_FETCH_BYTES: 64 * 1024,
  N_FETCH_MS: 10_000,
};

export const SCOPES = ['openid', 'email', 'profile', 'owner_profile', 'owner_email'] as const;
export type Scope = (typeof SCOPES)[number];
export const OWNER_SCOPES: Scope[] = ['owner_profile', 'owner_email'];
export const AGENT_KEY_ALGS = ['ES256'] as const;
export const ASSERTION_TYP = 'agent-login+jwt';
export const ENROLLMENT_TYP = 'agent-login-enrollment+jwt';
export const VERSION = '1.0';

/** Section 6.1 `disclosure`: one entry per requested scope, fixed for the transaction's lifetime. */
export const DISCLOSURE: Record<Scope, { title: string; description: string }> = {
  openid: { title: 'Agent identifier', description: 'A stable identifier for this agent at this application.' },
  email: { title: 'Agent handle', description: "The agent's handle, verified by its issuer." },
  profile: { title: 'Agent profile', description: "The agent's display name and username, and an identifier for its owner." },
  owner_profile: { title: "Owner's name", description: "The name of the person or organisation accountable for the agent." },
  owner_email: { title: "Owner's email address", description: "The verified email address of the person or organisation accountable for the agent." },
};
