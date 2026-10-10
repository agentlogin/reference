// Agent Key storage (Section 7.1). The private key never leaves the keystore except to sign; it is never logged.
import { homedir } from 'node:os';
import { join } from 'node:path';
import { readPrivateJson, writePrivateJson } from './files.js';
import type { JWK } from 'jose';

export interface StoredKey {
  kid: string;
  handle: string;
  issuer: string;
  privateJwk: JWK;
  publicJwk: JWK;
  name?: string;
  createdAt: number;
  /** Expiry the Issuer recorded for the key (Section 7.1), seconds since the epoch. */
  expiresAt?: number;
  status: 'pending' | 'active' | 'revoked';
}
export interface Keystore {
  list(handle?: string): Promise<StoredKey[]>;
  get(kid: string): Promise<StoredKey | undefined>;
  put(key: StoredKey): Promise<void>;
  remove(kid: string): Promise<void>;
}

export const agentloginHome = (): string => process.env.AGENTLOGIN_HOME ?? join(homedir(), '.agentlogin');

export class MemoryKeystore implements Keystore {
  private keys = new Map<string, StoredKey>();
  async list(handle?: string) { return [...this.keys.values()].filter((k) => !handle || k.handle === handle); }
  async get(kid: string) { return this.keys.get(kid); }
  async put(key: StoredKey) { this.keys.set(key.kid, key); }
  async remove(kid: string) { this.keys.delete(kid); }
}

/** JSON file with mode 0600 in a 0700 directory. */
export class FileKeystore implements Keystore {
  constructor(public readonly path: string = join(agentloginHome(), 'keys.json')) {}
  private read(): StoredKey[] { return readPrivateJson<StoredKey[]>(this.path, []); }
  private write(keys: StoredKey[]) { writePrivateJson(this.path, keys); }
  async list(handle?: string) { return this.read().filter((k) => !handle || k.handle === handle); }
  async get(kid: string) { return this.read().find((k) => k.kid === kid); }
  async put(key: StoredKey) { this.write([...this.read().filter((k) => k.kid !== key.kid), key]); }
  async remove(kid: string) { this.write(this.read().filter((k) => k.kid !== kid)); }
}
