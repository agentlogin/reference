import type { JWK } from 'jose';
import { loadSigningKey, type createIssuer } from './index.js';

type Issuer = Awaited<ReturnType<typeof createIssuer>>;
export interface SigningConfiguration {
  keys: JWK[];
  activateKid?: string;
  retireKids?: string[];
  compromisedKids?: string[];
}
/** Strict, secret-safe validation before any durable mutation. Files should be replaced atomically, never edited in place. */
export async function validateSigningConfiguration(value: unknown): Promise<SigningConfiguration> {
  if (!value || typeof value!=='object' || Array.isArray(value)) throw new TypeError('Signing configuration must be an object');
  const input=value as Record<string,unknown>;
  if (Object.keys(input).some((k)=>!['keys','activateKid','retireKids','compromisedKids'].includes(k)) || !Array.isArray(input.keys) || input.keys.length===0) throw new TypeError('Invalid signing configuration');
  const keys=await Promise.all(input.keys.map((key)=>loadSigningKey(key as JWK)));
  if (new Set(keys.map((k)=>k.kid)).size!==keys.length) throw new TypeError('Duplicate signing key');
  for (const list of ['retireKids','compromisedKids'] as const) if (input[list]!==undefined && (!Array.isArray(input[list]) || !(input[list] as unknown[]).every((kid)=>typeof kid==='string' && kid.length>0))) throw new TypeError('Invalid signing removal list');
  const retiring=new Set([...(input.retireKids as string[]??[]),...(input.compromisedKids as string[]??[])]);
  if (keys.some((key)=>retiring.has(key.kid))) throw new TypeError('Removed keys must be absent from the configured private key ring');
  if (input.activateKid!==undefined && (typeof input.activateKid!=='string' || !keys.some((key)=>key.kid===input.activateKid))) throw new TypeError('Activation requires provisioned private key material');
  return structuredClone(value) as SigningConfiguration;
}
/** Publication precedes activation. Failed activation leaves the key staged and the previous active key unchanged. */
export async function reloadSigningConfiguration(issuer: Issuer, value: unknown): Promise<void> {
  const config=await validateSigningConfiguration(value);
  await issuer.publishSigningKeys(config.keys);
  // Emergency withdrawal always precedes activation; no availability fallback may restore a compromised key.
  for (const kid of config.compromisedKids??[]) await issuer.removeSigningKey(kid,true);
  if (config.activateKid && !await issuer.activateSigningKey(config.activateKid)) throw new Error('Key must be published before activation; wait for publication to precede activation on the issuer clock');
  for (const kid of config.retireKids??[]) if (!await issuer.removeSigningKey(kid)) throw new Error('Signing key overlap has not elapsed or the key is still active');
}
