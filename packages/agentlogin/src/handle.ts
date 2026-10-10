// Section 2.1 handle syntax (same rules as the issuer).
export interface Handle { handle: string; local: string; domain: string }
const ATEXT = /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+(\.[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+)*$/;
const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
export function parseHandle(input: string): Handle | null {
  if (typeof input !== 'string' || input.length > 254) return null;
  const at = input.lastIndexOf('@');
  if (at <= 0 || at === input.length - 1) return null;
  const local = input.slice(0, at);
  const domain = input.slice(at + 1).toLowerCase();
  if (Buffer.byteLength(local) > 64 || !ATEXT.test(local) || domain.length > 253) return null;
  const labels = domain.split('.');
  if (labels.length < 2 || !labels.every((l) => LABEL.test(l))) return null;
  return { handle: `${local}@${domain}`, local, domain };
}
export function domainServed(domain: string, handleDomains: string[]): boolean {
  return handleDomains.some((d) => (d.startsWith('*.') ? domain.endsWith(d.slice(1)) && domain.length > d.length - 1 : d === domain));
}
