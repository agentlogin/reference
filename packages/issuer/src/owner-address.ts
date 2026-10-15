import { domainToASCII } from 'node:url';

/** Core 7.6: mailbox identity, not provider alias normalization. Quoted local-parts are parsed before comparison. */
export function ownerAddressKey(email: string): string {
  if (typeof email !== 'string' || email.length > 1024 || /[\u0000-\u001f\u007f]/u.test(email)) throw new TypeError('Invalid Owner email address');
  const at = email.lastIndexOf('@');
  if (at < 1) throw new TypeError('Invalid Owner email address');
  let local = email.slice(0, at);
  const domain = domainToASCII(email.slice(at + 1)).toLowerCase();
  if (!domain || domain.length > 253 || domain.endsWith('.') || !domain.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw new TypeError('Invalid Owner email domain');
  if (local.startsWith('"')) {
    if (!/^"(?:[^"\\\r\n]|\\[ -~])*"$/u.test(local)) throw new TypeError('Invalid quoted Owner local-part');
    local = local.slice(1, -1).replace(/\\([ -~])/g, '$1');
  } else if (!/^[^\s@"(),:;<>\[\]\\.]+(?:\.[^\s@"(),:;<>\[\]\\.]+)*$/u.test(local)) throw new TypeError('Invalid Owner local-part');
  if (!local || Buffer.byteLength(local) > 64) throw new TypeError('Invalid Owner local-part');
  return `${Buffer.from(local, 'utf8').toString('base64url')}@${domain}`;
}
