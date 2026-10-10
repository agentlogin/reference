// Standalone server. Configuration by environment:
//   ISSUER           Issuer Identifier (default http://localhost:3000 in development)
//   HANDLE_DOMAINS   comma-separated handle domains (default: host of ISSUER)
//   PORT             listen port (default 3000)
//   ADMIN_TOKEN      bootstrap/registration token (generated and printed when absent)
//   SIGNING_JWK      private ES256 JWK as JSON (ephemeral when absent)
//   INSECURE_DEV=1   permit http issuer and loopback clients; print Owner sign-in codes instead of mailing them
import { serve } from '@hono/node-server';
import { createIssuer } from './index.js';

const insecure = process.env.INSECURE_DEV === '1' || !process.env.ISSUER;
const issuer = process.env.ISSUER ?? 'http://localhost:3000';
const port = Number(process.env.PORT ?? new URL(issuer).port ?? 3000) || 3000;
const handleDomains = (process.env.HANDLE_DOMAINS ?? new URL(issuer).hostname).split(',').map((s) => s.trim()).filter(Boolean);
const adminToken = process.env.ADMIN_TOKEN;

const { app, ctx } = await createIssuer({
  issuer,
  handleDomains,
  allowInsecureClients: insecure,
  adminToken,
  signingJwk: process.env.SIGNING_JWK ? JSON.parse(process.env.SIGNING_JWK) : undefined,
  // Development only: the one-time code of the Owner email sign-in is printed instead of mailed. A deployment passes a mailer.
  sendOwnerCode: insecure ? ({ email, code }) => console.log(`INSECURE_DEV: one-time code for ${email}: ${code}`) : undefined,
});
serve({ fetch: app.fetch, port }, () => {
  console.log(`Agent Login issuer ${issuer} listening on :${port}; handle domains ${handleDomains.join(', ')}`);
  if (!adminToken) console.log(`ADMIN_TOKEN (generated): ${ctx.adminToken}`);
  if (insecure) console.log('INSECURE_DEV: http and loopback clients are permitted');
});
