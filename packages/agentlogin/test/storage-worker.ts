// Run by storage.test.ts in several processes at once: each writes distinct keys and cookies.
import { join } from 'node:path';
import { FileCookieJar, FileKeystore, agentloginHome } from '../src/index.js';

const [id, count] = [process.argv[2]!, Number(process.argv[3])];
const keys = new FileKeystore(join(agentloginHome(), 'keys.json'));
const jar = FileCookieJar.forHandle('scout@example.com');
for (let i = 0; i < count; i += 1) {
  const kid = `p${id}-k${i}`;
  await keys.put({ kid, handle: 'scout@example.com', issuer: 'https://issuer.example', privateJwk: { kty: 'EC' }, publicJwk: { kty: 'EC' }, createdAt: 0, status: 'active' });
  await jar.store(new URL('https://app.example.org/'), [`c${id}x${i}=1; Path=/`]);
}
