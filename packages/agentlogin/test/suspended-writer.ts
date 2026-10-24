// Stop at exactly the old guard/rename race window. The parent ages the lock and starts a competing writer.
import { writeFileSync } from 'node:fs';
import { readPrivateJson, withFileLock, writePrivateJson } from '../src/files.js';
import type { StoredKey } from '../src/keystore.js';
const [file, marker] = process.argv.slice(2) as [string, string];
await withFileLock(file, (guard) => {
  const keys = readPrivateJson<StoredKey[]>(file, []);
  keys.push({ ...keys[0]!, kid: 'first' });
  writePrivateJson(file, keys, () => {
    guard();
    writeFileSync(marker, 'checked');
    process.kill(process.pid, 'SIGSTOP');
  });
});
