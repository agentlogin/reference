/** The public origin and internal listening port are independent behind a TLS proxy. */
export function listenPort(baseUrl: URL, configured?: string): number {
  const value = configured ?? (baseUrl.port || '4000');
  if (!/^[1-9]\d{0,4}$/.test(value) || Number(value) > 65535) throw new Error('PORT must be an integer from 1 to 65535');
  return Number(value);
}

/** Share an in-flight check and briefly cache its result so a public probe cannot exhaust the pool. */
export function readinessCheck(probe: () => Promise<void>, now: () => number = Date.now): () => Promise<boolean> {
  let pending: Promise<boolean> | undefined;
  let checkedAt = -Infinity;
  let healthy = false;
  return () => {
    if (pending) return pending;
    if (now() - checkedAt < 2_000) return Promise.resolve(healthy);
    pending = Promise.resolve().then(probe).then(() => true, () => false).then((result) => {
      healthy = result;
      checkedAt = now();
      pending = undefined;
      return result;
    });
    return pending;
  };
}
