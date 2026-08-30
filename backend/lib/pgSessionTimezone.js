/**
 * Apply TimeZone to every currently pooled connection (best-effort).
 * New connections still need pool `options` or a subsequent restart for a hard guarantee.
 *
 * @param {import('pg').Pool} pool
 * @param {string} timeZone
 */
export async function applySessionTimezoneToPool(pool, timeZone) {
  const { assertValidIanaTimezone, setClientSessionTimezone } = await import('./systemTime.js');
  const tz = assertValidIanaTimezone(timeZone);
  const clients = [];
  const target = Math.max(pool.totalCount || 0, pool.idleCount || 0, 1);
  try {
    for (let i = 0; i < target; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      const client = await pool.connect();
      // eslint-disable-next-line no-await-in-loop
      await setClientSessionTimezone(client, tz);
      clients.push(client);
    }
  } finally {
    for (const client of clients) client.release();
  }
  return tz;
}
