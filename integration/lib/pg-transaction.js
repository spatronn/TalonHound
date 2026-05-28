const LOG_PREFIX = '[integration-worker]';
const SLOW_TX_WARN_MS = 30000;

function formatMeta(meta = {}) {
  const parts = [];
  if (meta.label) parts.push(`label=${meta.label}`);
  if (meta.job_id) parts.push(`job_id=${meta.job_id}`);
  if (meta.source_key) parts.push(`source_key=${meta.source_key}`);
  if (meta.file) parts.push(`file=${meta.file}`);
  if (meta.batch != null) parts.push(`batch=${meta.batch}`);
  return parts.length ? ` ${parts.join(' ')}` : '';
}

async function rollbackQuietly(client, meta, startedAt) {
  try {
    await client.query('ROLLBACK');
    const durationMs = Date.now() - startedAt;
    console.log(`${LOG_PREFIX} transaction rollback duration_ms=${durationMs}${formatMeta(meta)}`);
  } catch (err) {
    console.error(
      `${LOG_PREFIX} transaction rollback failed type=${err?.name || 'Error'} message=${err?.message || err}${formatMeta(meta)}`
    );
  }
}

function isPgPool(poolOrClient) {
  return typeof poolOrClient?.connect === 'function' && typeof poolOrClient?.release !== 'function';
}

/**
 * Runs fn inside BEGIN/COMMIT with guaranteed ROLLBACK + release on error.
 * Pass an existing pool client to reuse a session (e.g. advisory lock holder).
 */
export async function withPgTransaction(poolOrClient, labelOrFn, maybeFn, meta = {}) {
  let label = 'transaction';
  let fn = labelOrFn;
  let clientMeta = meta;

  if (typeof labelOrFn === 'function') {
    fn = labelOrFn;
  } else {
    label = String(labelOrFn || 'transaction');
    fn = maybeFn;
    clientMeta = typeof maybeFn === 'object' && maybeFn !== null && !Array.isArray(maybeFn) ? maybeFn : meta;
  }

  if (typeof fn !== 'function') {
    throw new TypeError('withPgTransaction requires an async callback');
  }

  const ownsClient = isPgPool(poolOrClient);
  const client = ownsClient ? await poolOrClient.connect() : poolOrClient;
  const txMeta = { label, ...clientMeta };
  const startedAt = Date.now();

  console.log(`${LOG_PREFIX} transaction start${formatMeta(txMeta)}`);

  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    const durationMs = Date.now() - startedAt;
    const level = durationMs > SLOW_TX_WARN_MS ? 'warn' : 'log';
    const line = `${LOG_PREFIX} transaction commit duration_ms=${durationMs}${formatMeta(txMeta)}`;
    if (level === 'warn') console.warn(line);
    else console.log(line);
    return result;
  } catch (err) {
    await rollbackQuietly(client, txMeta, startedAt);
    console.error(
      `${LOG_PREFIX} transaction error type=${err?.name || 'Error'} message=${err?.message || err}${formatMeta(txMeta)}`
    );
    throw err;
  } finally {
    if (ownsClient) client.release();
  }
}
