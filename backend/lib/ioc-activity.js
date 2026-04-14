const OPEN_STATUS = 'open';

function normalizeVerdict(v) {
  const s = String(v || '').trim().toLowerCase();
  if (s === 'fp') return 'FP';
  if (s === 'tp') return 'TP';
  if (s === 'suspicious') return 'Suspicious';
  if (s === 'in progress' || s === 'in_progress') return 'In Progress';
  return 'Unreviewed';
}

function verdictWeight(verdict) {
  const v = normalizeVerdict(verdict);
  if (v === 'FP') return 0;
  if (v === 'TP') return 1;
  if (v === 'Suspicious') return 0.7;
  return 0.5; // Unreviewed / In Progress
}

export function calculateIncidentRiskScore(totalHits, verdict, baseWeight = 1) {
  const hits = Math.max(Number(totalHits || 0), 0);
  const w = Math.max(Number(baseWeight || 0), 0) * verdictWeight(verdict);
  if (w === 0 || hits <= 0) return 0;
  return Math.log1p(hits) * w;
}

export async function findOrCreateActivity(client, {
  iocValue,
  iocType,
  eventTime,
  hitCount = 1,
  cache
}) {
  const value = String(iocValue || '').trim().toLowerCase();
  const type = String(iocType || '').trim().toLowerCase();
  if (!value || !type) return null;

  const eventTs = eventTime ? new Date(eventTime) : new Date();
  const eventMs = Number.isNaN(eventTs.getTime()) ? Date.now() : eventTs.getTime();
  const eventIso = new Date(eventMs).toISOString();
  const hitInc = Math.max(Number(hitCount || 0), 1);

  const cacheKey = `${type}\t${value}`;
  const cached = cache instanceof Map ? cache.get(cacheKey) : null;
  if (cached) {
    const upd = await client.query(
      `UPDATE ioc_activity
       SET total_hits = total_hits + $2,
           first_seen = LEAST(first_seen, $3::timestamptz),
           last_seen = GREATEST(last_seen, $3::timestamptz),
           updated_at = NOW()
       WHERE id = $1
         AND status = '${OPEN_STATUS}'
       RETURNING id, ioc_value, ioc_type, first_seen, last_seen, total_hits, status, verdict`,
      [cached.id, hitInc, eventIso]
    );
    const row = upd.rows?.[0] || null;
    if (row) {
      if (cache instanceof Map) cache.set(cacheKey, row);
      return row;
    }
    if (cache instanceof Map) cache.delete(cacheKey);
  }

  const q = await client.query(
    `SELECT id, ioc_value, ioc_type, first_seen, last_seen, total_hits, status, verdict
     FROM ioc_activity
     WHERE ioc_value = $1
       AND ioc_type = $2
       AND status = '${OPEN_STATUS}'
     ORDER BY last_seen DESC
     LIMIT 1`,
    [value, type]
  );

  const open = q.rows?.[0] || null;
  if (open) {
    const upd = await client.query(
      `UPDATE ioc_activity
       SET total_hits = total_hits + $2,
           first_seen = LEAST(first_seen, $3::timestamptz),
           last_seen = GREATEST(last_seen, $3::timestamptz),
           updated_at = NOW()
       WHERE id = $1
         AND status = '${OPEN_STATUS}'
       RETURNING id, ioc_value, ioc_type, first_seen, last_seen, total_hits, status, verdict`,
      [open.id, hitInc, eventIso]
    );
    const row = upd.rows?.[0] || null;
    if (row) {
      if (cache instanceof Map) cache.set(cacheKey, row);
      return row;
    }
  }

  const ins = await client.query(
    `INSERT INTO ioc_activity (
      ioc_value, ioc_type, first_seen, last_seen, total_hits, status, verdict
    ) VALUES ($1, $2, $3::timestamptz, $3::timestamptz, $4, '${OPEN_STATUS}', 'Unreviewed')
    ON CONFLICT (ioc_value, ioc_type) WHERE status = '${OPEN_STATUS}'
    DO UPDATE SET
      total_hits = ioc_activity.total_hits + EXCLUDED.total_hits,
      first_seen = LEAST(ioc_activity.first_seen, EXCLUDED.first_seen),
      last_seen = GREATEST(ioc_activity.last_seen, EXCLUDED.last_seen),
      updated_at = NOW()
    RETURNING id, ioc_value, ioc_type, first_seen, last_seen, total_hits, status, verdict`,
    [value, type, eventIso, hitInc]
  );

  const row = ins.rows?.[0] || null;
  if (row && cache instanceof Map) cache.set(cacheKey, row);
  return row;
}
