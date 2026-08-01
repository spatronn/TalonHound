import '../lib/ensure-db-password.js';
import pg from 'pg';
import crypto from 'crypto';

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

const WINDOW_MS = Math.max(Number(process.env.IOC_ACTIVITY_SLIDING_WINDOW_MS || 60 * 60 * 1000), 60_000);
const IOC_BATCH = Math.max(Number(process.env.IOC_ACTIVITY_BACKFILL_IOC_BATCH || 100), 1);

function toIso(v) {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function eventTs(row) {
  return toIso(row.bucket_start) || toIso(row.first_seen_at) || toIso(row.event_time) || toIso(row.created_at) || new Date(0).toISOString();
}

function makeDeterministicUuid(seed) {
  const hex = crypto.createHash('sha1').update(seed).digest('hex').slice(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-5${hex.slice(13, 16)}-${((parseInt(hex.slice(16, 18), 16) & 0x3f) | 0x80).toString(16).padStart(2, '0')}${hex.slice(18, 20)}-${hex.slice(20, 32)}`;
}

function clusterRows(rows) {
  const clusters = [];
  let current = null;

  for (const row of rows) {
    const tsIso = eventTs(row);
    const tsMs = new Date(tsIso).getTime();
    const hit = Math.max(Number(row.hit_count || 1), 1);

    if (!current) {
      current = {
        firstSeen: tsIso,
        lastSeen: tsIso,
        totalHits: hit,
        rows: [row]
      };
      continue;
    }

    const prevMs = new Date(current.lastSeen).getTime();
    if ((tsMs - prevMs) <= WINDOW_MS) {
      current.lastSeen = tsIso;
      current.totalHits += hit;
      current.rows.push(row);
    } else {
      clusters.push(current);
      current = {
        firstSeen: tsIso,
        lastSeen: tsIso,
        totalHits: hit,
        rows: [row]
      };
    }
  }

  if (current) clusters.push(current);
  return clusters;
}

async function processIocKey(client, matchedIoc, iocType) {
  await client.query('BEGIN');
  try {
    const rowsQ = await client.query(
      `SELECT id, matched_ioc, ioc_type, hit_count, bucket_start, first_seen_at, event_time, created_at
       FROM ioc_match_events
       WHERE activity_id IS NULL
         AND matched_ioc = $1
         AND ioc_type = $2
       ORDER BY COALESCE(bucket_start, first_seen_at, event_time, created_at) ASC, id ASC
       FOR UPDATE`,
      [matchedIoc, iocType]
    );

    const rows = rowsQ.rows || [];
    if (!rows.length) {
      await client.query('COMMIT');
      return { eventsLinked: 0, activitiesUpserted: 0, iocTouched: false };
    }

    const clusters = clusterRows(rows);
    const eventIds = [];
    const activityIds = [];

    // close previous open for this IOC to keep one-open-per-IOC invariant.
    await client.query(
      `UPDATE ioc_activity
       SET status = 'closed', updated_at = NOW()
       WHERE ioc_value = $1
         AND ioc_type = $2
         AND status = 'open'`,
      [matchedIoc, iocType]
    );

    for (let i = 0; i < clusters.length; i += 1) {
      const c = clusters[i];
      const isLast = i === clusters.length - 1;
      const status = isLast ? 'open' : 'closed';
      const activityId = makeDeterministicUuid(`${iocType}|${matchedIoc}|${c.firstSeen}`);

      await client.query(
        `INSERT INTO ioc_activity (
          id, ioc_value, ioc_type, first_seen, last_seen, total_hits, status, verdict, created_at, updated_at
        ) VALUES ($1::uuid, $2, $3, $4::timestamptz, $5::timestamptz, $6, $7, 'Unreviewed', NOW(), NOW())
        ON CONFLICT (id)
        DO UPDATE SET
          ioc_value = EXCLUDED.ioc_value,
          ioc_type = EXCLUDED.ioc_type,
          first_seen = LEAST(ioc_activity.first_seen, EXCLUDED.first_seen),
          last_seen = GREATEST(ioc_activity.last_seen, EXCLUDED.last_seen),
          total_hits = GREATEST(ioc_activity.total_hits, EXCLUDED.total_hits),
          status = EXCLUDED.status,
          updated_at = NOW()`,
        [activityId, matchedIoc, iocType, c.firstSeen, c.lastSeen, c.totalHits, status]
      );

      for (const r of c.rows) {
        eventIds.push(Number(r.id));
        activityIds.push(activityId);
      }
    }

    if (eventIds.length) {
      await client.query(
        `UPDATE ioc_match_events m
         SET activity_id = v.activity_id::uuid
         FROM (
           SELECT unnest($1::bigint[]) AS id, unnest($2::text[]) AS activity_id
         ) v
         WHERE m.id = v.id
           AND m.activity_id IS NULL`,
        [eventIds, activityIds]
      );
    }

    await client.query('COMMIT');
    return { eventsLinked: eventIds.length, activitiesUpserted: clusters.length, iocTouched: true };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  }
}

async function finalizeTouchedIocs(client, touchedPairs) {
  if (!touchedPairs.length) return;

  const iocValues = touchedPairs.map((x) => x.ioc_value);
  const iocTypes = touchedPairs.map((x) => x.ioc_type);

  await client.query(
    `UPDATE ioc_activity a
     SET
       first_seen = agg.first_seen,
       last_seen = agg.last_seen,
       total_hits = agg.total_hits,
       updated_at = NOW()
     FROM (
       SELECT
         m.activity_id,
         MIN(COALESCE(m.bucket_start, m.first_seen_at, m.event_time, m.created_at)) AS first_seen,
         MAX(COALESCE(m.last_seen_at, m.bucket_start, m.first_seen_at, m.event_time, m.created_at)) AS last_seen,
         COALESCE(SUM(COALESCE(m.hit_count, 1)), 0)::bigint AS total_hits
       FROM ioc_match_events m
       WHERE m.activity_id IS NOT NULL
       GROUP BY m.activity_id
     ) agg
     WHERE a.id = agg.activity_id
       AND (a.ioc_value, a.ioc_type) IN (
         SELECT x.ioc_value, x.ioc_type
         FROM unnest($1::text[], $2::text[]) AS x(ioc_value, ioc_type)
       )`,
    [iocValues, iocTypes]
  );

  await client.query(
    `WITH ranked AS (
       SELECT
         a.id,
         a.ioc_value,
         a.ioc_type,
         ROW_NUMBER() OVER (PARTITION BY a.ioc_value, a.ioc_type ORDER BY a.last_seen DESC, a.id DESC) AS rn
       FROM ioc_activity a
       WHERE (a.ioc_value, a.ioc_type) IN (
         SELECT x.ioc_value, x.ioc_type
         FROM unnest($1::text[], $2::text[]) AS x(ioc_value, ioc_type)
       )
     )
     UPDATE ioc_activity a
     SET status = CASE WHEN r.rn = 1 THEN 'open' ELSE 'closed' END,
         updated_at = NOW()
     FROM ranked r
     WHERE a.id = r.id`,
    [iocValues, iocTypes]
  );
}

async function main() {
  console.log(`[backfill-ioc-activities] start window_ms=${WINDOW_MS} ioc_batch=${IOC_BATCH}`);

  let totalLinked = 0;
  let totalActivities = 0;
  let loops = 0;
  const touchedSet = new Set();

  while (true) {
    loops += 1;
    const listClient = await pool.connect();
    let keys;
    try {
      const q = await listClient.query(
        `SELECT matched_ioc, ioc_type, MIN(COALESCE(bucket_start, first_seen_at, event_time, created_at)) AS min_ts
         FROM ioc_match_events
         WHERE activity_id IS NULL
           AND matched_ioc IS NOT NULL
           AND matched_ioc <> ''
           AND ioc_type IS NOT NULL
           AND ioc_type <> ''
         GROUP BY matched_ioc, ioc_type
         ORDER BY min_ts ASC
         LIMIT $1`,
        [IOC_BATCH]
      );
      keys = q.rows || [];
    } finally {
      listClient.release();
    }

    if (!keys.length) break;

    for (const k of keys) {
      const client = await pool.connect();
      try {
        const out = await processIocKey(client, k.matched_ioc, k.ioc_type);
        totalLinked += out.eventsLinked;
        totalActivities += out.activitiesUpserted;
        if (out.iocTouched) touchedSet.add(`${k.matched_ioc}\t${k.ioc_type}`);
      } finally {
        client.release();
      }
    }

    console.log(`[backfill-ioc-activities] loop=${loops} processed_iocs=${keys.length} linked_events=${totalLinked} upserted_activities=${totalActivities}`);
  }

  const touchedPairs = Array.from(touchedSet).map((v) => {
    const [ioc_value, ioc_type] = v.split('\t');
    return { ioc_value, ioc_type };
  });

  if (touchedPairs.length) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await finalizeTouchedIocs(client, touchedPairs);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  const verifyClient = await pool.connect();
  try {
    const verify = await verifyClient.query(
      `SELECT
         (SELECT COUNT(*)::bigint FROM ioc_match_events WHERE activity_id IS NOT NULL) AS linked_events,
         (SELECT COUNT(*)::bigint FROM ioc_match_events WHERE activity_id IS NULL) AS orphan_events,
         (SELECT COUNT(*)::bigint FROM ioc_activity) AS total_activities`
    );
    const v = verify.rows?.[0] || {};
    console.log(`[backfill-ioc-activities] done linked_events=${Number(v.linked_events || 0)} orphan_events=${Number(v.orphan_events || 0)} total_activities=${Number(v.total_activities || 0)}`);
  } finally {
    verifyClient.release();
  }

  await pool.end();
}

main().catch(async (err) => {
  console.error('[backfill-ioc-activities] fatal', err?.message || err);
  await pool.end().catch(() => {});
  process.exit(1);
});
