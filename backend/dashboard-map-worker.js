import pg from 'pg';

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD || 'demo123',
  database: process.env.DB_NAME || 'demo'
});

const CHUNK_SIZE = Math.max(Number(process.env.DASHBOARD_MAP_CHUNK_SIZE || 1000), 100);
const LOOP_INTERVAL_MS = Math.max(Number(process.env.DASHBOARD_MAP_INTERVAL_MS || 5000), 1000);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function processFullRebuildChunk(client) {
  const stateRes = await client.query(`
    SELECT last_processed_ioc_id, full_rebuild_pending
    FROM dashboard_map_job_state
    WHERE singleton = TRUE
    FOR UPDATE
  `);

  const state = stateRes.rows[0];
  if (!state?.full_rebuild_pending) return false;

  const lastId = Number(state.last_processed_ioc_id || 0);
  if (lastId === 0) {
    await client.query('TRUNCATE TABLE dashboard_map_country_totals');
  }

  const chunkRes = await client.query(
    `SELECT id FROM ioc_items WHERE id > $1 ORDER BY id ASC LIMIT $2`,
    [lastId, CHUNK_SIZE]
  );

  if (!chunkRes.rows.length) {
    await client.query(`
      UPDATE dashboard_map_job_state
      SET full_rebuild_pending = FALSE,
          updated_at = NOW(),
          last_run_at = NOW()
      WHERE singleton = TRUE
    `);
    return false;
  }

  const nextLastId = Number(chunkRes.rows[chunkRes.rows.length - 1].id);

  await client.query(`
    WITH chunk AS (
      SELECT id, observable, observable_type
      FROM ioc_items
      WHERE id > $1
      ORDER BY id ASC
      LIMIT $2
    ), resolved AS (
      SELECT
        CASE
          WHEN c.observable_type = 'ip'
            AND split_part(c.observable, '/', 1) ~ '^[0-9]{1,3}(\\.[0-9]{1,3}){3}$'
          THEN split_part(c.observable, '/', 1)
          WHEN c.observable_type = 'url'
            AND c.observable ~* '^https?://[0-9]{1,3}(\\.[0-9]{1,3}){3}(:[0-9]+)?(/|$)'
          THEN substring(c.observable from '^https?://([0-9]{1,3}(?:\\.[0-9]{1,3}){3})')
          ELSE NULL
        END AS ip_text
      FROM chunk c
    ), with_num AS (
      SELECT
        r.ip_text,
        ((split_part(r.ip_text, '.', 1)::bigint << 24)
        + (split_part(r.ip_text, '.', 2)::bigint << 16)
        + (split_part(r.ip_text, '.', 3)::bigint << 8)
        +  split_part(r.ip_text, '.', 4)::bigint) AS ip_num
      FROM resolved r
      WHERE r.ip_text IS NOT NULL
        AND split_part(r.ip_text, '.', 1)::int BETWEEN 0 AND 255
        AND split_part(r.ip_text, '.', 2)::int BETWEEN 0 AND 255
        AND split_part(r.ip_text, '.', 3)::int BETWEEN 0 AND 255
        AND split_part(r.ip_text, '.', 4)::int BETWEEN 0 AND 255
    ), agg AS (
      SELECT
        COALESCE(cache.country_code, ranges.country_code, 'UN') AS country_code,
        COUNT(*)::bigint AS delta
      FROM with_num w
      LEFT JOIN ioc_ip_geo_cache cache ON cache.ip = w.ip_text::inet
      LEFT JOIN LATERAL (
        SELECT country_code
        FROM asn_ipv4_ranges r
        WHERE w.ip_num BETWEEN r.start_ip_num AND r.end_ip_num
        ORDER BY (r.end_ip_num - r.start_ip_num) ASC
        LIMIT 1
      ) ranges ON TRUE
      GROUP BY COALESCE(cache.country_code, ranges.country_code, 'UN')
    )
    INSERT INTO dashboard_map_country_totals (country_code, total, updated_at)
    SELECT country_code, delta, NOW()
    FROM agg
    ON CONFLICT (country_code)
    DO UPDATE SET total = dashboard_map_country_totals.total + EXCLUDED.total,
                  updated_at = NOW()
  `, [lastId, CHUNK_SIZE]);

  await client.query(`
    UPDATE dashboard_map_job_state
    SET last_processed_ioc_id = $1,
        updated_at = NOW(),
        last_run_at = NOW()
    WHERE singleton = TRUE
  `, [nextLastId]);

  return true;
}

async function processPendingEventChunk(client) {
  const pending = await client.query(
    `SELECT id, event_type, observable, observable_type
     FROM dashboard_map_pending_events
     ORDER BY id ASC
     LIMIT $1
     FOR UPDATE SKIP LOCKED`,
    [CHUNK_SIZE]
  );

  if (!pending.rows.length) return false;

  const ids = pending.rows.map((r) => Number(r.id));

  await client.query(`
    WITH picked AS (
      SELECT id, event_type, observable, observable_type
      FROM dashboard_map_pending_events
      WHERE id = ANY($1::bigint[])
    ), resolved AS (
      SELECT
        p.event_type,
        CASE
          WHEN p.observable_type = 'ip'
            AND split_part(p.observable, '/', 1) ~ '^[0-9]{1,3}(\\.[0-9]{1,3}){3}$'
          THEN split_part(p.observable, '/', 1)
          WHEN p.observable_type = 'url'
            AND p.observable ~* '^https?://[0-9]{1,3}(\\.[0-9]{1,3}){3}(:[0-9]+)?(/|$)'
          THEN substring(p.observable from '^https?://([0-9]{1,3}(?:\\.[0-9]{1,3}){3})')
          ELSE NULL
        END AS ip_text
      FROM picked p
    ), with_num AS (
      SELECT
        r.event_type,
        r.ip_text,
        ((split_part(r.ip_text, '.', 1)::bigint << 24)
        + (split_part(r.ip_text, '.', 2)::bigint << 16)
        + (split_part(r.ip_text, '.', 3)::bigint << 8)
        +  split_part(r.ip_text, '.', 4)::bigint) AS ip_num
      FROM resolved r
      WHERE r.ip_text IS NOT NULL
        AND split_part(r.ip_text, '.', 1)::int BETWEEN 0 AND 255
        AND split_part(r.ip_text, '.', 2)::int BETWEEN 0 AND 255
        AND split_part(r.ip_text, '.', 3)::int BETWEEN 0 AND 255
        AND split_part(r.ip_text, '.', 4)::int BETWEEN 0 AND 255
    ), agg AS (
      SELECT
        COALESCE(cache.country_code, ranges.country_code, 'UN') AS country_code,
        SUM(CASE WHEN w.event_type = 'add' THEN 1 ELSE -1 END)::bigint AS delta
      FROM with_num w
      LEFT JOIN ioc_ip_geo_cache cache ON cache.ip = w.ip_text::inet
      LEFT JOIN LATERAL (
        SELECT country_code
        FROM asn_ipv4_ranges r
        WHERE w.ip_num BETWEEN r.start_ip_num AND r.end_ip_num
        ORDER BY (r.end_ip_num - r.start_ip_num) ASC
        LIMIT 1
      ) ranges ON TRUE
      GROUP BY COALESCE(cache.country_code, ranges.country_code, 'UN')
      HAVING SUM(CASE WHEN w.event_type = 'add' THEN 1 ELSE -1 END) <> 0
    )
    INSERT INTO dashboard_map_country_totals (country_code, total, updated_at)
    SELECT country_code, delta, NOW()
    FROM agg
    ON CONFLICT (country_code)
    DO UPDATE SET total = GREATEST(0, dashboard_map_country_totals.total + EXCLUDED.total),
                  updated_at = NOW()
  `, [ids]);

  await client.query('DELETE FROM dashboard_map_pending_events WHERE id = ANY($1::bigint[])', [ids]);

  await client.query(`
    UPDATE dashboard_map_job_state
    SET updated_at = NOW(),
        last_run_at = NOW()
    WHERE singleton = TRUE
  `);

  return true;
}

async function tick() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const didRebuildWork = await processFullRebuildChunk(client);
    if (!didRebuildWork) {
      await processPendingEventChunk(client);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('[dashboard-map-worker] tick failed', err.message || err);
  } finally {
    client.release();
  }
}

async function main() {
  console.log(`[dashboard-map-worker] started (chunk=${CHUNK_SIZE}, intervalMs=${LOOP_INTERVAL_MS})`);
  // eslint-disable-next-line no-constant-condition
  while (true) {
    await tick();
    await sleep(LOOP_INTERVAL_MS);
  }
}

main().catch((err) => {
  console.error('[dashboard-map-worker] fatal', err);
  process.exit(1);
});
