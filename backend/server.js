import express from 'express';
import cors from 'cors';
import pg from 'pg';
import IORedis from 'ioredis';
import { Queue } from 'bullmq';

const { Pool } = pg;

const app = express();
const port = process.env.PORT || 3000;
const demoEmail = process.env.DEMO_EMAIL || 'demo@demo.local';
const demoPassword = process.env.DEMO_PASSWORD || 'Password1!';

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD || 'demo123',
  database: process.env.DB_NAME || 'demo'
});

const redisUrl = process.env.REDIS_URL || 'redis://redis:6379';
const queueName = process.env.QUEUE_NAME || 'integration-imports';
const redis = new IORedis(redisUrl, { maxRetriesPerRequest: null });
const importQueue = new Queue(queueName, { connection: redis });

app.use(cors());
app.use(express.json());

let geoCacheRefreshInProgress = false;

async function refreshGeoCache(limit = 20000) {
  if (geoCacheRefreshInProgress) return;
  geoCacheRefreshInProgress = true;
  try {
    const q = `
      WITH missing AS (
        SELECT DISTINCT i.ip
        FROM ioc_ips i
        LEFT JOIN ioc_ip_geo_cache c ON c.ip = i.ip
        WHERE c.ip IS NULL
        LIMIT $1
      ), with_num AS (
        SELECT
          m.ip,
          ((split_part(host(m.ip::inet), '.', 1)::bigint << 24)
          + (split_part(host(m.ip::inet), '.', 2)::bigint << 16)
          + (split_part(host(m.ip::inet), '.', 3)::bigint << 8)
          +  split_part(host(m.ip::inet), '.', 4)::bigint) AS ip_num
        FROM missing m
      )
      INSERT INTO ioc_ip_geo_cache (ip, country_code, asn, as_name, updated_at)
      SELECT
        w.ip,
        COALESCE(NULLIF(UPPER(TRIM(a.country_code)), ''), 'UN') AS country_code,
        a.asn,
        a.as_name,
        NOW()
      FROM with_num w
      LEFT JOIN LATERAL (
        SELECT r.asn, r.country_code, r.as_name
        FROM asn_ipv4_ranges r
        WHERE w.ip_num BETWEEN r.start_ip_num AND r.end_ip_num
        ORDER BY (r.end_ip_num - r.start_ip_num) ASC
        LIMIT 1
      ) a ON TRUE
      ON CONFLICT (ip)
      DO UPDATE SET
        country_code = EXCLUDED.country_code,
        asn = EXCLUDED.asn,
        as_name = EXCLUDED.as_name,
        updated_at = NOW()
    `;
    await pool.query(q, [limit]);
  } finally {
    geoCacheRefreshInProgress = false;
  }
}

// schema migrations are handled by migrate.js

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'backend', db: 'up' });
  } catch {
    res.status(500).json({ ok: false, service: 'backend', db: 'down' });
  }
});

app.get('/api/integrations', async (_req, res) => {
  try {
    const q = `
      WITH latest AS (
        SELECT DISTINCT ON (job_type)
          job_type, status, started_at, finished_at, records_processed, error_message
        FROM integration_runs
        ORDER BY job_type, started_at DESC
      )
      SELECT
        f.key,
        f.name,
        f.source_url,
        f.schedule_cron AS schedule,
        f.trust_level,
        COALESCE(l.status, 'never') AS last_status,
        l.started_at AS last_started_at,
        l.finished_at AS last_finished_at,
        COALESCE(l.records_processed, 0) AS last_records_processed,
        l.error_message AS last_error
      FROM integration_feeds f
      LEFT JOIN latest l
        ON l.job_type = CASE
          WHEN f.key = 'et-blockrules' THEN 'hourly_import'
          WHEN f.key = 'usom-trcert' THEN 'usom_import'
          ELSE f.key
        END
      WHERE f.active = TRUE
      ORDER BY f.name ASC
    `;

    const recentQ = `
      SELECT
        r.id,
        r.job_type,
        r.status,
        r.started_at,
        r.finished_at,
        r.records_processed,
        COALESCE(f.key, CASE
          WHEN r.job_type = 'hourly_import' THEN 'et-blockrules'
          WHEN r.job_type = 'usom_import' THEN 'usom-trcert'
          ELSE r.job_type
        END) AS integration_key,
        COALESCE(f.name, CASE
          WHEN r.job_type = 'hourly_import' THEN 'EmergingThreats Blockrules'
          WHEN r.job_type = 'usom_import' THEN 'USOM TR-CERT'
          ELSE r.job_type
        END) AS integration_name
      FROM integration_runs r
      LEFT JOIN integration_feeds f
        ON f.key = CASE
          WHEN r.job_type = 'hourly_import' THEN 'et-blockrules'
          WHEN r.job_type = 'usom_import' THEN 'usom-trcert'
          ELSE r.job_type
        END
      ORDER BY r.started_at DESC
      LIMIT 20
    `;

    const [integrationsRes, recentRes] = await Promise.all([
      pool.query(q),
      pool.query(recentQ)
    ]);

    let queue = {
      counts: { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 },
      jobs: []
    };

    try {
      const [counts, jobs] = await Promise.all([
        importQueue.getJobCounts('waiting', 'active', 'delayed', 'failed', 'completed'),
        importQueue.getJobs(['waiting', 'active', 'delayed'], 0, 20, true)
      ]);

      queue = {
        counts,
        jobs: jobs.map((j) => ({
          id: j.id,
          name: j.name,
          state: j.finishedOn ? 'completed' : (j.processedOn ? 'active' : 'waiting'),
          timestamp: j.timestamp,
          data: j.data || {}
        }))
      };
    } catch {
      // queue telemetry optional
    }

    return res.json({
      integrations: integrationsRes.rows,
      recent_runs: recentRes.rows,
      queue
    });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch integrations', detail: err.message });
  }
});

const INTEGRATION_JOBS = {
  'et-blockrules': 'hourly-import',
  'usom-trcert': 'usom-import'
};

const TRUST_LEVELS = new Set(['guvenilir', 'orta', 'not_categorized']);

app.post('/api/integrations/run-now', async (_req, res) => {
  try {
    const keys = Object.keys(INTEGRATION_JOBS);
    const jobs = await Promise.all(keys.map((key) => importQueue.add(INTEGRATION_JOBS[key], { triggeredBy: 'manual-ui-all', integration_key: key })));
    return res.status(202).json({ ok: true, queued: true, count: jobs.length, job_ids: jobs.map((j) => j.id) });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to queue integrations', detail: err.message });
  }
});

app.post('/api/integrations/:key/run-now', async (req, res) => {
  const { key } = req.params;
  const jobName = INTEGRATION_JOBS[key];
  if (!jobName) {
    return res.status(404).json({ message: 'Integration not found' });
  }

  try {
    const job = await importQueue.add(jobName, { triggeredBy: 'manual-ui-one', integration_key: key });
    return res.status(202).json({ ok: true, queued: true, key, job_id: job.id });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to queue integration run', detail: err.message });
  }
});

app.put('/api/integrations/:key/trust-level', async (req, res) => {
  const { key } = req.params;
  const trustLevel = String(req.body?.trust_level || '').trim();

  if (!TRUST_LEVELS.has(trustLevel)) {
    return res.status(400).json({ message: 'Invalid trust_level' });
  }

  try {
    const result = await pool.query(
      `UPDATE integration_feeds
       SET trust_level = $2, updated_at = NOW()
       WHERE key = $1
       RETURNING key, trust_level`,
      [key, trustLevel]
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: 'Integration not found' });
    }

    return res.json(result.rows[0]);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to update trust level', detail: err.message });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};

  if (email === demoEmail && password === demoPassword) {
    return res.json({
      token: 'demo-token-123',
      user: { email }
    });
  }

  return res.status(401).json({ message: 'Invalid email or password' });
});

app.get('/api/users/me/preferences', async (req, res) => {
  const email = String(req.headers['x-user-email'] || '').trim();
  if (!email) {
    return res.status(400).json({ message: 'x-user-email header is required' });
  }

  try {
    const { rows } = await pool.query('SELECT email, timezone FROM user_preferences WHERE email = $1', [email]);
    if (!rows.length) {
      return res.json({ email, timezone: null });
    }
    return res.json(rows[0]);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch preferences', detail: err.message });
  }
});

app.put('/api/users/me/preferences', async (req, res) => {
  const email = String(req.headers['x-user-email'] || '').trim();
  const timezone = String(req.body?.timezone || '').trim();

  if (!email) {
    return res.status(400).json({ message: 'x-user-email header is required' });
  }
  if (!timezone) {
    return res.status(400).json({ message: 'timezone is required' });
  }

  try {
    const q = `
      INSERT INTO user_preferences (email, timezone, updated_at)
      VALUES ($1, $2, NOW())
      ON CONFLICT (email)
      DO UPDATE SET timezone = EXCLUDED.timezone, updated_at = NOW()
      RETURNING email, timezone
    `;
    const { rows } = await pool.query(q, [email, timezone]);
    return res.json(rows[0]);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to save preferences', detail: err.message });
  }
});

app.post('/api/ioc/ip', async (req, res) => {
  const { ip, source_name, source_url, confidence = 'medium', category = null, note = null } = req.body || {};

  if (!ip || !source_name) {
    return res.status(400).json({ message: 'ip and source_name are required' });
  }

  try {
    const q = `
      INSERT INTO ioc_ips (ip, source_name, source_url, confidence, category, note)
      SELECT $1, $2, $3, $4, $5, $6
      WHERE NOT EXISTS (
        SELECT 1
        FROM ioc_ips
        WHERE ip = $1::inet
          AND source_name = $2
          AND confidence = $4
          AND COALESCE(category, '') = COALESCE($5, '')
          AND COALESCE(source_url, '') = COALESCE($3, '')
      )
      RETURNING *
    `;
    const values = [ip, source_name, source_url || null, confidence, category, note];
    const { rows } = await pool.query(q, values);

    if (!rows.length) {
      return res.status(200).json({ skipped: true, reason: 'duplicate_tuple' });
    }

    refreshGeoCache(1000).catch(() => {});
    return res.status(201).json(rows[0]);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to create record', detail: err.message });
  }
});

app.get('/api/ioc/ip', async (req, res) => {
  const { source_name, confidence, q, asn, country, day = 'today', page = '1', page_size = '5' } = req.query;
  const allowedSizes = [5, 10, 25, 100];
  const size = Number(page_size);
  const currentPage = Math.max(Number(page) || 1, 1);
  const limit = allowedSizes.includes(size) ? size : 5;
  const offset = (currentPage - 1) * limit;

  const filters = [];
  const params = [];

  if (day === 'today') {
    filters.push(`i.created_at::date = CURRENT_DATE`);
  } else if (day === '24h') {
    filters.push(`i.created_at >= NOW() - INTERVAL '24 hours'`);
  } else if (day === '7d') {
    filters.push(`i.created_at >= NOW() - INTERVAL '7 days'`);
  }

  if (source_name) {
    params.push(`%${source_name}%`);
    filters.push(`i.source_name ILIKE $${params.length}`);
  }

  if (confidence) {
    params.push(confidence);
    filters.push(`i.confidence = $${params.length}`);
  }

  if (q) {
    if (String(q).includes('/')) {
      params.push(q);
      filters.push(`i.ip << $${params.length}::cidr`);
    } else {
      params.push(`%${q}%`);
      filters.push(`(CAST(i.ip AS TEXT) ILIKE $${params.length} OR i.source_name ILIKE $${params.length} OR COALESCE(i.category, '') ILIKE $${params.length})`);
    }
  }

  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';

  try {
    const groupedBase = `
      WITH filtered AS (
        SELECT i.*
        FROM ioc_ips i
        ${where}
      ), grouped AS (
        SELECT
          MAX(id) AS id,
          ip,
          MIN(created_at) AS first_seen_at,
          MAX(created_at) AS last_seen_at,
          COUNT(*)::int AS source_count,
          ARRAY_AGG(DISTINCT source_name ORDER BY source_name) AS source_names,
          ARRAY_AGG(DISTINCT confidence ORDER BY confidence) AS confidence_set,
          ARRAY_AGG(DISTINCT COALESCE(category, '') ORDER BY COALESCE(category, '')) FILTER (WHERE category IS NOT NULL AND category <> '') AS category_set
        FROM filtered
        GROUP BY ip
      )
    `;

    const asnValue = asn ? Number(asn) : null;
    const countryValue = country ? `%${country}%` : null;

    if (!asnValue && !countryValue) {
      const countQ = `
        ${groupedBase}
        SELECT COUNT(*)::int AS total
        FROM grouped
      `;
      const { rows: countRows } = await pool.query(countQ, params);
      const total = countRows[0]?.total || 0;

      const listQ = `
        ${groupedBase}, paged AS (
          SELECT *
          FROM grouped
          ORDER BY last_seen_at DESC
          LIMIT $${params.length + 1}
          OFFSET $${params.length + 2}
        )
        SELECT
          p.*,
          a.asn,
          a.country_code,
          a.as_name
        FROM paged p
        CROSS JOIN LATERAL (
          SELECT
            ((split_part(host(p.ip::inet), '.', 1)::bigint << 24)
            + (split_part(host(p.ip::inet), '.', 2)::bigint << 16)
            + (split_part(host(p.ip::inet), '.', 3)::bigint << 8)
            +  split_part(host(p.ip::inet), '.', 4)::bigint) AS ip_num
        ) ipn
        LEFT JOIN LATERAL (
          SELECT r.asn, r.country_code, r.as_name
          FROM asn_ipv4_ranges r
          WHERE ipn.ip_num BETWEEN r.start_ip_num AND r.end_ip_num
          ORDER BY (r.end_ip_num - r.start_ip_num) ASC
          LIMIT 1
        ) a ON TRUE
        ORDER BY p.last_seen_at DESC
      `;
      const { rows } = await pool.query(listQ, [...params, limit, offset]);

      return res.json({
        items: rows,
        pagination: {
          page: currentPage,
          page_size: limit,
          total,
          total_pages: Math.max(Math.ceil(total / limit), 1)
        }
      });
    }

    const listQWithGeo = `
      ${groupedBase}
      SELECT
        g.*,
        a.asn,
        a.country_code,
        a.as_name
      FROM grouped g
      CROSS JOIN LATERAL (
        SELECT
          ((split_part(host(g.ip::inet), '.', 1)::bigint << 24)
          + (split_part(host(g.ip::inet), '.', 2)::bigint << 16)
          + (split_part(host(g.ip::inet), '.', 3)::bigint << 8)
          +  split_part(host(g.ip::inet), '.', 4)::bigint) AS ip_num
      ) ipn
      LEFT JOIN LATERAL (
        SELECT r.asn, r.country_code, r.as_name
        FROM asn_ipv4_ranges r
        WHERE ipn.ip_num BETWEEN r.start_ip_num AND r.end_ip_num
        ORDER BY (r.end_ip_num - r.start_ip_num) ASC
        LIMIT 1
      ) a ON TRUE
      WHERE ($${params.length + 1}::int IS NULL OR a.asn = $${params.length + 1})
        AND ($${params.length + 2}::text IS NULL OR a.country_code ILIKE $${params.length + 2})
      ORDER BY g.last_seen_at DESC
      LIMIT $${params.length + 3}
      OFFSET $${params.length + 4}
    `;

    const countQWithGeo = `
      ${groupedBase}
      SELECT COUNT(*)::int AS total
      FROM grouped g
      CROSS JOIN LATERAL (
        SELECT
          ((split_part(host(g.ip::inet), '.', 1)::bigint << 24)
          + (split_part(host(g.ip::inet), '.', 2)::bigint << 16)
          + (split_part(host(g.ip::inet), '.', 3)::bigint << 8)
          +  split_part(host(g.ip::inet), '.', 4)::bigint) AS ip_num
      ) ipn
      LEFT JOIN LATERAL (
        SELECT r.asn, r.country_code, r.as_name
        FROM asn_ipv4_ranges r
        WHERE ipn.ip_num BETWEEN r.start_ip_num AND r.end_ip_num
        ORDER BY (r.end_ip_num - r.start_ip_num) ASC
        LIMIT 1
      ) a ON TRUE
      WHERE ($${params.length + 1}::int IS NULL OR a.asn = $${params.length + 1})
        AND ($${params.length + 2}::text IS NULL OR a.country_code ILIKE $${params.length + 2})
    `;

    const [listResult, countResult] = await Promise.all([
      pool.query(listQWithGeo, [...params, asnValue, countryValue, limit, offset]),
      pool.query(countQWithGeo, [...params, asnValue, countryValue])
    ]);

    const total = countResult.rows[0]?.total || 0;

    return res.json({
      items: listResult.rows,
      pagination: {
        page: currentPage,
        page_size: limit,
        total,
        total_pages: Math.max(Math.ceil(total / limit), 1)
      }
    });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch records', detail: err.message });
  }
});

app.get('/api/ioc/ip/sources', async (req, res) => {
  const { ip } = req.query;
  if (!ip) {
    return res.status(400).json({ message: 'ip is required' });
  }

  try {
    const detailsQ = `
      SELECT
        id,
        ip,
        source_name,
        source_url,
        confidence,
        category,
        note,
        created_at
      FROM ioc_ips
      WHERE ip = $1::inet
      ORDER BY created_at DESC
    `;
    const { rows } = await pool.query(detailsQ, [ip]);
    return res.json({ ip, sources: rows });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch source details', detail: err.message });
  }
});

app.get('/api/ioc/ip/recent-raw', async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit || 10), 1), 100);

  try {
    const q = `
      SELECT
        i.*,
        a.asn,
        a.country_code,
        a.as_name
      FROM ioc_ips i
      CROSS JOIN LATERAL (
        SELECT
          ((split_part(host(i.ip::inet), '.', 1)::bigint << 24)
          + (split_part(host(i.ip::inet), '.', 2)::bigint << 16)
          + (split_part(host(i.ip::inet), '.', 3)::bigint << 8)
          +  split_part(host(i.ip::inet), '.', 4)::bigint) AS ip_num
      ) ipn
      LEFT JOIN LATERAL (
        SELECT r.asn, r.country_code, r.as_name
        FROM asn_ipv4_ranges r
        WHERE ipn.ip_num BETWEEN r.start_ip_num AND r.end_ip_num
        ORDER BY (r.end_ip_num - r.start_ip_num) ASC
        LIMIT 1
      ) a ON TRUE
      ORDER BY i.created_at DESC
      LIMIT $1
    `;

    const { rows } = await pool.query(q, [limit]);
    return res.json({ items: rows });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch recent IOC records', detail: err.message });
  }
});

app.delete('/api/ioc/ip/:ip', async (req, res) => {
  const { ip } = req.params;
  if (!ip) {
    return res.status(400).json({ message: 'Invalid ip' });
  }

  try {
    const result = await pool.query('DELETE FROM ioc_ips WHERE ip = $1::inet RETURNING id', [ip]);
    if (!result.rowCount) {
      return res.status(404).json({ message: 'Record not found' });
    }
    return res.json({ deleted: result.rowCount, ip });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to delete record', detail: err.message });
  }
});

app.post('/api/ioc/ip/bulk-delete', async (req, res) => {
  const ips = Array.isArray(req.body?.ips) ? req.body.ips.map((x) => String(x).trim()).filter(Boolean) : [];
  if (!ips.length) {
    return res.status(400).json({ message: 'ips array is required' });
  }

  try {
    const result = await pool.query('DELETE FROM ioc_ips WHERE ip = ANY($1::inet[]) RETURNING ip', [ips]);
    const uniqueIps = Array.from(new Set(result.rows.map((r) => r.ip)));
    return res.json({ deleted: result.rowCount || 0, ips: uniqueIps });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to bulk delete records', detail: err.message });
  }
});

app.get('/api/ioc/map/countries', async (_req, res) => {
  try {
    refreshGeoCache(50000).catch(() => {});

    const q = `
      SELECT
        COALESCE(c.country_code, 'UN') AS country_code,
        COUNT(*)::int AS total
      FROM ioc_ips i
      LEFT JOIN ioc_ip_geo_cache c ON c.ip = i.ip
      GROUP BY COALESCE(c.country_code, 'UN')
      ORDER BY total DESC
    `;

    const totalsQ = `
      SELECT COUNT(*)::int AS total_records, COUNT(DISTINCT ip)::int AS unique_ips
      FROM ioc_ips
    `;

    const [{ rows: byCountry }, { rows: totals }] = await Promise.all([
      pool.query(q),
      pool.query(totalsQ)
    ]);

    return res.json({
      total: totals[0]?.total_records || 0,
      unique_ips: totals[0]?.unique_ips || 0,
      countries: byCountry
    });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch map data', detail: err.message });
  }
});

app.get('/api/ioc/summary/today', async (req, res) => {
  const { day = 'today' } = req.query;
  let timeFilter = `created_at::date = CURRENT_DATE`;

  if (day === '24h') {
    timeFilter = `created_at >= NOW() - INTERVAL '24 hours'`;
  } else if (day === '7d') {
    timeFilter = `created_at >= NOW() - INTERVAL '7 days'`;
  } else if (day === 'all') {
    timeFilter = `TRUE`;
  }

  try {
    const total = await pool.query(`SELECT COUNT(*)::int AS count FROM ioc_ips WHERE ${timeFilter}`);
    const uniqueIps = await pool.query(`SELECT COUNT(DISTINCT ip)::int AS count FROM ioc_ips WHERE ${timeFilter}`);
    const bySource = await pool.query(`
      SELECT source_name, COUNT(*)::int AS count
      FROM ioc_ips
      WHERE ${timeFilter}
      GROUP BY source_name
      ORDER BY count DESC
    `);
    const byConfidence = await pool.query(`
      SELECT confidence, COUNT(*)::int AS count
      FROM ioc_ips
      WHERE ${timeFilter}
      GROUP BY confidence
      ORDER BY count DESC
    `);

    res.json({
      total: total.rows[0].count,
      unique_ips: uniqueIps.rows[0].count,
      by_source: bySource.rows,
      by_confidence: byConfidence.rows
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch summary', detail: err.message });
  }
});

app.listen(port, () => {
  console.log(`Backend listening on :${port}`);
  refreshGeoCache(100000).catch(() => {});
  setInterval(() => {
    refreshGeoCache(20000).catch(() => {});
  }, 60_000);
});
