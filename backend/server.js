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
const signalQueueName = process.env.SIGNAL_QUEUE_NAME || 'signal-events';
const redis = new IORedis(redisUrl, { maxRetriesPerRequest: null });
const importQueue = new Queue(queueName, { connection: redis });
const signalQueue = new Queue(signalQueueName, { connection: redis });

app.use(cors());
app.use(express.json());

let geoCacheRefreshInProgress = false;

async function refreshGeoCache(limit = 20000) {
  if (geoCacheRefreshInProgress) return;
  geoCacheRefreshInProgress = true;
  try {
    const q = `
      WITH missing AS (
        SELECT DISTINCT
          CASE
            WHEN i.observable_type = 'ip'
              AND i.observable ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/\d{1,2})?$'
            THEN i.observable::inet
            ELSE NULL
          END AS ip
        FROM ioc_items i
        LEFT JOIN ioc_ip_geo_cache c
          ON c.ip = CASE
            WHEN i.observable_type = 'ip'
              AND i.observable ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/\d{1,2})?$'
            THEN i.observable::inet
            ELSE NULL
          END
        WHERE i.observable_type = 'ip' AND c.ip IS NULL
        LIMIT $1
      ), with_num AS (
        SELECT
          m.ip,
          ((split_part(host(m.ip::inet), '.', 1)::bigint << 24)
          + (split_part(host(m.ip::inet), '.', 2)::bigint << 16)
          + (split_part(host(m.ip::inet), '.', 3)::bigint << 8)
          +  split_part(host(m.ip::inet), '.', 4)::bigint) AS ip_num
        FROM missing m
        WHERE m.ip IS NOT NULL
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

app.post('/api/sysmon/events', async (req, res) => {
  try {
    const events = Array.isArray(req.body?.events) ? req.body.events : [];
    if (!events.length) {
      return res.status(400).json({ ok: false, message: 'events array is required' });
    }

    const normalized = events.map((evt) => ({
      source_key: 'sysmon.windows',
      event_time: evt.event_time || evt.timeCreated || new Date().toISOString(),
      host_name: evt.host_name || evt.computer || null,
      username: evt.username || evt.user || null,
      process_name: evt.process_name || evt.image || null,
      process_id: evt.process_id || evt.processId || null,
      destination_ip: evt.destination_ip || evt.destinationIp || null,
      destination_port: evt.destination_port || evt.destinationPort || null,
      protocol: evt.protocol || null,
      raw: evt
    }));

    const job = await signalQueue.add('sysmon-network-events', { events: normalized }, {
      removeOnComplete: 50,
      removeOnFail: 100
    });

    return res.json({ ok: true, queued: normalized.length, jobId: job.id });
  } catch (err) {
    console.error('[sysmon-events] queue failed', err);
    return res.status(500).json({ ok: false, message: 'failed to enqueue events' });
  }
});

app.get('/api/analytics/data-sources', async (_req, res) => {
  try {
    const q = await pool.query(
      `SELECT key, name, platform, status, last_seen_at
       FROM signal_sources
       ORDER BY key ASC`
    );
    return res.json({
      total: q.rowCount,
      sources: q.rows
    });
  } catch (err) {
    console.error('[analytics-data-sources] failed', err);
    return res.status(500).json({ total: 0, sources: [] });
  }
});

app.get('/api/analytics/raw-events', async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query?.limit || 10), 1), 100);
    const q = await pool.query(
      `SELECT id, source_key, event_time, host_name, process_name, destination_ip, destination_port, protocol, created_at, raw
       FROM signal_events
       ORDER BY created_at DESC
       LIMIT $1`,
      [limit]
    );

    return res.json({ total: q.rowCount, items: q.rows });
  } catch (err) {
    console.error('[analytics-raw-events] failed', err);
    return res.status(500).json({ total: 0, items: [] });
  }
});

app.get('/api/analytics/ioc-matches', async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query?.limit || 10), 1), 100);
    const hours = Math.min(Math.max(Number(req.query?.hours || 24), 1), 168);

    const q = await pool.query(
      `WITH recent_events AS (
         SELECT id, event_time, host_name, process_name, destination_ip, destination_port, protocol, created_at
         FROM signal_events
         WHERE created_at >= NOW() - ($2::text || ' hours')::interval
           AND destination_ip IS NOT NULL
         ORDER BY created_at DESC
         LIMIT 5000
       )
       SELECT
         se.id,
         se.event_time,
         se.host_name,
         se.process_name,
         se.destination_ip,
         se.destination_port,
         se.protocol,
         i.observable AS matched_ioc,
         i.source_name,
         i.confidence,
         se.created_at
       FROM recent_events se
       JOIN ioc_items i
         ON i.observable_type = 'ip'
        AND i.observable = se.destination_ip
       ORDER BY se.created_at DESC
       LIMIT $1`,
      [limit, hours]
    );

    return res.json({ total: q.rowCount, items: q.rows });
  } catch (err) {
    console.error('[analytics-ioc-matches] failed', err);
    return res.status(500).json({ total: 0, items: [] });
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
        f.integration_id,
        f.name,
        f.source_url,
        f.schedule_cron AS schedule,
        f.trust_level,
        f.created_at,
        COALESCE(l.status, 'never') AS last_status,
        l.started_at AS last_started_at,
        l.finished_at AS last_finished_at,
        COALESCE(l.records_processed, 0) AS last_records_processed,
        CASE
          WHEN f.key = 'et-blockrules' THEN (
            SELECT COUNT(*)::int FROM ioc_items i WHERE i.source_name LIKE 'EmergingThreats:%'
          )
          WHEN f.key = 'usom-trcert' THEN (
            SELECT COUNT(*)::int FROM ioc_items o WHERE o.source_name = 'USOM:TR-CERT'
          )
          WHEN f.key = 'urlhaus-abusech' THEN (
            SELECT COUNT(*)::int FROM ioc_items o WHERE o.source_name = 'URLhaus:abuse.ch'
          )
          ELSE 0
        END AS total_records,
        l.error_message AS last_error
      FROM integration_feeds f
      LEFT JOIN latest l
        ON l.job_type = CASE
          WHEN f.key = 'et-blockrules' THEN 'hourly_import'
          WHEN f.key = 'usom-trcert' THEN 'usom_import'
          WHEN f.key = 'urlhaus-abusech' THEN 'urlhaus_import'
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
          WHEN r.job_type = 'urlhaus_import' THEN 'urlhaus-abusech'
          ELSE r.job_type
        END) AS integration_key,
        COALESCE(f.name, CASE
          WHEN r.job_type = 'hourly_import' THEN 'EmergingThreats Blockrules'
          WHEN r.job_type = 'usom_import' THEN 'USOM TR-CERT'
          WHEN r.job_type = 'urlhaus_import' THEN 'URLhaus abuse.ch'
          ELSE r.job_type
        END) AS integration_name
      FROM integration_runs r
      LEFT JOIN integration_feeds f
        ON f.key = CASE
          WHEN r.job_type = 'hourly_import' THEN 'et-blockrules'
          WHEN r.job_type = 'usom_import' THEN 'usom-trcert'
          WHEN r.job_type = 'urlhaus_import' THEN 'urlhaus-abusech'
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
      const [countRows, jobsRows] = await Promise.all([
        pool.query(`
          SELECT status, COUNT(*)::int AS cnt
          FROM integration_queue_jobs
          WHERE queued_at >= NOW() - INTERVAL '14 days'
          GROUP BY status
        `),
        pool.query(`
          SELECT
            q.job_id AS id,
            q.integration_key,
            COALESCE(f.name, q.integration_key) AS integration_name,
            f.integration_id,
            q.job_name AS name,
            q.status AS state,
            q.queued_at AS timestamp,
            q.error_message AS failed_reason
          FROM integration_queue_jobs q
          LEFT JOIN integration_feeds f ON f.key = q.integration_key
          ORDER BY q.queued_at DESC
          LIMIT 30
        `)
      ]);

      const mapped = { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 };
      for (const r of countRows.rows) {
        if (r.status === 'queued') mapped.waiting += r.cnt;
        else if (r.status === 'running') mapped.active += r.cnt;
        else if (r.status === 'failed') mapped.failed += r.cnt;
        else if (r.status === 'success') mapped.completed += r.cnt;
      }

      queue = {
        counts: mapped,
        jobs: jobsRows.rows
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
  'usom-trcert': 'usom-import',
  'urlhaus-abusech': 'urlhaus-import'
};

const TRUST_LEVELS = new Set(['guvenilir', 'orta', 'not_categorized']);

app.post('/api/integrations/run-now', async (_req, res) => {
  try {
    const keys = Object.keys(INTEGRATION_JOBS);
    const jobs = await Promise.all(keys.map((key) => importQueue.add(INTEGRATION_JOBS[key], { triggeredBy: 'manual-ui-all', integration_key: key })));

    await Promise.all(jobs.map((j, idx) => pool.query(
      `INSERT INTO integration_queue_jobs (job_id, integration_key, job_name, status, triggered_by, queued_at, updated_at)
       VALUES ($1, $2, $3, 'queued', 'manual-ui-all', NOW(), NOW())
       ON CONFLICT (job_id)
       DO UPDATE SET status='queued', updated_at=NOW()`,
      [String(j.id), keys[idx], INTEGRATION_JOBS[keys[idx]]]
    )));

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
    await pool.query(
      `INSERT INTO integration_queue_jobs (job_id, integration_key, job_name, status, triggered_by, queued_at, updated_at)
       VALUES ($1, $2, $3, 'queued', 'manual-ui-one', NOW(), NOW())
       ON CONFLICT (job_id)
       DO UPDATE SET status='queued', updated_at=NOW()`,
      [String(job.id), key, jobName]
    );
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

  const value = String(ip).trim();
  const isUrl = /^https?:\/\//i.test(value);
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(value);
  const inferredType = (isUrl || value.includes('/')) ? 'url' : (isIpv4 ? 'ip' : 'domain');

  try {
    if (inferredType !== 'ip') {
      const qObs = `
        INSERT INTO ioc_items (observable, observable_type, source_name, source_url, confidence, category, note)
        SELECT $1, $2, $3, $4, $5, $6, $7
        WHERE NOT EXISTS (
          SELECT 1
          FROM ioc_items
          WHERE observable = $1
            AND observable_type = $2
            AND source_name = $3
            AND confidence = $5
            AND COALESCE(category, '') = COALESCE($6, '')
            AND COALESCE(source_url, '') = COALESCE($4, '')
        )
        RETURNING *
      `;
      const { rows } = await pool.query(qObs, [value, inferredType, source_name, source_url || null, confidence, category, note]);
      if (!rows.length) return res.status(200).json({ skipped: true, reason: 'duplicate_tuple' });
      return res.status(201).json(rows[0]);
    }

    const q = `
      INSERT INTO ioc_items (observable, observable_type, source_name, source_url, confidence, category, note)
      SELECT $1, 'ip', $2, $3, $4, $5, $6
      WHERE NOT EXISTS (
        SELECT 1
        FROM ioc_items
        WHERE observable = $1
          AND observable_type = 'ip'
          AND source_name = $2
          AND confidence = $4
          AND COALESCE(category, '') = COALESCE($5, '')
          AND COALESCE(source_url, '') = COALESCE($3, '')
      )
      RETURNING *
    `;
    const values = [value, source_name, source_url || null, confidence, category, note];
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

app.get('/api/ioc/list', async (req, res) => {
  const { source_name, confidence, q, asn, country, page = '1', page_size = '5' } = req.query;
  const allowedSizes = [5, 10, 25, 100];
  const size = Number(page_size);
  const currentPage = Math.max(Number(page) || 1, 1);
  const limit = allowedSizes.includes(size) ? size : 5;
  const offset = (currentPage - 1) * limit;

  const filters = [];
  const params = [];

  if (source_name) {
    params.push(`%${source_name}%`);
    filters.push(`source_name ILIKE $${params.length}`);
  }

  if (confidence) {
    params.push(confidence);
    filters.push(`confidence = $${params.length}`);
  }

  if (q) {
    const qv = String(q).trim();
    if (qv.length < 3) {
      return res.json({
        items: [],
        pagination: { page: currentPage, page_size: limit, total: 0, total_pages: 1 },
        note: 'Search term must be at least 3 characters'
      });
    }
    params.push(`%${qv}%`);
    filters.push(`(observable ILIKE $${params.length} OR source_name ILIKE $${params.length} OR COALESCE(category, '') ILIKE $${params.length})`);
  }

  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
  const fullScan = Boolean(source_name || confidence || q || asn || country);

  try {
    const sourceSql = fullScan
      ? `SELECT observable, observable_type, source_name, confidence, category, created_at FROM ioc_items`
      : `SELECT observable, observable_type, source_name, confidence, category, created_at
         FROM ioc_items
         ORDER BY created_at DESC
         LIMIT 2000`;

    const base = `
      WITH combined AS (
        ${sourceSql}
      ), filtered AS (
        SELECT * FROM combined
        ${where}
      ), grouped AS (
        SELECT
          observable,
          observable_type,
          MIN(created_at) AS first_seen_at,
          MAX(created_at) AS last_seen_at,
          COUNT(*)::int AS source_count,
          ARRAY_AGG(DISTINCT source_name ORDER BY source_name) AS source_names,
          ARRAY_AGG(DISTINCT confidence ORDER BY confidence) AS confidence_set,
          ARRAY_AGG(DISTINCT COALESCE(category, '') ORDER BY COALESCE(category, '')) FILTER (WHERE category IS NOT NULL AND category <> '') AS category_set
        FROM filtered
        GROUP BY observable, observable_type
      )
    `;

    const asnValue = asn ? Number(asn) : null;
    const countryValue = country ? `%${country}%` : null;

    const countQ = `
      ${base}
      SELECT COUNT(*)::int AS total
      FROM grouped g
      LEFT JOIN ioc_ip_geo_cache c ON c.ip = CASE WHEN g.observable_type = 'ip' THEN g.observable::inet ELSE NULL END
      WHERE ($${params.length + 1}::int IS NULL OR c.asn = $${params.length + 1})
        AND ($${params.length + 2}::text IS NULL OR c.country_code ILIKE $${params.length + 2})
    `;

    const listQ = `
      ${base}
      SELECT
        g.*,
        g.observable AS ip,
        c.asn,
        c.country_code,
        c.as_name
      FROM grouped g
      LEFT JOIN ioc_ip_geo_cache c ON c.ip = CASE WHEN g.observable_type = 'ip' THEN g.observable::inet ELSE NULL END
      WHERE ($${params.length + 1}::int IS NULL OR c.asn = $${params.length + 1})
        AND ($${params.length + 2}::text IS NULL OR c.country_code ILIKE $${params.length + 2})
      ORDER BY g.last_seen_at DESC
      LIMIT $${params.length + 3}
      OFFSET $${params.length + 4}
    `;

    const [countRes, listRes] = await Promise.all([
      pool.query(countQ, [...params, asnValue, countryValue]),
      pool.query(listQ, [...params, asnValue, countryValue, limit, offset])
    ]);

    const total = countRes.rows[0]?.total || 0;

    return res.json({
      items: listRes.rows,
      pagination: {
        page: currentPage,
        page_size: limit,
        total,
        total_pages: Math.max(Math.ceil(total / limit), 1)
      }
    });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch IOC list', detail: err.message });
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
        observable AS ip,
        source_name,
        source_url,
        confidence,
        category,
        note,
        created_at
      FROM ioc_items
      WHERE observable_type='ip' AND observable = $1
      ORDER BY created_at DESC
    `;
    const { rows } = await pool.query(detailsQ, [ip]);
    return res.json({ ip, sources: rows });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch source details', detail: err.message });
  }
});

app.get('/api/ioc/recent', async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit || 10), 1), 100);

  try {
    const q = `
      SELECT
        i.id,
        i.observable,
        i.observable_type,
        i.source_name,
        i.confidence,
        i.category,
        i.created_at,
        c.asn,
        c.country_code,
        c.as_name
      FROM ioc_items i
      LEFT JOIN ioc_ip_geo_cache c ON c.ip = CASE WHEN i.observable_type = 'ip' THEN i.observable::inet ELSE NULL END
      ORDER BY i.created_at DESC
      LIMIT ($1)
    `;

    const { rows } = await pool.query(q, [limit]);
    return res.json({ items: rows });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch recent IOC records', detail: err.message });
  }
});

app.get('/api/ioc/map/countries', async (_req, res) => {
  try {
    refreshGeoCache(50000).catch(() => {});

    const q = `
      SELECT
        COALESCE(c.country_code, 'UN') AS country_code,
        COUNT(*)::int AS total
      FROM ioc_items i
      LEFT JOIN ioc_ip_geo_cache c
        ON c.ip = CASE
          WHEN i.observable_type = 'ip'
            AND i.observable ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/\d{1,2})?$'
          THEN i.observable::inet
          ELSE NULL
        END
      WHERE i.observable_type = 'ip'
      GROUP BY COALESCE(c.country_code, 'UN')
      ORDER BY total DESC
    `;

    const totalsQ = `
      SELECT COUNT(*)::int AS total_records,
             (COUNT(DISTINCT observable) FILTER (WHERE observable_type = 'ip'))::int AS unique_ips
      FROM ioc_items
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
  let timeFilter = `TRUE`;

  try {
    const base = `
      WITH filtered AS (
        SELECT observable, observable_type, source_name, confidence, created_at
        FROM ioc_items
        WHERE ${timeFilter}
      )
    `;

    const totalQ = `${base} SELECT COUNT(*)::int AS count FROM filtered`;
    const uniqueIpsQ = `${base} SELECT COUNT(DISTINCT observable)::int AS count FROM filtered WHERE observable_type = 'ip'`;
    const bySourceQ = `${base}
      SELECT source_name, COUNT(*)::int AS count
      FROM filtered
      GROUP BY source_name
      ORDER BY count DESC`;
    const byConfidenceQ = `${base}
      SELECT confidence, COUNT(*)::int AS count
      FROM filtered
      GROUP BY confidence
      ORDER BY count DESC`;
    const byTypeQ = `${base}
      SELECT observable_type, COUNT(*)::int AS count
      FROM filtered
      GROUP BY observable_type
      ORDER BY count DESC`;

    const [total, uniqueIps, bySource, byConfidence, byType] = await Promise.all([
      pool.query(totalQ),
      pool.query(uniqueIpsQ),
      pool.query(bySourceQ),
      pool.query(byConfidenceQ),
      pool.query(byTypeQ)
    ]);

    res.json({
      total: total.rows[0].count,
      unique_ips: uniqueIps.rows[0].count,
      by_source: bySource.rows,
      by_confidence: byConfidence.rows,
      by_type: byType.rows
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
