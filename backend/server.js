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

// Geo cache refresh tuning (local/kısıtlı ortam için düşürülebilir)
const GEO_CACHE_REFRESH_LIMIT = Math.max(Number(process.env.GEO_CACHE_REFRESH_LIMIT || 20000), 100);
const GEO_CACHE_REFRESH_INTERVAL_MS = Math.max(Number(process.env.GEO_CACHE_REFRESH_INTERVAL_MS || 60_000), 10_000);
const GEO_CACHE_ON_ADD_LIMIT = Math.max(Number(process.env.GEO_CACHE_ON_ADD_LIMIT || 500), 50);
const GEO_CACHE_DEBOUNCE_MS = Math.max(Number(process.env.GEO_CACHE_DEBOUNCE_MS || 2000), 500);

app.use(cors());
app.use(express.json());

let geoCacheRefreshInProgress = false;
let geoCacheDebounceTimer = null;

function isValidIpv4(input) {
  const parts = String(input || '').split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

function extractIpv4ForGeo(observable, observableType) {
  const raw = String(observable || '').trim();
  const type = String(observableType || '').toLowerCase();
  if (!raw) return null;

  if (type === 'ip') {
    const ip = raw.split('/')[0].trim();
    return isValidIpv4(ip) ? ip : null;
  }

  if (type === 'url') {
    try {
      const u = new URL(raw);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
      const host = u.hostname;
      return isValidIpv4(host) ? host : null;
    } catch {
      return null;
    }
  }

  return null;
}

function parseNoteKeyValues(note) {
  const out = {};
  const raw = String(note || '').trim();
  if (!raw) return out;

  const parts = raw.split('|').map((p) => p.trim()).filter(Boolean);
  for (const part of parts) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim().toLowerCase();
    const value = part.slice(idx + 1).trim();
    if (!key || !value) continue;
    out[key] = value;
  }

  return out;
}

function buildFileInformation(rows, observable, observableType) {
  const type = String(observableType || '').toLowerCase();
  const fileTypes = new Set(['md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh']);
  const looksLikeFileIoc = fileTypes.has(type);

  let md5 = null;
  let sha1 = null;
  let sha256 = null;
  let ssdeep = null;
  let imphash = null;
  let tlsh = null;
  let fileName = null;
  let fileType = null;
  let mime = null;
  let reporter = null;
  let vtpercent = null;

  for (const row of rows) {
    const kv = parseNoteKeyValues(row.note);
    md5 = md5 || kv.md5 || null;
    sha1 = sha1 || kv.sha1 || null;
    sha256 = sha256 || kv.sha256 || null;
    ssdeep = ssdeep || kv.ssdeep || null;
    imphash = imphash || kv.imphash || null;
    tlsh = tlsh || kv.tlsh || null;
    fileName = fileName || kv.file_name || null;
    fileType = fileType || kv.file_type || null;
    mime = mime || kv.mime || null;
    reporter = reporter || kv.reporter || null;
    vtpercent = vtpercent || kv.vtpercent || null;
  }

  if (type === 'sha256' && !sha256) sha256 = observable;
  if (type === 'sha1' && !sha1) sha1 = observable;
  if (type === 'md5' && !md5) md5 = observable;
  if (type === 'ssdeep' && !ssdeep) ssdeep = observable;

  const hasData = Boolean(
    md5 || sha1 || sha256 || ssdeep || imphash || tlsh || fileName || fileType || mime || reporter || vtpercent
  );

  if (!hasData && !looksLikeFileIoc) return null;

  return {
    md5,
    sha1,
    sha256,
    ssdeep,
    imphash,
    tlsh,
    file_name: fileName,
    file_type: fileType,
    mime,
    reporter,
    vtpercent
  };
}

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

/** Yeni IOC eklendiğinde tek tek ağır refresh yerine debounce: kısa süre içinde tek seferde hafif limit ile çalışır. */
function scheduleGeoCacheRefreshAfterAdd() {
  if (geoCacheDebounceTimer) clearTimeout(geoCacheDebounceTimer);
  geoCacheDebounceTimer = setTimeout(() => {
    geoCacheDebounceTimer = null;
    refreshGeoCache(GEO_CACHE_ON_ADD_LIMIT).catch(() => {});
  }, GEO_CACHE_DEBOUNCE_MS);
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
       WHERE destination_ip IS NOT NULL
         AND destination_ip ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
         AND NOT (
           destination_ip::inet <<= '10.0.0.0/8'::cidr OR
           destination_ip::inet <<= '172.16.0.0/12'::cidr OR
           destination_ip::inet <<= '192.168.0.0/16'::cidr OR
           destination_ip::inet <<= '127.0.0.0/8'::cidr OR
           destination_ip::inet <<= '169.254.0.0/16'::cidr
         )
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
    const hasHours = req.query?.hours !== undefined && req.query?.hours !== null && String(req.query.hours).trim() !== '';
    const hours = hasHours ? Math.min(Math.max(Number(req.query.hours), 1), 87600) : null;

    const q = hasHours
      ? await pool.query(
          `SELECT
             id,
             event_time,
             host_name,
             process_name,
             destination_ip,
             destination_port,
             protocol,
             matched_ioc,
             source_name,
             confidence,
             created_at
           FROM ioc_match_events
           WHERE created_at >= NOW() - ($2::text || ' hours')::interval
           ORDER BY created_at DESC
           LIMIT $1`,
          [limit, hours]
        )
      : await pool.query(
          `SELECT
             id,
             event_time,
             host_name,
             process_name,
             destination_ip,
             destination_port,
             protocol,
             matched_ioc,
             source_name,
             confidence,
             created_at
           FROM ioc_match_events
           ORDER BY created_at DESC
           LIMIT $1`,
          [limit]
        );

    return res.json({ total: q.rowCount, items: q.rows });
  } catch (err) {
    console.error('[analytics-ioc-matches] failed', err);
    return res.status(500).json({ total: 0, items: [] });
  }
});

app.get('/api/analytics/statistics', async (req, res) => {
  try {
    const hours = Math.min(Math.max(Number(req.query?.hours || 24), 1), 168);

    const topSourceQ = await pool.query(
      `SELECT source_key, COUNT(*)::bigint AS event_count
       FROM signal_events
       WHERE created_at >= NOW() - ($1::text || ' hours')::interval
       GROUP BY source_key
       ORDER BY event_count DESC
       LIMIT 10`,
      [hours]
    );

    const topClientQ = await pool.query(
      `SELECT host_name, COUNT(*)::bigint AS event_count
       FROM signal_events
       WHERE created_at >= NOW() - ($1::text || ' hours')::interval
         AND host_name IS NOT NULL
       GROUP BY host_name
       ORDER BY event_count DESC
       LIMIT 10`,
      [hours]
    );

    const timelineQ = await pool.query(
      `SELECT
         date_trunc('hour', created_at) AS bucket,
         source_key,
         host_name,
         COUNT(*)::bigint AS event_count
       FROM signal_events
       WHERE created_at >= NOW() - ($1::text || ' hours')::interval
       GROUP BY bucket, source_key, host_name
       ORDER BY bucket ASC`,
      [hours]
    );

    const riskyClientsQ = await pool.query(
      `SELECT
         host_name,
         COUNT(*)::bigint AS risky_event_count,
         MAX(created_at) AS last_risky_seen_at
       FROM ioc_match_events
       WHERE created_at >= NOW() - ($1::text || ' hours')::interval
         AND host_name IS NOT NULL
       GROUP BY host_name
       ORDER BY risky_event_count DESC, last_risky_seen_at DESC
       LIMIT 10`,
      [hours]
    );

    return res.json({
      hours,
      top_sources: topSourceQ.rows,
      top_clients: topClientQ.rows,
      risky_clients: riskyClientsQ.rows,
      timeline: timelineQ.rows
    });
  } catch (err) {
    console.error('[analytics-statistics] failed', err);
    return res.status(500).json({ hours: 24, top_sources: [], top_clients: [], risky_clients: [], timeline: [] });
  }
});

app.get('/api/integrations', async (req, res) => {
  try {
    const queuePage = Math.max(Number(req.query?.queue_page || 1) || 1, 1);
    const requestedSize = Number(req.query?.queue_page_size || 25) || 25;
    const queuePageSize = Math.min(Math.max(requestedSize, 1), 50);
    const queueOffset = (queuePage - 1) * queuePageSize;
    const queueSearch = String(req.query?.queue_search || '').trim();
    const queueWindow = String(req.query?.queue_window || '24h').trim();
    const queueWindowSql = queueWindow === '7d' ? "NOW() - INTERVAL '7 days'" : "NOW() - INTERVAL '24 hours'";

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
          WHEN f.key = 'threatfox-abusech' THEN (
            SELECT COUNT(*)::int FROM ioc_items o WHERE o.source_name = 'ThreatFox:abuse.ch'
          )
          WHEN f.key = 'malwarebazaar-abusech' THEN (
            SELECT COUNT(*)::int FROM ioc_items o WHERE o.source_name = 'MalwareBazaar:abuse.ch'
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
          WHEN f.key = 'threatfox-abusech' THEN 'threatfox_import'
          WHEN f.key = 'malwarebazaar-abusech' THEN 'malwarebazaar_import'
          ELSE f.key
        END
      WHERE f.active = TRUE
      ORDER BY f.created_at ASC, f.name ASC
    `;

    const recentQ = `
      SELECT
        q.job_id,
        q.integration_key,
        COALESCE(f.name, q.integration_key) AS integration_name,
        q.job_name AS name,
        q.status AS state,
        COALESCE(q.started_at, q.queued_at) AS timestamp,
        q.error_message AS failed_reason,
        q.records_processed,
        q.started_at,
        q.finished_at
      FROM integration_queue_jobs q
      LEFT JOIN integration_feeds f ON f.key = q.integration_key
      ORDER BY q.queued_at DESC
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
      const searchParams = [];
      let searchWhere = '';
      if (queueSearch) {
        searchParams.push(`%${queueSearch}%`);
        searchWhere = `
          AND (
            q.job_id ILIKE $1
            OR q.integration_key ILIKE $1
            OR q.job_name ILIKE $1
            OR q.status ILIKE $1
            OR COALESCE(q.error_message, '') ILIKE $1
            OR COALESCE(f.name, q.integration_key) ILIKE $1
          )
        `;
      }

      const countSql = `
        SELECT status, COUNT(*)::int AS cnt
        FROM integration_queue_jobs
        WHERE queued_at >= ${queueWindowSql}
        GROUP BY status
      `;

      const totalSql = `
        SELECT COUNT(*)::int AS total
        FROM integration_queue_jobs q
        LEFT JOIN integration_feeds f ON f.key = q.integration_key
        WHERE q.queued_at >= ${queueWindowSql}
        ${searchWhere}
      `;

      const jobsSql = `
        SELECT
          q.job_id AS id,
          q.integration_key,
          COALESCE(f.name, q.integration_key) AS integration_name,
          f.integration_id,
          q.job_name AS name,
          q.status AS state,
          COALESCE(q.started_at, q.queued_at) AS timestamp,
          q.error_message AS failed_reason,
          q.records_processed,
          q.started_at,
          q.finished_at
        FROM integration_queue_jobs q
        LEFT JOIN integration_feeds f ON f.key = q.integration_key
        WHERE q.queued_at >= ${queueWindowSql}
        ${searchWhere}
        ORDER BY q.queued_at DESC
        LIMIT $${searchParams.length + 1}
        OFFSET $${searchParams.length + 2}
      `;

      const [countRows, totalRows, jobsRows] = await Promise.all([
        pool.query(countSql),
        pool.query(totalSql, searchParams),
        pool.query(jobsSql, [...searchParams, queuePageSize, queueOffset])
      ]);

      const mapped = { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 };
      for (const r of countRows.rows) {
        if (r.status === 'queued') mapped.waiting += r.cnt;
        else if (r.status === 'running') mapped.active += r.cnt;
        else if (r.status === 'failed') mapped.failed += r.cnt;
        else if (r.status === 'success') mapped.completed += r.cnt;
      }

      const total = Number(totalRows.rows[0]?.total || 0);
      queue = {
        counts: mapped,
        jobs: jobsRows.rows,
        pagination: {
          page: queuePage,
          page_size: queuePageSize,
          total,
          total_pages: Math.max(1, Math.ceil(total / queuePageSize))
        },
        filters: {
          search: queueSearch,
          window: queueWindow
        }
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
  'urlhaus-abusech': 'urlhaus-import',
  'threatfox-abusech': 'threatfox-import',
  'malwarebazaar-abusech': 'malwarebazaar-import'
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
      scheduleGeoCacheRefreshAfterAdd();
      await pool.query(
        `INSERT INTO dashboard_map_pending_events (event_type, ioc_id, observable, observable_type)
         VALUES ('add', $1, $2, $3)`,
        [rows[0].id, rows[0].observable, rows[0].observable_type]
      ).catch(() => {});
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

    scheduleGeoCacheRefreshAfterAdd();
    await pool.query(
      `INSERT INTO dashboard_map_pending_events (event_type, ioc_id, observable, observable_type)
       VALUES ('add', $1, $2, $3)`,
      [rows[0].id, rows[0].observable, rows[0].observable_type]
    ).catch(() => {});

    return res.status(201).json(rows[0]);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to create record', detail: err.message });
  }
});

app.delete('/api/ioc/:publicId', async (req, res) => {
  const publicId = String(req.params?.publicId || '').trim();
  if (!publicId) {
    return res.status(400).json({ message: 'valid publicId is required' });
  }

  try {
    const prev = await pool.query('SELECT id, public_id, observable, observable_type FROM ioc_items WHERE public_id = $1::uuid LIMIT 1', [publicId]);
    if (!prev.rows.length) {
      return res.status(404).json({ message: 'IOC not found' });
    }

    await pool.query('DELETE FROM ioc_items WHERE public_id = $1::uuid', [publicId]);
    const row = prev.rows[0];
    await pool.query(
      `INSERT INTO dashboard_map_pending_events (event_type, ioc_id, observable, observable_type)
       VALUES ('delete', $1, $2, $3)`,
      [row.id, row.observable, row.observable_type]
    ).catch(() => {});

    return res.json({ ok: true, deleted_public_id: row.public_id });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to delete IOC', detail: err.message });
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

    const isMd5 = /^[a-f0-9]{32}$/i.test(qv);
    const isSha1 = /^[a-f0-9]{40}$/i.test(qv);
    const isSha256 = /^[a-f0-9]{64}$/i.test(qv);
    const isTlsh = /^[a-f0-9]{70,72}$/i.test(qv);
    const isSsdeep = /^\d+:[A-Za-z0-9/+]+:[A-Za-z0-9/+]+$/.test(qv);
    const isImphash = /^[a-f0-9]{32}$/i.test(qv);
    const isHashLike = isMd5 || isSha1 || isSha256 || isTlsh || isSsdeep || isImphash;

    if (isHashLike) {
      params.push(qv.toLowerCase());
      const exactIdx = params.length;
      const regexEscaped = qv.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      params.push(`(^|\\|\\s*)(md5|sha1|sha256|ssdeep|imphash|tlsh)\\s*=\\s*${regexEscaped}(\\s*\\||$)`);
      const noteRegexIdx = params.length;

      filters.push(`(
        LOWER(observable) = $${exactIdx}
        OR COALESCE(note, '') ~* $${noteRegexIdx}
      )`);
    } else {
      params.push(`%${qv}%`);
      filters.push(`(
        observable ILIKE $${params.length}
        OR source_name ILIKE $${params.length}
        OR COALESCE(category, '') ILIKE $${params.length}
        OR COALESCE(note, '') ILIKE $${params.length}
      )`);
    }
  }

  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
  const fullScan = Boolean(source_name || confidence || q || asn || country);
  // Filtre varken 20M+ satırda full scan önlemek: sadece son N gün (varsayılan 365)
  const maxAgeDays = Math.min(Math.max(Number(process.env.IOC_LIST_MAX_AGE_DAYS || 365) || 365, 30), 3650);
  const recentClause = fullScan ? ` WHERE created_at > now() - interval '1 day' * $${params.length + 1}` : '';
  const recentParam = fullScan ? maxAgeDays : null;

  try {
    const sourceSql = fullScan
      ? `SELECT id, public_id, observable, observable_type, source_name, confidence, category, note, created_at FROM ioc_items${recentClause}`
      : `SELECT id, public_id, observable, observable_type, source_name, confidence, category, note, created_at
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
          MIN(id)::int AS id,
          (ARRAY_AGG(public_id ORDER BY id ASC))[1]::text AS public_id,
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
    const numBase = params.length + (fullScan ? 1 : 0);
    const geoJoin = `LEFT JOIN ioc_ip_geo_cache c ON c.ip = CASE WHEN g.observable_type = 'ip' THEN g.observable::inet ELSE NULL END`;
    const geoWhere = `($${numBase + 1}::int IS NULL OR c.asn = $${numBase + 1}) AND ($${numBase + 2}::text IS NULL OR c.country_code ILIKE $${numBase + 2})`;

    // Tek sorguda hem sayfa hem toplam (COUNT(*) OVER()); boş sayfa için total ayrı çalışır
    const listQ = `
      ${base}
      , with_geo AS (
        SELECT g.*, g.observable AS ip, c.asn, c.country_code, c.as_name,
               COUNT(*) OVER()::int AS total
        FROM grouped g
        ${geoJoin}
        WHERE ${geoWhere}
      )
      SELECT id, public_id, observable, observable_type, ip, first_seen_at, last_seen_at, source_count,
             source_names, confidence_set, category_set, asn, country_code, as_name, total
      FROM with_geo
      ORDER BY last_seen_at DESC
      LIMIT $${numBase + 3}
      OFFSET $${numBase + 4}
    `;

    const listParams = fullScan ? [...params, recentParam, asnValue, countryValue, limit, offset] : [...params, asnValue, countryValue, limit, offset];
    const listRes = await pool.query(listQ, listParams);
    let total = listRes.rows[0]?.total ?? null;
    if (total === null && listRes.rows.length === 0) {
      const countQ = `
        ${base}
        SELECT COUNT(*)::int AS total
        FROM grouped g
        ${geoJoin}
        WHERE ${geoWhere}
      `;
      const countParams = fullScan ? [...params, recentParam, asnValue, countryValue] : [...params, asnValue, countryValue];
      const countRes = await pool.query(countQ, countParams);
      total = countRes.rows[0]?.total ?? 0;
    } else if (total === null) {
      total = listRes.rows.length;
    }
    const items = listRes.rows.map(({ total: _drop, ...row }) => row);

    const payload = {
      items,
      pagination: {
        page: currentPage,
        page_size: limit,
        total,
        total_pages: Math.max(Math.ceil(total / limit), 1)
      }
    };
    if (fullScan && recentParam) {
      payload.note = `Filtered list limited to last ${recentParam} days (IOC_LIST_MAX_AGE_DAYS).`;
    }
    return res.json(payload);
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

app.get('/api/ioc/details/resolve', async (req, res) => {
  const observable = String(req.query?.observable || '').trim();
  const observableType = String(req.query?.type || '').trim();

  if (!observable) {
    return res.status(400).json({ message: 'observable is required' });
  }

  try {
    const params = [observable];
    let typeFilter = '';
    if (observableType) {
      params.push(observableType);
      typeFilter = ` AND observable_type = $2 `;
    }

    const q = `
      SELECT MIN(public_id)::text AS public_id
      FROM ioc_items
      WHERE observable = $1
      ${typeFilter}
    `;
    const { rows } = await pool.query(q, params);
    const publicId = rows[0]?.public_id || null;
    return res.json({ public_id: publicId });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to resolve IOC detail id', detail: err.message });
  }
});

app.get('/api/ioc/details', async (req, res) => {
  const requestedPublicId = String(req.query?.public_id || '').trim();

  if (!requestedPublicId) {
    return res.status(400).json({ message: 'public_id is required' });
  }

  try {
    const byIdQ = `
      SELECT observable, observable_type, public_id
      FROM ioc_items
      WHERE public_id = $1::uuid
      LIMIT 1
    `;
    const byIdRes = await pool.query(byIdQ, [requestedPublicId]);
    const seed = byIdRes.rows[0];
    if (!seed) {
      return res.json({ summary: null, sources: [], matches: [] });
    }

    const observable = seed.observable;
    const observableType = seed.observable_type;

    const itemParams = [observable];
    let typeFilter = '';
    if (observableType) {
      itemParams.push(observableType);
      typeFilter = ` AND observable_type = $2 `;
    }

    const itemQ = `
      SELECT
        id,
        public_id,
        observable,
        observable_type,
        source_name,
        source_url,
        confidence,
        category,
        note,
        created_at
      FROM ioc_items
      WHERE observable = $1
      ${typeFilter}
      ORDER BY created_at DESC
      LIMIT 500
    `;

    const itemRes = await pool.query(itemQ, itemParams);
    const rows = itemRes.rows;

    if (!rows.length) {
      return res.json({ summary: null, sources: [], matches: [] });
    }

    const geoIp = extractIpv4ForGeo(observable, rows[0].observable_type);
    let geo = { ip: geoIp, asn: null, country_code: null, as_name: null };
    if (geoIp) {
      const geoQ = `
        WITH ip_input AS (
          SELECT
            $1::inet AS ip,
            ((split_part(host($1::inet), '.', 1)::bigint << 24)
            + (split_part(host($1::inet), '.', 2)::bigint << 16)
            + (split_part(host($1::inet), '.', 3)::bigint << 8)
            +  split_part(host($1::inet), '.', 4)::bigint) AS ip_num
        )
        SELECT
          i.ip::text AS ip,
          COALESCE(c.asn, r.asn) AS asn,
          COALESCE(c.country_code, r.country_code) AS country_code,
          COALESCE(c.as_name, r.as_name) AS as_name
        FROM ip_input i
        LEFT JOIN ioc_ip_geo_cache c ON c.ip = i.ip
        LEFT JOIN LATERAL (
          SELECT asn, country_code, as_name
          FROM asn_ipv4_ranges
          WHERE i.ip_num BETWEEN start_ip_num AND end_ip_num
          ORDER BY (end_ip_num - start_ip_num) ASC
          LIMIT 1
        ) r ON TRUE
      `;
      const geoRes = await pool.query(geoQ, [geoIp]);
      if (geoRes.rows[0]) {
        geo = {
          ip: geoRes.rows[0].ip || geoIp,
          asn: geoRes.rows[0].asn ?? null,
          country_code: geoRes.rows[0].country_code || null,
          as_name: geoRes.rows[0].as_name || null
        };
      }
    }

    const summary = {
      id: rows[0].id,
      public_id: rows[0].public_id,
      observable,
      observable_type: rows[0].observable_type,
      first_seen_at: rows[rows.length - 1]?.created_at || null,
      last_seen_at: rows[0]?.created_at || null,
      source_count: new Set(rows.map((r) => r.source_name)).size,
      confidence_set: [...new Set(rows.map((r) => r.confidence).filter(Boolean))],
      category_set: [...new Set(rows.map((r) => r.category).filter(Boolean))],
      geo,
      file_information: buildFileInformation(rows, observable, rows[0].observable_type)
    };

    const matchesQ = `
      SELECT
        id,
        event_time,
        host_name,
        process_name,
        destination_ip,
        destination_port,
        protocol,
        matched_ioc,
        source_name,
        confidence,
        created_at
      FROM ioc_match_events
      WHERE matched_ioc = $1
      ORDER BY created_at DESC
      LIMIT 20
    `;
    const matchesRes = await pool.query(matchesQ, [observable]);

    return res.json({
      summary,
      sources: rows,
      matches: matchesRes.rows
    });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch IOC details', detail: err.message });
  }
});

app.get('/api/ioc/recent', async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit || 10), 1), 100);

  try {
    const q = `
      SELECT
        i.id,
        i.public_id,
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
    const snapshotQ = `
      SELECT snapshot_time, total_records, unique_ips, countries
      FROM dashboard_map_display_snapshot
      WHERE singleton = TRUE
      LIMIT 1
    `;

    const stateQ = `
      SELECT full_rebuild_pending, last_run_at, snapshot_last_refreshed_at
      FROM dashboard_map_job_state
      WHERE singleton = TRUE
      LIMIT 1
    `;

    const [{ rows: snapshotRows }, { rows: stateRows }] = await Promise.all([
      pool.query(snapshotQ).catch(() => ({ rows: [] })),
      pool.query(stateQ).catch(() => ({ rows: [] }))
    ]);

    const snapshot = snapshotRows[0] || null;
    const state = stateRows[0] || null;

    return res.json({
      total: Number(snapshot?.total_records || 0),
      unique_ips: Number(snapshot?.unique_ips || 0),
      countries: Array.isArray(snapshot?.countries) ? snapshot.countries : [],
      snapshot_time: snapshot?.snapshot_time || null,
      note: 'This map shows a processed snapshot of the last 24 hours and is refreshed once per day around midnight (server local time).',
      batch: {
        full_rebuild_pending: Boolean(state?.full_rebuild_pending),
        last_run_at: state?.last_run_at || null,
        snapshot_last_refreshed_at: state?.snapshot_last_refreshed_at || null
      }
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
  refreshGeoCache(GEO_CACHE_REFRESH_LIMIT).catch(() => {});
  setInterval(() => {
    refreshGeoCache(GEO_CACHE_REFRESH_LIMIT).catch(() => {});
  }, GEO_CACHE_REFRESH_INTERVAL_MS);
});
