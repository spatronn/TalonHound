import express from 'express';
import cors from 'cors';
import pg from 'pg';

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

app.use(cors());
app.use(express.json());

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_preferences (
      email TEXT PRIMARY KEY,
      timezone TEXT NOT NULL DEFAULT 'UTC',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ioc_ips_ip_created_at ON ioc_ips (ip, created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ioc_ips_created_at ON ioc_ips (created_at DESC)`);
}

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'backend', db: 'up' });
  } catch {
    res.status(500).json({ ok: false, service: 'backend', db: 'down' });
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
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `;
    const values = [ip, source_name, source_url || null, confidence, category, note];
    const { rows } = await pool.query(q, values);
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

app.get('/api/ioc/map/countries', async (req, res) => {
  const { day = 'all' } = req.query;
  let timeFilter = `TRUE`;

  if (day === 'today') {
    timeFilter = `i.created_at::date = CURRENT_DATE`;
  } else if (day === '24h') {
    timeFilter = `i.created_at >= NOW() - INTERVAL '24 hours'`;
  } else if (day === '7d') {
    timeFilter = `i.created_at >= NOW() - INTERVAL '7 days'`;
  }

  try {
    const q = `
      WITH ip_geo AS (
        SELECT DISTINCT
          i.ip,
          COALESCE(NULLIF(UPPER(TRIM(a.country_code)), ''), 'UN') AS country_code
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
        WHERE ${timeFilter}
      )
      SELECT country_code, COUNT(*)::int AS total
      FROM ip_geo
      GROUP BY country_code
      ORDER BY total DESC
    `;

    const totalQ = `
      SELECT COUNT(DISTINCT ip)::int AS total
      FROM ioc_ips i
      WHERE ${timeFilter}
    `;

    const [{ rows: byCountry }, { rows: totals }] = await Promise.all([
      pool.query(q),
      pool.query(totalQ)
    ]);

    return res.json({
      total: totals[0]?.total || 0,
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
      by_source: bySource.rows,
      by_confidence: byConfidence.rows
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch summary', detail: err.message });
  }
});

ensureSchema()
  .then(() => {
    app.listen(port, () => {
      console.log(`Backend listening on :${port}`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize schema', err);
    process.exit(1);
  });
