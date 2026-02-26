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
  const { source_name, confidence, day = 'today', page = '1', page_size = '5' } = req.query;
  const allowedSizes = [5, 10, 25, 100];
  const size = Number(page_size);
  const currentPage = Math.max(Number(page) || 1, 1);
  const limit = allowedSizes.includes(size) ? size : 5;
  const offset = (currentPage - 1) * limit;

  const filters = [];
  const params = [];

  if (day === 'today') {
    filters.push(`created_at::date = CURRENT_DATE`);
  }

  if (source_name) {
    params.push(source_name);
    filters.push(`source_name = $${params.length}`);
  }

  if (confidence) {
    params.push(confidence);
    filters.push(`confidence = $${params.length}`);
  }

  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';

  try {
    const countQ = `SELECT COUNT(*)::int AS total FROM ioc_ips ${where}`;
    const { rows: countRows } = await pool.query(countQ, params);
    const total = countRows[0]?.total || 0;

    const listQ = `
      SELECT * FROM ioc_ips
      ${where}
      ORDER BY created_at DESC
      LIMIT $${params.length + 1}
      OFFSET $${params.length + 2}
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
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch records', detail: err.message });
  }
});

app.get('/api/ioc/summary/today', async (_req, res) => {
  try {
    const total = await pool.query(`SELECT COUNT(*)::int AS count FROM ioc_ips WHERE created_at::date = CURRENT_DATE`);
    const bySource = await pool.query(`
      SELECT source_name, COUNT(*)::int AS count
      FROM ioc_ips
      WHERE created_at::date = CURRENT_DATE
      GROUP BY source_name
      ORDER BY count DESC
    `);

    res.json({
      total: total.rows[0].count,
      by_source: bySource.rows
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch summary', detail: err.message });
  }
});

app.listen(port, () => {
  console.log(`Backend listening on :${port}`);
});
