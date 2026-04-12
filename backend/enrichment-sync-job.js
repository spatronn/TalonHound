import './lib/ensure-db-password.js';
import fs from 'fs';
import pg from 'pg';

const { Pool } = pg;

const SOURCE_FILE = '/tmp/asn_full.json';
const LOOP_INTERVAL_MS = Math.max(Number(process.env.ENRICHMENT_SYNC_INTERVAL_MS || 86400000), 60000);
const INSERT_BATCH_SIZE = Math.max(Number(process.env.ENRICHMENT_SYNC_BATCH_SIZE || 5000), 500);
const RUN_ONCE = String(process.env.ENRICHMENT_SYNC_ONCE || '0') === '1';

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'demo'
});

function ipv4ToInt(ip) {
  const parts = String(ip || '').trim().split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = (n << 8) + v;
  }
  return n >>> 0;
}

function cidrToRange(cidr) {
  const [ip, prefixRaw] = String(cidr || '').trim().split('/');
  const base = ipv4ToInt(ip);
  const prefix = Number(prefixRaw);
  if (base == null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  if (prefix === 0) return { start: 0, end: 0xffffffff };
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  const start = (base & mask) >>> 0;
  const size = 2 ** (32 - prefix);
  const end = Math.min(0xffffffff, start + size - 1) >>> 0;
  return { start, end };
}

function parseIpRange(v) {
  const raw = String(v || '').trim();
  if (!raw) return null;
  if (raw.includes('/')) return cidrToRange(raw);
  if (raw.includes('-')) {
    const [a, b] = raw.split('-').map((x) => x.trim());
    const s = ipv4ToInt(a);
    const e = ipv4ToInt(b);
    if (s == null || e == null) return null;
    return { start: Math.min(s, e), end: Math.max(s, e) };
  }
  const x = ipv4ToInt(raw);
  if (x == null) return null;
  return { start: x, end: x };
}

function asnToNumber(v) {
  if (v == null) return null;
  const s = String(v).trim().toUpperCase();
  const m = s.match(/AS(\d+)/) || s.match(/(\d+)/);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isFinite(n) ? n : null;
}

function extractRange(obj) {
  const candidates = [
    obj.start_ip_int != null && obj.end_ip_int != null ? { start: Number(obj.start_ip_int), end: Number(obj.end_ip_int) } : null,
    obj.start_ip && obj.end_ip ? { start: ipv4ToInt(obj.start_ip), end: ipv4ToInt(obj.end_ip) } : null,
    parseIpRange(obj.range),
    parseIpRange(obj.ip_range),
    parseIpRange(obj.network),
    parseIpRange(obj.cidr),
    parseIpRange(obj.prefix),
    parseIpRange(obj.ip)
  ].filter(Boolean);

  for (const c of candidates) {
    if (c.start == null || c.end == null) continue;
    if (!Number.isFinite(c.start) || !Number.isFinite(c.end)) continue;
    return { start: Math.min(c.start, c.end), end: Math.max(c.start, c.end) };
  }
  return null;
}

function extractRow(obj) {
  const range = extractRange(obj);
  if (!range) return null;

  const asn = asnToNumber(obj.asn ?? obj.as_number ?? obj.autonomous_system_number ?? obj.asn_id);
  const asnOwner = String(obj.asn_owner ?? obj.owner ?? obj.org ?? obj.organization ?? obj.as_name ?? obj.name ?? '').trim() || null;
  const country = String(obj.country ?? obj.country_code ?? obj.cc ?? '').trim() || null;

  return {
    start_ip_int: Math.trunc(range.start),
    end_ip_int: Math.trunc(range.end),
    asn,
    asn_owner: asnOwner,
    country
  };
}

async function* streamTopLevelAsnEntries(filePath) {
  const stream = fs.createReadStream(filePath, { encoding: 'utf8' });

  let inString = false;
  let escaped = false;
  let started = false;
  let depth = 0;

  let readingKey = false;
  let currentKey = '';

  let readingValue = false;
  let valueDepth = 0;
  let valueBuf = '';

  for await (const chunk of stream) {
    for (let i = 0; i < chunk.length; i += 1) {
      const ch = chunk[i];

      if (!started) {
        if (ch === '{') {
          started = true;
          depth = 1;
        }
        continue;
      }

      if (readingValue) {
        valueBuf += ch;

        if (inString) {
          if (escaped) escaped = false;
          else if (ch === '\\') escaped = true;
          else if (ch === '"') inString = false;
          continue;
        }

        if (ch === '"') {
          inString = true;
        } else if (ch === '{') {
          valueDepth += 1;
          depth += 1;
        } else if (ch === '}') {
          valueDepth -= 1;
          depth -= 1;
          if (valueDepth === 0) {
            yield { asnKey: currentKey, objectText: valueBuf };
            readingValue = false;
            valueBuf = '';
            currentKey = '';
          }
        }
        continue;
      }

      if (readingKey) {
        if (escaped) {
          currentKey += ch;
          escaped = false;
        } else if (ch === '\\') {
          escaped = true;
        } else if (ch === '"') {
          readingKey = false;
        } else {
          currentKey += ch;
        }
        continue;
      }

      if (inString) {
        if (escaped) escaped = false;
        else if (ch === '\\') escaped = true;
        else if (ch === '"') inString = false;
        continue;
      }

      if (ch === '"' && depth == 1 && !currentKey) {
        readingKey = true;
        currentKey = '';
        continue;
      }

      if (ch === '{') {
        depth += 1;
        if (depth === 2 && currentKey) {
          readingValue = true;
          valueDepth = 1;
          valueBuf = '{';
          inString = false;
          escaped = false;
        }
      } else if (ch === '}') {
        depth -= 1;
      }
    }
  }
}

async function insertBatch(client, tableName, rows) {
  if (!rows.length) return;
  const starts = rows.map((r) => r.start_ip_int);
  const ends = rows.map((r) => r.end_ip_int);
  const asns = rows.map((r) => r.asn);
  const owners = rows.map((r) => r.asn_owner);
  const countries = rows.map((r) => r.country);

  await client.query(
    `INSERT INTO ${tableName} (start_ip_int, end_ip_int, asn, asn_owner, country)
     SELECT * FROM UNNEST($1::bigint[], $2::bigint[], $3::bigint[], $4::text[], $5::text[])`,
    [starts, ends, asns, owners, countries]
  );
}

async function buildAndSwap() {
  if (!fs.existsSync(SOURCE_FILE)) {
    throw new Error(`source file not found: ${SOURCE_FILE}`);
  }

  const client = await pool.connect();
  const startedAt = Date.now();
  const nextTable = 'asn_lookup_next';
  let parsed = 0;
  let accepted = 0;
  let rejected = 0;

  try {
    await client.query(`DROP TABLE IF EXISTS ${nextTable}`);
    await client.query(`
      CREATE TABLE ${nextTable} (
        id BIGSERIAL PRIMARY KEY,
        start_ip_int BIGINT NOT NULL,
        end_ip_int BIGINT NOT NULL,
        asn BIGINT,
        asn_owner TEXT,
        country TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CHECK (start_ip_int >= 0 AND end_ip_int >= 0 AND start_ip_int <= end_ip_int)
      )
    `);

    let batch = [];
    for await (const entry of streamTopLevelAsnEntries(SOURCE_FILE)) {
      parsed += 1;
      let obj;
      try {
        obj = JSON.parse(entry.objectText);
      } catch {
        rejected += 1;
        continue;
      }

      const owner = String(obj.organization ?? obj.info?.name ?? obj.info?.descr ?? '').trim() || null;
      const country = String(obj.info?.country ?? '').trim() || null;
      const asnNum = asnToNumber(entry.asnKey);
      const prefixes = Array.isArray(obj.ipv4) ? obj.ipv4 : [];

      if (!prefixes.length) {
        rejected += 1;
        continue;
      }

      for (const prefix of prefixes) {
        const r = parseIpRange(prefix);
        if (!r) continue;
        batch.push({ start_ip_int: Math.trunc(r.start), end_ip_int: Math.trunc(r.end), asn: asnNum, asn_owner: owner, country });
        accepted += 1;

        if (batch.length >= INSERT_BATCH_SIZE) {
          await insertBatch(client, nextTable, batch);
          batch = [];
        }
      }

      if (parsed % 5000 === 0) {
        console.log(`[enrichment-sync-job] progress parsed_asn=${parsed} accepted_ranges=${accepted} rejected_asn=${rejected}`);
      }
    }

    if (batch.length) {
      await insertBatch(client, nextTable, batch);
    }

    await client.query(`CREATE INDEX IF NOT EXISTS idx_${nextTable}_start_end ON ${nextTable} (start_ip_int, end_ip_int)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_${nextTable}_asn ON ${nextTable} (asn)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_${nextTable}_country ON ${nextTable} (country)`);

    const backupTable = `asn_lookup_prev_${Date.now()}`;
    await client.query('BEGIN');
    await client.query('LOCK TABLE asn_lookup IN ACCESS EXCLUSIVE MODE');
    await client.query(`ALTER TABLE asn_lookup RENAME TO ${backupTable}`);
    await client.query(`ALTER TABLE ${nextTable} RENAME TO asn_lookup`);
    await client.query('COMMIT');

    await client.query(`DROP TABLE IF EXISTS ${backupTable}`);

    const ms = Date.now() - startedAt;
    console.log(`[enrichment-sync-job] success parsed=${parsed} accepted=${accepted} rejected=${rejected} duration_ms=${ms}`);
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    await client.query(`DROP TABLE IF EXISTS ${nextTable}`).catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function main() {
  console.log(`[enrichment-sync-job] started source=${SOURCE_FILE} interval_ms=${LOOP_INTERVAL_MS} batch_size=${INSERT_BATCH_SIZE} run_once=${RUN_ONCE ? 1 : 0}`);

  while (true) {
    try {
      await buildAndSwap();
    } catch (err) {
      console.error('[enrichment-sync-job] failed', err?.message || err);
    }

    if (RUN_ONCE) break;
    await new Promise((resolve) => setTimeout(resolve, LOOP_INTERVAL_MS));
  }
}

main().catch((err) => {
  console.error('[enrichment-sync-job] fatal', err?.message || err);
  process.exit(1);
});
