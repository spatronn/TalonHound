import pg from 'pg';
import { config } from './config.js';

const { Pool } = pg;
const pool = new Pool(config.db);

function parseLinks(html) {
  const links = [...html.matchAll(/href="\.\/([^"]+)"/g)].map((m) => m[1]);
  return links.filter((name) => {
    if (!/\.(rules|txt)$/i.test(name)) return false;
    if (/\.suricata\.rules$/i.test(name)) return false;
    return true;
  });
}

function isIPv4(value) {
  const m = value.match(/^(\d{1,3})(?:\.(\d{1,3})){3}$/);
  if (!m) return false;
  return value.split('.').every((x) => Number(x) >= 0 && Number(x) <= 255);
}

function isCIDR(value) {
  const [ip, mask] = value.split('/');
  if (!ip || mask == null) return false;
  return isIPv4(ip) && Number.isInteger(Number(mask)) && Number(mask) >= 0 && Number(mask) <= 32;
}

function extractIPs(text) {
  const found = new Set();
  const ipv4Like = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\b/g) || [];
  for (const token of ipv4Like) {
    if (isIPv4(token) || isCIDR(token)) found.add(token);
  }
  return [...found];
}

function inferCategory(fileName) {
  const f = fileName.toLowerCase();
  if (f.includes('threatview') || f.includes('_c2')) return 'c2';
  if (f.includes('botcc')) return 'botnet-c2';
  if (f.includes('tor')) return 'tor';
  if (f.includes('compromised')) return 'compromised-host';
  if (f.includes('drop')) return 'known-malicious';
  if (f.includes('dshield')) return 'scanner';
  if (f.includes('ciarmy')) return 'bruteforce';
  return 'malicious-ip';
}

function inferConfidence(fileName) {
  const f = fileName.toLowerCase();
  if (f.includes('threatview') || f.includes('high-confidence')) return 'high';
  if (f.includes('drop') || f.includes('compromised') || f.includes('botcc') || f.includes('ciarmy')) return 'high';
  return 'medium';
}

export async function runHourlyImport() {
  const client = await pool.connect();
  const startedAt = new Date();
  let runId = null;

  try {
    await client.query('BEGIN');

    const lockResult = await client.query('SELECT pg_try_advisory_lock(942001) AS acquired');
    if (!lockResult.rows[0]?.acquired) {
      await client.query('ROLLBACK');
      return { skipped: true, reason: 'lock_not_acquired' };
    }

    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('hourly_import', 'running', NOW(), 'scheduler')
       RETURNING id`
    );
    runId = runInsert.rows[0].id;

    const indexRes = await fetch(config.sourceIndexUrl);
    if (!indexRes.ok) throw new Error(`Failed to fetch source index: ${indexRes.status}`);
    const indexHtml = await indexRes.text();

    const files = parseLinks(indexHtml);
    let inserted = 0;

    for (const file of files) {
      const sourceUrl = new URL(file, config.sourceIndexUrl).toString();
      const response = await fetch(sourceUrl);
      if (!response.ok) continue;

      const body = await response.text();
      const ips = extractIPs(body);
      const sourceName = `EmergingThreats:${file}`;
      const confidence = inferConfidence(file);
      const category = inferCategory(file);

      for (const ip of ips) {
        const dedupKey = `${sourceName}|${ip}`;
        const dedup = await client.query(
          `INSERT INTO import_dedup (source_name, external_id)
           VALUES ($1, $2)
           ON CONFLICT (source_name, external_id) DO NOTHING
           RETURNING source_name`,
          [config.sourceName, dedupKey]
        );

        if (!dedup.rowCount) continue;

        await client.query(
          `INSERT INTO ioc_ips (ip, source_name, source_url, confidence, category, note, first_seen_at, last_seen_at)
           VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
          [ip, sourceName, sourceUrl, confidence, category, `Auto-imported from ET blockrules (${file})`]
        );
        inserted += 1;
      }
    }

    await client.query(
      `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
      [config.sourceName, startedAt.toISOString()]
    );

    await client.query(
      `UPDATE integration_runs
       SET status='success', finished_at=NOW(), records_processed=$2
       WHERE id=$1`,
      [runId, inserted]
    );

    await client.query('COMMIT');
    return { ok: true, runId, recordsProcessed: inserted };
  } catch (err) {
    await client.query('ROLLBACK');

    if (runId) {
      await client.query(
        `UPDATE integration_runs
         SET status='failed', finished_at=NOW(), error_message=$2
         WHERE id=$1`,
        [runId, String(err.message).slice(0, 4000)]
      );
    }

    throw err;
  } finally {
    try {
      await client.query('SELECT pg_advisory_unlock(942001)');
    } catch {
      // ignore
    }
    client.release();
  }
}
