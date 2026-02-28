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

function mapUsomConfidence(level) {
  const n = Number(level);
  if (Number.isNaN(n)) return 'medium';
  if (n <= 3) return 'high';
  if (n <= 6) return 'medium';
  return 'low';
}

async function insertIoc(client, { ip, sourceName, sourceUrl, confidence, category, note, dedupSource }) {
  const dedupKey = `${ip}|${sourceName}|${confidence}|${category || ''}|${sourceUrl || ''}`;
  const dedup = await client.query(
    `INSERT INTO import_dedup (source_name, external_id)
     VALUES ($1, $2)
     ON CONFLICT (source_name, external_id) DO NOTHING
     RETURNING source_name`,
    [dedupSource, dedupKey]
  );

  if (!dedup.rowCount) return false;

  const ins = await client.query(
    `INSERT INTO ioc_ips (ip, source_name, source_url, confidence, category, note, first_seen_at, last_seen_at)
     SELECT $1, $2, $3, $4, $5, $6, NOW(), NOW()
     WHERE NOT EXISTS (
       SELECT 1
       FROM ioc_ips
       WHERE ip = $1::inet
         AND source_name = $2
         AND confidence = $4
         AND COALESCE(category, '') = COALESCE($5, '')
         AND COALESCE(source_url, '') = COALESCE($3, '')
     )
     RETURNING id`,
    [ip, sourceName, sourceUrl, confidence, category, note]
  );

  return Boolean(ins.rowCount);
}

async function insertObservable(client, { observable, observableType, sourceName, sourceUrl, confidence, category, note, dedupSource }) {
  const dedupKey = `${observableType}|${observable}|${sourceName}|${confidence}|${category || ''}|${sourceUrl || ''}`;
  const dedup = await client.query(
    `INSERT INTO import_dedup (source_name, external_id)
     VALUES ($1, $2)
     ON CONFLICT (source_name, external_id) DO NOTHING
     RETURNING source_name`,
    [dedupSource, dedupKey]
  );

  if (!dedup.rowCount) return false;

  const ins = await client.query(
    `INSERT INTO ioc_observables (observable, observable_type, source_name, source_url, confidence, category, note)
     SELECT $1, $2, $3, $4, $5, $6, $7
     WHERE NOT EXISTS (
       SELECT 1
       FROM ioc_observables
       WHERE observable = $1
         AND observable_type = $2
         AND source_name = $3
         AND confidence = $5
         AND COALESCE(category, '') = COALESCE($6, '')
         AND COALESCE(source_url, '') = COALESCE($4, '')
     )
     RETURNING id`,
    [observable, observableType, sourceName, sourceUrl, confidence, category, note]
  );

  return Boolean(ins.rowCount);
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
        const ok = await insertIoc(client, {
          ip,
          sourceName,
          sourceUrl,
          confidence,
          category,
          note: `Auto-imported from ET blockrules (${file})`,
          dedupSource: config.sourceName
        });

        if (ok) inserted += 1;
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

export async function runUsomImport() {
  const client = await pool.connect();
  const startedAt = new Date();
  let runId = null;

  try {
    await client.query('BEGIN');

    const lockResult = await client.query('SELECT pg_try_advisory_lock(942002) AS acquired');
    if (!lockResult.rows[0]?.acquired) {
      await client.query('ROLLBACK');
      return { skipped: true, reason: 'lock_not_acquired' };
    }

    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('usom_import', 'running', NOW(), 'scheduler')
       RETURNING id`
    );
    runId = runInsert.rows[0].id;

    let page = 0;
    let pageCount = 1;
    let inserted = 0;

    const usomTypes = ['ip', 'domain', 'url', 'ip6', 'ip6net'];

    for (const usomType of usomTypes) {
      page = 0;
      pageCount = 1;

      while (page < pageCount) {
        const url = new URL(config.usomApiUrl);
        url.searchParams.set('type', usomType);
        url.searchParams.set('page', String(page));

        const res = await fetch(url.toString());
        if (!res.ok) throw new Error(`USOM API request failed (${usomType}): ${res.status}`);
        const data = await res.json();

        pageCount = Number(data?.pageCount || 1);
        const models = Array.isArray(data?.models) ? data.models : [];

        for (const m of models) {
          const observable = String(m?.url || '').trim();
          if (!observable) continue;

          const sourceName = config.usomSourceName;
          const sourceUrl = 'https://www.usom.gov.tr/api/address/index';
          const confidence = mapUsomConfidence(m?.criticality_level);
          const category = m?.desc ? String(m.desc).toLowerCase().replace(/\s+/g, '-').slice(0, 100) : 'threat-intel';
          const note = `Auto-imported from USOM API (id=${m?.id ?? '-'}, type=${m?.type ?? usomType})`;

          const okObs = await insertObservable(client, {
            observable,
            observableType: usomType,
            sourceName,
            sourceUrl,
            confidence,
            category,
            note,
            dedupSource: config.usomSourceName
          });

          if (okObs) inserted += 1;

          if (usomType === 'ip') {
            await insertIoc(client, {
              ip: observable,
              sourceName,
              sourceUrl,
              confidence,
              category,
              note,
              dedupSource: `${config.usomSourceName}:ip-db`
            });
          }
        }

        page += 1;
        if (page > 1000) break;
      }
    }

    await client.query(
      `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
      [config.usomSourceName, startedAt.toISOString()]
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
      await client.query('SELECT pg_advisory_unlock(942002)');
    } catch {
      // ignore
    }
    client.release();
  }
}
