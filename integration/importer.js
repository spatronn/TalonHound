import pg from 'pg';
import { createHash } from 'node:crypto';
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
  if (!ip || mask == null || mask === '') return false;
  if (!/^\d{1,2}$/.test(mask)) return false;
  const n = Number(mask);
  return isIPv4(ip) && Number.isInteger(n) && n >= 0 && n <= 32;
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

function classifyUsomObservable(rawObservable) {
  const observable = String(rawObservable || '').trim();
  if (!observable || observable.startsWith('#')) return null;

  const normalizedIp = observable.endsWith('/') ? observable.slice(0, -1) : observable;

  let observableType = 'domain';
  if (/^https?:\/\//i.test(observable) || observable.includes('/')) observableType = 'url';
  else if (isIPv4(normalizedIp) || isCIDR(normalizedIp)) observableType = 'ip';
  else if (observable.includes(':')) observableType = 'ip6';

  return {
    observable: observableType === 'ip' ? normalizedIp : observable,
    observableType
  };
}

function hashEntries(entries) {
  return createHash('sha256').update(JSON.stringify(entries)).digest('hex');
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
    `INSERT INTO ioc_items (observable, observable_type, source_name, source_url, confidence, category, note, first_seen_at, last_seen_at)
     SELECT $1, 'ip', $2, $3, $4, $5, $6, NOW(), NOW()
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
    `INSERT INTO ioc_items (observable, observable_type, source_name, source_url, confidence, category, note)
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
       VALUES ('hourly_import', 'running', clock_timestamp(), 'scheduler')
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
       SET status='success', finished_at=clock_timestamp(), records_processed=$2
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
         SET status='failed', finished_at=clock_timestamp(), error_message=$2
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
  let runId = null;

  try {
    const lockResult = await client.query('SELECT pg_try_advisory_lock(942002) AS acquired');
    if (!lockResult.rows[0]?.acquired) {
      return { skipped: true, reason: 'lock_not_acquired' };
    }

    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('usom_import', 'running', clock_timestamp(), 'scheduler')
       RETURNING id`
    );
    runId = runInsert.rows[0].id;

    let inserted = 0;

    const res = await fetch(config.usomApiUrl);
    if (!res.ok) throw new Error(`USOM URL list request failed: ${res.status}`);
    const txt = await res.text();

    const entries = txt
      .split(/\r?\n/)
      .map((line) => classifyUsomObservable(line))
      .filter(Boolean)
      .sort((a, b) => `${a.observableType}|${a.observable}`.localeCompare(`${b.observableType}|${b.observable}`));

    const currentHash = hashEntries(entries);

    const prevState = await client.query(
      `SELECT content_hash, items_json
       FROM integration_source_state
       WHERE source_name = $1`,
      [config.usomSourceName]
    );

    const previousHash = prevState.rows[0]?.content_hash || null;
    const previousItems = Array.isArray(prevState.rows[0]?.items_json) ? prevState.rows[0].items_json : [];
    const previousSet = new Set(previousItems.map((x) => `${x.observableType}|${x.observable}`));

    if (previousHash === currentHash) {
      await client.query(
        `UPDATE integration_runs
         SET status='success', finished_at=clock_timestamp(), records_processed=0
         WHERE id=$1`,
        [runId]
      );

      await client.query(
        `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (source_name)
         DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
        [config.usomSourceName, `hash:${currentHash}`]
      );

      return { ok: true, runId, recordsProcessed: 0, skipped: true, reason: 'same_hash' };
    }

    const addedEntries = entries.filter((e) => !previousSet.has(`${e.observableType}|${e.observable}`));
    const batchSize = Number(process.env.USOM_BATCH_SIZE || 1000);

    for (let i = 0; i < addedEntries.length; i += batchSize) {
      const batch = addedEntries.slice(i, i + batchSize);
      await client.query('BEGIN');
      try {
        for (const entry of batch) {
          const { observable, observableType } = entry;
          const sourceName = config.usomSourceName;
          const sourceUrl = config.usomApiUrl;
          const confidence = 'medium';
          const category = 'threat-intel';
          const note = 'Auto-imported from USOM URL list';

          const okObs = await insertObservable(client, {
            observable,
            observableType,
            sourceName,
            sourceUrl,
            confidence,
            category,
            note,
            dedupSource: config.usomSourceName
          });

          if (okObs) inserted += 1;

        }
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      }
    }

    await client.query(
      `INSERT INTO integration_source_state (source_name, content_hash, items_json, updated_at)
       VALUES ($1, $2, $3::jsonb, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET content_hash = EXCLUDED.content_hash, items_json = EXCLUDED.items_json, updated_at = NOW()`,
      [config.usomSourceName, currentHash, JSON.stringify(entries)]
    );

    await client.query(
      `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
      [config.usomSourceName, `hash:${currentHash}`]
    );

    await client.query(
      `UPDATE integration_runs
       SET status='success', finished_at=clock_timestamp(), records_processed=$2
       WHERE id=$1`,
      [runId, inserted]
    );

    return { ok: true, runId, recordsProcessed: inserted };
  } catch (err) {
    if (runId) {
      await client.query(
        `UPDATE integration_runs
         SET status='failed', finished_at=clock_timestamp(), error_message=$2
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


export async function runUrlhausImport() {
  const client = await pool.connect();
  let runId = null;

  try {
    const lockResult = await client.query('SELECT pg_try_advisory_lock(942003) AS acquired');
    if (!lockResult.rows[0]?.acquired) {
      return { skipped: true, reason: 'lock_not_acquired' };
    }

    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('urlhaus_import', 'running', clock_timestamp(), 'scheduler')
       RETURNING id`
    );
    runId = runInsert.rows[0].id;

    let inserted = 0;

    const res = await fetch(config.urlhausUrl);
    if (!res.ok) throw new Error(`URLhaus list request failed: ${res.status}`);
    const txt = await res.text();

    const entries = txt
      .split(/\r?\n/)
      .map((line) => classifyUsomObservable(line))
      .filter(Boolean)
      .sort((a, b) => `${a.observableType}|${a.observable}`.localeCompare(`${b.observableType}|${b.observable}`));

    const currentHash = hashEntries(entries);

    const prevState = await client.query(
      `SELECT content_hash, items_json
       FROM integration_source_state
       WHERE source_name = $1`,
      [config.urlhausSourceName]
    );

    const previousHash = prevState.rows[0]?.content_hash || null;
    const previousItems = Array.isArray(prevState.rows[0]?.items_json) ? prevState.rows[0].items_json : [];
    const previousSet = new Set(previousItems.map((x) => `${x.observableType}|${x.observable}`));

    if (previousHash === currentHash) {
      await client.query(
        `UPDATE integration_runs
         SET status='success', finished_at=clock_timestamp(), records_processed=0
         WHERE id=$1`,
        [runId]
      );

      await client.query(
        `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (source_name)
         DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
        [config.urlhausSourceName, `hash:${currentHash}`]
      );

      return { ok: true, runId, recordsProcessed: 0, skipped: true, reason: 'same_hash' };
    }

    const addedEntries = entries.filter((e) => !previousSet.has(`${e.observableType}|${e.observable}`));
    const batchSize = Number(process.env.URLHAUS_BATCH_SIZE || 1000);

    for (let i = 0; i < addedEntries.length; i += batchSize) {
      const batch = addedEntries.slice(i, i + batchSize);
      await client.query('BEGIN');
      try {
        for (const entry of batch) {
          const { observable, observableType } = entry;
          const sourceName = config.urlhausSourceName;
          const sourceUrl = config.urlhausUrl;
          const confidence = 'high';
          const category = 'malware-url';
          const note = 'Auto-imported from URLhaus text list';

          const okObs = await insertObservable(client, {
            observable,
            observableType,
            sourceName,
            sourceUrl,
            confidence,
            category,
            note,
            dedupSource: config.urlhausSourceName
          });

          if (okObs) inserted += 1;
        }
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      }
    }

    await client.query(
      `INSERT INTO integration_source_state (source_name, content_hash, items_json, updated_at)
       VALUES ($1, $2, $3::jsonb, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET content_hash = EXCLUDED.content_hash, items_json = EXCLUDED.items_json, updated_at = NOW()`,
      [config.urlhausSourceName, currentHash, JSON.stringify(entries)]
    );

    await client.query(
      `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
      [config.urlhausSourceName, `hash:${currentHash}`]
    );

    await client.query(
      `UPDATE integration_runs
       SET status='success', finished_at=clock_timestamp(), records_processed=$2
       WHERE id=$1`,
      [runId, inserted]
    );

    return { ok: true, runId, recordsProcessed: inserted };
  } catch (err) {
    if (runId) {
      await client.query(
        `UPDATE integration_runs
         SET status='failed', finished_at=clock_timestamp(), error_message=$2
         WHERE id=$1`,
        [runId, String(err.message).slice(0, 4000)]
      );
    }

    throw err;
  } finally {
    try {
      await client.query('SELECT pg_advisory_unlock(942003)');
    } catch {
      // ignore
    }
    client.release();
  }
}
