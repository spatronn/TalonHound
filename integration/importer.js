import pg from 'pg';
import { createHash } from 'node:crypto';
import { strFromU8, unzipSync } from 'fflate';
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

/** Allowed observable_type values for ioc_observables index (source-agnostic). */
const OBSERVABLE_INDEX_TYPES = new Set([
  'md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh',
  'ip', 'ip6', 'domain', 'url'
]);

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

function normalizeObservableValue(observableType, value) {
  if (!value || typeof value !== 'string') return '';
  const v = value.trim();
  const t = String(observableType || '').toLowerCase();
  if (['md5', 'sha1', 'sha256', 'imphash', 'tlsh', 'domain', 'url'].includes(t)) return v.toLowerCase();
  if (t === 'ssdeep') return v.toLowerCase();
  return v;
}

/**
 * Extract all searchable observables from primary observable + note (key=value).
 * Returns deduplicated list of { observable_type, observable_value } (normalized).
 * Used to populate ioc_observables index so any hash/ip/domain/url is searchable.
 */
export function extractObservablesFromNote(primaryType, primaryValue, note) {
  const seen = new Set();
  const out = [];
  const add = (type, value) => {
    if (!OBSERVABLE_INDEX_TYPES.has(type)) return;
    const normalized = normalizeObservableValue(type, value);
    if (!normalized) return;
    const key = `${type}:${normalized}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ observable_type: type, observable_value: normalized });
  };

  add(primaryType, primaryValue);
  const kv = parseNoteKeyValues(note);
  for (const [k, v] of Object.entries(kv)) {
    if (OBSERVABLE_INDEX_TYPES.has(k)) add(k, v);
  }
  return out;
}

async function insertObservablesIndex(client, iocPublicId, observables) {
  if (!observables.length) return;
  for (const { observable_type, observable_value } of observables) {
    await client.query(
      `INSERT INTO ioc_observables (ioc_public_id, observable_type, observable_value)
       VALUES ($1, $2, $3)
       ON CONFLICT (ioc_public_id, observable_type, observable_value) DO NOTHING`,
      [iocPublicId, observable_type, observable_value]
    );
  }
}

function splitCsvLine(line) {
  const out = [];
  let cur = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        cur += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (ch === ',' && !inQuotes) {
      out.push(cur.trim());
      cur = '';
      continue;
    }
    cur += ch;
  }
  out.push(cur.trim());
  return out;
}

function mapThreatFoxConfidence(level) {
  const n = Number(level);
  if (Number.isNaN(n)) return 'medium';
  if (n >= 80) return 'high';
  if (n >= 50) return 'medium';
  return 'low';
}

async function readThreatFoxCsvText(response) {
  const bytes = new Uint8Array(await response.arrayBuffer());
  const looksZip = bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b;

  if (!looksZip) {
    return new TextDecoder('utf-8').decode(bytes);
  }

  const files = unzipSync(bytes);
  const names = Object.keys(files);
  if (!names.length) return '';

  const csvName = names.find((n) => n.toLowerCase().endsWith('.csv')) || names[0];
  return strFromU8(files[csvName]);
}

function classifyThreatFoxObservable(iocValue, iocType) {
  const raw = String(iocValue || '').trim();
  const type = String(iocType || '').trim().toLowerCase();
  if (!raw) return null;

  if (type === 'ip:port') {
    const [host] = raw.split(':');
    if (!host) return null;
    if (isIPv4(host)) return { observable: host, observableType: 'ip' };
    return null;
  }

  if (type === 'ip') {
    if (isIPv4(raw) || isCIDR(raw)) return { observable: raw, observableType: 'ip' };
    return null;
  }

  if (type === 'url') return { observable: raw, observableType: 'url' };
  if (type === 'domain') return { observable: raw, observableType: 'domain' };

  return null;
}

function hashEntries(entries) {
  return createHash('sha256').update(JSON.stringify(entries)).digest('hex');
}

const BATCH_INSERT_CHUNK = Math.min(Math.max(Number(process.env.IOC_BATCH_INSERT_CHUNK || 150), 50), 500);

/**
 * ET feed gibi tek tip (ip) toplu ekleme: tek sorguda chunk kadar satır, WHERE NOT EXISTS ile dedup.
 * idempotent ekleme: aynı feed tekrar çalışırsa INSERT no-op (WHERE NOT EXISTS).
 */
async function batchInsertIocs(client, entries, observableType = 'ip') {
  if (!entries.length) return 0;
  let totalInserted = 0;
  const now = new Date();
  for (let i = 0; i < entries.length; i += BATCH_INSERT_CHUNK) {
    const chunk = entries.slice(i, i + BATCH_INSERT_CHUNK);
    const placeholders = [];
    const params = [];
    chunk.forEach((e, idx) => {
      const off = idx * 8;
      placeholders.push(`($${off + 1}::text, $${off + 2}::text, $${off + 3}::text, $${off + 4}::text, $${off + 5}::text, $${off + 6}::text, $${off + 7}::timestamptz, $${off + 8}::timestamptz)`);
      params.push(
        e.observable ?? e.ip,
        e.sourceName,
        e.sourceUrl ?? null,
        e.confidence,
        e.category ?? null,
        e.note ?? null,
        now,
        now
      );
    });
    const typeParam = chunk.length * 8 + 1;
    const valuesList = placeholders.join(',\n');
    const ins = await client.query(
      `INSERT INTO ioc_items (observable, observable_type, source_name, source_url, confidence, category, note, first_seen_at, last_seen_at)
       SELECT v.observable, $${typeParam}::text, v.source_name, v.source_url, v.confidence, v.category, v.note, v.first_seen_at, v.last_seen_at
       FROM (VALUES ${valuesList}) AS v(observable, source_name, source_url, confidence, category, note, first_seen_at, last_seen_at)
       WHERE NOT EXISTS (
         SELECT 1 FROM ioc_items i
         WHERE i.observable = v.observable AND i.observable_type = $${typeParam}
           AND i.source_name = v.source_name AND i.confidence = v.confidence
           AND COALESCE(i.category, '') = COALESCE(v.category, '')
           AND COALESCE(i.source_url, '') = COALESCE(v.source_url, '')
       )
       RETURNING public_id, observable, note`,
      [...params.flat(), observableType]
    );
    const rows = ins.rows ?? [];
    totalInserted += rows.length;
    for (const row of rows) {
      const observables = extractObservablesFromNote(observableType, row.observable, row.note);
      await insertObservablesIndex(client, row.public_id, observables);
    }
  }
  return totalInserted;
}

async function insertObservable(client, { observable, observableType, sourceName, sourceUrl, confidence, category, note }) {
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
     RETURNING public_id`,
    [observable, observableType, sourceName, sourceUrl, confidence, category, note]
  );

  if (!ins.rowCount) return false;

  const publicId = ins.rows[0].public_id;
  const observables = extractObservablesFromNote(observableType, observable, note);
  await insertObservablesIndex(client, publicId, observables);
  return true;
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
      const note = `Auto-imported from ET blockrules (${file})`;

      const entries = ips.map((ip) => ({
        ip,
        sourceName,
        sourceUrl,
        confidence,
        category,
        note
      }));
      inserted += await batchInsertIocs(client, entries, 'ip');
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
            note
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
            note
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

export async function runThreatfoxImport() {
  const client = await pool.connect();
  let runId = null;

  try {
    const lockResult = await client.query('SELECT pg_try_advisory_lock(942004) AS acquired');
    if (!lockResult.rows[0]?.acquired) {
      return { skipped: true, reason: 'lock_not_acquired' };
    }

    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('threatfox_import', 'running', clock_timestamp(), 'scheduler')
       RETURNING id`
    );
    runId = runInsert.rows[0].id;

    let inserted = 0;

    const res = await fetch(config.threatfoxCsvUrl);
    if (!res.ok) throw new Error(`ThreatFox CSV request failed: ${res.status}`);
    const txt = await readThreatFoxCsvText(res);

    const entries = txt
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'))
      .map((line) => splitCsvLine(line))
      .filter((cols) => cols.length >= 15)
      .map((cols) => {
        const observable = classifyThreatFoxObservable(cols[2], cols[3]);
        if (!observable) return null;
        return {
          ...observable,
          iocId: cols[1],
          threatType: cols[4],
          malwarePrintable: cols[7],
          confidence: mapThreatFoxConfidence(cols[9]),
          reference: cols[11],
          tags: cols[12],
          reporter: cols[14]
        };
      })
      .filter(Boolean)
      .sort((a, b) => `${a.observableType}|${a.observable}`.localeCompare(`${b.observableType}|${b.observable}`));

    const currentHash = hashEntries(entries.map((e) => ({ o: e.observable, t: e.observableType, id: e.iocId })));

    const prevState = await client.query(
      `SELECT content_hash, items_json
       FROM integration_source_state
       WHERE source_name = $1`,
      [config.threatfoxSourceName]
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
        [config.threatfoxSourceName, `hash:${currentHash}`]
      );

      return { ok: true, runId, recordsProcessed: 0, skipped: true, reason: 'same_hash' };
    }

    const addedEntries = entries.filter((e) => !previousSet.has(`${e.observableType}|${e.observable}`));
    const batchSize = Number(process.env.THREATFOX_BATCH_SIZE || 1000);

    for (let i = 0; i < addedEntries.length; i += batchSize) {
      const batch = addedEntries.slice(i, i + batchSize);
      await client.query('BEGIN');
      try {
        for (const entry of batch) {
          const noteParts = [
            'Auto-imported from ThreatFox CSV',
            entry.iocId ? `ioc_id=${entry.iocId}` : null,
            entry.malwarePrintable ? `malware=${entry.malwarePrintable}` : null,
            entry.reporter ? `reporter=${entry.reporter}` : null,
            entry.tags ? `tags=${entry.tags}` : null
          ].filter(Boolean);

          const okObs = await insertObservable(client, {
            observable: entry.observable,
            observableType: entry.observableType,
            sourceName: config.threatfoxSourceName,
            sourceUrl: config.threatfoxCsvUrl,
            confidence: entry.confidence,
            category: entry.threatType || 'threat-intel',
            note: noteParts.join(' | ')
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
      [config.threatfoxSourceName, currentHash, JSON.stringify(entries.map((e) => ({ observable: e.observable, observableType: e.observableType })))]
    );

    await client.query(
      `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
      [config.threatfoxSourceName, `hash:${currentHash}`]
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
      await client.query('SELECT pg_advisory_unlock(942004)');
    } catch {
      // ignore
    }
    client.release();
  }
}

function toNullable(value) {
  const v = String(value ?? '').trim();
  if (!v) return null;
  if (v.toLowerCase() === 'n/a') return null;
  return v;
}

function parseUtcTimestamp(value) {
  const raw = toNullable(value);
  if (!raw) return null;
  const normalized = raw.replace(' ', 'T');
  const dt = new Date(`${normalized}Z`);
  if (Number.isNaN(dt.getTime())) return null;
  return dt;
}

function mapMalwareBazaarRow(cols) {
  if (!Array.isArray(cols) || cols.length < 14) return null;

  const firstSeenUtc = parseUtcTimestamp(cols[0]);
  const sha256 = toNullable(cols[1])?.toLowerCase();
  if (!sha256 || !/^[a-f0-9]{64}$/.test(sha256)) return null;

  const signature = toNullable(cols[8]);
  const vtPercentRaw = toNullable(cols[10]);
  const confidence = vtPercentRaw && /^\d{1,3}$/.test(vtPercentRaw)
    ? (Number(vtPercentRaw) >= 70 ? 'high' : Number(vtPercentRaw) >= 30 ? 'medium' : 'low')
    : (signature ? 'high' : 'medium');

  const category = signature || 'malware-sample';

  const noteParts = [
    'Auto-imported from MalwareBazaar CSV',
    toNullable(cols[5]) ? `file_name=${toNullable(cols[5])}` : null,
    toNullable(cols[6]) ? `file_type=${toNullable(cols[6])}` : null,
    toNullable(cols[7]) ? `mime=${toNullable(cols[7])}` : null,
    toNullable(cols[4]) ? `reporter=${toNullable(cols[4])}` : null,
    toNullable(cols[2]) ? `md5=${toNullable(cols[2])}` : null,
    toNullable(cols[3]) ? `sha1=${toNullable(cols[3])}` : null,
    toNullable(cols[11]) ? `imphash=${toNullable(cols[11])}` : null,
    toNullable(cols[12]) ? `ssdeep=${toNullable(cols[12])}` : null,
    toNullable(cols[13]) ? `tlsh=${toNullable(cols[13])}` : null,
    vtPercentRaw ? `vtpercent=${vtPercentRaw}` : null
  ].filter(Boolean);

  return {
    observable: sha256,
    observableType: 'sha256',
    firstSeenUtc,
    confidence,
    category,
    note: noteParts.join(' | ')
  };
}

export async function runMalwareBazaarImport() {
  const client = await pool.connect();
  let runId = null;

  try {
    const lockResult = await client.query('SELECT pg_try_advisory_lock(942005) AS acquired');
    if (!lockResult.rows[0]?.acquired) {
      return { skipped: true, reason: 'lock_not_acquired' };
    }

    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('malwarebazaar_import', 'running', clock_timestamp(), 'scheduler')
       RETURNING id`
    );
    runId = runInsert.rows[0].id;

    const cpRes = await client.query(
      `SELECT last_cursor
       FROM integration_checkpoints
       WHERE source_name = $1`,
      [config.malwareBazaarSourceName]
    );

    const previousCursor = cpRes.rows[0]?.last_cursor || null;
    const previousCursorDate = previousCursor ? new Date(previousCursor) : null;

    let inserted = 0;
    let processed = 0;
    let maxSeenDate = previousCursorDate;

    const res = await fetch(config.malwareBazaarCsvUrl);
    if (!res.ok) throw new Error(`MalwareBazaar CSV request failed: ${res.status}`);
    const txt = await readThreatFoxCsvText(res);

    const lines = txt.split(/\r?\n/);
    let olderStreak = 0;
    const stopAfterOlderStreak = Number(process.env.MALWARE_BAZAAR_OLDER_STREAK || 5000);

    const batch = [];
    const flushBatch = async () => {
      if (!batch.length) return;
      await client.query('BEGIN');
      try {
        for (const entry of batch) {
          const okObs = await insertObservable(client, {
            observable: entry.observable,
            observableType: entry.observableType,
            sourceName: config.malwareBazaarSourceName,
            sourceUrl: config.malwareBazaarCsvUrl,
            confidence: entry.confidence,
            category: entry.category,
            note: entry.note
          });

          if (okObs) inserted += 1;
        }
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      } finally {
        batch.length = 0;
      }
    };

    const batchSize = Number(process.env.MALWARE_BAZAAR_BATCH_SIZE || 1000);

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;

      const cols = splitCsvLine(line);
      if (cols.length < 14) continue;
      if (String(cols[0]).toLowerCase().includes('first_seen_utc')) continue;

      const entry = mapMalwareBazaarRow(cols);
      if (!entry) continue;

      processed += 1;

      if (entry.firstSeenUtc && (!maxSeenDate || entry.firstSeenUtc > maxSeenDate)) {
        maxSeenDate = entry.firstSeenUtc;
      }

      if (previousCursorDate && entry.firstSeenUtc && entry.firstSeenUtc <= previousCursorDate) {
        olderStreak += 1;
        if (olderStreak >= stopAfterOlderStreak) break;
        continue;
      }

      olderStreak = 0;
      batch.push(entry);
      if (batch.length >= batchSize) {
        await flushBatch();
      }
    }

    await flushBatch();

    const nextCursor = maxSeenDate ? maxSeenDate.toISOString() : previousCursor || new Date().toISOString();

    await client.query(
      `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (source_name)
       DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
      [config.malwareBazaarSourceName, nextCursor]
    );

    await client.query(
      `UPDATE integration_runs
       SET status='success', finished_at=clock_timestamp(), records_processed=$2
       WHERE id=$1`,
      [runId, inserted]
    );

    return { ok: true, runId, recordsProcessed: inserted, parsedRecords: processed, cursor: nextCursor };
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
      await client.query('SELECT pg_advisory_unlock(942005)');
    } catch {
      // ignore
    }
    client.release();
  }
}

export async function runPhishtankImport() {
  const client = await pool.connect();
  let runId = null;

  try {
    await client.query('BEGIN');

    const lockResult = await client.query('SELECT pg_try_advisory_lock(942006) AS acquired');
    if (!lockResult.rows[0]?.acquired) {
      await client.query('ROLLBACK');
      return { skipped: true, reason: 'lock_not_acquired' };
    }

    const runInsert = await client.query(
      `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
       VALUES ('phishtank_import', 'running', clock_timestamp(), 'scheduler')
       RETURNING id`
    );
    runId = runInsert.rows[0].id;

    const response = await fetch(config.phishTankCsvUrl, {
      headers: { 'User-Agent': 'demo-runbook-integration/1.0' }
    });
    if (!response.ok) throw new Error(`Failed to fetch PhishTank CSV: ${response.status}`);

    const text = await response.text();
    const lines = text.split(/\r?\n/).filter(Boolean);
    if (lines.length <= 1) {
      await client.query(
        `UPDATE integration_runs
         SET status='success', finished_at=clock_timestamp(), records_processed=0
         WHERE id=$1`,
        [runId]
      );
      await client.query('COMMIT');
      return { ok: true, runId, recordsProcessed: 0, parsedRecords: 0 };
    }

    let inserted = 0;
    let parsed = 0;
    const sourceName = config.phishTankSourceName;
    const sourceUrl = config.phishTankCsvUrl;

    // online-valid.csv header: phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
    for (let i = 1; i < lines.length; i += 1) {
      const cols = splitCsvLine(lines[i]);
      if (!cols.length) continue;
      const url = String(cols[1] || '').trim();
      if (!url || !/^https?:\/\//i.test(url)) continue;
      // Guard against oversized TEXT index entries in Postgres (btree tuple limit).
      if (url.length > 1800) continue;
      parsed += 1;

      const ok = await insertObservable(client, {
        observable: url,
        observableType: 'url',
        sourceName,
        sourceUrl,
        confidence: 'high',
        category: 'phishing',
        note: 'Auto-imported from PhishTank online-valid.csv'
      });
      if (ok) inserted += 1;
    }

    await client.query(
      `UPDATE integration_runs
       SET status='success', finished_at=clock_timestamp(), records_processed=$2
       WHERE id=$1`,
      [runId, inserted]
    );

    await client.query('COMMIT');
    return { ok: true, runId, recordsProcessed: inserted, parsedRecords: parsed };
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
      await client.query('SELECT pg_advisory_unlock(942006)');
    } catch {
      // ignore
    }
    client.release();
  }
}
