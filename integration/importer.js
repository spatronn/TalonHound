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
            note: noteParts.join(' | '),
            dedupSource: config.threatfoxSourceName
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
            note: entry.note,
            dedupSource: config.malwareBazaarSourceName
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
