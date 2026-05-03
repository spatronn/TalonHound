import './lib/ensure-db-password.js';
import pg from 'pg';
import { createHash } from 'node:crypto';
import IORedis from 'ioredis';
import { Queue } from 'bullmq';
import { getRedisUrl } from './lib/redis-url.js';
import { ensureIocCorrelationAssets, syncIocLookupFromPostgres, query as clickhouseQuery } from './lib/clickhouse.js';
import { findOrCreateActivity } from './lib/ioc-activity.js';
import { buildIncidentStatsSnapshot, buildIncidentVersion, shouldTriggerLlm } from './risk/llmRiskCommon.js';

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'demo'
});

const WORKER_NAME = process.env.IOC_CORRELATION_WORKER_NAME || 'clickhouse-ioc-correlation-v1';
const POLL_INTERVAL_MS = Math.max(Number(process.env.IOC_CORRELATION_POLL_INTERVAL_MS || 3000), 500);
const BATCH_SIZE = Math.max(Number(process.env.IOC_CORRELATION_BATCH_SIZE || 5000), 100);
const MAX_BATCHES_PER_TICK = Math.max(Number(process.env.IOC_CORRELATION_MAX_BATCHES_PER_TICK || 5), 1);
const DEDUP_WINDOW_SECONDS = Math.max(Number(process.env.IOC_CORRELATION_DEDUP_WINDOW_SECONDS || 300), 60);
const IOC_LOOKUP_SYNC_INTERVAL_SECONDS = Math.max(Number(process.env.IOC_LOOKUP_SYNC_INTERVAL_SECONDS || 1800), 60);
const IOC_LOOKUP_SYNC_BATCH_SIZE = Math.max(Number(process.env.IOC_LOOKUP_SYNC_BATCH_SIZE || 20000), 1000);
const CH_MAX_THREADS = Math.max(Number(process.env.IOC_CORRELATION_CH_MAX_THREADS || 2), 1);
const CH_MAX_EXECUTION_TIME_SECONDS = Math.max(Number(process.env.IOC_CORRELATION_CH_MAX_EXECUTION_TIME_SECONDS || 20), 5);
const REPLAY_WINDOW_SECONDS = Math.max(Number(process.env.IOC_CORRELATION_REPLAY_WINDOW_SECONDS || 600), 60);
const REPLAY_BATCH_SIZE = Math.max(Number(process.env.IOC_CORRELATION_REPLAY_BATCH_SIZE || 2000), 100);
const IOC_LOOKUP_SYNC_ENABLED = process.env.IOC_LOOKUP_SYNC_ENABLED === '1' || process.env.IOC_LOOKUP_SYNC_ENABLED === 'true';
const LLM_RISK_QUEUE_NAME = process.env.LLM_RISK_QUEUE_NAME || 'llm-risk-jobs';
const LLM_RISK_TRIGGER_ENABLED = process.env.LLM_RISK_TRIGGER_ENABLED !== '0';
const LLM_RISK_SNAPSHOT_TTL_SECONDS = Math.max(Number(process.env.LLM_RISK_SNAPSHOT_TTL_SECONDS || 7 * 24 * 3600), 3600);

const redisUrl = getRedisUrl();
const redis = new IORedis(redisUrl, { maxRetriesPerRequest: null });
const llmRiskQueue = new Queue(LLM_RISK_QUEUE_NAME, { connection: redis });

let stopping = false;
let lastIocLookupSyncAtMs = 0;
let lastReplayWindowAtMs = 0;
const REPLAY_WINDOW_RUN_INTERVAL_MS = Math.max(Number(process.env.IOC_CORRELATION_REPLAY_RUN_INTERVAL_MS || 300000), 15000);

function makeQueryId(name) {
  return `ioc-correlation:${name}:${Date.now().toString(36)}:${Math.random().toString(36).slice(2, 8)}`;
}

function esc(value) {
  return String(value || '').replace(/'/g, "''");
}

function formatChDateTime(value) {
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return '1970-01-01 00:00:00';
  return d.toISOString().slice(0, 19).replace('T', ' ');
}

function floorToBucket(tsIso, seconds) {
  const d = new Date(tsIso);
  const ms = d.getTime();
  const bucketMs = seconds * 1000;
  const floored = Math.floor(ms / bucketMs) * bucketMs;
  return new Date(floored).toISOString();
}

function dedupKeyOf(row) {
  return [
    row.match_type || 'unknown',
    row.matched_ioc || '',
    row.host || '',
    row.source || '',
    row.parser_source || 'unknown'
  ].join('|');
}

const MERGE_TYPES = new Set(['ipv4', 'domain', 'url', 'sha256']);

function canonicalizeUrlForMatch(v) {
  try {
    const u = new URL(String(v || '').trim());
    u.hostname = u.hostname.toLowerCase();
    if ((u.protocol === 'http:' && u.port === '80') || (u.protocol === 'https:' && u.port === '443')) u.port = '';
    if (!u.pathname) u.pathname = '/';
    return u.toString().toLowerCase();
  } catch {
    return String(v || '').trim().toLowerCase();
  }
}

function normalizeMergedObs(o) {
  if (!o || typeof o !== 'object') return null;
  const type = String(o.type || '').toLowerCase();
  const value = String(o.value || '').trim();
  const source = o.source === 'parser' ? 'parser' : 'generic';
  if (!MERGE_TYPES.has(type) || !value) return null;
  return { type, value, source };
}

function expandRowObservables(r) {
  const raw = r.merged_observables;
  if (raw != null && String(raw).trim() !== '' && String(raw).trim() !== '[]') {
    try {
      const arr = JSON.parse(String(raw));
      if (Array.isArray(arr) && arr.length > 0) {
        const out = [];
        for (const item of arr) {
          const n = normalizeMergedObs(item);
          if (n) out.push(n);
        }
        if (out.length) return out;
      }
    } catch {
      /* fall through to legacy */
    }
  }

  const legacy = [];
  if (r.ioc_query && String(r.ioc_query).trim()) {
    legacy.push({
      type: 'domain',
      value: String(r.ioc_query).toLowerCase(),
      source: 'parser'
    });
  }
  if (r.ioc_ip && String(r.ioc_ip).trim()) {
    legacy.push({ type: 'ipv4', value: String(r.ioc_ip), source: 'parser' });
  }
  return legacy;
}

function lookupTuplesForObs(obs) {
  const t = obs.type;
  const v = String(obs.value || '').trim();
  if (!v) return [];
  if (t === 'ipv4') return [[v, 'ip']];
  if (t === 'sha256') return [[v.toLowerCase(), 'sha256']];
  if (t === 'domain') {
    const lv = v.toLowerCase();
    return [
      [lv, 'domain'],
      [lv, 'url']
    ];
  }
  if (t === 'url') return [[canonicalizeUrlForMatch(v), 'url']];
  return [];
}

function pickBestLookup(a, b) {
  if (!a) return b || null;
  if (!b) return a;
  const ta = new Date(a.updated_at).getTime();
  const tb = new Date(b.updated_at).getTime();
  if (Number.isNaN(ta) && Number.isNaN(tb)) return a;
  if (Number.isNaN(ta)) return b;
  if (Number.isNaN(tb)) return a;
  if (tb !== ta) return tb > ta ? b : a;
  return Number(b.confidence || 0) > Number(a.confidence || 0) ? b : a;
}

function matchObsToLookup(obs, lookupMap) {
  const t = obs.type;
  const v = String(obs.value || '').trim();
  if (!v) return null;
  if (t === 'ipv4') {
    return lookupMap.get(`ip\t${v}`) || null;
  }
  if (t === 'sha256') {
    return lookupMap.get(`sha256\t${v.toLowerCase()}`) || null;
  }
  if (t === 'domain') {
    const lv = v.toLowerCase();
    return pickBestLookup(lookupMap.get(`domain\t${lv}`), lookupMap.get(`url\t${lv}`));
  }
  if (t === 'url') {
    const lv = v.toLowerCase();
    return pickBestLookup(lookupMap.get(`url\t${lv}`), lookupMap.get(`domain\t${lv}`));
  }
  return null;
}

function iocTypeForPg(obsType) {
  return obsType === 'ipv4' ? 'ip' : obsType;
}

function matchedIocValue(obs) {
  if (obs.type === 'ipv4') return obs.value;
  if (obs.type === 'domain' || obs.type === 'url' || obs.type === 'sha256') return obs.value.toLowerCase();
  return obs.value;
}

async function fetchIocLookupMatches(tupleList) {
  if (!tupleList.length) return new Map();
  const parts = tupleList.map(([obs, typ]) => `('${esc(obs)}','${esc(typ)}')`).join(',');
  const q = `
    SELECT observable, observable_type, confidence, source_name, updated_at
    FROM default.ioc_lookup_by_updated
    WHERE (observable, observable_type) IN (${parts})
    ORDER BY updated_at DESC
    LIMIT 1 BY observable, observable_type
    SETTINGS max_threads = ${CH_MAX_THREADS}, max_execution_time = ${CH_MAX_EXECUTION_TIME_SECONDS}
  `;
  const rows = await clickhouseQuery(q, { queryId: makeQueryId('lookup-batch'), logTag: 'ioc-correlation.lookup-batch' });
  const map = new Map();
  for (const row of rows || []) {
    const o = String(row.observable || '');
    const typ = String(row.observable_type || '');
    map.set(`${typ}\t${o}`, row);
  }
  return map;
}

function collectLookupTuplesForBatch(chRows) {
  const tupleSet = new Set();
  const tupleList = [];
  for (const r of chRows) {
    for (const obs of expandRowObservables(r)) {
      for (const pair of lookupTuplesForObs(obs)) {
        const k = `${pair[0]}\t${pair[1]}`;
        if (tupleSet.has(k)) continue;
        tupleSet.add(k);
        tupleList.push(pair);
      }
    }
  }
  return tupleList;
}

function parseKv(raw) {
  const out = {};
  const re = /(\w+)=((?:"[^"]*")|\S+)/g;
  let m;
  while ((m = re.exec(String(raw || ''))) !== null) {
    out[m[1]] = m[2].startsWith('"') && m[2].endsWith('"') ? m[2].slice(1, -1) : m[2];
  }
  return out;
}

function normalizeSourceType(r = {}, matchContext = {}) {
  const tokens = [r.parser_source, r.source, r.host, matchContext?.parsed_query, matchContext?.query_type]
    .map((v) => String(v || '').toLowerCase())
    .join(' ');
  if (/(proxy|url|http|webproxy|swg)/.test(tokens)) return 'proxy';
  if (/(^|\s)dns(\s|$)|resolver|query_type/.test(tokens)) return 'dns';
  if (/(waf|f5|asm|modsecurity|nginx-waf)/.test(tokens)) return 'waf';
  if (/(endpoint|edr|xdr|sysmon|process|file)/.test(tokens)) return 'endpoint';
  if (/(firewall|traffic|forti|palo|pan-os|checkpoint|netflow)/.test(tokens)) return 'firewall';
  return 'generic';
}

function rowToMatchEvents(r, lookupMap) {
  const out = [];
  const ingestMs = r.ingest_time ? new Date(r.ingest_time).getTime() : 0;
  const kv = parseKv(r.raw || '');
  for (const obs of expandRowObservables(r)) {
    const hit = matchObsToLookup(obs, lookupMap);
    if (!hit) continue;
    const iocUpdatedMs = hit.updated_at ? new Date(hit.updated_at).getTime() : 0;
    const iocWasPresent = ingestMs > 0 && iocUpdatedMs > 0 && iocUpdatedMs <= ingestMs;
    const matchedIoc = matchedIocValue(obs);
    const iocType = iocTypeForPg(obs.type);
    const rawLogSnapshot = r.raw ? String(r.raw) : null;
    const normalizedEvent = {
      source_type: null,
      src_ip: kv.srcip || kv.client_ip || kv.clientip || null,
      dst_ip: kv.dstip || r.parsed_ip || null,
      url: kv.url || null,
      domain: kv.query || r.parsed_query || null,
      method: kv.method || null,
      status: kv.status || null,
      action: kv.action || null,
      parser_source: r.parser_source || null,
      matched_ioc: matchedIoc,
      ioc_type: iocType
    };
    const matchContext = {
      parsed_query: r.parsed_query || null,
      parsed_ip: r.parsed_ip || null,
      ioc_query: r.ioc_query || null,
      ioc_ip: r.ioc_ip || null,
      response_ip: kv.response_ip || kv.responseip || null,
      client_ip: kv.client_ip || kv.clientip || null,
      query_type: kv.query_type || null,
      action: kv.action || null,
      srcip: kv.srcip || null,
      dstip: kv.dstip || null,
      dstport: kv.dstport || null,
      service: kv.service || null,
      sentbyte: kv.sentbyte || null,
      rcvdbyte: kv.rcvdbyte || null,
      processing_path: 'realtime',
      observable_merge_type: obs.type,
      detection_type: 'realtime',
      match_source: obs.source,
      ioc_was_present_at_ingest: iocWasPresent
    };
    const sourceType = normalizeSourceType(r, matchContext);
    normalizedEvent.source_type = sourceType;

    out.push({
      event_time: r.ts,
      host: r.host,
      source: r.source,
      parser_source: r.parser_source,
      destination_ip: r.parsed_ip || null,
      protocol: 'syslog',
      matched_ioc: matchedIoc,
      ioc_type: iocType,
      ioc_item_id: null,
      source_name: hit.source_name || null,
      confidence: String(hit.confidence != null ? hit.confidence : ''),
      detection_type: 'realtime',
      match_source: obs.source,
      match_context: matchContext,
      normalized_event_json: normalizedEvent,
      raw_log_snapshot: rawLogSnapshot,
      raw_log_hash: rawLogSnapshot ? createHash('sha256').update(rawLogSnapshot).digest('hex') : null,
      syslog_log_id: null,
      source_type: sourceType
    });
  }
  return out;
}

async function toMatchRowsFromScanned(chRows) {
  if (!chRows.length) return [];
  const tupleList = collectLookupTuplesForBatch(chRows);
  const lookupMap = await fetchIocLookupMatches(tupleList);
  const out = [];
  for (const r of chRows) {
    out.push(...rowToMatchEvents(r, lookupMap));
  }
  return out;
}

async function getOrInitState(client) {
  const q = await client.query(
    `SELECT worker_name, last_ts, last_row_hash
     FROM ioc_correlation_state
     WHERE worker_name = $1`,
    [WORKER_NAME]
  );

  if (q.rowCount) return q.rows[0];

  const init = await client.query(
    `INSERT INTO ioc_correlation_state (worker_name, last_ts, last_row_hash, batch_size)
     VALUES ($1, to_timestamp(0), 0, $2)
     RETURNING worker_name, last_ts, last_row_hash`,
    [WORKER_NAME, BATCH_SIZE]
  );
  return init.rows[0];
}

async function saveState(client, lastTs, lastRowHash) {
  await client.query(
    `UPDATE ioc_correlation_state
     SET last_ts = $2,
         last_row_hash = $3,
         batch_size = $4,
         updated_at = NOW()
     WHERE worker_name = $1`,
    [WORKER_NAME, lastTs, String(lastRowHash), BATCH_SIZE]
  );
}

function buildScanQuery(lastTs, lastRowHash, limit) {
  const ingestTs = esc(formatChDateTime(lastTs));
  const hash = String(lastRowHash || '0').replace(/[^0-9]/g, '') || '0';
  const lim = Number(limit || BATCH_SIZE);

  return `
    SELECT
      ts,
      ingest_time,
      source,
      host,
      parser_source,
      parsed_ip,
      parsed_query,
      ioc_ip,
      ioc_query,
      ifNull(merged_observables, '') AS merged_observables,
      ifNull(raw, '') AS raw,
      toString(cityHash64(concat(toString(ingest_time), '|', coalesce(source, ''), '|', coalesce(raw, '')))) AS row_hash
    FROM default.syslog_logs
    WHERE (
      ingest_time > toDateTime('${ingestTs}')
      OR (
        ingest_time = toDateTime('${ingestTs}')
        AND cityHash64(concat(toString(ingest_time), '|', coalesce(source, ''), '|', coalesce(raw, ''))) > toUInt64('${hash}')
      )
    )
      AND (
        (length(trim(ifNull(merged_observables, ''))) > 2 AND ifNull(merged_observables, '') != '[]')
        OR notEmpty(ifNull(ioc_query, ''))
        OR notEmpty(ifNull(ioc_ip, ''))
      )
    ORDER BY ingest_time, row_hash
    LIMIT ${lim}
    SETTINGS max_threads = ${CH_MAX_THREADS}, max_execution_time = ${CH_MAX_EXECUTION_TIME_SECONDS}
  `;
}

function buildReplayQuery(windowSeconds = REPLAY_WINDOW_SECONDS, limit = REPLAY_BATCH_SIZE) {
  const win = Math.max(Number(windowSeconds || REPLAY_WINDOW_SECONDS), 60);
  const lim = Math.max(Number(limit || REPLAY_BATCH_SIZE), 100);

  return `
    SELECT
      ts,
      ingest_time,
      source,
      host,
      parser_source,
      parsed_ip,
      parsed_query,
      ioc_ip,
      ioc_query,
      ifNull(merged_observables, '') AS merged_observables,
      ifNull(raw, '') AS raw,
      toString(cityHash64(concat(toString(ingest_time), '|', coalesce(source, ''), '|', coalesce(raw, '')))) AS row_hash
    FROM default.syslog_logs
    WHERE ingest_time >= now() - INTERVAL ${win} SECOND
      AND (
        (length(trim(ifNull(merged_observables, ''))) > 2 AND ifNull(merged_observables, '') != '[]')
        OR notEmpty(ifNull(ioc_query, ''))
        OR notEmpty(ifNull(ioc_ip, ''))
      )
    ORDER BY ingest_time DESC
    LIMIT ${lim}
    SETTINGS max_threads = ${CH_MAX_THREADS}, max_execution_time = ${CH_MAX_EXECUTION_TIME_SECONDS}
  `;
}

async function insertMatchEvents(client, rows) {
  if (!rows.length) return { inserted: 0, affectedActivityIds: [] };

  // Deduplicate same (dedup_key, bucket_start) inside this batch to avoid
  // "ON CONFLICT DO UPDATE command cannot affect row a second time".
  const uniq = new Map();
  for (const r of rows) {
    const bucketStart = floorToBucket(r.event_time, DEDUP_WINDOW_SECONDS);
    const dedupKey = dedupKeyOf({ ...r, match_type: r.ioc_type });
    const k = `${dedupKey}@@${bucketStart}`;

    const prev = uniq.get(k);
    if (!prev) {
      uniq.set(k, { ...r, _bucketStart: bucketStart, _dedupKey: dedupKey, _hitInc: 1 });
      continue;
    }

    prev._hitInc += 1;
    if (new Date(r.event_time).getTime() > new Date(prev.event_time).getTime()) {
      prev.event_time = r.event_time;
      prev.destination_ip = r.destination_ip;
      prev.protocol = r.protocol;
      prev.source_name = r.source_name || prev.source_name;
      prev.confidence = r.confidence || prev.confidence;
      prev.match_context = r.match_context || prev.match_context;
      prev.detection_type = r.detection_type || prev.detection_type;
      prev.match_source = r.match_source ?? prev.match_source;
    }
  }

  const normalizedRows = Array.from(uniq.values());
  const values = [];
  const params = [];
  const activityCache = new Map();
  const affectedActivityIds = new Set();

  for (let i = 0; i < normalizedRows.length; i += 1) {
    const r = normalizedRows[i];
    const activity = await findOrCreateActivity(client, {
      iocValue: r.matched_ioc,
      iocType: r.ioc_type,
      eventTime: r.event_time,
      hitCount: r._hitInc,
      cache: activityCache
    });
    if (activity?.id) affectedActivityIds.add(String(activity.id));

    const base = i * 26;

    values.push(`($${base + 1},$${base + 2},$${base + 3},$${base + 4},$${base + 5},$${base + 6},$${base + 7},$${base + 8},$${base + 9},$${base + 10},$${base + 11},$${base + 12},$${base + 13},$${base + 14},$${base + 15},$${base + 16},$${base + 17},$${base + 18},$${base + 19},$${base + 20},$${base + 21},$${base + 22},$${base + 23},$${base + 24},$${base + 25},$${base + 26})`);
    params.push(
      r.event_time,
      r.host || null,
      null, // process_name
      r.destination_ip || null,
      null, // destination_port
      r.protocol || null,
      r.matched_ioc,
      r.source_name || null,
      r.confidence || null,
      r.ioc_type,
      r.ioc_item_id,
      r.parser_source || null,
      r.source || null,
      JSON.stringify(r.match_context || {}),
      r._dedupKey,
      r._bucketStart,
      r.event_time, // last_seen_at seed
      r._hitInc,
      r.detection_type || 'realtime',
      r.match_source ?? null,
      activity?.id || null,
      r.normalized_event_json ? JSON.stringify(r.normalized_event_json) : null,
      r.raw_log_snapshot || null,
      r.raw_log_hash || null,
      r.syslog_log_id || null,
      r.source_type || null
    );
  }

  const sql = `
    INSERT INTO ioc_match_events (
      event_time, host_name, process_name, destination_ip, destination_port, protocol,
      matched_ioc, source_name, confidence, ioc_type, ioc_item_id,
      parser_source, source, match_context, dedup_key, bucket_start, last_seen_at, hit_count,
      detection_type, match_source, activity_id,
      normalized_event_json, raw_log_snapshot, raw_log_hash, syslog_log_id, source_type
    ) VALUES ${values.join(',')}
    ON CONFLICT (dedup_key, bucket_start)
    DO UPDATE SET
      hit_count = ioc_match_events.hit_count + EXCLUDED.hit_count,
      last_seen_at = GREATEST(ioc_match_events.last_seen_at, EXCLUDED.last_seen_at),
      confidence = COALESCE(EXCLUDED.confidence, ioc_match_events.confidence),
      source_name = COALESCE(EXCLUDED.source_name, ioc_match_events.source_name),
      match_context = COALESCE(EXCLUDED.match_context, ioc_match_events.match_context),
      detection_type = CASE
        WHEN COALESCE(ioc_match_events.detection_type, 'realtime') = 'realtime' THEN ioc_match_events.detection_type
        ELSE COALESCE(EXCLUDED.detection_type, ioc_match_events.detection_type)
      END,
      match_source = COALESCE(EXCLUDED.match_source, ioc_match_events.match_source),
      activity_id = COALESCE(EXCLUDED.activity_id, ioc_match_events.activity_id)
  `;

  await client.query(sql, params);
  const withRaw = normalizedRows.filter((r) => Boolean(r.raw_log_snapshot)).length;
  const withNorm = normalizedRows.filter((r) => Boolean(r.normalized_event_json)).length;
  console.info(`[ioc-event-create] inserted=${normalizedRows.length} source_type_sample=${normalizedRows[0]?.source_type || 'unknown'} has_raw_log_snapshot=${withRaw > 0} has_normalized_event_json=${withNorm > 0}`);
  return { inserted: normalizedRows.length, affectedActivityIds: Array.from(affectedActivityIds) };
}

async function runBatch() {
  const startedAtMs = Date.now();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const state = await getOrInitState(client);
    const query = buildScanQuery(state.last_ts, state.last_row_hash, BATCH_SIZE);
    const scanned = await clickhouseQuery(query, { queryId: makeQueryId('scan-batch'), logTag: 'ioc-correlation.scan-batch' });

    if (!scanned.length) {
      await client.query('COMMIT');
      return { scanned: 0, matched: 0, inserted: 0, affectedActivityIds: [], duration_ms: Date.now() - startedAtMs };
    }

    const matchedRows = await toMatchRowsFromScanned(scanned);
    const insertResult = await insertMatchEvents(client, matchedRows);

    const last = scanned[scanned.length - 1];
    await saveState(client, last.ingest_time || last.ts, last.row_hash);
    await client.query('COMMIT');

    return {
      scanned: scanned.length,
      matched: matchedRows.length,
      inserted: insertResult.inserted,
      affectedActivityIds: insertResult.affectedActivityIds,
      last_ts: last.ingest_time || last.ts,
      last_row_hash: last.row_hash,
      duration_ms: Date.now() - startedAtMs
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function loadIncidentSnapshotsByIds(ids = []) {
  if (!ids.length) return [];
  const placeholders = ids.map((_, i) => `$${i + 1}`).join(',');
  const q = await pool.query(
    `SELECT
       a.id,
       a.total_hits,
       a.verdict,
       COUNT(m.*)::bigint AS total_events,
       COUNT(DISTINCT COALESCE(NULLIF(m.destination_ip, ''), NULLIF(m.host_name, '')))::int AS unique_hosts,
       SUM(CASE WHEN LOWER(COALESCE(m.match_context->>'action', '')) IN ('accept','accepted','allow','allowed','permit') THEN 1 ELSE 0 END)::bigint AS accepted_connections,
       SUM(CASE WHEN LOWER(COALESCE(m.match_context->>'action', '')) IN ('deny','denied','drop','blocked','block') THEN 1 ELSE 0 END)::bigint AS blocked_connections,
       SUM(CASE
             WHEN LOWER(COALESCE(m.match_context->>'list', '')) = 'blacklist'
               OR LOWER(COALESCE(m.match_context->>'threat_list', '')) = 'blacklist'
               OR LOWER(COALESCE(m.source_name, '')) LIKE '%blacklist%'
             THEN 1 ELSE 0
           END)::bigint AS blacklist_hits
     FROM ioc_activity a
     LEFT JOIN ioc_match_events m ON m.activity_id = a.id
     WHERE a.id IN (${placeholders})
     GROUP BY a.id, a.total_hits, a.verdict`,
    ids
  );

  return q.rows || [];
}

async function maybeTriggerLlmForActivityIds(activityIds = []) {
  if (!LLM_RISK_TRIGGER_ENABLED || !activityIds.length) return;

  try {
    const incidents = await loadIncidentSnapshotsByIds(activityIds);
    for (const row of incidents) {
      const snapshot = buildIncidentStatsSnapshot(row);
      const incidentId = String(snapshot.incident_id || row.id || '');
      if (!incidentId) continue;

      const snapshotKey = `risk:llm:snapshot:incident:${incidentId}`;
      let prevSnapshot = null;
      try {
        const prevRaw = await redis.get(snapshotKey);
        prevSnapshot = prevRaw ? JSON.parse(prevRaw) : null;
      } catch {
        prevSnapshot = null;
      }

      const decision = shouldTriggerLlm(prevSnapshot, snapshot);
      try {
        await redis.set(snapshotKey, JSON.stringify(snapshot), 'EX', LLM_RISK_SNAPSHOT_TTL_SECONDS);
      } catch {
        // ignore snapshot cache failures
      }

      if (!decision.trigger) continue;

      const version = buildIncidentVersion(snapshot);
      try {
        await llmRiskQueue.add(
          'llm-risk-evaluate',
          { incidentId, version, reason: decision.reason },
          {
            jobId: `llm-risk:${incidentId}:${version}`,
            removeOnComplete: true,
            removeOnFail: 200,
            attempts: 1
          }
        );
      } catch {
        // no-op
      }
    }
  } catch (err) {
    console.error('[ioc-correlation] llm-trigger failed', err?.message || err);
  }
}

async function tick() {
  let totalScanned = 0;
  let totalMatched = 0;
  let totalInserted = 0;
  let totalDurationMs = 0;
  const affectedActivityIds = new Set();

  for (let i = 0; i < MAX_BATCHES_PER_TICK; i += 1) {
    const result = await runBatch();
    totalScanned += result.scanned;
    totalMatched += result.matched;
    totalInserted += result.inserted;
    for (const id of (result.affectedActivityIds || [])) affectedActivityIds.add(String(id));
    totalDurationMs += Number(result.duration_ms || 0);
    if (result.scanned < BATCH_SIZE) break;
  }

  // Replay window to catch out-of-order arrivals near ingest boundary; dedup prevents duplicate events.
  let replayScanned = 0;
  let replayMatched = 0;
  let replayInserted = 0;
  let lateArrivalCount = 0;
  const nowMs = Date.now();
  const shouldRunReplay = (nowMs - lastReplayWindowAtMs) >= REPLAY_WINDOW_RUN_INTERVAL_MS;

  if (shouldRunReplay) {
    try {
      const replayRows = await clickhouseQuery(buildReplayQuery(), { queryId: makeQueryId('replay-window'), logTag: 'ioc-correlation.replay-window' });
      replayScanned = replayRows.length;
      lastReplayWindowAtMs = nowMs;
      if (replayRows.length) {
        const mapped = await toMatchRowsFromScanned(replayRows);
        replayMatched = mapped.length;
        lateArrivalCount = replayRows.filter((r) => {
          const ets = r?.ts ? new Date(r.ts).getTime() : 0;
          const its = r?.ingest_time ? new Date(r.ingest_time).getTime() : 0;
          return ets > 0 && its > 0 && (its - ets) > 60_000;
        }).length;
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          const replayInsertResult = await insertMatchEvents(client, mapped);
          replayInserted = replayInsertResult.inserted;
          for (const id of (replayInsertResult.affectedActivityIds || [])) affectedActivityIds.add(String(id));
          await client.query('COMMIT');
        } catch (err) {
          await client.query('ROLLBACK');
          throw err;
        } finally {
          client.release();
        }
      }
    } catch (err) {
      console.error('[ioc-correlation] replay-window failed', err?.message || err);
    }
  }

  if (affectedActivityIds.size > 0) {
    await maybeTriggerLlmForActivityIds(Array.from(affectedActivityIds));
  }

  if (totalScanned > 0 || replayScanned > 0) {
    console.log(`[ioc-correlation] realtime_scanned=${totalScanned} realtime_matched=${totalMatched} realtime_inserted=${totalInserted} replay_scanned=${replayScanned} replay_matched=${replayMatched} replay_inserted=${replayInserted} llm_trigger_candidates=${affectedActivityIds.size} late_arrival_count=${lateArrivalCount} duration_ms=${totalDurationMs} replay_ran=${shouldRunReplay}`);
  }
}


async function maybeSyncIocLookup(force = false) {
  if (!IOC_LOOKUP_SYNC_ENABLED) return false;
  const now = Date.now();
  if (!force && (now - lastIocLookupSyncAtMs) < (IOC_LOOKUP_SYNC_INTERVAL_SECONDS * 1000)) return false;
  const syncRes = await syncIocLookupFromPostgres({ workerName: 'ioc-correlation-sync-v1', batchSize: IOC_LOOKUP_SYNC_BATCH_SIZE });
  lastIocLookupSyncAtMs = now;
  console.log(`[ioc-correlation] ioc_lookup sync completed interval_s=${IOC_LOOKUP_SYNC_INTERVAL_SECONDS} changed=${Boolean(syncRes?.changed)}`);
  return true;
}


async function bootstrap() {
  await ensureIocCorrelationAssets();
  await maybeSyncIocLookup(true);
  console.log(`[ioc-correlation] started worker=${WORKER_NAME} poll_ms=${POLL_INTERVAL_MS} batch=${BATCH_SIZE} dedup_window_s=${DEDUP_WINDOW_SECONDS} replay_window_s=${REPLAY_WINDOW_SECONDS} replay_batch=${REPLAY_BATCH_SIZE}`);

  while (!stopping) {
    try {
      await maybeSyncIocLookup(false);
      await tick();
    } catch (err) {
      console.error('[ioc-correlation] tick failed', err?.message || err);
    }
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
}

async function shutdown(code = 0) {
  stopping = true;
  try { await llmRiskQueue.close(); } catch {}
  try { await redis.quit(); } catch {}
  try { await pool.end(); } catch {}
  process.exit(code);
}

process.on('SIGINT', async () => {
  await shutdown(0);
});

process.on('SIGTERM', async () => {
  await shutdown(0);
});

bootstrap().catch(async (err) => {
  console.error('[ioc-correlation] bootstrap failed', err?.message || err);
  await shutdown(1);
});
