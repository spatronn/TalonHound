import dgram from "dgram";
import http from "http";
import crypto from "crypto";
import pg from "pg";
import { insertLogs, insertObservables, ensureSyslogTable, pingClickhouse } from "./lib/clickhouse.js";

const { Pool } = pg;

const LOG_STORAGE = (process.env.LOG_STORAGE || "postgres").toLowerCase();
const USE_CLICKHOUSE = LOG_STORAGE === "clickhouse";

const SYSLOG_PORT = Number(process.env.SYSLOG_PORT || 514);
const SYSLOG_HOST = process.env.SYSLOG_HOST || "0.0.0.0";
const HEALTH_PORT = Number(process.env.SYSLOG_HEALTH_PORT || 8081);
const FLUSH_INTERVAL_MS = Math.max(Number(process.env.SYSLOG_FLUSH_INTERVAL_MS || 150), 50);
const BATCH_SIZE = Math.max(Number(process.env.SYSLOG_BATCH_SIZE || 5000), 10);
const MAX_BUFFERED = Math.max(Number(process.env.SYSLOG_MAX_BUFFERED || 100000), BATCH_SIZE);
const FLUSH_WORKERS = Math.max(Number(process.env.SYSLOG_FLUSH_WORKERS || 1), 1);
const SOCKET_RCVBUF = Math.max(Number(process.env.SYSLOG_SOCKET_RCVBUF || 8 * 1024 * 1024), 256 * 1024);
const OVERFLOW_POLICY = String(process.env.SYSLOG_OVERFLOW_POLICY || "drop_oldest").toLowerCase();

const pool = new Pool({
  host: process.env.DB_HOST || "db",
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || "demo",
  password: process.env.DB_PASSWORD || "demo123",
  database: process.env.DB_NAME || "demo",
  max: Math.max(FLUSH_WORKERS + 2, 6)
});

const udp = dgram.createSocket({ type: "udp4", reuseAddr: true });
const queue = [];
let flushingWorkers = 0;
let flushTimer = null;
let flushInFlight = null;

function makeQueryId(name) {
  return `syslog-receiver:${name}:${Date.now().toString(36)}:${Math.random().toString(36).slice(2, 8)}`;
}

const metrics = {
  storage_backend: LOG_STORAGE,
  received_logs: 0,
  dropped_logs: 0,
  dropped_queue_full: 0,
  insert_errors: 0,
  inserted_logs: 0,
  enqueued_logs: 0,
  flush_runs: 0,
  flush_duration_ms_last: 0,
  flush_duration_ms_max: 0,
  queue_depth_high_watermark: 0,
  socket_recv_buffer_size: null,
  clickhouse_insert_latency: 0,
  clickhouse_insert_latency_max: 0,
  batch_size_avg: 0,
  flush_time_avg: 0,
  last_flush_at: null,
  started_at: new Date().toISOString()
};

const sev = ["emerg","alert","crit","err","warning","notice","info","debug"];
const fac = ["kern","user","mail","daemon","auth","syslog","lpr","news","uucp","clock","authpriv","ftp","ntp","audit","alert","clock2","local0","local1","local2","local3","local4","local5","local6","local7"];

function armFlushTimer() {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    flushOnce().catch(() => {});
  }, FLUSH_INTERVAL_MS);
}

function normalizeTail(text) {
  let t = String(text || '');
  t = t.replace(/\n$/, '');
  t = t.replace(/\\n$/, '');
  if (/\)n$/.test(t)) t = t.slice(0, -1);
  return t;
}

function isPrivateIPv4(ip) {
  const m = String(ip || '').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  if ([a, b].some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function decodeMicrosoftDnsName(raw) {
  const parts = [];
  const re = /\((\d+)\)([^()]+)/g;
  let m;
  while ((m = re.exec(raw)) !== null) {
    const len = Number(m[1]);
    const label = String(m[2] || '').trim();
    if (Number.isNaN(len)) continue;
    if (len === 0) break;
    if (label) parts.push(label);
  }
  if (parts.length === 0) return null;
  return parts.join('.').toLowerCase();
}

function parseMicrosoftDnsDebug(line) {
  const raw = normalizeTail(line);
  const ipMatch = raw.match(/\b(?:Snd|Rcv)\s+(\d{1,3}(?:\.\d{1,3}){3})\b/i);
  const srcIp = ipMatch?.[1] || null;
  const query = decodeMicrosoftDnsName(raw);
  if (!srcIp && !query) return null;

  const srcIpPrivate = srcIp ? isPrivateIPv4(srcIp) : null;
  return {
    parser_source: 'microsoft_dns_debug',
    parsed_ip: srcIp,
    parsed_query: query,
    parsed_ip_private: srcIpPrivate,
    ioc_ip: srcIp && srcIpPrivate === false ? srcIp : null,
    ioc_query: query || null
  };
}

function parseKvPairs(raw) {
  const out = {};
  const re = /(\w+)=((?:"[^"]*")|\S+)/g;
  let m;
  while ((m = re.exec(raw)) !== null) {
    const k = m[1];
    const v = m[2];
    out[k] = v.startsWith('"') && v.endsWith('"') ? v.slice(1, -1) : v;
  }
  return out;
}

function parseFortiTraffic(line) {
  const raw = normalizeTail(line);
  if (!/(?:^|\s)type="traffic"(?:\s|$)/i.test(raw)) return null;

  const kv = parseKvPairs(raw);
  const srcIp = kv.srcip || null;
  const dstIp = kv.dstip || null;
  if (!dstIp && !srcIp && !kv.service) return null;

  const srcIpPrivate = srcIp ? isPrivateIPv4(srcIp) : null;
  const dstIpPrivate = dstIp ? isPrivateIPv4(dstIp) : null;

  return {
    parser_source: 'fortigate_traffic',
    parsed_ip: dstIp || srcIp,
    parsed_query: null,
    parsed_ip_private: dstIp ? dstIpPrivate : srcIpPrivate,
    ioc_ip: dstIp && dstIpPrivate === false ? dstIp : null,
    ioc_ip_secondary: srcIp && srcIpPrivate === false ? srcIp : null,
    ioc_query: null
  };
}

function parseSyslogLine(line, sourceIp) {
  const raw = normalizeTail(line);
  const now = new Date();
  const out = {
    ts: now.toISOString().slice(0, 19).replace("T", " "),
    source: `syslog:${sourceIp}`,
    host: sourceIp || "unknown",
    program: "unknown",
    severity: "info",
    facility: "syslog",
    message: raw,
    raw
  };

  const pri = raw.match(/^<(\d+)>/);
  if (pri) {
    const p = Number(pri[1]);
    const si = p % 8;
    const fi = Math.floor(p / 8);
    out.severity = sev[si] || String(si);
    out.facility = fac[fi] || String(fi);
  }

  const m = raw.match(/^<\d+>[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d\s+(\S+)\s+([^:\[]+)(?:\[\d+\])?:\s*(.*)$/);
  if (m) {
    out.host = m[1] || out.host;
    out.program = (m[2] || "unknown").trim();
    out.message = normalizeTail(m[3] || raw);
  }

  const parsed = parseFortiTraffic(raw) || parseMicrosoftDnsDebug(raw);
  out.parser_source = parsed?.parser_source || 'unknown';
  out.parsed_ip = parsed?.parsed_ip || null;
  out.parsed_query = parsed?.parsed_query || null;
  out.parsed_ip_private = parsed?.parsed_ip_private ?? null;
  out.ioc_ip = parsed?.ioc_ip || null;
  out.ioc_ip_secondary = parsed?.ioc_ip_secondary || null;
  out.ioc_query = parsed?.ioc_query || null;

  return out;
}

function enqueue(sourceIp, rawEvent) {
  metrics.received_logs += 1;
  if (queue.length >= MAX_BUFFERED) {
    if (OVERFLOW_POLICY === "drop_newest") {
      metrics.dropped_logs += 1;
      metrics.dropped_queue_full += 1;
      return;
    }
    if (OVERFLOW_POLICY === "drop_oldest") {
      queue.shift();
      metrics.dropped_logs += 1;
      metrics.dropped_queue_full += 1;
    } else {
      metrics.dropped_logs += 1;
      metrics.dropped_queue_full += 1;
      return;
    }
  }

  queue.push({ sourceIp, receivedAt: new Date(), rawEvent });
  metrics.enqueued_logs += 1;
  if (queue.length > metrics.queue_depth_high_watermark) metrics.queue_depth_high_watermark = queue.length;
  if (queue.length >= BATCH_SIZE) flushOnce().catch(() => {});
  else armFlushTimer();
}

function updateAverages(batchSize, flushMs, chLatencyMs = 0) {
  const n = metrics.flush_runs;
  metrics.batch_size_avg = n <= 1 ? batchSize : ((metrics.batch_size_avg * (n - 1)) + batchSize) / n;
  metrics.flush_time_avg = n <= 1 ? flushMs : ((metrics.flush_time_avg * (n - 1)) + flushMs) / n;
  metrics.clickhouse_insert_latency = chLatencyMs;
  if (chLatencyMs > metrics.clickhouse_insert_latency_max) metrics.clickhouse_insert_latency_max = chLatencyMs;
}

function buildPgBatch(events) {
  const values = [];
  const params = [];
  const byIp = new Map();

  for (let i = 0; i < events.length; i += 1) {
    const e = events[i];
    const base = i * 7;
    values.push(`($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, $${base + 5}, $${base + 6}::jsonb, $${base + 7})`);
    params.push(
      `syslog:${e.sourceIp}`,
      e.sourceIp,
      e.receivedAt.toISOString(),
      e.receivedAt.toISOString(),
      e.rawEvent,
      JSON.stringify({ source_ip: e.sourceIp, received_at: e.receivedAt.toISOString(), raw_event: e.rawEvent, protocol: "syslog" }),
      "syslog"
    );
    byIp.set(e.sourceIp, (byIp.get(e.sourceIp) || 0) + 1);
  }

  return { values, params, byIp };
}

async function flushToPostgres(events) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const { values, params, byIp } = buildPgBatch(events);
    await client.query(
      `INSERT INTO signal_events (source_key, source_ip, event_time, received_at, raw_event, raw, protocol)
       VALUES ${values.join(",")}`,
      params
    );

    const ips = [...byIp.keys()];
    const srcValues = [];
    const srcParams = [];
    for (let i = 0; i < ips.length; i += 1) {
      const ip = ips[i];
      const base = i * 7;
      srcValues.push(`($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, $${base + 5}, $${base + 6}, $${base + 7}, NOW(), NOW())`);
      srcParams.push(`syslog:${ip}`, `Syslog ${ip}`, "syslog", "active", ip, "syslog", byIp.get(ip));
    }

    await client.query(
      `INSERT INTO signal_sources (key, name, platform, status, source_ip, protocol, event_count, first_seen_at, last_seen_at)
       VALUES ${srcValues.join(",")}
       ON CONFLICT (key)
       DO UPDATE SET
         status = EXCLUDED.status,
         source_ip = EXCLUDED.source_ip,
         protocol = EXCLUDED.protocol,
         event_count = signal_sources.event_count + EXCLUDED.event_count,
         last_seen_at = NOW()`,
      srcParams
    );

    await client.query("COMMIT");
    return { inserted: events.length, chLatency: 0 };
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

function buildObservableRows(parsedBatch) {
  const rows = [];
  for (const r of parsedBatch) {
    const rawRowHash = crypto.createHash('sha1').update(String(r.raw || '')).digest('hex');
    if (r.ioc_query) {
      rows.push({
        ts: r.ts,
        source: r.source,
        host: r.host,
        observable: String(r.ioc_query).toLowerCase(),
        observable_type: 'domain',
        raw_row_hash: rawRowHash
      });
    }
    const ipSet = new Set([r.ioc_ip, r.ioc_ip_secondary].filter(Boolean).map((v) => String(v)));
    for (const ip of ipSet) {
      rows.push({
        ts: r.ts,
        source: r.source,
        host: r.host,
        observable: ip,
        observable_type: 'ip',
        raw_row_hash: rawRowHash
      });
    }
  }
  return rows;
}

async function flushToClickhouse(events) {
  const batch = events.map((e) => parseSyslogLine(e.rawEvent, e.sourceIp));
  const observablesBatch = buildObservableRows(batch);
  const t0 = Date.now();
  await insertLogs(batch, { queryId: makeQueryId('insert-batch'), logTag: 'syslog-receiver.insert-batch' });
  if (observablesBatch.length > 0) {
    await insertObservables(observablesBatch, { queryId: makeQueryId('insert-observables'), logTag: 'syslog-receiver.insert-observables' });
  }
  const t1 = Date.now() - t0;
  return { inserted: batch.length, chLatency: t1 };
}

async function flushOnce() {
  if (queue.length === 0) return;
  if (flushInFlight) return flushInFlight;
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }

  flushInFlight = (async () => {
    const events = queue.splice(0, BATCH_SIZE);
    if (events.length === 0) return;

    const started = Date.now();
    try {
      const result = USE_CLICKHOUSE ? await flushToClickhouse(events) : await flushToPostgres(events);
      metrics.inserted_logs += result.inserted;
      metrics.flush_runs += 1;
      metrics.last_flush_at = new Date().toISOString();

      const duration = Date.now() - started;
      metrics.flush_duration_ms_last = duration;
      if (duration > metrics.flush_duration_ms_max) metrics.flush_duration_ms_max = duration;
      updateAverages(events.length, duration, result.chLatency || 0);
    } catch (err) {
      metrics.insert_errors += 1;
      const canRequeue = Math.max(0, MAX_BUFFERED - queue.length);
      if (canRequeue > 0) queue.unshift(...events.slice(0, canRequeue));
      console.error("[syslog-receiver] flush error", err?.message || err);
    } finally {
      flushInFlight = null;
      if (queue.length > 0) armFlushTimer();
    }
  })();

  return flushInFlight;
}

async function flushWorkerTick() {
  if (queue.length === 0) return;
  flushingWorkers += 1;
  try { await flushOnce(); }
  finally { flushingWorkers = Math.max(0, flushingWorkers - 1); }
}

udp.on("message", (msg, rinfo) => enqueue(rinfo.address || "unknown", msg.toString("utf8")));
udp.on("error", (err) => console.error("[syslog-receiver] udp error", err?.message || err));

udp.bind(SYSLOG_PORT, SYSLOG_HOST, () => {
  try { udp.setRecvBufferSize(SOCKET_RCVBUF); } catch {}
  try { metrics.socket_recv_buffer_size = udp.getRecvBufferSize(); } catch { metrics.socket_recv_buffer_size = null; }
  console.log(`[syslog-receiver] listening udp://${SYSLOG_HOST}:${SYSLOG_PORT}`);
  console.log(`[syslog-receiver] storage=${LOG_STORAGE} workers=${FLUSH_WORKERS} batch=${BATCH_SIZE} interval=${FLUSH_INTERVAL_MS}ms overflow=${OVERFLOW_POLICY}`);
});

const timers = [];
for (let i = 0; i < FLUSH_WORKERS; i += 1) timers.push(setInterval(() => flushWorkerTick().catch(() => {}), FLUSH_INTERVAL_MS));

const health = http.createServer((req, res) => {
  if (req.url !== "/health" && req.url !== "/receiver/health") {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: false }));
    return;
  }
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ ok: true, service: "demo-syslog-receiver", queue_depth: queue.length, flushing_workers: flushingWorkers, metrics }));
});

async function bootstrap() {
  if (USE_CLICKHOUSE) {
    await ensureSyslogTable();
    await pingClickhouse();
  }
  health.listen(HEALTH_PORT, "0.0.0.0", () => {
    console.log(`[syslog-receiver] health endpoint on :${HEALTH_PORT}/receiver/health`);
  });
}

async function shutdown() {
  for (const t of timers) clearInterval(t);
  for (let i = 0; i < FLUSH_WORKERS * 4 && queue.length > 0; i += 1) await flushOnce().catch(() => {});
  udp.close();
  health.close();
  await pool.end();
  process.exit(0);
}

bootstrap().catch((err) => {
  console.error("[syslog-receiver] bootstrap failed", err?.message || err);
  process.exit(1);
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
