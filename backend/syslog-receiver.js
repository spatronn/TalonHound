import dgram from "dgram";
import http from "http";
import crypto from "crypto";

const SYSLOG_PORT = Number(process.env.SYSLOG_PORT || 514);
const SYSLOG_HOST = process.env.SYSLOG_HOST || "0.0.0.0";
const HEALTH_PORT = Number(process.env.SYSLOG_HEALTH_PORT || 8081);
const FLUSH_INTERVAL_MS = Math.max(Number(process.env.SYSLOG_FLUSH_INTERVAL_MS || 3000), 200);
const BATCH_SIZE = Math.max(Number(process.env.SYSLOG_BATCH_SIZE || 3000), 10);
const MIN_FLUSH_SIZE = Math.max(Number(process.env.SYSLOG_MIN_FLUSH_SIZE || 1000), 1);
const MIN_INSERT_ROWS = Math.max(Number(process.env.SYSLOG_MIN_INSERT_ROWS || MIN_FLUSH_SIZE), 1);
const FORCE_FLUSH_MAX_MS = Math.max(Number(process.env.SYSLOG_FORCE_FLUSH_MAX_MS || 60000), FLUSH_INTERVAL_MS);
const MAX_BUFFERED = Math.max(Number(process.env.SYSLOG_MAX_BUFFERED || 100000), BATCH_SIZE);
const FLUSH_WORKERS = Math.max(Number(process.env.SYSLOG_FLUSH_WORKERS || 1), 1);
const SOCKET_RCVBUF = Math.max(Number(process.env.SYSLOG_SOCKET_RCVBUF || 8 * 1024 * 1024), 256 * 1024);
const OVERFLOW_POLICY = String(process.env.SYSLOG_OVERFLOW_POLICY || "drop_oldest").toLowerCase();
/** If set, each UDP datagram must begin with UTF-8 `SECRET|` (timing-safe check); remainder is parsed as syslog. Mitigates open 514 when published to the host. */
const UDP_INGEST_SECRET = String(process.env.SYSLOG_UDP_SHARED_SECRET || "").trim();

const udp = dgram.createSocket({ type: "udp4", reuseAddr: true });
const queue = [];
let flushingWorkers = 0;
let flushTimer = null;
let flushInFlight = null;

function makeQueryId(name) {
  return `syslog-receiver:${name}:${Date.now().toString(36)}:${Math.random().toString(36).slice(2, 8)}`;
}

const metrics = {
  storage_backend: 'postgres',
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
  batch_size_avg: 0,
  flush_time_avg: 0,
  last_flush_at: null,
  started_at: new Date().toISOString(),
  udp_rejected_key: 0
};

const sev = ["emerg","alert","crit","err","warning","notice","info","debug"];
const fac = ["kern","user","mail","daemon","auth","syslog","lpr","news","uucp","clock","authpriv","ftp","ntp","audit","alert","clock2","local0","local1","local2","local3","local4","local5","local6","local7"];

function armFlushTimer() {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    // timer is fallback path: flush whatever is buffered
    flushOnce(true).catch(() => {});
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

const GENERIC_IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const GENERIC_SHA256_RE = /\b[a-fA-F0-9]{64}\b/g;
const GENERIC_URL_RE = /\bhttps?:\/\/[^\s<>"']+/gi;
const GENERIC_DOMAIN_RE = /\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
const HOST_IS_IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

function trimTrailingUrlPunct(s) {
  return String(s || '').replace(/[.,;:!?)>\]'"]+$/, '');
}

/**
 * Fallback + enrichment IOC extraction from raw syslog text (no structured parser required).
 * Returns { type, value } with type ipv4 | domain | url | sha256 (source applied in mergeObservables).
 */
function extractGenericIOCs(raw) {
  const text = String(raw || '');
  const items = [];
  const seenLocal = new Set();

  const push = (type, value) => {
    const v = String(value || '');
    if (!v) return;
    const k = `${type}\0${v}`;
    if (seenLocal.has(k)) return;
    seenLocal.add(k);
    items.push({ type, value: v });
  };

  for (const m of text.matchAll(GENERIC_SHA256_RE)) {
    push('sha256', m[0].toLowerCase());
  }

  for (const m of text.matchAll(GENERIC_IPV4_RE)) {
    const ip = m[0];
    if (isPrivateIPv4(ip)) continue;
    push('ipv4', ip);
  }

  for (const m of text.matchAll(GENERIC_URL_RE)) {
    const trimmed = trimTrailingUrlPunct(m[0]);
    try {
      const u = new URL(trimmed);
      push('url', u.href);
      const host = u.hostname;
      if (host && HOST_IS_IPV4_RE.test(host)) {
        if (!isPrivateIPv4(host)) push('ipv4', host);
      } else if (host) {
        push('domain', host.toLowerCase());
      }
    } catch {
      /* ignore malformed URLs */
    }
  }

  for (const m of text.matchAll(GENERIC_DOMAIN_RE)) {
    push('domain', m[0].toLowerCase());
  }

  return items;
}

/**
 * Combines parser-derived IOCs (ioc_*) with generic extraction.
 * Unique key (type, value); parser wins over generic for the same key.
 */
function mergeObservables(row, genericList) {
  const fromParser = [];
  if (row.ioc_query) {
    const v = String(row.ioc_query).toLowerCase();
    if (v) fromParser.push({ type: 'domain', value: v, source: 'parser' });
  }
  for (const ip of [row.ioc_ip, row.ioc_ip_secondary].filter(Boolean)) {
    const v = String(ip);
    if (v) fromParser.push({ type: 'ipv4', value: v, source: 'parser' });
  }

  const genericTagged = (genericList || []).map((it) => ({
    type: it.type,
    value: String(it.value || ''),
    source: 'generic'
  })).filter((it) => it.type && it.value);

  const byKey = new Map();
  for (const it of genericTagged) {
    const k = `${it.type}\0${it.value}`;
    if (!byKey.has(k)) byKey.set(k, it);
  }
  for (const it of fromParser) {
    const k = `${it.type}\0${it.value}`;
    byKey.set(k, it);
  }
  return Array.from(byKey.values());
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
    ioc_query: null,
    context: {
      srcip: srcIp,
      dstip: dstIp,
      dstport: kv.dstport || null,
      service: kv.service || null,
      action: kv.action || null,
      sentbyte: kv.sentbyte || null,
      rcvdbyte: kv.rcvdbyte || null
    }
  };
}

function parseDnsKv(line) {
  const raw = normalizeTail(line);
  if (!/(?:^|\s)type=dns(?:\s|$)/i.test(raw)) return null;
  const kv = parseKvPairs(raw);
  const query = (kv.query || '').toLowerCase() || null;
  const responseIp = kv.response_ip || kv.responseip || null;
  const clientIp = kv.client_ip || kv.clientip || null;
  if (!query && !responseIp) return null;
  const responseIsPublic = responseIp && !isPrivateIPv4(responseIp);
  return {
    parser_source: 'dns_kv',
    parsed_ip: responseIp || clientIp || null,
    parsed_query: query,
    parsed_ip_private: responseIp ? isPrivateIPv4(responseIp) : (clientIp ? isPrivateIPv4(clientIp) : null),
    ioc_ip: responseIsPublic ? responseIp : null,
    ioc_query: query,
    context: {
      activity_type: 'dns',
      query,
      query_type: kv.query_type || null,
      response_ip: responseIp,
      client_ip: clientIp,
      raw_source: 'syslog'
    }
  };
}

function parseSyslogLine(line, sourceIp) {
  const raw = normalizeTail(line);
  const now = new Date();

  const bindTsMatch = raw.match(/\b(\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)\b/);
  const squidTsMatch = raw.match(/\bsquid_proxy:\s*(\d{10}(?:\.\d+)?)\b/);

  let parsedTs = now;
  if (squidTsMatch) {
    const ms = Math.floor(Number(squidTsMatch[1]) * 1000);
    if (Number.isFinite(ms) && ms > 0) parsedTs = new Date(ms);
  } else if (bindTsMatch) {
    const p = bindTsMatch[1].replace(/\.(\d{1,3})$/, '');
    const d = new Date(`${p} UTC`);
    if (!Number.isNaN(d.getTime())) parsedTs = d;
  }

  const out = {
    ts: parsedTs.toISOString().slice(0, 19).replace("T", " "),
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

  const isSquid = /\bsquid_proxy:\s*\d{10}(?:\.\d+)?\s+\d+\s+\d{1,3}(?:\.\d{1,3}){3}\s+[A-Z_]+\/\d{3}\s+\d+\s+[A-Z]+\s+\S+/i.test(raw);
  const isBind = /\bbind_dns:\s*\d{2}-[A-Za-z]{3}-\d{4}\b.*\bquery:\s*\S+/i.test(raw);

  const parsed = parseFortiTraffic(raw) || parseDnsKv(raw) || parseMicrosoftDnsDebug(raw);
  out.parser_source = parsed?.parser_source || (isSquid ? 'squid_proxy' : (isBind ? 'bind_dns' : 'unknown'));
  out.parsed_ip = parsed?.parsed_ip || null;
  out.parsed_query = parsed?.parsed_query || null;
  out.parsed_ip_private = parsed?.parsed_ip_private ?? null;
  out.ioc_ip = parsed?.ioc_ip || null;
  out.ioc_ip_secondary = parsed?.ioc_ip_secondary || null;
  out.ioc_query = parsed?.ioc_query || null;

  out.merged_observables = mergeObservables(out, extractGenericIOCs(raw));

  return out;
}

function stripUdpIngestPrefix(buf) {
  if (!UDP_INGEST_SECRET) return { ok: true, payload: buf };
  const prefix = Buffer.from(`${UDP_INGEST_SECRET}|`, "utf8");
  if (buf.length < prefix.length) return { ok: false };
  try {
    if (!crypto.timingSafeEqual(buf.subarray(0, prefix.length), prefix)) return { ok: false };
  } catch {
    return { ok: false };
  }
  return { ok: true, payload: buf.subarray(prefix.length) };
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
  if (queue.length >= BATCH_SIZE) flushOnce(false).catch(() => {});
  else armFlushTimer();
}

function updateAverages(batchSize, flushMs) {
  const n = metrics.flush_runs;
  metrics.batch_size_avg = n <= 1 ? batchSize : ((metrics.batch_size_avg * (n - 1)) + batchSize) / n;
  metrics.flush_time_avg = n <= 1 ? flushMs : ((metrics.flush_time_avg * (n - 1)) + flushMs) / n;
}


async function flushToPostgres(events) {
  // signal_events and signal_sources tables were removed in migration 110;
  // the downstream signal-engine is no longer deployed. Accept and drop.
  return { inserted: events.length };
}


async function flushOnce(force = false) {
  if (queue.length === 0) return;

  const oldestAgeMs = queue.length > 0
    ? Math.max(0, Date.now() - new Date(queue[0].receivedAt).getTime())
    : 0;

  // Hard gate to avoid small-part writes:
  // flush only if queue reached MIN_INSERT_ROWS OR oldest buffered event is too old.
  if (queue.length < MIN_INSERT_ROWS && oldestAgeMs <= FORCE_FLUSH_MAX_MS) {
    armFlushTimer();
    return;
  }
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
      const result = await flushToPostgres(events);
      metrics.inserted_logs += result.inserted;
      metrics.flush_runs += 1;
      metrics.last_flush_at = new Date().toISOString();

      const duration = Date.now() - started;
      metrics.flush_duration_ms_last = duration;
      if (duration > metrics.flush_duration_ms_max) metrics.flush_duration_ms_max = duration;
      updateAverages(events.length, duration);
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

udp.on("message", (msg, rinfo) => {
  const buf = Buffer.isBuffer(msg) ? msg : Buffer.from(msg);
  const stripped = stripUdpIngestPrefix(buf);
  if (!stripped.ok) {
    metrics.udp_rejected_key += 1;
    return;
  }
  enqueue(rinfo.address || "unknown", stripped.payload.toString("utf8"));
});
udp.on("error", (err) => console.error("[syslog-receiver] udp error", err?.message || err));

udp.bind(SYSLOG_PORT, SYSLOG_HOST, () => {
  try { udp.setRecvBufferSize(SOCKET_RCVBUF); } catch {}
  try { metrics.socket_recv_buffer_size = udp.getRecvBufferSize(); } catch { metrics.socket_recv_buffer_size = null; }
  console.log(`[syslog-receiver] listening udp://${SYSLOG_HOST}:${SYSLOG_PORT}`);
  const udpKeyHint = UDP_INGEST_SECRET ? " udp_ingest_key=required(prefix SECRET|)" : "";
  console.log(`[syslog-receiver] storage=postgres mode=batch-first batch=${BATCH_SIZE} min_flush=${MIN_FLUSH_SIZE} min_insert=${MIN_INSERT_ROWS} force_flush_max_ms=${FORCE_FLUSH_MAX_MS} fallback_interval=${FLUSH_INTERVAL_MS}ms overflow=${OVERFLOW_POLICY}${udpKeyHint}`);
});

const timers = [];

const HEALTH_TOKEN = String(process.env.SYSLOG_HEALTH_TOKEN || "").trim();

function extractHealthToken(req) {
  const auth = req.headers.authorization;
  if (auth && typeof auth === "string") {
    const m = auth.match(/^Bearer\s+(\S+)/i);
    if (m) return m[1].trim();
  }
  const x = req.headers["x-syslog-health-token"];
  if (x && typeof x === "string") return x.trim();
  return "";
}

function healthAuthOk(req) {
  if (!HEALTH_TOKEN) return true;
  const provided = extractHealthToken(req);
  if (!provided) return false;
  try {
    const a = Buffer.from(provided, "utf8");
    const b = Buffer.from(HEALTH_TOKEN, "utf8");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

const health = http.createServer((req, res) => {
  if (req.url !== "/health" && req.url !== "/receiver/health") {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: false }));
    return;
  }
  if (!healthAuthOk(req)) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: false }));
    return;
  }
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ ok: true, service: "demo-syslog-receiver", queue_depth: queue.length, flushing_workers: flushingWorkers, metrics }));
});

async function bootstrap() {
  health.listen(HEALTH_PORT, "0.0.0.0", () => {
    const authHint = HEALTH_TOKEN ? " (Bearer or X-Syslog-Health-Token required)" : " (unauthenticated — set SYSLOG_HEALTH_TOKEN)";
    console.log(`[syslog-receiver] health endpoint on :${HEALTH_PORT}/receiver/health${authHint}`);
  });
}

async function shutdown() {
  for (const t of timers) clearInterval(t);
  for (let i = 0; i < Math.max(FLUSH_WORKERS * 4, 8) && queue.length > 0; i += 1) await flushOnce(true).catch(() => {});
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
