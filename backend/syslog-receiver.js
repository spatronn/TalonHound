import dgram from "dgram";
import http from "http";
import pg from "pg";

const { Pool } = pg;

const SYSLOG_PORT = Number(process.env.SYSLOG_PORT || 514);
const SYSLOG_HOST = process.env.SYSLOG_HOST || "0.0.0.0";
const HEALTH_PORT = Number(process.env.SYSLOG_HEALTH_PORT || 8081);
const FLUSH_INTERVAL_MS = Math.max(Number(process.env.SYSLOG_FLUSH_INTERVAL_MS || 250), 50);
const BATCH_SIZE = Math.max(Number(process.env.SYSLOG_BATCH_SIZE || 1000), 10);
const MAX_BUFFERED = Math.max(Number(process.env.SYSLOG_MAX_BUFFERED || 100000), BATCH_SIZE);
const FLUSH_WORKERS = Math.max(Number(process.env.SYSLOG_FLUSH_WORKERS || 4), 1);
const SOCKET_RCVBUF = Math.max(Number(process.env.SYSLOG_SOCKET_RCVBUF || 8 * 1024 * 1024), 256 * 1024);

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

const metrics = {
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
  last_flush_at: null,
  started_at: new Date().toISOString()
};

function enqueue(sourceIp, rawEvent) {
  metrics.received_logs += 1;
  if (queue.length >= MAX_BUFFERED) {
    metrics.dropped_logs += 1;
    metrics.dropped_queue_full += 1;
    return;
  }

  queue.push({ sourceIp, receivedAt: new Date(), rawEvent });
  metrics.enqueued_logs += 1;

  if (queue.length > metrics.queue_depth_high_watermark) {
    metrics.queue_depth_high_watermark = queue.length;
  }
}

function buildBatchInsert(events) {
  const values = [];
  const params = [];

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
  }

  return { values, params };
}

async function flushOnce() {
  if (queue.length === 0) return;

  const events = queue.splice(0, BATCH_SIZE);
  if (events.length === 0) return;

  const byIp = new Map();
  for (const e of events) byIp.set(e.sourceIp, (byIp.get(e.sourceIp) || 0) + 1);

  const started = Date.now();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const { values, params } = buildBatchInsert(events);
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
    metrics.inserted_logs += events.length;
    metrics.flush_runs += 1;
    metrics.last_flush_at = new Date().toISOString();

    const duration = Date.now() - started;
    metrics.flush_duration_ms_last = duration;
    if (duration > metrics.flush_duration_ms_max) metrics.flush_duration_ms_max = duration;
  } catch (err) {
    await client.query("ROLLBACK");
    metrics.insert_errors += 1;
    const canRequeue = Math.max(0, MAX_BUFFERED - queue.length);
    if (canRequeue > 0) queue.unshift(...events.slice(0, canRequeue));
    console.error("[syslog-receiver] flush error", err?.message || err);
  } finally {
    client.release();
  }
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
});

const timers = [];
for (let i = 0; i < FLUSH_WORKERS; i += 1) timers.push(setInterval(() => flushWorkerTick().catch(() => {}), FLUSH_INTERVAL_MS));

const health = http.createServer((req, res) => {
  if (req.url !== "/health") return res.writeHead(404).end(JSON.stringify({ ok: false }));
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ ok: true, service: "demo-syslog-receiver", queue_depth: queue.length, flushing_workers: flushingWorkers, metrics }));
});

health.listen(HEALTH_PORT, "0.0.0.0");

async function shutdown() {
  for (const t of timers) clearInterval(t);
  for (let i = 0; i < FLUSH_WORKERS * 4 && queue.length > 0; i += 1) await flushOnce().catch(() => {});
  udp.close(); health.close(); await pool.end(); process.exit(0);
}
process.on("SIGINT", shutdown); process.on("SIGTERM", shutdown);
