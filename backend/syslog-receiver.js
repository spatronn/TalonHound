import dgram from "dgram";
import http from "http";
import pg from "pg";

const { Pool } = pg;

const SYSLOG_PORT = Number(process.env.SYSLOG_PORT || 514);
const SYSLOG_HOST = process.env.SYSLOG_HOST || "0.0.0.0";
const HEALTH_PORT = Number(process.env.SYSLOG_HEALTH_PORT || 8081);
const FLUSH_INTERVAL_MS = Math.max(Number(process.env.SYSLOG_FLUSH_INTERVAL_MS || 500), 100);
const BATCH_SIZE = Math.max(Number(process.env.SYSLOG_BATCH_SIZE || 200), 10);
const MAX_BUFFERED = Math.max(Number(process.env.SYSLOG_MAX_BUFFERED || 20000), BATCH_SIZE);

const pool = new Pool({
  host: process.env.DB_HOST || "db",
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || "demo",
  password: process.env.DB_PASSWORD || "demo123",
  database: process.env.DB_NAME || "demo"
});

const udp = dgram.createSocket({ type: "udp4", reuseAddr: true });
const queue = [];
let flushing = false;

const metrics = {
  received_logs: 0,
  dropped_logs: 0,
  insert_errors: 0,
  inserted_logs: 0,
  last_flush_at: null,
  started_at: new Date().toISOString()
};

function enqueue(sourceIp, rawEvent) {
  metrics.received_logs += 1;
  if (queue.length >= MAX_BUFFERED) {
    metrics.dropped_logs += 1;
    return;
  }
  queue.push({ sourceIp, receivedAt: new Date(), rawEvent });
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
      JSON.stringify({
        source_ip: e.sourceIp,
        received_at: e.receivedAt.toISOString(),
        raw_event: e.rawEvent,
        protocol: "syslog"
      }),
      "syslog"
    );
  }

  return { values, params };
}

async function flushOnce() {
  if (flushing || queue.length === 0) return;
  flushing = true;

  const events = queue.splice(0, BATCH_SIZE);
  const byIp = new Map();
  for (const e of events) byIp.set(e.sourceIp, (byIp.get(e.sourceIp) || 0) + 1);

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const { values, params } = buildBatchInsert(events);
    await client.query(
      `INSERT INTO signal_events (source_key, source_ip, event_time, received_at, raw_event, raw, protocol)
       VALUES ${values.join(",")}`,
      params
    );

    for (const [ip, count] of byIp.entries()) {
      await client.query(
        `INSERT INTO signal_sources (key, name, platform, status, source_ip, protocol, event_count, first_seen_at, last_seen_at)
         VALUES ($1, $2, 'syslog', 'active', $3, 'syslog', $4, NOW(), NOW())
         ON CONFLICT (key)
         DO UPDATE SET
           status = 'active',
           source_ip = EXCLUDED.source_ip,
           protocol = EXCLUDED.protocol,
           event_count = signal_sources.event_count + EXCLUDED.event_count,
           last_seen_at = NOW()`,
        [`syslog:${ip}`, `Syslog ${ip}`, ip, count]
      );
    }

    await client.query("COMMIT");
    metrics.inserted_logs += events.length;
    metrics.last_flush_at = new Date().toISOString();
  } catch (err) {
    await client.query("ROLLBACK");
    metrics.insert_errors += 1;

    // Best-effort retry by pushing items back to queue head if capacity allows.
    queue.unshift(...events.slice(0, Math.max(0, MAX_BUFFERED - queue.length)));
    console.error("[syslog-receiver] flush error", err?.message || err);
  } finally {
    client.release();
    flushing = false;
  }
}

udp.on("message", (msg, rinfo) => {
  enqueue(rinfo.address || "unknown", msg.toString("utf8"));
});

udp.on("error", (err) => {
  console.error("[syslog-receiver] udp error", err?.message || err);
});

udp.bind(SYSLOG_PORT, SYSLOG_HOST, () => {
  try {
    udp.setRecvBufferSize(4 * 1024 * 1024);
  } catch {
    // ignore
  }
  console.log(`[syslog-receiver] listening udp://${SYSLOG_HOST}:${SYSLOG_PORT}`);
});

const timer = setInterval(() => {
  flushOnce().catch((err) => console.error("[syslog-receiver] flush tick error", err?.message || err));
}, FLUSH_INTERVAL_MS);

const health = http.createServer((req, res) => {
  if (req.url !== "/health") {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: false }));
    return;
  }

  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(
    JSON.stringify({
      ok: true,
      service: "demo-syslog-receiver",
      queue_depth: queue.length,
      flushing,
      metrics
    })
  );
});

health.listen(HEALTH_PORT, "0.0.0.0", () => {
  console.log(`[syslog-receiver] health endpoint on :${HEALTH_PORT}/health`);
});

async function shutdown() {
  clearInterval(timer);
  await flushOnce().catch(() => {});
  udp.close();
  health.close();
  await pool.end();
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
