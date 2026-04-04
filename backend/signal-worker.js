import './lib/ensure-db-password.js';
import pg from 'pg';
import IORedis from 'ioredis';
import { Worker } from 'bullmq';

const { Pool } = pg;

const redisUrl = process.env.REDIS_URL || 'redis://redis:6379';
const signalQueueName = process.env.SIGNAL_QUEUE_NAME || 'signal-events';
const signalWorkerConcurrency = Number(process.env.SIGNAL_WORKER_CONCURRENCY || 2);

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'demo'
});

const redis = new IORedis(redisUrl, { maxRetriesPerRequest: null });

function scoreEvent(evt) {
  let score = 0;
  const reasons = [];

  const p = String(evt.process_name || '').toLowerCase();
  if (['powershell.exe', 'cmd.exe', 'mshta.exe', 'rundll32.exe', 'wscript.exe', 'cscript.exe'].includes(p)) {
    score += 40;
    reasons.push('LOLBIN_NET');
  }

  if (evt.destination_ip && !String(evt.destination_ip).startsWith('10.') && !String(evt.destination_ip).startsWith('192.168.') && !String(evt.destination_ip).startsWith('172.16.')) {
    score += 20;
    reasons.push('EXTERNAL_IP');
  }

  if (Number(evt.destination_port) === 4444 || Number(evt.destination_port) === 3389) {
    score += 20;
    reasons.push('SENSITIVE_PORT');
  }

  return { score, reasons };
}

const worker = new Worker(
  signalQueueName,
  async (job) => {
    const events = Array.isArray(job.data?.events) ? job.data.events : [];
    if (!events.length) return { inserted: 0, skipped: 0 };

    const client = await pool.connect();
    let inserted = 0;
    let skipped = 0;

    try {
      await client.query('BEGIN');

      for (const evt of events) {
        const { score, reasons } = scoreEvent(evt);
        if (score < 20) {
          skipped += 1;
          continue;
        }

        const insertSignal = await client.query(
          `INSERT INTO signal_events (
            source_key, event_time, host_name, username, process_name, process_id,
            destination_ip, destination_port, protocol, score, reason_codes, raw
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
          RETURNING id`,
          [
            evt.source_key || 'sysmon.windows',
            evt.event_time || new Date().toISOString(),
            evt.host_name || null,
            evt.username || null,
            evt.process_name || null,
            evt.process_id || null,
            evt.destination_ip || null,
            evt.destination_port ? Number(evt.destination_port) : null,
            evt.protocol || null,
            score,
            reasons,
            evt
          ]
        );

        const signalEventId = insertSignal.rows?.[0]?.id;

        if (evt.destination_ip) {
          const matches = await client.query(
            `SELECT observable, source_name, confidence
             FROM ioc_items
             WHERE observable_type = 'ip'
               AND observable = $1
             LIMIT 10`,
            [evt.destination_ip]
          );

          for (const m of matches.rows) {
            await client.query(
              `INSERT INTO ioc_match_events (
                signal_event_id, event_time, host_name, process_name, destination_ip,
                destination_port, protocol, matched_ioc, source_name, confidence
              ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
              [
                signalEventId || null,
                evt.event_time || new Date().toISOString(),
                evt.host_name || null,
                evt.process_name || null,
                evt.destination_ip || null,
                evt.destination_port ? Number(evt.destination_port) : null,
                evt.protocol || null,
                m.observable,
                m.source_name || null,
                m.confidence || null
              ]
            );
          }
        }

        inserted += 1;
      }

      await client.query(
        `INSERT INTO signal_sources (key, name, platform, status)
         VALUES ($1, $2, $3, 'active')
         ON CONFLICT (key)
         DO UPDATE SET status='active', last_seen_at=NOW()`,
        ['sysmon.windows', 'Sysmon', 'Windows']
      );

      await client.query('COMMIT');
      return { inserted, skipped };
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  },
  { connection: redis, concurrency: signalWorkerConcurrency }
);

worker.on('completed', (job, result) => {
  console.log(`[signal-worker] job ${job.id} completed`, result);
});

worker.on('failed', (job, err) => {
  console.error(`[signal-worker] job ${job?.id} failed`, err?.message || err);
});

console.log(`[signal-worker] listening queue=${signalQueueName} concurrency=${signalWorkerConcurrency}`);

process.on('SIGINT', async () => {
  await worker.close();
  await redis.quit();
  await pool.end();
  process.exit(0);
});
