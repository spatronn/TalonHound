import './lib/ensure-db-password.js';
import pg from 'pg';
import { createAuditLogService } from './lib/auditLogService.js';
import { runExpirationWorkerBatch } from './lib/iocExpiration.js';
import { pushIocLookupTombstones } from './lib/clickhouse.js';

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'demo'
});

const POLL_MS = Math.max(Number(process.env.IOC_EXPIRATION_POLL_INTERVAL_MS || 60000), 5000);
const BATCH_SIZE = Math.max(Number(process.env.IOC_EXPIRATION_BATCH_SIZE || 500), 50);

const audit = createAuditLogService(pool);
let stopping = false;

async function tick() {
  const client = await pool.connect();
  try {
    const res = await runExpirationWorkerBatch(client, {
      batchSize: BATCH_SIZE,
      audit
    });

    if (res.expiredMemberships > 0) {
      const tomb = await client.query(
        `SELECT DISTINCT lower(i.observable) AS observable,
                CASE WHEN i.observable_type = 'hostname' THEN 'domain' ELSE i.observable_type END AS observable_type,
                i.source_name
         FROM ioc_feed_memberships m
         JOIN ioc_items i ON i.id = m.ioc_item_id AND i.observable_type = m.ioc_observable_type
         WHERE m.status = 'expired' AND m.expired_at >= NOW() - INTERVAL '2 minutes'
           AND i.observable_type IN ('domain', 'url', 'ip', 'sha256')
         LIMIT 5000`
      );
      if (tomb.rows?.length) {
        await pushIocLookupTombstones(tomb.rows).catch((err) => {
          console.warn('[ioc-expiration] lookup tombstone push failed', err?.message || err);
        });
      }
    }

    if (res.expiredMemberships > 0 || res.iocGlobalExpired > 0) {
      console.log(
        `[ioc-expiration] expired_memberships=${res.expiredMemberships} ioc_recomputed=${res.iocRecomputed} ioc_global_expired=${res.iocGlobalExpired}`
      );
    }
  } catch (err) {
    console.error('[ioc-expiration] tick failed', err?.message || err);
  } finally {
    client.release();
  }
}

async function main() {
  console.log(`[ioc-expiration] worker started poll_ms=${POLL_MS} batch_size=${BATCH_SIZE}`);
  while (!stopping) {
    await tick();
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
}

process.on('SIGINT', () => { stopping = true; });
process.on('SIGTERM', () => { stopping = true; });

main().catch((err) => {
  console.error('[ioc-expiration] fatal', err);
  process.exit(1);
});
