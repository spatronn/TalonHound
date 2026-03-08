#!/usr/bin/env node
/**
 * One-off backfill: populate ioc_observables from existing ioc_items (~1.7M).
 * Uses extractObservablesFromNote + batch INSERT with ON CONFLICT DO NOTHING.
 * Keyset pagination (public_id) for stable, fast iteration.
 *
 * Usage: node integration/backfill-ioc-observables.js
 *   IOC_BACKFILL_BATCH_SIZE=1000 (default)
 *   IOC_BACKFILL_DRY_RUN=1 to only count and log, no inserts
 */

import pg from 'pg';
import { config } from './config.js';
import { extractObservablesFromNote } from './importer.js';

const { Pool } = pg;
const pool = new Pool(config.db);

const BATCH_SIZE = Math.min(Math.max(Number(process.env.IOC_BACKFILL_BATCH_SIZE) || 1000, 100), 5000);
const DRY_RUN = process.env.IOC_BACKFILL_DRY_RUN === '1' || process.env.IOC_BACKFILL_DRY_RUN === 'true';
const INSERT_CHUNK = 2000;

function run() {
  return pool.connect().then((client) => {
    let totalItems = 0;
    let totalObservables = 0;
    let lastPublicId = null;
    const start = Date.now();

    function fetchBatch() {
      if (lastPublicId) {
        return client.query(
          `SELECT public_id, observable_type, observable, note
           FROM ioc_items
           WHERE public_id > $1
           ORDER BY public_id
           LIMIT $2`,
          [lastPublicId, BATCH_SIZE]
        );
      }
      return client.query(
        `SELECT public_id, observable_type, observable, note
         FROM ioc_items
         ORDER BY public_id
         LIMIT $1`,
        [BATCH_SIZE]
      );
    }

    function insertObservablesBatch(rows) {
      if (rows.length === 0) return Promise.resolve();
      const values = [];
      const placeholders = [];
      let idx = 0;
      for (const r of rows) {
        placeholders.push(`($${idx + 1}, $${idx + 2}, $${idx + 3})`);
        values.push(r.ioc_public_id, r.observable_type, r.observable_value);
        idx += 3;
      }
      return client.query(
        `INSERT INTO ioc_observables (ioc_public_id, observable_type, observable_value)
         VALUES ${placeholders.join(', ')}
         ON CONFLICT (ioc_public_id, observable_type, observable_value) DO NOTHING`,
        values
      );
    }

    function processBatch() {
      return fetchBatch()
        .then((res) => {
          const rows = res.rows;
          if (rows.length === 0) return { done: true, totalItems, totalObservables };

          const flat = [];
          const seen = new Set();
          for (const row of rows) {
            const observables = extractObservablesFromNote(
              row.observable_type,
              row.observable,
              row.note
            );
            for (const o of observables) {
              const key = `${row.public_id}:${o.observable_type}:${o.observable_value}`;
              if (seen.has(key)) continue;
              seen.add(key);
              flat.push({
                ioc_public_id: row.public_id,
                observable_type: o.observable_type,
                observable_value: o.observable_value
              });
            }
          }

          totalItems += rows.length;
          totalObservables += flat.length;
          lastPublicId = rows[rows.length - 1].public_id;

          if (DRY_RUN) {
            return Promise.resolve({ done: false, totalItems, totalObservables });
          }

          const chunks = [];
          for (let i = 0; i < flat.length; i += INSERT_CHUNK) {
            chunks.push(flat.slice(i, i + INSERT_CHUNK));
          }
          return Promise.all(chunks.map(insertObservablesBatch)).then(() => ({
            done: false,
            totalItems,
            totalObservables
          }));
        })
        .then(({ done, totalItems: ti, totalObservables: to }) => {
          totalItems = ti;
          totalObservables = to;
          return done;
        });
    }

    function runBatch() {
      return client.query('BEGIN').then(() => processBatch()).then((done) => {
        return client.query(done ? 'ROLLBACK' : 'COMMIT').then(() => {
          if (done) return true;
          if (totalItems % 10000 < BATCH_SIZE) {
            console.log(`[backfill] items=${totalItems} observables=${totalObservables} elapsed=${((Date.now() - start) / 1000).toFixed(1)}s`);
          }
          return runBatch();
        });
      }).catch((err) => {
        return client.query('ROLLBACK').then(() => {
          throw err;
        });
      });
    }

    console.log(`[backfill] batch_size=${BATCH_SIZE} dry_run=${DRY_RUN}`);
    return runBatch().then(() => {
      client.release();
      const elapsed = ((Date.now() - start) / 1000).toFixed(1);
      console.log(`[backfill] done items=${totalItems} observables=${totalObservables} elapsed=${elapsed}s`);
    });
  }).catch((err) => {
    console.error('[backfill]', err);
    process.exit(1);
  }).finally(() => pool.end());
}

run();
