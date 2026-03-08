#!/usr/bin/env node
/**
 * One-off backfill: populate ioc_observables from existing ioc_items (~1.7M).
 * Each extracted observable (md5, sha1, sha256, imphash, ssdeep, tlsh, etc.)
 * is inserted as a row in ioc_observables with same source_name, confidence, etc.
 * uq_ioc_observables_dedup prevents duplicate (observable, type, source, ...).
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
const INSERT_CHUNK = 500;

const INSERT_SQL = `
  INSERT INTO ioc_observables (observable, observable_type, source_name, source_url, confidence, category, note)
  VALUES ($1, $2, $3, $4, $5, $6, $7)
`;

function run() {
  return pool.connect().then((client) => {
    let totalItems = 0;
    let totalObservables = 0;
    let lastPublicId = null;
    const start = Date.now();

    function fetchBatch() {
      if (lastPublicId) {
        return client.query(
          `SELECT public_id, observable, observable_type, source_name, source_url, confidence, category, note
           FROM ioc_items
           WHERE public_id > $1
           ORDER BY public_id
           LIMIT $2`,
          [lastPublicId, BATCH_SIZE]
        );
      }
      return client.query(
        `SELECT public_id, observable, observable_type, source_name, source_url, confidence, category, note
         FROM ioc_items
         ORDER BY public_id
         LIMIT $1`,
        [BATCH_SIZE]
      );
    }

    function insertRow(row) {
      return client.query(INSERT_SQL, [
        row.observable,
        row.observable_type,
        row.source_name,
        row.source_url ?? null,
        row.confidence,
        row.category ?? null,
        row.note ?? null
      ]).catch((err) => {
        if (err.code === '23505') return; // unique_violation, skip
        throw err;
      });
    }

    function insertObservablesBatch(rows) {
      if (rows.length === 0) return Promise.resolve();
      if (rows.length === 1) return insertRow(rows[0]);

      const placeholders = [];
      const values = [];
      let idx = 0;
      for (const r of rows) {
        placeholders.push(`($${idx + 1}, $${idx + 2}, $${idx + 3}, $${idx + 4}, $${idx + 5}, $${idx + 6}, $${idx + 7})`);
        values.push(
          r.observable,
          r.observable_type,
          r.source_name,
          r.source_url ?? null,
          r.confidence,
          r.category ?? null,
          r.note ?? null
        );
        idx += 7;
      }
      return client.query(
        `INSERT INTO ioc_observables (observable, observable_type, source_name, source_url, confidence, category, note)
         VALUES ${placeholders.join(', ')}`,
        values
      ).catch((err) => {
        if (err.code === '23505') {
          return Promise.all(rows.map(insertRow));
        }
        throw err;
      });
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
              const key = `${o.observable_type}:${o.observable_value}:${row.source_name}:${row.confidence}:${row.category ?? ''}:${row.source_url ?? ''}`;
              if (seen.has(key)) continue;
              seen.add(key);
              flat.push({
                observable: o.observable_value,
                observable_type: o.observable_type,
                source_name: row.source_name,
                source_url: row.source_url,
                confidence: row.confidence,
                category: row.category,
                note: row.note
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
