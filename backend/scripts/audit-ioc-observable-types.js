#!/usr/bin/env node
/**
 * Read-only IOC semantic type-integrity audit.
 *
 * Streams the domain and URL partitions with SQL prefilters (colon, dotted
 * quad, CIDR). Does not load the catalog into memory. Classifies with
 * parseNetworkObservable. A confirmed mismatch is repairable only when it is
 * the Threat Library IPv6-as-domain inference defect; other mismatches are
 * reported and not treated as a repair set.
 *
 *   node scripts/audit-ioc-observable-types.js
 */
import '../lib/ensure-db-password.js';
import pg from 'pg';
import { classifyStoredNetworkRow, planHistoricalTypeRepair } from '../lib/iocTypeIntegrity.js';

function connectionConfig() {
  return {
    host: process.env.DB_HOST || 'db',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'talonhound',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'talonhound',
    max: 2,
    statement_timeout: 180000
  };
}

const SCANS = [
  {
    label: 'domain_networkish',
    sql: `SELECT id, observable, observable_type, source_name, created_origin, public_id::text AS public_id,
                 note, status
          FROM ioc_domain
          WHERE position(':' in observable) > 0
             OR observable ~ '^[0-9]{1,3}(\\.[0-9]{1,3}){3}(/[0-9]{1,3})?$'`
  },
  {
    label: 'url_networkish',
    sql: `SELECT id, observable, observable_type, source_name, created_origin, public_id::text AS public_id,
                 note, status
          FROM ioc_url
          WHERE observable !~* '^https?://'
            AND (
              position(':' in observable) > 0
              OR observable ~ '^[0-9]{1,3}(\\.[0-9]{1,3}){3}(/[0-9]{1,3})?$'
            )`
  },
  {
    label: 'ip_with_colon',
    sql: `SELECT id, observable, observable_type, source_name, created_origin, public_id::text AS public_id,
                 note, status
          FROM ioc_ip
          WHERE position(':' in observable) > 0`
  },
  {
    label: 'ipv6_noncanonical',
    sql: `SELECT id, observable, observable_type, source_name, created_origin, public_id::text AS public_id,
                 note, status
          FROM ioc_ipv6`
  }
];

async function scan(client, spec) {
  const counts = { inspected: 0, confirmed: 0 };
  const byDefect = {};
  const confirmed = [];
  await client.query('DECLARE type_scan NO SCROLL CURSOR FOR ' + spec.sql);
  for (;;) {
    const { rows } = await client.query('FETCH 2000 FROM type_scan');
    if (!rows.length) break;
    for (const row of rows) {
      counts.inspected += 1;
      const cls = classifyStoredNetworkRow(row);
      if (!cls?.confirmed) continue;
      counts.confirmed += 1;
      byDefect[cls.defect] = (byDefect[cls.defect] || 0) + 1;
      confirmed.push({ ...row, ...cls });
    }
  }
  await client.query('CLOSE type_scan');
  return { label: spec.label, counts, byDefect, confirmed };
}

async function main() {
  const pool = new pg.Pool({ ...connectionConfig(), options: '-c default_transaction_read_only=on' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    await client.query("SET statement_timeout = '180s'");
    const scans = [];
    const confirmed = [];
    for (const spec of SCANS) {
      const result = await scan(client, spec);
      confirmed.push(...result.confirmed);
      scans.push({
        label: result.label,
        inspected: result.counts.inspected,
        confirmed: result.counts.confirmed,
        by_defect: result.byDefect
      });
    }

    const plans = { retype: 0, out_of_scope: 0, blocked: 0, unchanged: 0 };
    const retype = [];
    const outOfScope = [];
    if (confirmed.length) {
      const ids = confirmed.map((r) => Number(r.id));
      const types = confirmed.map((r) => r.observable_type);
      const linked = await client.query(
        `SELECT c.matched_ioc_id, c.matched_ioc_observable_type, c.candidate_type, c.normalized_value,
                c.review_status, c.report_id, r.public_id::text AS report_public_id
         FROM threat_report_candidates c
         JOIN threat_reports r ON r.id = c.report_id
         WHERE (c.matched_ioc_id, c.matched_ioc_observable_type) IN (
           SELECT * FROM unnest($1::bigint[], $2::text[])
         )`,
        [ids, types]
      );
      const linkByIoc = new Map(linked.rows.map((r) => [Number(r.matched_ioc_id), r]));
      const existing = await client.query(
        `SELECT observable_type, observable FROM ioc_items
         WHERE (observable_type, observable) IN (
           SELECT * FROM unnest($1::text[], $2::text[])
         )`,
        [confirmed.map((r) => r.expected_type), confirmed.map((r) => r.canonical)]
      );
      const existingKeys = new Set(existing.rows.map((r) => `${r.observable_type}\t${r.observable}`));
      for (const row of confirmed) {
        const link = linkByIoc.get(Number(row.id));
        const joined = link ? { ...row, ...link, id: row.id } : row;
        const collision = existingKeys.has(`${row.expected_type}\t${row.canonical}`);
        const plan = planHistoricalTypeRepair(joined, { collision });
        plans[plan.action] = (plans[plan.action] || 0) + 1;
        const brief = {
          id: Number(row.id),
          defect: row.defect,
          observable: row.observable,
          source_name: row.source_name,
          reason: plan.reason
        };
        if (plan.action === 'retype') retype.push(brief);
        else outOfScope.push(brief);
      }
    }

    await client.query('COMMIT');
    process.stdout.write(`${JSON.stringify({
      scans,
      inspected: scans.reduce((n, s) => n + s.inspected, 0),
      confirmed: confirmed.length,
      plans,
      retype,
      out_of_scope: outOfScope
    }, null, 2)}\n`);
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    console.error(err);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

main();
