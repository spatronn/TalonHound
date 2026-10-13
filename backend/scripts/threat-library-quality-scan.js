#!/usr/bin/env node
/**
 * Read-only Threat Library extraction quality + refresh preview scan.
 *
 * Opens a READ-ONLY database session (default_transaction_read_only=on) and,
 * for each selected report, runs the same preview as
 * GET …/reports/:id/refresh-extraction/preview: deterministic extraction of
 * the stored canonical document (or its retained source), extraction quality
 * warnings, and the membership diff + guard verdict a Refresh extraction would
 * produce. It never writes, never calls a model and never fetches a URL.
 *
 *   node scripts/threat-library-quality-scan.js [--report <uuid>]... [--limit 200] [--json]
 *        [--clean <uuid>,<uuid>]   reports an analyst verified as correct:
 *                                  warning-level findings on them count as false warnings
 */

import '../lib/ensure-db-password.js';
import pg from 'pg';
import { previewExtractionRefresh } from '../lib/threatLibrary/extractionRefresh.js';

export function parseScanArgs(argv) {
  const out = { reports: [], limit: 200, json: false, clean: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--report') out.reports.push(argv[++i]);
    else if (a === '--limit') out.limit = Math.min(Math.max(Number(argv[++i]) || 200, 1), 5000);
    else if (a === '--json') out.json = true;
    else if (a === '--clean') out.clean.push(...String(argv[++i] || '').split(',').map((s) => s.trim()).filter(Boolean));
    else throw new Error(`unknown argument: ${a}`);
  }
  return out;
}

/**
 * Aggregate per-report scan rows (pure).
 * @param {{ id: string, quality?: object|null, guard?: object|null, membership_diff?: object|null, error?: string|null }[]} rows
 * @param {string[]} [clean] analyst-verified report ids
 */
export function summarizeScan(rows, clean = []) {
  const cleanSet = new Set(clean);
  const summary = {
    reports: rows.length,
    errors: 0,
    quality_status: { clean: 0, info: 0, warning: 0, high: 0 },
    codes: {},
    guard: { apply: 0, apply_accepted: 0, block: 0 },
    reports_with_membership_changes: 0,
    verified_clean: { reports: 0, flagged: 0, flagged_ids: [] }
  };
  for (const r of rows) {
    if (r.error) {
      summary.errors += 1;
      continue;
    }
    const status = r.quality?.status || 'clean';
    summary.quality_status[status] = (summary.quality_status[status] || 0) + 1;
    for (const w of r.quality?.warnings || []) summary.codes[w.code] = (summary.codes[w.code] || 0) + 1;
    if (r.guard?.decision) summary.guard[r.guard.decision] = (summary.guard[r.guard.decision] || 0) + 1;
    const c = r.membership_diff?.counts || {};
    if ((c.added_indicators || 0) + (c.removed_indicators || 0) > 0) summary.reports_with_membership_changes += 1;
    if (cleanSet.has(r.id)) {
      summary.verified_clean.reports += 1;
      if (status === 'warning' || status === 'high') {
        summary.verified_clean.flagged += 1;
        summary.verified_clean.flagged_ids.push(r.id);
      }
    }
  }
  return summary;
}

async function main() {
  const args = parseScanArgs(process.argv.slice(2));
  const pool = new pg.Pool({
    host: process.env.DB_HOST || 'db',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'talonhound',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'talonhound',
    max: 2,
    options: '-c default_transaction_read_only=on'
  });
  try {
    const { rows: reports } = args.reports.length
      ? await pool.query(`SELECT * FROM threat_reports WHERE public_id = ANY($1::uuid[]) AND deleted_at IS NULL ORDER BY id`, [args.reports])
      : await pool.query(
        `SELECT * FROM threat_reports
         WHERE deleted_at IS NULL AND source_type IN ('url', 'pdf')
           AND analysis_status IN ('review_required', 'ready')
         ORDER BY id DESC LIMIT $1`,
        [args.limit]
      );
    const rows = [];
    for (const report of reports) {
      const started = Date.now();
      try {
        const p = await previewExtractionRefresh(pool, report);
        rows.push({
          id: report.public_id,
          title: String(report.title || '').slice(0, 80),
          quality: p.quality,
          guard: { decision: p.guard.decision, reasons: p.guard.reasons.map((r) => r.code) },
          membership_diff: { indicators: p.membership_diff.indicators, counts: p.membership_diff.counts },
          elapsed_ms: Date.now() - started
        });
      } catch (err) {
        rows.push({ id: report.public_id, title: String(report.title || '').slice(0, 80), error: err?.code || err?.message || 'error' });
      }
    }
    const summary = summarizeScan(rows, args.clean);
    if (args.json) {
      console.log(JSON.stringify({ summary, reports: rows }, null, 2));
      return;
    }
    for (const r of rows) {
      if (r.error) {
        console.log(`ERR  ${r.id} ${r.error}  ${r.title}`);
        continue;
      }
      const codes = [...new Set((r.quality?.warnings || []).filter((w) => w.severity !== 'info').map((w) => w.code))];
      const d = r.membership_diff;
      console.log(
        `${(r.quality?.status || 'clean').padEnd(7)} ${r.guard.decision.padEnd(14)} ${r.id} ` +
          `Indicators ${d.indicators.before}→${d.indicators.after} (+${d.counts.added_indicators} -${d.counts.removed_indicators})` +
          `${codes.length ? `  ⚠ ${codes.join(',')}` : ''}  ${r.title}`
      );
    }
    console.log(`\n${JSON.stringify(summary, null, 2)}`);
  } finally {
    await pool.end();
  }
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('threat-library-quality-scan.js')) {
  main().catch((err) => {
    console.error(err?.message || err);
    process.exitCode = 1;
  });
}
