#!/usr/bin/env node
/**
 * Operational diagnostic: prove every Basic Published Feed has exactly one active
 * public generation window equal to its configured Window (Query-mode → all).
 *
 * Usage (inside backend container):
 *   node scripts/published-feed-single-window-invariant.js
 *
 * Exit 0 when violations=0; exit 2 when any Basic feed violates the contract.
 */
import pg from 'pg';

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

const { rows } = await pool.query(`
  SELECT f.id,
         f.name,
         f.filter_mode,
         f.ioc_types::text AS ioc_types,
         f.time_window AS configured_window,
         f.formats::text AS formats,
         f.last_status,
         left(coalesce(f.last_error, ''), 80) AS last_error,
         COALESCE((
           SELECT array_agg(ag.snapshot_window ORDER BY ag.snapshot_window)
           FROM published_feed_active_generations ag
           WHERE ag.feed_id = f.id
         ), ARRAY[]::text[]) AS active_windows,
         COALESCE((
           SELECT array_agg(DISTINCT w ORDER BY w)
           FROM (
             SELECT COALESCE(s.params->>'window', 'all') AS w
             FROM published_feed_snapshots s
             WHERE s.feed_id = f.id AND s.status = 'success'
           ) x
         ), ARRAY[]::text[]) AS success_snap_windows
  FROM published_feeds f
  WHERE f.enabled = TRUE
  ORDER BY f.id
`);

const violations = [];
for (const row of rows) {
  const queryMode = String(row.filter_mode || '') === 'query';
  const configured = queryMode ? 'all' : String(row.configured_window || 'all');
  const active = row.active_windows || [];
  // Chunked feeds expose active_generations; small legacy feeds may only have snapshots.
  if (active.length > 1) {
    violations.push({ ...row, reason: 'active_public_windows_gt_1', configured, active });
    continue;
  }
  if (active.length === 1 && active[0] !== configured) {
    violations.push({ ...row, reason: 'active_ne_configured', configured, active });
    continue;
  }
  const snaps = (row.success_snap_windows || []).filter(Boolean);
  const badSnaps = snaps.filter((w) => w !== configured);
  if (badSnaps.length) {
    violations.push({
      ...row,
      reason: 'success_snapshot_alternate_window',
      configured,
      active,
      badSnaps
    });
  }
}

console.log(JSON.stringify({
  feeds: rows.length,
  violations: violations.length,
  rows: rows.map((r) => ({
    id: r.id,
    name: r.name,
    ioc_types: r.ioc_types,
    configured: r.filter_mode === 'query' ? 'all' : r.configured_window,
    active: r.active_windows,
    formats: r.formats,
    status: r.last_status,
    last_error: r.last_error || null
  })),
  violation_detail: violations
}, null, 2));

await pool.end();
process.exit(violations.length ? 2 : 0);
