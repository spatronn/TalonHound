#!/usr/bin/env node
/**
 * Threat Library source identity operations (logical article identity,
 * migration 056). Runs inside the backend container (reads retained fetch
 * artifacts from the Threat Library storage volume; never fetches).
 *
 *   audit       READ-ONLY duplicate inventory. Recomputes every active URL
 *               report's identity from its retained url_fetch artifact
 *               (submitted URL, final URL after redirects, source.html:
 *               canonical / og:url / JSON-LD / WordPress post id / hreflang)
 *               and groups reports that share a proven identity key. Each
 *               group carries a reconciliation dry-run verdict (blockers or
 *               ok). Reports that only look alike (same normalised title and
 *               publication day, no shared key) are listed separately as
 *               `similar_only` — never treated as duplicates.
 *
 *   backfill    Record the fetch-derived identity keys of existing reports
 *               (oldest first; a key another report owns is reported, not
 *               taken) and fill source_identity where empty. Writes only
 *               threat_report_identity_keys and threat_reports.source_identity.
 *               Dry-run unless --apply. Idempotent.
 *
 *   reconcile   Supersede --secondary into --primary after every invariant in
 *               reportSupersession.planReportReconciliation holds (re-checked
 *               under row + identity locks). Non-destructive; audited.
 *               Dry-run (rolled back) unless --apply. Idempotent.
 *
 *   node scripts/threat-library-source-identity.js audit [--out <file.json>]
 *   node scripts/threat-library-source-identity.js backfill [--apply]
 *   node scripts/threat-library-source-identity.js reconcile --primary <uuid> --secondary <uuid> [--apply]
 *       [--accept-secondary-only] [--accept-decision '<type>|<value>' ...] --reason "<why, >= 12 chars>"
 *
 *               Acceptances (reportSupersession.js) cover only pending unlinked
 *               context rows, entity-entity relationships and individually
 *               named decision conflicts; they are recorded, never copied.
 */

import '../lib/ensure-db-password.js';
import { writeFile } from 'node:fs/promises';
import pg from 'pg';
import { createAuditLogService } from '../lib/auditLogService.js';
import { lockIdentityKeys, recordIdentityKeys } from '../lib/threatLibrary/importIdentity.js';
import {
  isSupersededInto,
  planReportReconciliation,
  rankLogicalReportMembers,
  reconcileDuplicateReports,
  resolveStoredReportIdentity
} from '../lib/threatLibrary/reportSupersession.js';

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const opt = (name) => {
    const i = rest.indexOf(`--${name}`);
    return i >= 0 ? rest[i + 1] : null;
  };
  const all = (name) => rest.flatMap((v, i) => (v === `--${name}` && rest[i + 1] ? [rest[i + 1]] : []));
  return {
    command,
    apply: rest.includes('--apply'),
    out: opt('out'),
    primary: opt('primary'),
    secondary: opt('secondary'),
    acceptSecondaryOnly: rest.includes('--accept-secondary-only'),
    acceptDecisions: all('accept-decision'),
    reason: opt('reason')
  };
}

function connectionConfig(readOnly) {
  return {
    host: process.env.DB_HOST || 'db',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'talonhound',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'talonhound',
    max: 3,
    ...(readOnly ? { options: '-c default_transaction_read_only=on' } : {})
  };
}

const REPORT_COLUMNS = `id, public_id, title, source_type, source_name, source_url, source_url_canonical,
  import_status, analysis_status, finalized_at, published_at, created_at, deleted_at,
  superseded_by_report_id, superseded_at, source_identity`;

async function loadActiveUrlReports(db) {
  const { rows } = await db.query(
    `SELECT ${REPORT_COLUMNS} FROM threat_reports
      WHERE source_type = 'url' AND deleted_at IS NULL
      ORDER BY created_at ASC, id ASC`
  );
  return rows;
}

function normTitle(t) {
  return String(t || '').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim();
}

function day(v) {
  return v ? new Date(v).toISOString().slice(0, 10) : null;
}

function brief(r) {
  return {
    report_id: r.public_id,
    id: Number(r.id),
    title: r.title,
    publisher: r.source_name,
    source_url: r.source_url,
    import_status: r.import_status,
    finalized: Boolean(r.finalized_at),
    published_date: day(r.published_at),
    imported_at: r.created_at,
    superseded_by_report_id: r.superseded_by_report_id ? Number(r.superseded_by_report_id) : null
  };
}

const STRONG_EVIDENCE = new Set(['submitted', 'redirect', 'canonical', 'og_url', 'json_ld', 'wp_post']);

async function audit(pool, args) {
  const reports = await loadActiveUrlReports(pool);
  const identities = new Map();
  const artifactGaps = [];
  for (const r of reports) {
    const identity = await resolveStoredReportIdentity(pool, r);
    identities.set(Number(r.id), identity);
    if (!identity?.artifact?.html) artifactGaps.push({ report_id: r.public_id, artifact: identity?.artifact || null });
  }

  // Union-find over shared identity keys.
  const parent = new Map(reports.map((r) => [Number(r.id), Number(r.id)]));
  const find = (x) => (parent.get(x) === x ? x : (parent.set(x, find(parent.get(x))), parent.get(x)));
  const owners = new Map();
  for (const r of reports) {
    for (const k of identities.get(Number(r.id))?.keys || []) {
      if (!k.evidence.some((e) => STRONG_EVIDENCE.has(e))) continue;
      if (!owners.has(k.key)) owners.set(k.key, []);
      owners.get(k.key).push({ id: Number(r.id), evidence: k.evidence });
    }
  }
  for (const list of owners.values()) {
    for (let i = 1; i < list.length; i += 1) parent.set(find(list[i].id), find(list[0].id));
  }
  // Reciprocal hreflang (translations listing each other).
  const keysOf = (id) => new Set((identities.get(id)?.keys || []).map((k) => k.key));
  const translationLinks = [];
  for (const r of reports) {
    const id = Number(r.id);
    for (const alt of identities.get(id)?.hreflang || []) {
      for (const o of owners.get(alt.key) || []) {
        if (o.id === id) continue;
        const back = (identities.get(o.id)?.hreflang || []).some((h) => keysOf(id).has(h.key));
        if (back && id < o.id) {
          translationLinks.push({ a: id, b: o.id, lang: alt.lang });
          parent.set(find(o.id), find(id));
        }
      }
    }
  }

  const byId = new Map(reports.map((r) => [Number(r.id), r]));
  const groups = new Map();
  for (const r of reports) {
    const root = find(Number(r.id));
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root).push(r);
  }
  const duplicateGroups = [];
  for (const members of groups.values()) {
    if (members.length < 2) continue;
    const ids = new Set(members.map((m) => Number(m.id)));
    const sharedKeys = [...owners.entries()]
      .filter(([, list]) => list.filter((o) => ids.has(o.id)).length > 1)
      .map(([key, list]) => ({ key, reports: list.filter((o) => ids.has(o.id)).map((o) => ({ report_id: byId.get(o.id).public_id, evidence: o.evidence })) }));
    const titles = new Set(members.map((m) => normTitle(m.title)));
    const dates = new Set(members.map((m) => day(m.published_at)));
    // Recommended primary: the group's existing primary (not superseded), then
    // finalized, then oldest import (never "newest").
    const ordered = rankLogicalReportMembers(members);
    const primary = ordered[0];
    const plans = [];
    for (const secondary of ordered.slice(1)) {
      if (isSupersededInto(secondary, primary.id, members)) {
        plans.push({ secondary: secondary.public_id, status: 'already_reconciled' });
        continue;
      }
      const plan = await planReportReconciliation(pool, {
        primary,
        secondary,
        primaryIdentity: identities.get(Number(primary.id)),
        secondaryIdentity: identities.get(Number(secondary.id))
      });
      plans.push({ secondary: secondary.public_id, status: plan.ok ? 'reconcilable' : 'blocked', blockers: plan.blockers, checks: plan.checks, secondary_only: plan.secondary_only });
    }
    const translation = translationLinks.filter((t) => ids.has(t.a));
    duplicateGroups.push({
      confidence: sharedKeys.length ? 'confirmed_identity' : 'translation_reciprocal_hreflang',
      reports: ordered.map(brief),
      shared_keys: sharedKeys,
      translation_links: translation.map((t) => ({ a: byId.get(t.a).public_id, b: byId.get(t.b).public_id, lang: t.lang })),
      conflicting_metadata: {
        titles_differ: titles.size > 1,
        published_dates_differ: dates.size > 1
      },
      recommended_primary: primary.public_id,
      recommendation: plans
    });
  }

  // Look-alikes without any shared identity key: listed for analysts, never merged.
  const similar = new Map();
  for (const r of reports) {
    const t = normTitle(r.title);
    if (!t || t.length < 12) continue;
    const k = `${t}|${day(r.published_at) || ''}`;
    if (!similar.has(k)) similar.set(k, []);
    similar.get(k).push(r);
  }
  const similarOnly = [...similar.values()]
    .filter((list) => list.length > 1 && new Set(list.map((r) => find(Number(r.id)))).size > 1)
    .map((list) => ({ reports: list.map(brief), reason: 'same_title_and_publication_day_without_shared_identity' }));

  const result = {
    generated_at: new Date().toISOString(),
    url_reports: reports.length,
    reports_without_retained_html: artifactGaps.length,
    duplicate_groups: duplicateGroups,
    similar_only: similarOnly
  };
  const text = JSON.stringify(result, null, 2);
  if (args.out) await writeFile(args.out, text);
  console.log(JSON.stringify({
    url_reports: result.url_reports,
    reports_without_retained_html: result.reports_without_retained_html,
    duplicate_groups: duplicateGroups.length,
    similar_only: similarOnly.length,
    out: args.out || null
  }));
  if (!args.out) console.log(text);
}

async function backfill(pool, args) {
  const reports = (await loadActiveUrlReports(pool)).filter((r) => !r.superseded_by_report_id);
  const summary = { scanned: reports.length, keys_inserted: 0, identity_filled: 0, conflicts: [], without_html: 0 };
  for (const r of reports) {
    const identity = await resolveStoredReportIdentity(pool, r);
    if (!identity) continue;
    if (!identity.artifact?.html) summary.without_html += 1;
    if (!args.apply) {
      const { rows } = await pool.query(
        `SELECT identity_key, report_id FROM threat_report_identity_keys WHERE identity_key = ANY($1::text[])`,
        [identity.keys.map((k) => k.key)]
      );
      const owned = new Map(rows.map((x) => [x.identity_key, Number(x.report_id)]));
      for (const k of identity.keys) {
        if (!owned.has(k.key)) summary.keys_inserted += 1;
        else if (owned.get(k.key) !== Number(r.id)) summary.conflicts.push({ report_id: r.public_id, key: k.key, owner_id: owned.get(k.key) });
      }
      if (!r.source_identity) summary.identity_filled += 1;
      continue;
    }
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await lockIdentityKeys(client, identity.keys.map((k) => k.key));
      const rec = await recordIdentityKeys(client, r.id, identity.keys, 'backfill');
      summary.keys_inserted += rec.inserted.length;
      for (const c of rec.conflicts) summary.conflicts.push({ report_id: r.public_id, key: c.key, owner_id: c.report_id });
      const filled = await client.query(
        `UPDATE threat_reports SET source_identity = $2::jsonb WHERE id = $1 AND source_identity IS NULL`,
        [r.id, JSON.stringify({ ...identity, outcome: 'backfill', conflicts: rec.conflicts, claimed_at: new Date().toISOString() })]
      );
      summary.identity_filled += filled.rowCount;
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }
  console.log(JSON.stringify({ mode: args.apply ? 'apply' : 'dry_run', ...summary }, null, 2));
}

async function reconcile(pool, args) {
  if (!args.primary || !args.secondary) throw new Error('--primary and --secondary are required');
  const auditService = createAuditLogService(pool);
  const result = await reconcileDuplicateReports(pool, {
    primaryPublicId: args.primary,
    secondaryPublicId: args.secondary,
    actor: null,
    auditLogInTransaction: auditService.auditLogInTransaction,
    dryRun: !args.apply,
    accept: {
      reason: args.reason,
      secondaryOnlyContext: args.acceptSecondaryOnly,
      decisionConflicts: args.acceptDecisions
    }
  });
  console.log(JSON.stringify(result, null, 2));
  if (result.status === 'blocked') process.exitCode = 2;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const commands = { audit, backfill, reconcile };
  if (!commands[args.command]) {
    console.error('usage: threat-library-source-identity.js audit|backfill|reconcile [...]');
    process.exit(64);
  }
  // audit and dry-run backfill run in a read-only session; reconcile needs row
  // locks even for its (rolled back) dry-run.
  const readOnly = args.command === 'audit' || (args.command === 'backfill' && !args.apply);
  const pool = new pg.Pool(connectionConfig(readOnly));
  try {
    await commands[args.command](pool, args);
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error(err?.stack || err);
  process.exit(1);
});
