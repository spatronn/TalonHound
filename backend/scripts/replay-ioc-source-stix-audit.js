#!/usr/bin/env node
/**
 * Offline replay of Phase-2 IOC Source URLs through the STIX-aware parser.
 * Fetches publisher content (read-only) — never writes to TalonHound DB.
 *
 * Usage:
 *   node scripts/replay-ioc-source-stix-audit.js /path/to/disposition.json [out.json]
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseIocSourceContent } from '../lib/threatLibrary/iocSources/parseContent.js';
import { enumerateGitHubIocSource } from '../lib/threatLibrary/iocSources/github.js';
import { fetchIocSourceUrl, validateIocSourceUrl } from '../lib/threatLibrary/iocSources/fetchSafe.js';
import { isReadmePath } from '../lib/threatLibrary/iocSources/campaignScope.js';
import { IOC_SOURCE_FETCH } from '../lib/threatLibrary/iocSources/constants.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function fetchText(url) {
  const policy = validateIocSourceUrl(url);
  if (!policy.ok) return { ok: false, code: 'blocked_url', message: policy.error };
  try {
    const fetched = await fetchIocSourceUrl(url, { maxBytes: IOC_SOURCE_FETCH.MAX_BYTES });
    return { ok: true, body: fetched.body, contentType: fetched.contentType, finalUrl: fetched.finalUrl };
  } catch (err) {
    return { ok: false, code: err.code || 'fetch_failed', message: String(err.message || err).slice(0, 240) };
  }
}

async function replayOne(item) {
  const url = item.source_url || item.canonical_url || item.url;
  const reportId = item.report_id;
  const baseline = {
    format: item.format,
    status: item.status,
    unique: item.unique,
    notes: item.notes
  };
  const out = {
    report_id: reportId,
    source_url: url,
    baseline,
    format: null,
    ok: false,
    code: null,
    unique_indicators: 0,
    classification: null,
    files: [],
    diagnostics: []
  };

  if (!url) {
    out.code = 'missing_url';
    return out;
  }

  const reportScope = {
    reportUrl: item.report_url || item.reportUrl || null,
    reportTitle: item.report_title || item.reportTitle || null
  };

  if (/github\.com\//i.test(url) && /\/tree\//i.test(url)) {
    const listing = await enumerateGitHubIocSource(url);
    if (!listing.ok) {
      out.code = listing.code;
      out.message = listing.message;
      return out;
    }
    const parseResults = [];
    for (const file of listing.files) {
      const fetched = await fetchText(file.download_url);
      if (!fetched.ok) {
        parseResults.push({ ok: false, code: fetched.code, message: fetched.message, path: file.path });
        out.files.push({ path: file.path, ok: false, code: fetched.code });
        continue;
      }
      const parsed = await parseIocSourceContent({
        body: fetched.body,
        contentType: fetched.contentType,
        url: file.download_url,
        path: file.path,
        reportScope
      });
      parseResults.push({ ...parsed, path: file.path });
      out.files.push({
        path: file.path,
        ok: parsed.ok,
        code: parsed.code || null,
        format: parsed.format,
        unique: parsed.unique_count ?? 0,
        classification: parsed.classification || null,
        scope: parsed.scope || null
      });
    }
    const okFiles = parseResults.filter((r) => r.ok && !isReadmePath(r.path || ''));
    const readmeOk = parseResults.some((r) => r.ok && isReadmePath(r.path || ''));
    const anyOk = parseResults.some((r) => r.ok);
    out.ok = anyOk;
    out.format = 'github_dir';
    out.code = anyOk ? 'inspected' : 'no_parsable_files';
    out.repo_revision = listing.repo_revision || null;
    // Dedup indicators across files
    const byKey = new Map();
    const classification = { indicator: 0, context_only: 0, excluded: 0, uncertain: 0, unsupported: 0 };
    for (const r of parseResults) {
      if (!r.ok) continue;
      if (r.classification) {
        for (const k of Object.keys(classification)) classification[k] += Number(r.classification[k] || 0);
      }
      for (const c of r.candidates || []) {
        byKey.set(`${c.candidate_type}\0${c.normalized_value}`, c);
      }
    }
    out.unique_indicators = byKey.size;
    out.classification = classification;
    out.readme_resolved = readmeOk;
    out.non_readme_ok = okFiles.length;
    return out;
  }

  const fetched = await fetchText(url);
  if (!fetched.ok) {
    out.code = fetched.code;
    out.message = fetched.message;
    return out;
  }
  const parsed = await parseIocSourceContent({
    body: fetched.body,
    contentType: fetched.contentType,
    url: fetched.finalUrl || url,
    path: path.basename(new URL(url).pathname),
    reportScope
  });
  out.ok = parsed.ok;
  out.format = parsed.format;
  out.code = parsed.ok ? 'inspected' : parsed.code;
  out.message = parsed.message || null;
  out.unique_indicators = parsed.unique_count ?? 0;
  out.classification = parsed.classification || null;
  out.type_breakdown = parsed.type_breakdown || null;
  out.diagnostics = (parsed.stix_diagnostics || []).slice(0, 20);
  out.stix_meta = parsed.stix_meta || null;
  return out;
}

async function main() {
  const dispositionPath = process.argv[2];
  const outPath = process.argv[3] || path.join(path.dirname(dispositionPath || '.'), 'stix-replay-after.json');
  if (!dispositionPath) {
    console.error('Usage: node scripts/replay-ioc-source-stix-audit.js disposition.json [out.json]');
    process.exit(2);
  }
  const items = JSON.parse(fs.readFileSync(dispositionPath, 'utf8'));
  if (!Array.isArray(items)) {
    console.error('disposition.json must be an array');
    process.exit(2);
  }

  // Enrich report URLs from optional sidecar / audit inventory.
  const reportUrls = new Map();
  const tsvPath = path.join(path.dirname(dispositionPath), 'report-urls.tsv');
  if (fs.existsSync(tsvPath)) {
    for (const line of fs.readFileSync(tsvPath, 'utf8').split(/\r?\n/)) {
      if (!line.trim()) continue;
      const [id, url, title] = line.split('\t');
      const rid = Number(id);
      if (rid && url) reportUrls.set(rid, url);
      if (rid && title) reportUrls.set(`title:${rid}`, title);
    }
  }
  const auditPath = path.join(path.dirname(dispositionPath), 'source-audit.json');
  if (fs.existsSync(auditPath)) {
    try {
      const audit = JSON.parse(fs.readFileSync(auditPath, 'utf8'));
      const rows = Array.isArray(audit)
        ? audit
        : audit.inventory || audit.sources || audit.items || [];
      for (const row of rows) {
        const rid = row.report_id;
        const ru = row.report_url || row.reportUrl || row.source_page_url;
        if (rid && ru && !reportUrls.has(rid)) reportUrls.set(rid, ru);
        if (rid && row.report_title && !reportUrls.has(`title:${rid}`)) {
          reportUrls.set(`title:${rid}`, row.report_title);
        }
      }
    } catch {
      // optional
    }
  }

  const results = [];
  for (const item of items) {
    const enriched = {
      ...item,
      report_url: item.report_url || reportUrls.get(item.report_id) || null,
      report_title: item.report_title || reportUrls.get(`title:${item.report_id}`) || null
    };
    process.stderr.write(`replay ${item.report_id} ${String(item.source_url || '').slice(-60)}\n`);
    try {
      results.push(await replayOne(enriched));
    } catch (err) {
      results.push({
        report_id: item.report_id,
        source_url: item.source_url,
        ok: false,
        code: 'replay_exception',
        message: String(err?.message || err).slice(0, 240)
      });
    }
  }

  const summary = {
    total: results.length,
    ok: results.filter((r) => r.ok).length,
    by_format: {},
    by_code: {},
    stix_json_ok: 0,
    stix_json_total: 0,
    stix_xml_ok: 0,
    stix_xml_total: 0,
    github_ok: 0,
    github_total: 0,
    total_unique_indicators: 0,
    classification_totals: { indicator: 0, context_only: 0, excluded: 0, uncertain: 0, unsupported: 0 }
  };
  for (const r of results) {
    const f = r.format || 'unknown';
    summary.by_format[f] = (summary.by_format[f] || 0) + 1;
    const c = r.code || 'unknown';
    summary.by_code[c] = (summary.by_code[c] || 0) + 1;
    if (f === 'stix_json' || (r.baseline?.format === 'stix_json')) {
      summary.stix_json_total += 1;
      if (r.ok) summary.stix_json_ok += 1;
    }
    if (f === 'stix_xml' || r.baseline?.format === 'stix_xml') {
      summary.stix_xml_total += 1;
      if (r.ok) summary.stix_xml_ok += 1;
    }
    if (f === 'github_dir' || r.baseline?.format === 'github_dir') {
      summary.github_total += 1;
      if (r.ok) summary.github_ok += 1;
    }
    summary.total_unique_indicators += Number(r.unique_indicators || 0);
    if (r.classification) {
      for (const k of Object.keys(summary.classification_totals)) {
        summary.classification_totals[k] += Number(r.classification[k] || 0);
      }
    }
  }

  const payload = { generated_at: new Date().toISOString(), summary, results };
  fs.writeFileSync(outPath, JSON.stringify(payload, null, 2));
  console.log(JSON.stringify(summary, null, 2));
  console.log(`wrote ${outPath}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
