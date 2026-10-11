#!/usr/bin/env node
/**
 * Historical AlienVault OTX attribution backfill.
 *
 * Scope: IOCs with AlienVault OTX feed evidence that include a pulse_id in the
 * note (or provider_metadata). Loads structured adversary / malware_families
 * from otx_pulse_snapshots when present, otherwise fetches GET /pulses/{id}
 * (rate-limited). Applies the same applyOtxPulseAttributions path as live sync.
 *
 * Usage:
 *   node scripts/otx-attribution-backfill.js --dry-run
 *   node scripts/otx-attribution-backfill.js --limit=200
 *   node scripts/otx-attribution-backfill.js --resume
 *
 * Safe: idempotent upserts, does not mutate IOC status/confidence/membership.
 */

import { createIntegrationPool } from '../lib/pg-pool.js';
import { config } from '../config.js';
import {
  ALIENVAULT_OTX_SOURCE_NAME,
  buildOtxPulseReferenceUrl,
  fetchOtxPulseById,
  normalizeOtxAdversary,
  normalizeOtxMalwareFamilies,
  parseOtxTimestamp,
  resolveOtxApiKey,
  sanitizeOtxErrorMessage
} from '../lib/alienvaultOtx.js';
import {
  applyOtxPulseAttributions,
  upsertOtxPulseSnapshot
} from '../../backend/lib/iocSourceAttributions.js';

const CHECKPOINT_SOURCE = 'AlienVault OTX Attribution Backfill';

function argFlag(name) {
  return process.argv.includes(`--${name}`);
}

function argValue(name, fallback = null) {
  const prefix = `--${name}=`;
  const hit = process.argv.find((a) => a.startsWith(prefix));
  if (!hit) return fallback;
  return hit.slice(prefix.length);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function parseNoteField(note, key) {
  const text = String(note || '');
  const re = new RegExp(`(?:^|\\|\\s*)${key}=([^|]+)`, 'i');
  const m = text.match(re);
  return m ? String(m[1]).trim() : null;
}

function parseNoteList(note, key) {
  const raw = parseNoteField(note, key);
  if (!raw) return [];
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
}

async function loadCandidates(client, { afterId = 0, limit = 500 } = {}) {
  const { rows } = await client.query(
    `SELECT e.id AS evidence_id, e.ioc_item_id, e.ioc_observable_type,
            e.note, e.provider_metadata, e.source_url,
            i.observable
     FROM ioc_feed_source_evidence e
     JOIN ioc_items i ON i.id = e.ioc_item_id AND i.observable_type = e.ioc_observable_type
     WHERE e.source_name = $1
       AND e.id > $2
     ORDER BY e.id ASC
     LIMIT $3`,
    [ALIENVAULT_OTX_SOURCE_NAME, afterId, limit]
  );
  return rows;
}

function extractPulseContext(row) {
  const meta = row.provider_metadata && typeof row.provider_metadata === 'object'
    ? row.provider_metadata
    : {};
  const pulseId = String(meta.pulse_id || parseNoteField(row.note, 'pulse_id') || '').trim();
  if (!pulseId) return null;
  const adversaryFromMeta = meta.adversaries || meta.adversary || null;
  const familiesFromMeta = meta.malware_families || null;
  const adversaryFromNote = parseNoteField(row.note, 'adversary');
  const familiesFromNote = parseNoteList(row.note, 'malware_families');
  return {
    evidenceId: row.evidence_id,
    iocId: row.ioc_item_id,
    observableType: row.ioc_observable_type,
    observable: row.observable,
    pulseId,
    pulseName: meta.pulse_name || parseNoteField(row.note, 'pulse_name'),
    pulseUrl: meta.otx_reference || row.source_url || buildOtxPulseReferenceUrl(pulseId),
    adversary: normalizeOtxAdversary(adversaryFromMeta?.length ? adversaryFromMeta : adversaryFromNote),
    malwareFamilies: normalizeOtxMalwareFamilies(
      (Array.isArray(familiesFromMeta) && familiesFromMeta.length)
        ? familiesFromMeta
        : familiesFromNote
    ),
    needsFetch: !(
      (adversaryFromMeta && (Array.isArray(adversaryFromMeta) ? adversaryFromMeta.length : adversaryFromMeta))
      || adversaryFromNote
      || (Array.isArray(familiesFromMeta) && familiesFromMeta.length)
      || familiesFromNote.length
    )
  };
}

async function loadPulseSnapshot(client, pulseId) {
  const { rows } = await client.query(
    `SELECT pulse_id, pulse_name, adversary, malware_families, tags, tlp, author_name,
            pulse_created, pulse_modified, pulse_url
     FROM otx_pulse_snapshots WHERE pulse_id = $1`,
    [pulseId]
  );
  return rows[0] || null;
}

async function resolvePulseMetadata(client, ctx, { apiKey, dryRun, fetchCache, stats }) {
  const snap = await loadPulseSnapshot(client, ctx.pulseId);
  if (snap) {
    stats.snapshotHits += 1;
    const adversary = normalizeOtxAdversary(snap.adversary || ctx.adversary);
    const malwareFamilies = normalizeOtxMalwareFamilies(
      (snap.malware_families && snap.malware_families.length)
        ? snap.malware_families
        : ctx.malwareFamilies
    );
    // Snapshot without families but note also empty → still try API once if allowed.
    if (malwareFamilies.length || !apiKey || dryRun) {
      return {
        pulseId: snap.pulse_id,
        pulseName: snap.pulse_name || ctx.pulseName,
        pulseUrl: snap.pulse_url || ctx.pulseUrl,
        adversary,
        malwareFamilies,
        observedAt: snap.pulse_modified || snap.pulse_created || null,
        fromSnapshot: true
      };
    }
  }

  // Historical notes usually lack malware_families. Prefer a complete pulse fetch
  // whenever families are missing, even if adversary was already parsed from the note.
  const needsFamilyFetch = !(ctx.malwareFamilies?.length);
  const hasNoteAttribution = Boolean(ctx.adversary.length || ctx.malwareFamilies.length);

  if (!needsFamilyFetch && hasNoteAttribution) {
    stats.noteHits += 1;
    return {
      pulseId: ctx.pulseId,
      pulseName: ctx.pulseName,
      pulseUrl: ctx.pulseUrl,
      adversary: ctx.adversary,
      malwareFamilies: ctx.malwareFamilies,
      observedAt: null,
      fromSnapshot: false
    };
  }

  if (fetchCache.has(ctx.pulseId)) {
    const cached = fetchCache.get(ctx.pulseId);
    // Merge note adversary if API/cache omitted it.
    if (!cached.adversary?.length && ctx.adversary.length) {
      return { ...cached, adversary: ctx.adversary };
    }
    return cached;
  }

  if (dryRun) {
    stats.wouldFetch += 1;
    const placeholder = {
      pulseId: ctx.pulseId,
      pulseName: ctx.pulseName,
      pulseUrl: ctx.pulseUrl,
      adversary: ctx.adversary,
      malwareFamilies: ctx.malwareFamilies,
      observedAt: null,
      unresolved: !hasNoteAttribution
    };
    fetchCache.set(ctx.pulseId, placeholder);
    if (hasNoteAttribution) {
      stats.noteHits += 1;
      stats.iocsWouldEnrichFamilies = (stats.iocsWouldEnrichFamilies || 0) + 1;
    }
    return placeholder;
  }

  if (!apiKey) {
    stats.skippedNoKey += 1;
    const unresolved = {
      pulseId: ctx.pulseId,
      pulseName: ctx.pulseName,
      pulseUrl: ctx.pulseUrl,
      adversary: ctx.adversary,
      malwareFamilies: ctx.malwareFamilies,
      observedAt: null,
      unresolved: !hasNoteAttribution
    };
    fetchCache.set(ctx.pulseId, unresolved);
    return unresolved;
  }

  try {
    const pulse = await fetchOtxPulseById({ apiKey, pulseId: ctx.pulseId });
    stats.fetched += 1;
    const meta = {
      pulseId: String(pulse?.id || ctx.pulseId),
      pulseName: String(pulse?.name || ctx.pulseName || '').trim() || null,
      pulseUrl: buildOtxPulseReferenceUrl(pulse?.id || ctx.pulseId),
      adversary: normalizeOtxAdversary(pulse?.adversary?.length ? pulse.adversary : ctx.adversary),
      malwareFamilies: normalizeOtxMalwareFamilies(pulse?.malware_families),
      observedAt: parseOtxTimestamp(pulse?.modified) || parseOtxTimestamp(pulse?.created),
      fromApi: true
    };
    await upsertOtxPulseSnapshot(client, {
      pulseId: meta.pulseId,
      pulseName: meta.pulseName,
      adversary: meta.adversary,
      malwareFamilies: meta.malwareFamilies,
      tags: Array.isArray(pulse?.tags) ? pulse.tags : [],
      tlp: pulse?.tlp || null,
      authorName: pulse?.author_name || null,
      pulseCreated: parseOtxTimestamp(pulse?.created),
      pulseModified: parseOtxTimestamp(pulse?.modified),
      pulseUrl: meta.pulseUrl,
      isBackfill: true
    });
    fetchCache.set(ctx.pulseId, meta);
    await sleep(Number(process.env.OTX_BACKFILL_DELAY_MS || 350));
    return meta;
  } catch (err) {
    stats.fetchFailed += 1;
    console.warn(`[otx-backfill] pulse ${ctx.pulseId}: ${sanitizeOtxErrorMessage(err.message)}`);
    const unresolved = {
      pulseId: ctx.pulseId,
      pulseName: ctx.pulseName,
      pulseUrl: ctx.pulseUrl,
      adversary: ctx.adversary,
      malwareFamilies: ctx.malwareFamilies,
      observedAt: null,
      unresolved: !hasNoteAttribution
    };
    fetchCache.set(ctx.pulseId, unresolved);
    return unresolved;
  }
}

async function main() {
  const dryRun = argFlag('dry-run');
  const resume = argFlag('resume');
  const maxEvidence = Number(argValue('limit', process.env.OTX_BACKFILL_LIMIT || '5000'));
  const pageSize = Number(argValue('page-size', '200'));

  const pool = createIntegrationPool(config.db);
  const client = await pool.connect();
  const stats = {
    examined: 0,
    withPulse: 0,
    iocsAffected: new Set(),
    actorAssertions: 0,
    familyAssertions: 0,
    withdrawn: 0,
    skippedNoPulse: 0,
    skippedNoKey: 0,
    snapshotHits: 0,
    noteHits: 0,
    fetched: 0,
    wouldFetch: 0,
    fetchFailed: 0,
    unresolvedLabels: 0,
    failed: 0
  };

  try {
    let afterId = 0;
    if (resume) {
      const cp = await client.query(
        `SELECT last_cursor FROM integration_checkpoints WHERE source_name = $1`,
        [CHECKPOINT_SOURCE]
      );
      afterId = Number(cp.rows[0]?.last_cursor || 0) || 0;
    }

    const apiKey = dryRun ? null : await resolveOtxApiKey(client, config.alienvaultOtxApiKey);
    const fetchCache = new Map();
    let processed = 0;

    console.log(JSON.stringify({
      phase: 'start',
      dryRun,
      resume,
      afterId,
      maxEvidence,
      hasApiKey: Boolean(apiKey)
    }));

    while (processed < maxEvidence) {
      const batchLimit = Math.min(pageSize, maxEvidence - processed);
      const rows = await loadCandidates(client, { afterId, limit: batchLimit });
      if (!rows.length) break;

      for (const row of rows) {
        afterId = Number(row.evidence_id);
        processed += 1;
        stats.examined += 1;

        const ctx = extractPulseContext(row);
        if (!ctx) {
          stats.skippedNoPulse += 1;
          continue;
        }
        stats.withPulse += 1;

        const meta = await resolvePulseMetadata(client, ctx, { apiKey, dryRun, fetchCache, stats });
        if (meta.unresolved && !meta.adversary.length && !meta.malwareFamilies.length) {
          stats.unresolvedLabels += 1;
          continue;
        }

        if (dryRun) {
          stats.iocsAffected.add(`${ctx.observableType}|${ctx.iocId}`);
          stats.actorAssertions += meta.adversary.length;
          stats.familyAssertions += meta.malwareFamilies.length;
          continue;
        }

        try {
          await client.query('BEGIN');
          const result = await applyOtxPulseAttributions(client, {
            iocId: ctx.iocId,
            observableType: ctx.observableType,
            pulseId: meta.pulseId,
            pulseName: meta.pulseName,
            pulseUrl: meta.pulseUrl,
            adversary: meta.adversary,
            malwareFamilies: meta.malwareFamilies,
            observedAt: meta.observedAt,
            isBackfill: true,
            completeObservation: true
          });
          await client.query('COMMIT');
          stats.iocsAffected.add(`${ctx.observableType}|${ctx.iocId}`);
          stats.actorAssertions += result.actors;
          stats.familyAssertions += result.families;
          stats.withdrawn += result.withdrawn;
        } catch (err) {
          try { await client.query('ROLLBACK'); } catch { /* ignore */ }
          stats.failed += 1;
          console.warn(`[otx-backfill] ioc ${ctx.iocId}: ${sanitizeOtxErrorMessage(err.message)}`);
        }
      }

      if (!dryRun) {
        await client.query(
          `INSERT INTO integration_checkpoints (source_name, last_cursor, updated_at)
           VALUES ($1, $2, NOW())
           ON CONFLICT (source_name)
           DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()`,
          [CHECKPOINT_SOURCE, String(afterId)]
        );
      }
    }

    const report = {
      phase: 'complete',
      dryRun,
      pulses_examined_evidence_rows: stats.examined,
      evidence_with_pulse: stats.withPulse,
      iocs_affected: stats.iocsAffected.size,
      actor_assertions_upserted: stats.actorAssertions,
      malware_family_assertions_upserted: stats.familyAssertions,
      withdrawn: stats.withdrawn,
      skipped_no_pulse: stats.skippedNoPulse,
      snapshot_hits: stats.snapshotHits,
      note_hits: stats.noteHits,
      api_fetched: stats.fetched,
      would_fetch: stats.wouldFetch,
      fetch_failed: stats.fetchFailed,
      unresolved_or_empty: stats.unresolvedLabels,
      skipped_no_api_key: stats.skippedNoKey,
      failed: stats.failed,
      checkpoint_after_id: afterId
    };
    console.log(JSON.stringify(report, null, 2));
    return report;
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error(sanitizeOtxErrorMessage(err?.message || err));
  process.exit(1);
});
