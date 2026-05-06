import { createHash } from 'node:crypto';
import { clickhouse, ensureRelatedLogsEvidenceTable } from './clickhouse.js';

const SAMPLE_MAX = Math.max(Number(process.env.RELATED_LOG_SAMPLE_MAX_LENGTH || 2000), 256);
let ensureEvidenceTablePromise = null;

async function ensureEvidenceTableReady() {
  if (!ensureEvidenceTablePromise) {
    ensureEvidenceTablePromise = ensureRelatedLogsEvidenceTable().catch((e) => {
      console.error('[related-logs] ensureRelatedLogsEvidenceTable failed (non-fatal)', e?.message || e);
      ensureEvidenceTablePromise = null;
      return false;
    });
  }
  return ensureEvidenceTablePromise;
}

export function buildRelatedEvidenceRow(input = {}) {
  const logHost = String(input.logHost || '');
  const logTs = input.logTs || null;
  const observedHost = String(input.observedHost || '');
  const matchedIoc = String(input.matchedIoc || '').toLowerCase();
  const observableType = String(input.observableType || '').toLowerCase();
  const rawMessage = String(input.rawMessage || '');
  const rawHash = createHash('sha256').update(rawMessage).digest('hex');
  const rawSample = rawMessage.slice(0, SAMPLE_MAX);
  const evidenceSeed = [logHost, logTs || '', observedHost, rawHash, matchedIoc, observableType].join('|');
  const evidenceHash = createHash('sha256').update(evidenceSeed).digest('hex');

  return {
    activity_id: String(input.activityId || ''),
    incident_id: Number(input.incidentId || 0),
    match_event_id: Number(input.matchEventId || 0),
    evidence_hash: evidenceHash,
    log_ts: logTs,
    matched_ioc: String(input.matchedIoc || ''),
    observable_type: String(input.observableType || ''),
    log_host: logHost,
    observed_host: observedHost,
    parser_source: String(input.parserSource || ''),
    source_type: String(input.sourceType || ''),
    raw_message_hash: rawHash,
    raw_message_sample: rawSample
  };
}

export async function insertIncidentRelatedLogEvidenceSafe(row) {
  try {
    if (!row?.activity_id || !row?.log_ts || !row?.matched_ioc) return false;
    await ensureEvidenceTableReady();
    await clickhouse.insert({
      table: 'security_evidence.incident_related_logs',
      values: [row],
      format: 'JSONEachRow'
    });
    return true;
  } catch (e) {
    console.warn('[related-logs] clickhouse insert failed (non-fatal)', e?.message || e);
    return false;
  }
}
