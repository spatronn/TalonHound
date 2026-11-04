/**
 * The extraction contract bundle: every version constant that can change what
 * a report's extraction produces, plus one fingerprint of the set.
 *
 * Recorded on each extraction run, and compared by the benchmark gate, so a
 * result always names the exact code contract that produced it.
 */

import crypto from 'node:crypto';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { THREAT_LIBRARY_DOCUMENT_ZONES_VERSION } from './documentZones.js';
import { TABLE_SEMANTICS_VERSION } from './tableSemantics.js';
import { OBSERVABLE_TYPE_RESOLVER_VERSION } from './observableTypeResolver.js';
import { THREAT_LIBRARY_HTML_EXTRACTOR_VERSION } from './extract/extractHtml.js';
import { PDF_LAYOUT_VERSION } from './pdfLayout.js';
import { EXTRACTION_QUALITY_VERSION } from './extractionQuality.js';
import { SECTION_TREE_VERSION, SECTION_TREE_SCOPE_ENGINE_VERSION } from './sectionTree/version.js';
import { EVIDENCE_INTEGRITY_VERSION } from './evidenceIntegrity.js';
import { IOC_SOURCE_SCOPE_VERSION } from './iocSources/campaignScope.js';
import { STRUCTURED_SOURCE_PARSER_VERSION } from './iocSources/structuredSources.js';
import { OBSERVABLE_DISPOSITION_VERSION } from './observableDispositions.js';
import { MEMBERSHIP_DECISION_VERSION } from './membershipDecision.js';

/** @returns {Record<string, string>} */
export function extractionContractBundle() {
  return {
    candidates: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
    zones: THREAT_LIBRARY_DOCUMENT_ZONES_VERSION,
    tables: TABLE_SEMANTICS_VERSION,
    type_resolver: OBSERVABLE_TYPE_RESOLVER_VERSION,
    html: THREAT_LIBRARY_HTML_EXTRACTOR_VERSION,
    pdf: PDF_LAYOUT_VERSION,
    section_tree: SECTION_TREE_VERSION,
    scope_engine: SECTION_TREE_SCOPE_ENGINE_VERSION,
    quality: EXTRACTION_QUALITY_VERSION,
    evidence_integrity: EVIDENCE_INTEGRITY_VERSION,
    ioc_source_scope: IOC_SOURCE_SCOPE_VERSION,
    structured_sources: STRUCTURED_SOURCE_PARSER_VERSION,
    dispositions: OBSERVABLE_DISPOSITION_VERSION,
    membership: MEMBERSHIP_DECISION_VERSION
  };
}

/**
 * Stable hash of a bundle (key order independent).
 * @param {Record<string, string>} bundle
 */
export function contractFingerprint(bundle = extractionContractBundle()) {
  const canonical = Object.keys(bundle).sort().map((k) => `${k}=${bundle[k]}`).join('\n');
  return crypto.createHash('sha256').update(canonical).digest('hex').slice(0, 32);
}
