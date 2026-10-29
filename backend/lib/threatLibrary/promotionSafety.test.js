/**
 * Promotion-safety gate (review contract on tl-candidates-v45).
 *
 * A narrative Context Only value is promotable only with positive publisher
 * evidence or operational evidence plus an auditable corroboration. Lacking a
 * negative stance is not enough. No domain allowlist and no report id is
 * consulted.
 *
 * Shapes below match audited reports without binding the gate to those ids:
 * a connectivity check (34432 / 34445), a narrative C2 host, a third-party
 * URL the actor abused, a parent domain of that URL, and reference-only rows.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { applyAnalystState } from './candidateAnalystState.js';
import {
  classifyPromoteEligibility,
  publicPromoteEligibility,
  PROMOTION_CORROBORATION_MIN
} from './promotion.js';
import { applyCandidateReviewActions } from './reviewService.js';
import { CANDIDATE_REVIEW_MODULE, importFrontendModule } from '../../test-support/frontendModule.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://vendor-research.example/blog/promotion-safety/';
const CORROBORATION = 'The narrative names this exact observable as attacker infrastructure.';

function doc(inner) {
  const html = `<!doctype html><html lang="en"><head><title>Safety</title></head><body><article>
<h1>Campaign note</h1>
<p>Background paragraph describing the intrusion and its tooling across several environments.</p>
${inner}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  return r.document;
}

const IOC_TABLE = `<h2>Indicators Of Compromise (IOCs)</h2>
<table><thead><tr><th>Indicator</th><th>Type</th></tr></thead><tbody>
<tr><td>198.51.100.10</td><td>IP</td></tr>
</tbody></table>`;

function run(inner) {
  return extractReportCandidates({ source_type: 'url', source_url: SOURCE }, doc(inner));
}

function persisted(c, patch = {}) {
  return {
    ...c,
    has_original_document_occurrence: true,
    review_status: 'pending',
    evidence: buildCandidateEvidenceRecord(c),
    ...patch
  };
}

function find(out, value) {
  return out.candidates.find((c) => String(c.normalized_value).toLowerCase() === value.toLowerCase());
}

test('connectivity check: a neutral resolver target cannot be promoted (34432 shape)', () => {
  const out = run(`<h2>Persistence and privilege strategy</h2>
<p>-ServiceMode | Runs the implant as a service; verifies internet connectivity (by resolving connectivity-check.example) before executing.</p>
${IOC_TABLE}`);
  const c = find(out, 'connectivity-check.example');
  assert.ok(c, 'the connectivity target is still a candidate');
  const row = persisted(c);
  assert.equal(isReportIndicatorMember(row), false);
  const elig = classifyPromoteEligibility(row);
  assert.equal(elig.ok, false);
  assert.equal(elig.promotable, false);
  assert.equal(elig.code, 'promote_connectivity_check');
  assert.equal(elig.blocked_class, 'connectivity_check');
  const forced = classifyPromoteEligibility(row, { corroboration: CORROBORATION });
  assert.equal(forced.ok, false, 'a written reason does not override a connectivity check');
  assert.equal(forced.promotable, false);
});

test('connectivity check: reaching a public homepage to test the link is the same class (34445 shape)', () => {
  const out = run(`<h2>Anti-analysis techniques</h2>
<p>Following the initial checks, the stealer verifies internet connectivity by attempting to reach https://www.connectivity-check.example. If the machine is offline, it exits.</p>
${IOC_TABLE}`);
  const c = find(out, 'https://www.connectivity-check.example/') || find(out, 'https://www.connectivity-check.example');
  assert.ok(c);
  const elig = classifyPromoteEligibility(persisted(c));
  assert.equal(elig.promotable, false);
  assert.equal(elig.code, 'promote_connectivity_check');
});

test('narrative C2 promotion stays available and requires an auditable corroboration', () => {
  const out = run(`<h2>Infrastructure overlap</h2>
<p>The second stage beacons to c2-relay.example as its command and control server.</p>
${IOC_TABLE}`);
  const c = find(out, 'c2-relay.example');
  assert.ok(c);
  const row = persisted(c);
  assert.equal(isReportIndicatorMember(row), false);
  const pending = classifyPromoteEligibility(row);
  assert.equal(pending.promotable, true, JSON.stringify(pending));
  assert.equal(pending.requires_corroboration, true);
  assert.equal(pending.ok, false);
  assert.equal(pending.code, 'promote_corroboration_required');
  assert.ok(pending.publisher_evidence);
  assert.ok(pending.reason);
  const short = classifyPromoteEligibility(row, { corroboration: 'c2' });
  assert.equal(short.ok, false);
  assert.equal(short.promotable, true);
  const confirmed = classifyPromoteEligibility(row, { corroboration: CORROBORATION });
  assert.equal(confirmed.ok, true);
  assert.equal(confirmed.basis, 'operational_evidence');
  assert.equal(confirmed.accepted_corroboration, CORROBORATION);
  assert.ok(confirmed.accepted_corroboration.length >= PROMOTION_CORROBORATION_MIN);
});

test('third-party service abuse promotes the URL, not the provider domain', () => {
  const out = run(`<h2>Delivery</h2>
<p>The actor abused that hosting link and the payload was downloaded from https://shared-bin.example/drop/stage.bin.</p>
${IOC_TABLE}`);
  const url = find(out, 'https://shared-bin.example/drop/stage.bin');
  assert.ok(url, 'the payload URL is a candidate');
  const urlRow = persisted(url);
  const urlPending = classifyPromoteEligibility(urlRow);
  assert.equal(urlPending.promotable, true, JSON.stringify(urlPending));
  assert.equal(classifyPromoteEligibility(urlRow, { corroboration: CORROBORATION }).ok, true);

  const domain = find(out, 'shared-bin.example');
  if (domain) {
    const domainDecision = classifyPromoteEligibility(persisted(domain));
    assert.equal(domainDecision.promotable, false);
    assert.equal(domainDecision.code, 'promote_narrower_identity');
  } else {
    const synthesized = {
      candidate_type: 'domain',
      normalized_value: 'shared-bin.example',
      assessment: 'context_only',
      match_state: 'context_only',
      review_status: 'pending',
      role: 'reference',
      is_ioc: true,
      has_original_document_occurrence: true,
      source_assertion: 'body_mention',
      document_has_authoritative_scope: true,
      evidence: {
        document_has_authoritative_scope: true,
        policy_decision: 'context_only_narrative_with_authoritative_scope',
        source_relation: 'operational_malicious',
        occurrences: [{
          zone: 'report_body',
          occurrence_kind: 'narrative_mention',
          source_relation: 'operational_malicious',
          surrounding_text: 'the payload was downloaded from https://shared-bin.example/drop/stage.bin'
        }]
      }
    };
    const domainDecision = classifyPromoteEligibility(synthesized);
    assert.equal(domainDecision.promotable, false);
    assert.equal(domainDecision.code, 'promote_narrower_identity');
  }
});

test('publisher-negative and reference-only rows stay blocked', () => {
  const reference = {
    candidate_type: 'domain',
    normalized_value: 'cited-vendor.example',
    assessment: 'context_only',
    match_state: 'context_only',
    review_status: 'pending',
    role: 'reference',
    is_ioc: true,
    has_original_document_occurrence: true,
    source_assertion: 'reference_only',
    evidence: {
      document_has_authoritative_scope: true,
      policy_decision: 'context_only_reference_relation',
      source_relation: 'reference',
      occurrences: [{
        zone: 'report_body',
        occurrence_kind: 'narrative_mention',
        source_relation: 'reference',
        surrounding_text: 'According to the write-up published by cited-vendor.example, the campaign began in March.'
      }]
    }
  };
  const refDecision = classifyPromoteEligibility(reference, { corroboration: CORROBORATION });
  assert.equal(refDecision.promotable, false);
  assert.equal(refDecision.code, 'promote_outside_publisher_scope');

  const docs = {
    ...reference,
    candidate_type: 'ipv6',
    normalized_value: '2001:db8::1',
    role: 'reference',
    rfc_example: true,
    evidence: {
      document_has_authoritative_scope: true,
      policy_decision: 'context_only_rfc_example',
      rfc_example: true,
      occurrences: [{
        zone: 'report_body',
        surrounding_text: 'The documentation address 2001:db8::1 is never contacted.'
      }]
    }
  };
  const docsDecision = classifyPromoteEligibility(docs);
  assert.equal(docsDecision.promotable, false);
  assert.ok(docsDecision.code === 'promote_documentation' || docsDecision.code === 'promote_outside_publisher_scope');

  const placeholder = {
    candidate_type: 'url',
    normalized_value: 'https://cdn.example/loader/{token}',
    assessment: 'context_only',
    match_state: 'context_only',
    review_status: 'pending',
    role: 'payload_hosting',
    is_ioc: true,
    has_original_document_occurrence: true,
    source_assertion: 'body_mention',
    evidence: {
      document_has_authoritative_scope: true,
      policy_decision: 'context_only_narrative_with_authoritative_scope',
      occurrences: [{
        zone: 'report_body',
        surrounding_text: 'The template URL is https://cdn.example/loader/{token} until the campaign id is filled in.'
      }]
    }
  };
  assert.equal(classifyPromoteEligibility(placeholder).code, 'promote_placeholder');
});

test('refresh keeps an audited promotion corroboration on the same identity', () => {
  const fresh = {
    candidate_type: 'domain',
    normalized_value: 'c2-relay.example',
    assessment: 'context_only',
    match_state: 'context_only',
    role: 'reference',
    is_ioc: true
  };
  const prior = {
    review_status: 'approved',
    evidence: {
      decision_source: 'analyst',
      promoted_from: {
        assessment: 'context_only',
        role: 'command_and_control',
        corroboration: CORROBORATION,
        basis: 'operational_evidence'
      }
    }
  };
  applyAnalystState(fresh, prior);
  assert.equal(fresh.review_status, 'approved');
  assert.equal(fresh.assessment, 'suspicious');
  assert.equal(fresh.promoted_from.corroboration, CORROBORATION);
  assert.equal(fresh.promoted_from.basis, 'operational_evidence');
  assert.equal(isReportIndicatorMember({
    ...fresh,
    has_original_document_occurrence: true,
    document_has_authoritative_scope: true,
    source_assertion: 'body_mention',
    evidence: { document_has_authoritative_scope: true, promoted_from: fresh.promoted_from }
  }), true);
});

test('UI, API, and MCP share one promotion decision', async () => {
  const { describePromoteBlocker } = await importFrontendModule(CANDIDATE_REVIEW_MODULE);
  const row = {
    id: 7,
    candidate_type: 'domain',
    normalized_value: 'connectivity-check.example',
    assessment: 'context_only',
    match_state: 'context_only',
    review_status: 'pending',
    role: 'reference',
    is_ioc: true,
    has_original_document_occurrence: true,
    source_assertion: 'body_mention',
    evidence: {
      document_has_authoritative_scope: true,
      policy_decision: 'context_only_narrative_with_authoritative_scope',
      source_relation: 'contextual',
      occurrences: [{
        zone: 'report_body',
        occurrence_kind: 'narrative_mention',
        source_relation: 'contextual',
        section_heading: 'Persistence and privilege strategy',
        surrounding_text: 'verifies internet connectivity (by resolving connectivity-check.example) before executing'
      }]
    }
  };
  const apiDecision = publicPromoteEligibility(row);
  assert.equal(apiDecision.promotable, false);
  assert.equal(apiDecision.code, 'promote_connectivity_check');
  assert.match(String(apiDecision.publisher_evidence), /connectivity/);
  assert.equal(apiDecision.observable_role, 'reference');
  const blocker = describePromoteBlocker([{ ...row, promote_eligibility: apiDecision }]);
  assert.equal(blocker, apiDecision.detail);

  const c2 = {
    ...row,
    id: 8,
    normalized_value: 'c2-relay.example',
    assessment: 'malicious',
    match_state: 'new',
    role: 'command_and_control',
    evidence: {
      document_has_authoritative_scope: true,
      policy_decision: 'pass',
      source_relation: 'operational_malicious',
      occurrences: [{
        zone: 'report_body',
        source_relation: 'operational_malicious',
        section_heading: 'Infrastructure overlap',
        surrounding_text: 'The second stage beacons to c2-relay.example as its command and control server.'
      }]
    }
  };
  const c2Decision = publicPromoteEligibility(c2);
  assert.equal(c2Decision.promotable, true);
  assert.equal(c2Decision.requires_corroboration, true);
  assert.equal(describePromoteBlocker([{ ...c2, promote_eligibility: c2Decision }]), null);
  const withReason = publicPromoteEligibility(c2, { corroboration: CORROBORATION });
  assert.equal(withReason.ok, true);
  assert.equal(withReason.basis, 'operational_evidence');
});

test('promote_to_ioc writes the corroboration and refuses a connectivity row before any write', async () => {
  const narrative = {
    id: 2,
    candidate_type: 'domain',
    normalized_value: 'c2-relay.example',
    assessment: 'malicious',
    match_state: 'new',
    review_status: 'pending',
    role: 'command_and_control',
    is_ioc: true,
    has_original_document_occurrence: true,
    source_assertion: 'body_mention',
    matched_ioc_id: null,
    evidence: {
      document_has_authoritative_scope: true,
      policy_decision: 'pass',
      source_relation: 'operational_malicious',
      occurrences: [{
        zone: 'report_body',
        source_relation: 'operational_malicious',
        surrounding_text: 'The payload beacons to c2-relay.example as its command and control server.'
      }]
    }
  };
  const connectivity = {
    id: 3,
    candidate_type: 'domain',
    normalized_value: 'connectivity-check.example',
    assessment: 'context_only',
    match_state: 'context_only',
    review_status: 'pending',
    role: 'reference',
    is_ioc: true,
    has_original_document_occurrence: true,
    source_assertion: 'body_mention',
    evidence: {
      document_has_authoritative_scope: true,
      policy_decision: 'context_only_narrative_with_authoritative_scope',
      source_relation: 'contextual',
      occurrences: [{
        zone: 'report_body',
        occurrence_kind: 'narrative_mention',
        source_relation: 'contextual',
        surrounding_text: 'verifies internet connectivity (by resolving connectivity-check.example) before executing'
      }]
    }
  };
  const report = { id: 9, public_id: 'rep-9', title: 'Brief', analysis_status: 'review_required', source_url: null };
  const writes = [];
  const rows = [narrative, connectivity];
  const pool = {
    rows,
    async query(sql, params = []) {
      if (/FROM ioc_sources WHERE name/i.test(sql)) return { rows: [{ id: 4 }] };
      if (/^\s*SELECT/i.test(sql)) {
        if (/FROM threat_reports/i.test(sql)) return { rows: [report] };
        const ids = (params[1] || []).map(Number);
        return { rows: rows.filter((r) => ids.includes(Number(r.id))) };
      }
      writes.push(sql);
      if (/UPDATE threat_report_candidates/i.test(sql) && /evidence =/i.test(sql)) {
        const patch = JSON.parse(params[2]);
        const row = rows.find((r) => Number(r.id) === Number(params[1]));
        Object.assign(row, {
          review_status: 'approved',
          assessment: row.assessment === 'malicious' ? 'malicious' : 'suspicious',
          is_ioc: true,
          match_state: 'new',
          evidence: { ...(row.evidence || {}), ...patch }
        });
        return { rows: [row], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    }
  };
  const events = [];
  const refused = await applyCandidateReviewActions(pool, 9, {
    action: 'promote_to_ioc',
    candidateIds: [3],
    corroboration: CORROBORATION,
    createIoc: async () => { throw new Error('must not create'); },
    audit: { auditLog: async (ev) => { events.push(ev); } }
  });
  assert.equal(refused.ok, false);
  assert.equal(refused.code, 'promote_connectivity_check');
  assert.equal(writes.length, 0);
  assert.equal(events.length, 0);

  const created = [];
  const promoted = await applyCandidateReviewActions(pool, 9, {
    action: 'promote_to_ioc',
    candidateIds: [2],
    corroboration: CORROBORATION,
    user: { email: 'analyst@example.test' },
    createIoc: async (_pool, body) => {
      created.push(body.observable);
      return { status: 201, body: { id: 50, public_id: 'ioc-50', observable_type: 'domain' } };
    },
    findExistingIoc: async () => null,
    audit: { auditLog: async (ev) => { events.push(ev); } }
  });
  assert.equal(promoted.ok, true, JSON.stringify(promoted));
  assert.deepEqual(created, ['c2-relay.example']);
  assert.equal(narrative.evidence.promoted_from.corroboration, CORROBORATION);
  assert.equal(narrative.evidence.promoted_from.basis, 'operational_evidence');
  assert.equal(events.some((ev) => ev.metadata?.corroboration === CORROBORATION), true);
});
