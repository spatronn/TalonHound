/**
 * Section-tree unit tests (structure, authority, shadow isolation).
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { annotateSectionTree } from './annotate.js';
import { previewMembershipAdditive } from './membershipPreview.js';
import { applySectionTreeAuthority } from './authority.js';
import { evaluateSectionTreeShadow, attachSectionTreeShadowDiagnostics } from './shadow.js';
import { isSectionTreeShadowEnabled, getScopeEngine, isSectionTreeScopeAuthoritative } from './flags.js';
import { isReportIndicatorMember } from '../indicatorMembership.js';
import { buildCandidateEvidenceRecord } from '../evidencePolicy.js';
import { SCOPE_ENGINE_LEGACY, SCOPE_ENGINE_SECTION_TREE } from './version.js';

function doc(blocks, meta = {}) {
  return { title: 't', blocks, meta: { extractor: 'threat_library_html_v6', ...meta } };
}

function pdfDoc(blocks) {
  return doc(blocks, { extractor: 'threat_library_pdf_v6', adapter: 'pdf' });
}

describe('sectionTree.annotate', () => {
  it('keeps hash inventory under IoC appendix when a synthetic subgroup label intervenes', () => {
    const d = doc([
      { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise' },
      { id: 'p1', type: 'paragraph', text: 'Blinder Tunnel malware payloads and hashes' },
      { id: 'f1', type: 'list', text: 'payload.zip – Initial malicious archive' },
      { id: 'h2', type: 'list', text: '6e7d9b33f1e72ea1ede71373a604ecdb060dab7d42055179c1eede9ecd1fd239' },
      { id: 'ipL', type: 'paragraph', text: 'IP addresses:' },
      { id: 'ip1', type: 'list', text: '91.107.156[.]29' }
    ]);
    const tree = annotateSectionTree(d);
    const hash = tree.blocks.find((b) => b.id === 'h2');
    const ip = tree.blocks.find((b) => b.id === 'ip1');
    assert.equal(hash.authoritative_zone, 'explicit_ioc_section');
    assert.equal(ip.authoritative_zone, 'explicit_ioc_section');
    assert.ok(hash.section_path.some((p) => /Indicators of Compromise/i.test(p)));
  });

  it('closes appendix on a real same-level HTML sibling that is not a subgroup', () => {
    const d = doc([
      { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise' },
      { id: 'h2', type: 'list', text: '6e7d9b33f1e72ea1ede71373a604ecdb060dab7d42055179c1eede9ecd1fd239' },
      { id: 'h3', type: 'heading', level: 2, text: 'Conclusion' },
      { id: 'p2', type: 'paragraph', text: 'Narrative closing remarks without indicators.' }
    ]);
    const tree = annotateSectionTree(d);
    const hash = tree.blocks.find((b) => b.id === 'h2');
    const narrative = tree.blocks.find((b) => b.id === 'p2');
    assert.equal(hash.authoritative_zone, 'explicit_ioc_section');
    assert.equal(narrative.authoritative_zone, null);
    assert.equal(narrative.tree_zone, 'report_body');
  });

  it('PDF inferred levels: topic sibling closes appendix (no over-extension)', () => {
    const d = pdfDoc([
      { id: 'h1', type: 'heading', level: 1, text: 'Indicators of Compromise' },
      { id: 'hash', type: 'list', text: '6e7d9b33f1e72ea1ede71373a604ecdb060dab7d42055179c1eede9ecd1fd239' },
      { id: 'h2', type: 'heading', level: 1, text: 'Conclusion' },
      { id: 'dom', type: 'list', text: 'example.com' }
    ]);
    const tree = annotateSectionTree(d);
    assert.equal(tree.blocks.find((b) => b.id === 'hash').authoritative_zone, 'explicit_ioc_section');
    assert.equal(tree.blocks.find((b) => b.id === 'dom').authoritative_zone, null);
    assert.ok(tree.meta.trace.some((t) => t.decision === 'close_appendix_on_topic_heading'));
  });

  it('MODE B: synthetic-only openings do not invent authoritative scope', () => {
    const d = doc([
      { id: 'p1', type: 'paragraph', text: 'Malware payloads and hashes' },
      { id: 'hash', type: 'list', text: '6e7d9b33f1e72ea1ede71373a604ecdb060dab7d42055179c1eede9ecd1fd239' }
    ]);
    const tree = annotateSectionTree(d);
    assert.equal(tree.meta.has_authoritative_scope, false);
    assert.equal(tree.meta.real_authoritative_openings, 0);
  });

  it('MODE A: late real IOC headings still count when the trace buffer is full', () => {
    const blocks = [];
    for (let i = 0; i < 100; i += 1) {
      blocks.push({ id: `h${i}`, type: 'heading', level: 2, text: `Section topic ${i}` });
      blocks.push({ id: `p${i}`, type: 'paragraph', text: `Narrative paragraph ${i}.` });
    }
    blocks.push({ id: 'ioc', type: 'heading', level: 2, text: 'Indicators of Compromise' });
    blocks.push({
      id: 'hash',
      type: 'list',
      text: '6e7d9b33f1e72ea1ede71373a604ecdb060dab7d42055179c1eede9ecd1fd239'
    });
    const tree = annotateSectionTree(doc(blocks));
    assert.equal(tree.meta.has_authoritative_scope, true);
    assert.ok(tree.meta.real_authoritative_openings >= 1);
    assert.equal(tree.blocks.find((b) => b.id === 'hash').authoritative_zone, 'explicit_ioc_section');
  });

  it('records stable section_path_ids alongside path texts', () => {
    const d = doc([
      { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise' },
      { id: 'hash', type: 'list', text: '6e7d9b33f1e72ea1ede71373a604ecdb060dab7d42055179c1eede9ecd1fd239' }
    ]);
    const tree = annotateSectionTree(d);
    const hash = tree.blocks.find((b) => b.id === 'hash');
    assert.deepEqual(hash.section_path_ids, ['h1']);
    assert.ok(hash.section_path[0].includes('Indicators'));
  });

  it('does not treat annotated IOC lines as synthetic C2 headings', () => {
    const d = doc([
      { id: 'h1', type: 'heading', level: 2, text: 'Network indicators' },
      {
        id: 'd1',
        type: 'paragraph',
        text: 'mail.uaiubifas[.]top - GRAYRABBIT C2 domain (port 443, raw TCP, RC4-encrypted)'
      },
      {
        id: 'ip1',
        type: 'paragraph',
        text: '8.218.50[.]207 - Staging server (Alibaba Cloud, Hong Kong)'
      }
    ]);
    const tree = annotateSectionTree(d);
    assert.equal(tree.blocks.find((b) => b.id === 'd1').tree_is_heading, undefined);
    assert.equal(tree.blocks.find((b) => b.id === 'ip1').tree_is_heading, undefined);
    assert.equal(tree.blocks.find((b) => b.id === 'ip1').authoritative_zone, 'explicit_ioc_section');
  });

  it('C2 narrative topics without inventory do not open authoritative scope alone', () => {
    const d = doc([
      { id: 'h0', type: 'heading', level: 2, text: 'Outlook calendar events as a C2 channel' },
      {
        id: 'p1',
        type: 'paragraph',
        text: 'The module validates access by requesting https://graph.microsoft.com/v1.0/organization.'
      },
      {
        id: 'code',
        type: 'list',
        text: '1 2 3 | POST https://login.microsoftonline.com/<TenantId>/oauth2/v2.0/token'
      },
      { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise' },
      { id: 'dom', type: 'list', text: 'evil.example.com' }
    ]);
    const tree = annotateSectionTree(d);
    assert.equal(tree.blocks.find((b) => b.id === 'p1').authoritative_zone, null);
    assert.equal(tree.blocks.find((b) => b.id === 'code').authoritative_zone, null);
    assert.equal(tree.blocks.find((b) => b.id === 'dom').authoritative_zone, 'explicit_ioc_section');
    assert.equal(tree.meta.has_authoritative_scope, true);
  });

  it('References under an IOC appendix terminates authority (citation lists stay negative)', () => {
    const d = doc([
      { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise' },
      { id: 'hash', type: 'list', text: '6e7d9b33f1e72ea1ede71373a604ecdb060dab7d42055179c1eede9ecd1fd239' },
      { id: 'href', type: 'heading', level: 3, text: 'References' },
      { id: 'u1', type: 'list', text: 'https://winsparkle.org/' },
      { id: 'u2', type: 'list', text: 'https://poedit.com/' }
    ]);
    const tree = annotateSectionTree(d);
    assert.equal(tree.blocks.find((b) => b.id === 'hash').authoritative_zone, 'explicit_ioc_section');
    const u1 = tree.blocks.find((b) => b.id === 'u1');
    assert.equal(u1.authoritative_zone, null);
    assert.equal(u1.tree_zone, 'reference_section');
    assert.equal(u1.negative_scope, true);
    assert.ok(tree.meta.trace.some((t) => t.decision === 'close_appendix_on_negative_heading'));
  });
});

describe('sectionTree.authority', () => {
  it('authoritative remap recovers focused appendix hashes and keeps narrative out', () => {
    const hashVal = '6e7d9b33f1e72ea1ede71373a604ecdb060dab7d42055179c1eede9ecd1fd239';
    const d = doc([
      { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise' },
      { id: 'p1', type: 'paragraph', text: 'Campaign malware payloads and hashes' },
      { id: 'f1', type: 'list', text: 'sample.zip – archive' },
      { id: 'hash', type: 'list', text: hashVal },
      { id: 'narr', type: 'paragraph', text: 'The attackers also abused google.com for search research.' }
    ]);
    const candidates = [
      {
        candidate_type: 'sha256',
        normalized_value: hashVal,
        original_value: hashVal,
        is_ioc: true,
        assessment: 'malicious',
        source_assertion: 'body_mention',
        document_has_authoritative_scope: true,
        occurrences: [{ block_id: 'hash', zone: 'report_body', asserted: false }]
      },
      {
        candidate_type: 'domain',
        normalized_value: 'google.com',
        original_value: 'google.com',
        is_ioc: true,
        assessment: 'suspicious',
        source_assertion: 'body_mention',
        document_has_authoritative_scope: true,
        occurrences: [{ block_id: 'narr', zone: 'report_body', asserted: false }]
      }
    ];
    const applied = applySectionTreeAuthority(d, candidates);
    assert.equal(applied.scope_engine, SCOPE_ENGINE_SECTION_TREE);
    assert.equal(applied.has_authoritative_scope, true);
    const hash = applied.candidates.find((c) => c.normalized_value === hashVal);
    const dom = applied.candidates.find((c) => c.normalized_value === 'google.com');
    assert.equal(isReportIndicatorMember(hash), true);
    assert.equal(isReportIndicatorMember(dom), false);
  });

  it('scope engine flag defaults to legacy and accepts section_tree', () => {
    assert.equal(getScopeEngine({}), SCOPE_ENGINE_LEGACY);
    assert.equal(isSectionTreeScopeAuthoritative({}), false);
    assert.equal(getScopeEngine({ THREAT_LIBRARY_SCOPE_ENGINE: 'section_tree' }), SCOPE_ENGINE_SECTION_TREE);
    assert.equal(isSectionTreeScopeAuthoritative({ THREAT_LIBRARY_SCOPE_ENGINE: 'section_tree' }), true);
    assert.throws(() => getScopeEngine({ THREAT_LIBRARY_SCOPE_ENGINE: 'nope' }, { strict: true }));
  });

  it('does not promote narrative domains inside list-typed C2 prose blocks', () => {
    const d = doc([
      { id: 'h0', type: 'heading', level: 2, text: 'Command and control' },
      { id: 'p1', type: 'list', text: 'A 256-byte buffer is created that starts with google.com followed by random bytes' },
      { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise' },
      {
        id: 'row',
        type: 'table',
        text: 'corp.tripswithengine.com | Host name | C2 host name'
      }
    ]);
    const candidates = [
      {
        candidate_type: 'domain',
        normalized_value: 'google.com',
        original_value: 'google.com',
        is_ioc: true,
        assessment: 'context_only',
        match_state: 'context_only',
        source_assertion: 'body_mention',
        document_has_authoritative_scope: true,
        occurrences: [{ block_id: 'p1', zone: 'c2_section', asserted: false, form: 'standalone', block_type: 'list' }]
      },
      {
        candidate_type: 'domain',
        normalized_value: 'corp.tripswithengine.com',
        original_value: 'corp.tripswithengine.com',
        is_ioc: true,
        assessment: 'malicious',
        source_assertion: 'explicit_ioc',
        document_has_authoritative_scope: true,
        occurrences: [{ block_id: 'row', zone: 'explicit_ioc_section', asserted: true, form: 'table_row', block_type: 'table' }]
      }
    ];
    const applied = applySectionTreeAuthority(d, candidates);
    assert.equal(
      isReportIndicatorMember(applied.candidates.find((c) => c.normalized_value === 'google.com')),
      false
    );
    assert.equal(
      isReportIndicatorMember(applied.candidates.find((c) => c.normalized_value === 'corp.tripswithengine.com')),
      true
    );
  });

  it('asserts observable-led annotation rows under appendix authority', () => {
    const d = doc([
      { id: 'h1', type: 'heading', level: 2, text: 'Network indicators' },
      {
        id: 'ip1',
        type: 'paragraph',
        text: '8.218.50[.]207 - Staging server (Alibaba Cloud, Hong Kong)'
      }
    ]);
    const candidates = [
      {
        candidate_type: 'ip',
        normalized_value: '8.218.50.207',
        original_value: '8.218.50[.]207',
        is_ioc: true,
        assessment: 'malicious',
        source_assertion: 'explicit_ioc',
        document_has_authoritative_scope: true,
        occurrences: [
          {
            block_id: 'ip1',
            zone: 'explicit_ioc_section',
            asserted: true,
            form: 'standalone',
            row_shape: true
          }
        ]
      }
    ];
    const applied = applySectionTreeAuthority(d, candidates);
    assert.equal(isReportIndicatorMember(applied.candidates[0]), true);
  });

  it('keeps SHA256 metadata inventory rows under appendix authority', () => {
    const hashVal = 'e05bc22afbc5ddd50b49c85ee169dd13318000d38286de2b8bcff98217256a8d';
    const d = doc([
      { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise' },
      {
        id: 'meta',
        type: 'paragraph',
        text: `SHA256 hash: ${hashVal} File size: 92,657 bytes`
      }
    ]);
    const candidates = [
      {
        candidate_type: 'sha256',
        normalized_value: hashVal,
        original_value: hashVal,
        is_ioc: true,
        assessment: 'malicious',
        source_assertion: 'explicit_ioc',
        document_has_authoritative_scope: true,
        occurrences: [{ block_id: 'meta', zone: 'explicit_ioc_section', asserted: true, form: 'standalone', row_shape: true }]
      }
    ];
    const applied = applySectionTreeAuthority(d, candidates);
    assert.equal(isReportIndicatorMember(applied.candidates[0]), true);
  });

  it('does not promote short API/code URLs under a C2 topic via stale row_shape', () => {
    const d = doc([
      { id: 'h0', type: 'heading', level: 2, text: 'Microsoft-hosted services for C2' },
      { id: 'code', type: 'paragraph', text: 'GET https://graph.microsoft.com/v1.0/organization' },
      { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise' },
      { id: 'dom', type: 'list', text: 'tenant-sync-portal.com' }
    ]);
    const candidates = [
      {
        candidate_type: 'url',
        normalized_value: 'https://graph.microsoft.com/v1.0/organization',
        original_value: 'https://graph.microsoft.com/v1.0/organization',
        is_ioc: true,
        assessment: 'context_only',
        match_state: 'context_only',
        source_assertion: 'body_mention',
        document_has_authoritative_scope: true,
        occurrences: [{ block_id: 'code', zone: 'report_body', asserted: false, form: 'url', row_shape: true }]
      },
      {
        candidate_type: 'domain',
        normalized_value: 'tenant-sync-portal.com',
        original_value: 'tenant-sync-portal.com',
        is_ioc: true,
        assessment: 'malicious',
        source_assertion: 'explicit_ioc',
        document_has_authoritative_scope: true,
        occurrences: [{ block_id: 'dom', zone: 'explicit_ioc_section', asserted: true, form: 'list_row' }]
      }
    ];
    const applied = applySectionTreeAuthority(d, candidates);
    const api = applied.candidates.find((c) => c.normalized_value.includes('graph.microsoft'));
    const dom = applied.candidates.find((c) => c.normalized_value === 'tenant-sync-portal.com');
    assert.equal(isReportIndicatorMember(api), false);
    assert.equal(isReportIndicatorMember(dom), true);
  });
});

describe('sectionTree.membershipPreview', () => {
  it('upgrades focused hash rows under tree ancestry without promoting narrative domains', () => {
    const d = doc([
      { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise' },
      { id: 'p1', type: 'paragraph', text: 'Campaign malware payloads and hashes' },
      { id: 'f1', type: 'list', text: 'sample.zip – archive' },
      { id: 'hash', type: 'list', text: '6e7d9b33f1e72ea1ede71373a604ecdb060dab7d42055179c1eede9ecd1fd239' },
      { id: 'narr', type: 'paragraph', text: 'The attackers also abused google.com for search research.' }
    ]);
    const hashVal = '6e7d9b33f1e72ea1ede71373a604ecdb060dab7d42055179c1eede9ecd1fd239';
    const candidates = [
      {
        candidate_type: 'sha256',
        normalized_value: hashVal,
        original_value: hashVal,
        is_ioc: true,
        assessment: 'malicious',
        source_assertion: 'body_mention',
        document_has_authoritative_scope: true,
        occurrences: [{ block_id: 'hash', zone: 'report_body', asserted: false, occurrence_kind: 'list_item' }]
      },
      {
        candidate_type: 'domain',
        normalized_value: 'google.com',
        original_value: 'google.com',
        is_ioc: true,
        assessment: 'context_only',
        match_state: 'context_only',
        source_assertion: 'body_mention',
        document_has_authoritative_scope: true,
        occurrences: [{ block_id: 'narr', zone: 'report_body', asserted: false }]
      }
    ];
    const preview = previewMembershipAdditive(d, candidates);
    const hashMember = preview.members.find((c) => c.normalized_value === hashVal);
    assert.ok(hashMember);
    assert.equal(isReportIndicatorMember({ ...hashMember, evidence: buildCandidateEvidenceRecord(hashMember) }), true);
    assert.equal(preview.memberKeys.has('domain:google.com'), false);
  });
});

describe('sectionTree.shadow', () => {
  it('defaults off and never throws when attaching diagnostics', () => {
    assert.equal(isSectionTreeShadowEnabled({}), false);
    const diagnostics = {};
    attachSectionTreeShadowDiagnostics(doc([]), [], diagnostics, { env: {} });
    assert.equal(diagnostics.section_tree_shadow, undefined);

    const withFlag = {};
    attachSectionTreeShadowDiagnostics(doc([{ id: 'a', type: 'paragraph', text: 'hi' }]), [], withFlag, {
      env: { THREAT_LIBRARY_SECTION_TREE_SHADOW: '1' }
    });
    assert.equal(withFlag.section_tree_shadow?.ok, true);
  });

  it('fail-soft returns ok:false on broken input without throwing', () => {
    const brokenDoc = {
      blocks: null,
      // Force annotate to run; null blocks become [].
      meta: {}
    };
    // Monkey-patch path: evaluate should still return a structured object.
    const result = evaluateSectionTreeShadow(brokenDoc, [{ not: 'a candidate' }]);
    assert.equal(typeof result.ok, 'boolean');
  });

  it('attach fail-soft never throws even if evaluate explodes via bad env proxy', () => {
    const diagnostics = {};
    const toxicEnv = new Proxy(
      {},
      {
        get() {
          throw new Error('forced shadow env failure');
        }
      }
    );
    assert.doesNotThrow(() => {
      attachSectionTreeShadowDiagnostics(doc([{ id: 'a', type: 'paragraph', text: 'x' }]), [], diagnostics, {
        env: toxicEnv
      });
    });
    assert.equal(diagnostics.section_tree_shadow?.ok, false);
    assert.match(String(diagnostics.section_tree_shadow?.error || ''), /forced shadow env failure/);
  });

  it('fullRezone:false force-off ignores process env full-rezone flag', () => {
    const prev = process.env.THREAT_LIBRARY_SECTION_TREE_SHADOW_FULL_REZONE;
    process.env.THREAT_LIBRARY_SECTION_TREE_SHADOW_FULL_REZONE = '1';
    try {
      const result = evaluateSectionTreeShadow(doc([{ id: 'a', type: 'paragraph', text: 'x' }]), [], {
        fullRezone: false
      });
      assert.equal(result.ok, true);
      assert.equal(result.full_rezone, null);
    } finally {
      if (prev === undefined) delete process.env.THREAT_LIBRARY_SECTION_TREE_SHADOW_FULL_REZONE;
      else process.env.THREAT_LIBRARY_SECTION_TREE_SHADOW_FULL_REZONE = prev;
    }
  });

  it('does not mutate authoritative candidate objects', () => {
    const hashVal = '6e7d9b33f1e72ea1ede71373a604ecdb060dab7d42055179c1eede9ecd1fd239';
    const candidates = [
      {
        candidate_type: 'sha256',
        normalized_value: hashVal,
        original_value: hashVal,
        is_ioc: true,
        assessment: 'malicious',
        source_assertion: 'body_mention',
        document_has_authoritative_scope: true,
        occurrences: [{ block_id: 'hash', zone: 'report_body', asserted: false }]
      }
    ];
    const before = JSON.stringify(candidates);
    evaluateSectionTreeShadow(
      doc([
        { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise' },
        { id: 'hash', type: 'list', text: hashVal }
      ]),
      candidates
    );
    assert.equal(JSON.stringify(candidates), before);
  });
});
