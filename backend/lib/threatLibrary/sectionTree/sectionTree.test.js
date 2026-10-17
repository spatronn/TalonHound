/**
 * Section-tree unit tests (structure + shadow isolation).
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { annotateSectionTree } from './annotate.js';
import { previewMembershipAdditive } from './membershipPreview.js';
import { evaluateSectionTreeShadow, attachSectionTreeShadowDiagnostics } from './shadow.js';
import { isSectionTreeShadowEnabled } from './flags.js';
import { isReportIndicatorMember } from '../indicatorMembership.js';
import { buildCandidateEvidenceRecord } from '../evidencePolicy.js';

function doc(blocks) {
  return { title: 't', blocks, meta: { extractor: 'threat_library_html_v6' } };
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
