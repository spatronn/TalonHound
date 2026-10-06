/**
 * Pipeline reuse contract: which stored artifacts survive a Retry.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { isDocumentContractCurrent } from './pipeline.js';
import { THREAT_LIBRARY_PDF_EXTRACTOR_VERSION } from './pdfIngest.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION } from './ai/contract.js';
import { THREAT_LIBRARY_HTML_EXTRACTOR_VERSION } from './extract/extractHtml.js';
import * as prompts from './ai/prompts.js';
import { AI_OUTPUT_BOUNDS, buildProviderJsonSchema } from './ai/contract.js';

test('internal contract versions for this change', () => {
  assert.equal(THREAT_LIBRARY_PDF_EXTRACTOR_VERSION, 'threat_library_pdf_v3');
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v16');
  assert.equal(THREAT_LIBRARY_HTML_EXTRACTOR_VERSION, 'threat_library_html_v4');
  assert.equal(THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION, 'threat-library-semantic-v9');
});

test('semantic-v8+ never asks the model for MITRE ATT&CK (system, chunk, synthesis, schema, bounds)', () => {
  const input = {
    documentTitle: 't', language: 'en', chunkIndex: 0, chunkTotal: 2,
    blocksText: 'body', blockIds: ['b0'], toClassify: [], resolved: []
  };
  const texts = [
    prompts.buildSystemPrompt(),
    prompts.buildChunkPrompt(input),
    prompts.buildChunkPrompt({ ...input, compactRecovery: true }),
    prompts.buildSynthesisPrompt({ documentTitle: 't', partialsText: '[]' })
  ];
  for (const t of texts) {
    assert.doesNotMatch(t, /mitre|technique_id|sub-technique|T1566/i);
    assert.match(t, /report_tags/);
  }
  assert.equal('MITRE_LINE' in prompts, false);
  for (const opts of [{}, { maxEntities: 15, maxRelationships: 12 }]) {
    const schema = buildProviderJsonSchema(opts);
    assert.equal('mitre_attack' in schema.properties, false);
    assert.ok('report_tags' in schema.properties);
  }
  assert.equal(Object.keys(AI_OUTPUT_BOUNDS).some((k) => /mitre/i.test(k)), false);
});

test('outdated PDF/HTML canonical documents are rebuilt from the stored artifact; current ones are reused', () => {
  const blocks = [{ id: 'p1-b01', type: 'paragraph', text: 'x', page: 1 }];
  assert.equal(isDocumentContractCurrent({ source_type: 'pdf' }, { blocks, meta: { extractor: 'threat_library_pdf_v1' } }), false);
  assert.equal(isDocumentContractCurrent({ source_type: 'pdf' }, { blocks, meta: {} }), false);
  assert.equal(isDocumentContractCurrent({ source_type: 'pdf' }, { blocks, meta: { extractor: THREAT_LIBRARY_PDF_EXTRACTOR_VERSION } }), true);
  assert.equal(isDocumentContractCurrent({ source_type: 'pdf' }, { blocks, meta: { extractor: 'threat_library_pdf_v2' } }), false);
  assert.equal(isDocumentContractCurrent({ source_type: 'url' }, { blocks, meta: { extractor: 'threat_library_html_v1' } }), false);
  assert.equal(isDocumentContractCurrent({ source_type: 'url' }, { blocks, meta: { extractor: THREAT_LIBRARY_HTML_EXTRACTOR_VERSION } }), true);
  // v3 keeps <br> line structure: v2 HTML documents are re-extracted from the retained source HTML.
  assert.equal(isDocumentContractCurrent({ source_type: 'url' }, { blocks, meta: { extractor: 'threat_library_html_v2' } }), false);
  assert.equal(isDocumentContractCurrent({ source_type: 'url' }, { blocks, meta: { extractor: 'threat_library_weixin_v2' } }), false);
  assert.equal(isDocumentContractCurrent({ source_type: 'url' }, { blocks, meta: { extractor: 'threat_library_weixin_v3' } }), true);
  assert.equal(isDocumentContractCurrent({ source_type: 'url' }, { blocks, meta: { extractor: 'threat_library_text_v2' } }), true);
  assert.equal(isDocumentContractCurrent({ source_type: 'pdf' }, { blocks: [] }), false);
  assert.equal(isDocumentContractCurrent({ source_type: 'pdf' }, null), false);
});

test('no active Threat Library MITRE path remains (persistence, reads, routes, phishing remaps)', async () => {
  const { readdir, readFile } = await import('node:fs/promises');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const here = path.dirname(fileURLToPath(import.meta.url));
  const files = [];
  async function walk(dir) {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) await walk(p);
      else if (/\.js$/.test(e.name) && !/\.test\.js$/.test(e.name)) files.push(p);
    }
  }
  await walk(here);
  files.push(path.join(here, '../../routes/threatLibrary.js'));
  // The ATT&CK catalog stays for Threat Classifications; only TL-only helpers are gone.
  const catalogSrc = await readFile(path.join(here, '../threatClassifications/mitreReference.js'), 'utf8');
  assert.doesNotMatch(catalogSrc, /resolveCanonicalTechnique|lookupMitreRecord|tactics/);
  for (const f of files) {
    let src;
    try { src = await readFile(f, 'utf8'); } catch { continue; }
    const rel = path.relative(here, f);
    assert.doesNotMatch(src, /threat_report_mitre_mappings\s*\(|FROM threat_report_mitre_mappings|INTO threat_report_mitre_mappings/, `${rel} reads/writes MITRE rows`);
    assert.doesNotMatch(src, /T1566|reconcilePhishingDelivery|resolveCanonicalTechnique|loadMitreReference/, `${rel} keeps technique-specific MITRE logic`);
    // normalize.js drops a legacy property; contract.js documents the v8 bump.
    if (!['normalize.js', 'contract.js'].includes(path.basename(f)) || path.basename(path.dirname(f)) !== 'ai') {
      assert.doesNotMatch(src, /mitre_attack/, `${rel} still carries mitre_attack`);
    }
  }
});
