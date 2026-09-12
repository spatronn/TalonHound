/**
 * Pipeline reuse contract: which stored artifacts survive a Retry.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { isDocumentContractCurrent } from './pipeline.js';
import { THREAT_LIBRARY_PDF_EXTRACTOR_VERSION } from './pdfIngest.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION } from './ai/contract.js';

test('internal contract versions for this change', () => {
  assert.equal(THREAT_LIBRARY_PDF_EXTRACTOR_VERSION, 'threat_library_pdf_v2');
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v3');
  assert.equal(THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION, 'threat-library-semantic-v4');
});

test('PDF canonical documents from the v1 extractor are rebuilt from the stored upload; v2 and URL docs are reused', () => {
  const blocks = [{ id: 'p1-b01', type: 'paragraph', text: 'x', page: 1 }];
  assert.equal(isDocumentContractCurrent({ source_type: 'pdf' }, { blocks, meta: { extractor: 'threat_library_pdf_v1' } }), false);
  assert.equal(isDocumentContractCurrent({ source_type: 'pdf' }, { blocks, meta: {} }), false);
  assert.equal(isDocumentContractCurrent({ source_type: 'pdf' }, { blocks, meta: { extractor: THREAT_LIBRARY_PDF_EXTRACTOR_VERSION } }), true);
  assert.equal(isDocumentContractCurrent({ source_type: 'url' }, { blocks, meta: { extractor: 'threat_library_html_v1' } }), true);
  assert.equal(isDocumentContractCurrent({ source_type: 'pdf' }, { blocks: [] }), false);
  assert.equal(isDocumentContractCurrent({ source_type: 'pdf' }, null), false);
});
