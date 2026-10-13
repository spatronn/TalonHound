/**
 * Metamorphic layout variants for the Threat Library extraction benchmark.
 *
 * One publisher IOC set is rendered in structurally equivalent layouts: real
 * HTML heading hierarchies, bold/synthetic headings, tables, <pre> sample
 * inventories, filename/hash pairs and level-less PDF-style headings. The
 * publisher asserts the same Indicators in every variant, so report Indicator
 * membership must be identical across them. Ground truth is defined here by
 * construction, never read from TalonHound output.
 */

import crypto from 'node:crypto';
import { createCanonicalDocument, createTableBlock } from '../canonicalDocument.js';
import { extractCanonicalDocumentFromHtml } from '../extract/extractHtml.js';
import { PDF_LAYOUT_VERSION } from '../pdfLayout.js';

export const LAYOUT_VARIANT_SOURCE_URL = 'https://research.example/blog/layout-variant/';

const hex = (seed) => crypto.createHash('md5').update(`tl-benchmark:${seed}`).digest('hex');

/** The publisher IOC set every variant renders (2 network values + 4 loader samples). */
export const LAYOUT_VARIANT_IOC_SET = Object.freeze({
  network: Object.freeze([
    Object.freeze({ type: 'domain', source: 'update-relay[.]net', value: 'update-relay.net' }),
    Object.freeze({ type: 'ip', source: '203.0.113.77', value: '203.0.113.77' })
  ]),
  samples: Object.freeze(
    ['vulkan-1.dll', 'oleasapi.dll', 'msbasesysdc.dll', 'loader.exe'].map((file, i) =>
      Object.freeze({ type: 'md5', value: hex(`sample-${i}`), file })
    )
  )
});

/** HTML / PDF heading structures around the network list and the sample inventory. */
const STRUCTURES = Object.freeze({
  html_flat: { format: 'html', description: 'h2 IOC appendix, no sub-headings', network: null, samples: null },
  html_typed_subsections: { format: 'html', description: 'h2 IOCs › h3 Network › h3 File hashes', network: ['h3', 'Network'], samples: ['h3', 'File hashes'] },
  html_family_sibling: { format: 'html', description: 'h2 IOCs › h3 Network › h3 malware-family name', network: ['h3', 'Network'], samples: ['h3', 'OctLurk'] },
  html_c2_then_loaders: { format: 'html', description: 'h2 IOCs › h3 C2 servers › h3 Loaders', network: ['h3', 'C2 servers'], samples: ['h3', 'Loaders'] },
  html_c2_then_nested_plugins: { format: 'html', description: 'h2 IOCs › h3 C2 servers › h4 Plugins', network: ['h3', 'C2 servers'], samples: ['h4', 'Plugins'] },
  html_bold_subsections: { format: 'html', description: 'h2 IOCs › bold C2 servers › bold Loaders', network: ['strong', 'C2 servers'], samples: ['strong', 'Loaders'] },
  html_bold_appendix: { format: 'html', description: 'bold IOC appendix › bold Network › bold Samples', appendix: 'strong', network: ['strong', 'Network'], samples: ['strong', 'Samples'] },
  pdf_flat: { format: 'pdf', description: 'level-less PDF IOC heading, no sub-headings', network: null, samples: null },
  pdf_typed_subsections: { format: 'pdf', description: 'level-less PDF IOCs › Network › Samples', network: 'Network', samples: 'Samples' },
  pdf_c2_then_loaders: { format: 'pdf', description: 'level-less PDF IOCs › C2 servers › Loaders', network: 'C2 servers', samples: 'Loaders' }
});

/** How the sample inventory is written. */
const REPRESENTATIONS = Object.freeze({
  table: 'Filename | MD5 table',
  hash_lines: 'one hash per line',
  hash_filename_lines: '"<hash> <filename>" lines',
  filename_hash_lines: '"<filename> <hash>" lines'
});

const PDF_REPRESENTATIONS = new Set(['table', 'hash_lines', 'filename_hash_lines']);

function htmlHeading(spec) {
  if (!spec) return '';
  const [tag, text] = spec;
  return tag === 'strong' ? `<p><strong>${text}</strong></p>` : `<${tag}>${text}</${tag}>`;
}

function htmlSamples(repr, samples) {
  if (repr === 'table') {
    const rows = samples.map((s) => `<tr><td>${s.file}</td><td>${s.value}</td></tr>`).join('');
    return `<table><thead><tr><th>Filename</th><th>MD5</th></tr></thead><tbody>${rows}</tbody></table>`;
  }
  if (repr === 'hash_lines') return samples.map((s) => `<p>${s.value}</p>`).join('\n');
  if (repr === 'hash_filename_lines') return `<pre>${samples.map((s) => `${s.value} ${s.file}`).join('\n')}</pre>`;
  return `<pre>${samples.map((s) => `${s.file} ${s.value}`).join('\n')}</pre>`;
}

function htmlVariant(structure, repr, iocSet) {
  const appendix = structure.appendix === 'strong'
    ? '<p><strong>Indicators of compromise</strong></p>'
    : '<h2>Indicators of compromise</h2>';
  const network = `<ul>${iocSet.network.map((n) => `<li>${n.source}</li>`).join('')}</ul>`;
  const html = `<!doctype html><html lang="en"><head><title>Layout variant</title></head><body><article>
<h1>Layout variant report</h1>
<p>The intrusion set deploys a modular loader chain against several regional targets across multiple waves.</p>
${appendix}
${htmlHeading(structure.network)}
${network}
${htmlHeading(structure.samples)}
${htmlSamples(repr, iocSet.samples)}
<h2>Conclusion</h2>
<p>The actor continues to evolve its toolset and infrastructure.</p>
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, {
    url: LAYOUT_VARIANT_SOURCE_URL,
    finalUrl: LAYOUT_VARIANT_SOURCE_URL,
    httpStatus: 200
  });
  if (!r.ok) throw new Error(`layout variant HTML extraction failed: ${r.code}`);
  return r.document;
}

/**
 * PDF-style canonical blocks, shaped like pdfLayout.linesToBlocks output:
 * headings carry no `level`, observable-only lines are `observable_row` list
 * items, other consecutive lines merge into one paragraph.
 */
function pdfVariant(structure, repr, iocSet) {
  let n = 0;
  const id = () => `p1-b${String(++n).padStart(2, '0')}`;
  const heading = (text) => ({ id: id(), type: 'heading', text, page: 1, section: text });
  const paragraph = (text) => ({ id: id(), type: 'paragraph', text, page: 1, section: null });
  const row = (text) => ({ id: id(), type: 'list_item', text, page: 1, section: null, layout: 'observable_row' });
  const blocks = [
    paragraph('The intrusion set deploys a modular loader chain against several regional targets across multiple waves.'),
    heading('Indicators of compromise')
  ];
  if (structure.network) blocks.push(heading(structure.network));
  for (const v of iocSet.network) blocks.push(row(v.source));
  if (structure.samples) blocks.push(heading(structure.samples));
  if (repr === 'table') {
    blocks.push(createTableBlock({
      id: id(),
      page: 1,
      headers: ['Filename', 'MD5'],
      rows: iocSet.samples.map((s) => [s.file, s.value]),
      source: 'pdf_geometry'
    }));
  } else if (repr === 'hash_lines') {
    for (const s of iocSet.samples) blocks.push(row(s.value));
  } else {
    blocks.push(paragraph(iocSet.samples.map((s) => `${s.file} ${s.value}`).join(' ')));
  }
  blocks.push(heading('Conclusion'), paragraph('The actor continues to evolve its toolset and infrastructure.'));
  return createCanonicalDocument({
    title: 'Layout variant',
    language: 'en',
    blocks,
    meta: { extractor: PDF_LAYOUT_VERSION, adapter: 'pdf' }
  });
}

/**
 * Every (structure × representation) variant id, e.g. `pdf_c2_then_loaders/table`.
 * @returns {string[]}
 */
export function listLayoutVariantIds() {
  const ids = [];
  for (const [structureId, structure] of Object.entries(STRUCTURES)) {
    for (const repr of Object.keys(REPRESENTATIONS)) {
      if (structure.format === 'pdf' && !PDF_REPRESENTATIONS.has(repr)) continue;
      ids.push(`${structureId}/${repr}`);
    }
  }
  return ids;
}

/**
 * Canonical document + description of one layout variant.
 * @param {string} variantId `<structure>/<representation>`
 * @param {typeof LAYOUT_VARIANT_IOC_SET} [iocSet]
 */
export function buildLayoutVariant(variantId, iocSet = LAYOUT_VARIANT_IOC_SET) {
  const [structureId, repr] = String(variantId).split('/');
  const structure = STRUCTURES[structureId];
  if (!structure || !REPRESENTATIONS[repr]) throw new Error(`unknown layout variant: ${variantId}`);
  const document = structure.format === 'pdf' ? pdfVariant(structure, repr, iocSet) : htmlVariant(structure, repr, iocSet);
  return {
    id: variantId,
    format: structure.format,
    description: `${structure.description}; samples as ${REPRESENTATIONS[repr]}`,
    document,
    sourceUrl: structure.format === 'html' ? LAYOUT_VARIANT_SOURCE_URL : null
  };
}

/**
 * Ground truth shared by every variant: the publisher asserts all six values
 * inside its IOC appendix, so all six are report Indicators with an explicit
 * publisher assertion, and the sample sub-section is authoritative scope.
 * @param {typeof LAYOUT_VARIANT_IOC_SET} [iocSet]
 */
export function layoutVariantGroundTruth(iocSet = LAYOUT_VARIANT_IOC_SET) {
  return {
    provenance: {
      method: 'constructed: every value is rendered inside the publisher IOC appendix of the variant',
      verified_by: 'construction (layoutVariants.js)',
      verified_at: '2026-10-14'
    },
    indicators: [
      ...iocSet.network.map((v) => ({ type: v.type, value: v.value, assertion: 'explicit' })),
      ...iocSet.samples.map((s) => ({ type: s.type, value: s.value, assertion: 'explicit' }))
    ],
    context_only: [],
    excluded_legitimate: [],
    sections: []
  };
}
