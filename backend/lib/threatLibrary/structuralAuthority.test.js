/**
 * One structural authority: only the section graph writes authority, and everything
 * that reads structure (zones, the table interpreter, AI block selection) reads it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { annotateSectionTree } from './sectionTree/annotate.js';
import { annotateDocumentZones } from './documentZones.js';
import { selectSemanticBlocks } from './ai/analyze.js';
import { createCanonicalDocument, createTableBlock } from './canonicalDocument.js';

const here = path.dirname(fileURLToPath(import.meta.url));

function sources(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) sources(full, out);
    else if (/\.js$/.test(e.name) && !/\.test\.js$/.test(e.name)) out.push(full);
  }
  return out;
}

const document = () => createCanonicalDocument({
  title: 'Report',
  language: 'en',
  blocks: [
    { id: 'p1', type: 'paragraph', text: 'The operators rotate infrastructure between waves across several regions.' },
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise' },
    createTableBlock({ id: 't1', headers: ['Type', 'Value'], rows: [['domain', 'evil-c2-one.net']] }),
    { id: 'h2', type: 'heading', level: 3, text: 'About the Author' },
    { id: 'p2', type: 'paragraph', text: 'Follow the author at author-homepage.net for more research.' },
    { id: 'h3', type: 'heading', level: 2, text: 'References' },
    { id: 'l1', type: 'list_item', text: 'https://research-blog.net/post' }
  ]
});

test('only the section graph assigns authority; documentZones copies its reading', () => {
  const writers = sources(here)
    .filter((f) => /\bauthoritative_ancestor_id\s*=(?!=)/.test(fs.readFileSync(f, 'utf8')))
    .map((f) => path.relative(here, f).replace(/\\/g, '/'))
    .sort();
  assert.deepEqual(writers, ['documentZones.js', 'sectionTree/annotate.js']);
  const zones = fs.readFileSync(path.join(here, 'documentZones.js'), 'utf8');
  assert.match(zones, /authoritative_ancestor_id = graph\.authoritative_ancestor_id/);
});

test('no scope engine switch, fallback or shadow path remains', () => {
  for (const f of sources(here)) {
    const s = fs.readFileSync(f, 'utf8');
    assert.doesNotMatch(s, /THREAT_LIBRARY_SCOPE_ENGINE|THREAT_LIBRARY_SECTION_TREE_SHADOW|SCOPE_ENGINE_LEGACY/, path.relative(here, f));
  }
  assert.equal(fs.existsSync(path.join(here, 'experiments')), false);
});

test('zones agree with the section graph for every block', () => {
  const graph = annotateSectionTree(document());
  const zoned = annotateDocumentZones(document());
  const byId = new Map(graph.blocks.map((b) => [b.id, b]));
  for (const b of zoned.blocks) {
    assert.equal(b.authoritative_ancestor_id || null, byId.get(b.id).authoritative_ancestor_id || null, b.id);
  }
  assert.ok(byId.get('t1').authoritative_ancestor_id, 'the table is inside the appendix');
  assert.equal(byId.get('p2').authoritative_ancestor_id, null, 'About the Author is not');
});

test('the table interpreter reads its scope from that same reading', () => {
  const zoned = annotateDocumentZones(document());
  const table = zoned.blocks.find((b) => b.id === 't1');
  assert.equal(table.zone, 'explicit_ioc_section');
  assert.equal(table.ioc_table.kind, 'ioc_table');
});

test('AI block selection reads the same structure: references stay out, the appendix stays in', () => {
  const selected = selectSemanticBlocks(annotateDocumentZones(document()));
  const ids = selected.blocks.map((b) => b.id);
  assert.ok(ids.includes('t1'));
  assert.ok(!ids.includes('l1'), 'a reference row is not body text for the model');
  const unannotated = selectSemanticBlocks(document());
  assert.deepEqual(unannotated.blocks.map((b) => b.id), ids, 'annotating first or not gives one answer');
});
