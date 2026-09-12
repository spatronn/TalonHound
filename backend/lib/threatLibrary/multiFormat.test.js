/**
 * The evidence model must not depend on one publisher layout or language.
 * Same rules, different formats: English HTML vendor blog, Turkish plain text,
 * German headings the hint table does not know, and a heading-less list.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { htmlToCanonicalDocument } from './urlIngest.js';
import { plainTextToBlocks } from './pdfLayout.js';
import { createCanonicalDocument } from './canonicalDocument.js';
import { extractCandidatesFromDocument, summarizeCandidateSet } from './candidateExtraction.js';
import { partitionCandidatesForAi, selectSemanticBlocks } from './ai/analyze.js';
import { SOURCE_ASSERTIONS } from './evidencePolicy.js';

const byKey = (cands) => new Map(cands.map((c) => [`${c.candidate_type}:${c.normalized_value}`, c]));

test('English HTML vendor report: IOC table authoritative, references context-only, no host duplication', () => {
  const html = `<html lang="en"><head><title>LNK loader campaign</title></head><body>
    <nav><a href="https://vendor.example-research.com/">Home</a> · <a href="https://vendor.example-research.com/about">About us</a></nav>
    <article>
      <h1>LNK loader campaign</h1>
      <p>The loader posts host data to https://cdn-update.badhost-example.net/gate.php and pulls a second stage.</p>
      <p>Persistence is a scheduled task named "Chrome Update".</p>
      <h2>Indicators of Compromise</h2>
      <table>
        <tr><th>Type</th><th>Value</th></tr>
        <tr><td>URL</td><td>https://cdn-update.badhost-example.net/gate.php</td></tr>
        <tr><td>IP</td><td>203.0.113.21</td></tr>
        <tr><td>SHA256</td><td>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</td></tr>
        <tr><td>Domain</td><td>telemetry.badhost-example.net</td></tr>
      </table>
      <h2>References</h2>
      <ul>
        <li><a href="https://other-vendor.example-blog.org/lnk-campaigns">https://other-vendor.example-blog.org/lnk-campaigns</a></li>
        <li>https://another.example-news.com/story/123</li>
      </ul>
    </article>
    <footer>© Vendor Research https://vendor.example-research.com/privacy</footer>
  </body></html>`;
  const doc = htmlToCanonicalDocument(html, { url: 'https://vendor.example-research.com/blog/lnk-loader' });
  const cands = extractCandidatesFromDocument(doc, { sourceUrl: 'https://vendor.example-research.com/blog/lnk-loader' });
  const k = byKey(cands);

  const gate = k.get('url:https://cdn-update.badhost-example.net/gate.php');
  assert.ok(gate);
  assert.equal(gate.assessment, 'malicious');
  assert.equal(gate.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_IOC);
  assert.equal(gate.occurrence_count, 2, 'body mention + IOC table row aggregate');
  assert.equal(k.has('domain:cdn-update.badhost-example.net'), false, 'URL host not exploded');

  for (const key of ['ip:203.0.113.21', 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'domain:telemetry.badhost-example.net']) {
    assert.equal(k.get(key)?.assessment, 'malicious', key);
    assert.equal(k.get(key)?.ai_needed, false, key);
  }
  for (const key of ['url:https://other-vendor.example-blog.org/lnk-campaigns', 'url:https://another.example-news.com/story/123']) {
    assert.equal(k.get(key)?.assessment, 'context_only', key);
    assert.equal(k.get(key)?.source_assertion, SOURCE_ASSERTIONS.REFERENCE_ONLY, key);
  }
  assert.equal(k.has('domain:other-vendor.example-blog.org'), false);
  assert.equal(k.has('domain:another.example-news.com'), false);
  // Publisher's own links (nav/footer/source) never become IOC candidates
  for (const c of cands) {
    if (c.normalized_value.includes('vendor.example-research.com')) {
      assert.equal(c.assessment, 'context_only', c.normalized_value);
    }
  }
  const s = summarizeCandidateSet(cands);
  assert.equal(s.ai_needed, 0);
  assert.equal(s.explicit_assertions, 4);
});

test('Turkish plain-text report: Göstergeler/Kaynaklar headings, IP:port with suffix, body URL needs AI', () => {
  const text = [
    'Kampanya Analizi',
    'Zararlı yükleyici, https://indir.kotu-alan-ornek.com/asama2.bin adresinden ikinci aşamayı indirir.',
    'Arka kapı 203.0.113.9:8443\'e sabit bağlantı kurar ve komutları bekler.',
    'Göstergeler',
    'MD5',
    'c4ca4238a0b923820dcc509a6f75849b',
    'c81e728d9d4c2f636f067f89cc14862c',
    'Komuta Kontrol',
    '203.0.113.9:8443',
    'https://indir.kotu-alan-ornek.com/asama2.bin',
    'Kaynaklar',
    '[1] https://arastirma.ornek-firma.com.tr/rapor/2026',
    '[2] https://haber.ornek-medya.com/apt-analizi'
  ].join('\n');
  const { blocks } = plainTextToBlocks(text, 1, 1);
  const doc = createCanonicalDocument({ title: 'Kampanya', language: 'tr', blocks });
  const cands = extractCandidatesFromDocument(doc);
  const k = byKey(cands);

  const ep = k.get('ip:203.0.113.9');
  assert.ok(ep, 'IP:port endpoint (Turkish suffix -e) extracted');
  assert.deepEqual(ep.parsed.ports, [8443]);
  assert.equal(ep.assessment, 'malicious');
  assert.equal(ep.role, 'command_and_control');
  assert.equal(ep.occurrence_count, 2);

  const url = k.get('url:https://indir.kotu-alan-ornek.com/asama2.bin');
  assert.equal(url.assessment, 'malicious');
  assert.equal(url.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_C2);
  assert.equal(k.has('domain:indir.kotu-alan-ornek.com'), false);

  assert.equal(k.get('md5:c4ca4238a0b923820dcc509a6f75849b').role, 'malware_sample');
  for (const ref of ['url:https://arastirma.ornek-firma.com.tr/rapor/2026', 'url:https://haber.ornek-medya.com/apt-analizi']) {
    assert.equal(k.get(ref).assessment, 'context_only', ref);
  }
  assert.equal(cands.some((c) => c.candidate_type === 'domain'), false);
  assert.equal(summarizeCandidateSet(cands).ai_needed, 0);
});

test('unknown-language headings: structural observable list still yields explicit assertions; prose URL goes to AI', () => {
  const doc = createCanonicalDocument({
    title: 'Bericht',
    language: 'de',
    blocks: [
      { id: 'h1', type: 'heading', page: 1, text: 'Zusammenfassung' },
      { id: 'p1', type: 'paragraph', page: 1, text: 'Die Malware lädt Module von https://update.schlecht-beispiel.de/m.dll nach.' },
      { id: 'h2', type: 'heading', page: 2, text: 'Indikatoren der Kompromittierung' },
      { id: 'r1', type: 'list_item', layout: 'observable_row', page: 2, text: 'https://update.schlecht-beispiel.de/m.dll' },
      { id: 'r2', type: 'list_item', layout: 'observable_row', page: 2, text: '198.51.100.200' },
      { id: 'r3', type: 'list_item', layout: 'observable_row', page: 2, text: 'relay.schlecht-beispiel.de' },
      { id: 'h3', type: 'heading', page: 2, text: 'Quellen' },
      { id: 'q1', type: 'list_item', layout: 'observable_row', page: 2, text: '[1] https://blog.sicherheit-beispiel.org/analyse' },
      { id: 'q2', type: 'list_item', layout: 'observable_row', page: 2, text: '[2] https://news.beispiel-medien.de/artikel' },
      { id: 'q3', type: 'list_item', layout: 'observable_row', page: 2, text: '[3] https://cert.beispiel-behoerde.de/warnung' },
      { id: 'p2', type: 'paragraph', page: 3, text: 'Weitere Verbindungen zu 198.51.100.77 wurden beobachtet.' }
    ]
  });
  const cands = extractCandidatesFromDocument(doc);
  const k = byKey(cands);
  // "Indikatoren der Kompromittierung" is not in the hint table → the 3-row list itself is the evidence
  assert.equal(k.get('url:https://update.schlecht-beispiel.de/m.dll').assessment, 'malicious');
  assert.equal(k.get('ip:198.51.100.200').assessment, 'malicious');
  assert.equal(k.get('domain:relay.schlecht-beispiel.de').assessment, 'malicious');
  // "Quellen" unknown too → citation-marked list is recognised as references
  for (const key of ['url:https://blog.sicherheit-beispiel.org/analyse', 'url:https://news.beispiel-medien.de/artikel', 'url:https://cert.beispiel-behoerde.de/warnung']) {
    assert.equal(k.get(key).assessment, 'context_only', key);
    assert.equal(k.get(key).source_assertion, SOURCE_ASSERTIONS.REFERENCE_ONLY, key);
  }
  assert.equal(k.has('domain:update.schlecht-beispiel.de'), false);
  // Body-only IP with no list support → the one thing the model must judge
  const part = partitionCandidatesForAi(cands);
  assert.deepEqual(part.toClassify.map((c) => c.normalized_value), ['198.51.100.77']);
  assert.equal(part.explicit.length, 3);
});

test('HTML navigation/footer/source blocks are stripped from the model input regardless of language', () => {
  const html = `<html lang="fr"><body><nav><a href="/">Accueil</a></nav><article>
    <h1>Analyse</h1><p>Le chargeur contacte http://203.0.113.55/cmd toutes les heures.</p>
    <h2>Références</h2><ul><li>https://ref.exemple-recherche.fr/rapport</li></ul></article>
    <footer>https://editeur.exemple.fr/mentions-legales</footer></body></html>`;
  const doc = htmlToCanonicalDocument(html, { url: 'https://editeur.exemple.fr/analyse' });
  const sel = selectSemanticBlocks({ ...doc, meta: { ...doc.meta, source_url: 'https://editeur.exemple.fr/analyse', source_host: 'editeur.exemple.fr' } });
  const text = sel.blocks.map((b) => b.text).join('\n');
  assert.ok(text.includes('203.0.113.55/cmd'));
  assert.equal(text.includes('mentions-legales'), false);
});
