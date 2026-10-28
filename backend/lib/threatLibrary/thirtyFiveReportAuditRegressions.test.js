/**
 * Regression fixtures for the 35-report Threat Library batch audit.
 *
 * A. Unit42 Gremlin: `hxxp[:]194.87.92[.]109/i.php` (bracket colon, no
 *    authority slashes) refangs to a URL Indicator (tl-defang-v4).
 * B. Securelist Steam wallpapers: inventory-listed root C2 URLs under a C2
 *    subsection keep Indicator membership beside path siblings
 *    (tl-candidates-v42).
 * C. Securelist miner / Cloud Atlas: OpenTip lookup-path basenames must not
 *    demote publisher-defanged IOC domains (tl-type-resolver-v19).
 * D. Securelist Cloud Atlas: flattened block text that glues a one-letter
 *    conjunction onto a defanged link recovers the structured link domain
 *    (tl-candidates-v42).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { annotateDocumentZones } from './documentZones.js';
import { extractCandidatesFromDocument } from './candidateExtraction.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { refangTextForExtraction, refangObservable } from './defang.js';
import { resolveDottedToken } from './observableTypeResolver.js';

function run(html, url = 'https://publisher.example/report') {
  const r = extractCanonicalDocumentFromHtml(html, { url, finalUrl: url, httpStatus: 200 });
  assert.equal(r.ok, true, 'html extract ok');
  const doc = annotateDocumentZones(r.document, { sourceUrl: url, sourceHost: 'publisher.example' });
  return extractCandidatesFromDocument(doc, { sourceUrl: url });
}

function member(c) {
  return isReportIndicatorMember({
    ...c,
    has_original_document_occurrence: true,
    document_has_authoritative_scope: true
  });
}

function find(cands, type, value) {
  const v = String(value).toLowerCase();
  return cands.find(
    (c) => String(c.candidate_type) === type && String(c.normalized_value || '').toLowerCase() === v
  );
}

test('A. hxxp[:]host/path without authority slashes refangs to http://host/path', () => {
  const raw = 'hxxp[:]194.87.92[.]109/i.php';
  assert.equal(refangTextForExtraction(raw), 'http://194.87.92.109/i.php');
  assert.equal(refangObservable(raw), 'http://194.87.92.109/i.php');
  assert.equal(refangTextForExtraction('http[:]194.87.92[.]109/i.php'), 'http://194.87.92.109/i.php');
  assert.equal(refangTextForExtraction('see http: status code'), 'see http: status code');
});

test('A. Gremlin IoC list yields the incomplete-slash URL as an Indicator', () => {
  const html = `<article>
<h2>Indicators of Compromise</h2>
<ul>
<li>2172dae9a5a695e00e0e4609e7db0207d8566d225f7e815fada246ae995c0f9b</li>
<li>hxxp[:]194.87.92[.]109/i.php</li>
</ul>
</article>`;
  const cands = run(html, 'https://unit42.paloaltonetworks.com/gremlin-stealer-evolution/');
  const url = find(cands, 'url', 'http://194.87.92.109/i.php');
  assert.ok(url, `URL candidate extracted; got=${cands.filter((c) => c.candidate_type === 'url' || /194\.87|i\.php/i.test(c.normalized_value || '')).map((c) => `${c.candidate_type}:${c.normalized_value}:${c.source_assertion}`).join('|')}`);
  assert.equal(member(url), true, 'URL is an Indicator');
  const orphanPhp = find(cands, 'technical_artifact', 'i.php');
  assert.equal(orphanPhp ? member(orphanPhp) : false, false, 'i.php path alone is not an Indicator');
});

test('B. inventory-listed root C2 URLs stay Indicators beside path siblings', () => {
  const html = `<article>
<h2>Indicators of compromise</h2>
<h3>C2 servers</h3>
<ul>
<li>http://202.144.192[.]29</li>
<li>http://202.144.192[.]29/audit.php</li>
<li>http://120.48.156[.]17</li>
<li>http://120.48.156[.]17/ey.php?ka=user1&amp;id</li>
<li>http://brightly[.]to</li>
<li>http://brightly[.]to/download2/Themes2.zip</li>
</ul>
</article>`;
  const cands = run(html, 'https://securelist.com/dozens-of-malicious-wallpapers-found-on-steam-workshop/120186/');
  assert.equal(member(find(cands, 'url', 'http://202.144.192.29/')), true, 'root IP URL kept');
  assert.equal(member(find(cands, 'url', 'http://120.48.156.17/')), true, 'root IP URL kept');
  assert.equal(member(find(cands, 'url', 'http://brightly.to/')), true, 'root domain URL kept');
  assert.equal(member(find(cands, 'url', 'http://202.144.192.29/audit.php')), true);
  assert.equal(member(find(cands, 'url', 'http://brightly.to/download2/Themes2.zip')), true);
});

test('C. OpenTip path basenames do not demote publisher IOC domains', () => {
  const basenames = new Set(['m4yuri.online', 'kristina.quest', 'istochnik.org']);
  assert.equal(
    resolveDottedToken('m4yuri[.]online', {
      surroundingText: 'm4yuri[.]online',
      zone: 'c2_section',
      strongZone: true,
      form: 'list_row',
      indicatorRow: true,
      urlPathBasenames: basenames
    }).kind,
    'domain'
  );
  assert.equal(
    resolveDottedToken('kristina.quest', {
      surroundingText: 'UnamWebPanel control panel addresses\nkristina[.]quest',
      zone: 'c2_section',
      strongZone: true,
      form: 'list_row',
      indicatorRow: true,
      urlPathBasenames: basenames
    }).kind,
    'domain'
  );
  // A true file basename collision stays an artifact.
  assert.equal(
    resolveDottedToken('Themes2.zip', {
      surroundingText: 'Themes2.zip',
      urlPathBasenames: new Set(['themes2.zip'])
    }).kind,
    'technical_artifact'
  );
});

test('C. Securelist IoC domains survive OpenTip enrichment links in the same document', () => {
  const html = `<article>
<h2>Indicators of Compromise</h2>
<p>Malicious archive download URL</p>
<p><a href="https://opentip.kaspersky.com/urush1bar4.online/results">urush1bar4[.]online</a></p>
<p>UnamWebPanel control panel addresses</p>
<p><a href="https://opentip.kaspersky.com/m4yuri.online/results">m4yuri[.]online</a></p>
<p><a href="https://opentip.kaspersky.com/kristina.quest/results">kristina[.]quest</a></p>
</article>`;
  const cands = run(html, 'https://securelist.com/video-books-pirates-miners-rat/119943/');
  assert.equal(member(find(cands, 'domain', 'urush1bar4.online')), true);
  assert.equal(member(find(cands, 'domain', 'm4yuri.online')), true, 'm4yuri.online Indicator');
  assert.equal(member(find(cands, 'domain', 'kristina.quest')), true, 'kristina.quest Indicator');
});

test('C. a new subgroup lead-in clears a prior Configuration type label', () => {
  // Securelist miner shape: "Configuration retrieval address" types the IP
  // beneath it; the following "UnamWebPanel control panel addresses" lead-in
  // must not leave that config label on the panel domains.
  const html = `<article>
<h2>Indicators of Compromise</h2>
<p>RAT C&amp;C:</p>
<p>5d14vnfb[.]space</p>
<p>Configuration retrieval address</p>
<p>107[.]172[.]212[.]235</p>
<p>UnamWebPanel control panel addresses</p>
<p><a href="https://opentip.kaspersky.com/m4yuri.online/results">m4yuri[.]online</a></p>
<p><a href="https://opentip.kaspersky.com/kristina.quest/results">kristina[.]quest</a></p>
</article>`;
  const cands = run(html, 'https://securelist.com/video-books-pirates-miners-rat/119943/');
  assert.equal(member(find(cands, 'domain', 'm4yuri.online')), true, 'm4yuri not demoted by prior Configuration label');
  assert.equal(member(find(cands, 'domain', 'kristina.quest')), true, 'kristina not demoted by prior Configuration label');
  assert.equal(member(find(cands, 'ip', '107.172.212.235')), true);
  const art = find(cands, 'technical_artifact', 'm4yuri.online') || find(cands, 'technical_artifact', 'm4yuri[.]online');
  assert.equal(art ? member(art) : false, false);
});

test('C. Powershell/Configuration infrastructure titles do not demote domain rows', () => {
  assert.equal(resolveDottedToken('istochnik[.]org', {
    surroundingText: 'istochnik[.]org',
    typeLabel: 'Powershell payload staging',
    zone: 'explicit_ioc_section',
    strongZone: true,
    form: 'standalone',
    indicatorRow: true
  }).kind, 'domain');
  assert.equal(resolveDottedToken('m4yuri[.]online', {
    surroundingText: 'm4yuri[.]online',
    typeLabel: 'Configuration retrieval address',
    zone: 'c2_section',
    strongZone: true,
    form: 'standalone',
    indicatorRow: true
  }).kind, 'domain');
  // A true command/mutex label still demotes.
  assert.equal(resolveDottedToken('evil.com', {
    typeLabel: 'Mutex'
  }).kind, 'technical_artifact');
});

test('D. glued conjunction residue on a defanged link recovers the link domain', () => {
  // Securelist Cloud Atlas shape: block text "znews[.]neti" with section-level
  // OpenTip links whose anchor text is the correct "znews[.]net".
  const url = 'https://securelist.com/cloud-atlas-2026/119895/';
  const doc = annotateDocumentZones(
    {
      blocks: [
        { id: 'h1', type: 'heading', level: 2, text: 'Indicators of compromise' },
        {
          id: 'b217',
          type: 'paragraph',
          text: 'znews[.]neti',
          links: [
            { href: 'https://opentip.kaspersky.com/iznews.net/results', text: 'znews[.]net' },
            { href: 'https://opentip.kaspersky.com/istochnik.org/results', text: 'istochnik[.]org' }
          ]
        }
      ],
      meta: { source_url: url, source_host: 'securelist.com' }
    },
    { sourceUrl: url, sourceHost: 'securelist.com' }
  );
  const cands = extractCandidatesFromDocument(doc, { sourceUrl: url });
  assert.equal(member(find(cands, 'domain', 'znews.net')), true, 'recovered znews.net');
  assert.equal(find(cands, 'domain', 'znews.neti'), undefined, 'corrupted znews.neti not kept');
});
