/**
 * Report Indicators over-extraction: with a publisher-curated IOC section the
 * Indicator set is exactly the publisher-declared identities. Each test pins
 * one generic leak that let a non-declared identity in:
 *
 *  - membership by zone alone (a prose mention inside an IOC / C2 section)
 *  - a hex run of a hostname label read as a file hash
 *  - a closing typographic quote swallowed into a URL (new identity)
 *  - an elided value ("host/abc[…].pdf") accepted as a URL
 *  - a scheme-less "host/path" spelling kept apart from the listed absolute URL
 *  - a vendor sidebar heading resuming a closed IOC section
 *  - a prose-only "C2 …" topic heading opening an authoritative section
 *
 * Synthetic, sanitized fixtures only; the optional live acceptance test reads
 * a public article + its publisher IOC file when the network is available.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractCandidatesWithDiagnostics } from './candidateExtraction.js';
import { mergeAiCandidateUpdates } from './pipeline.js';
import {
  buildCandidateEvidenceRecord,
  isPublisherAuthoritativeReportIocMember,
  publisherAuthoritativeIocMembershipSql
} from './evidencePolicy.js';
import { isActionableReviewIndicator } from './promotion.js';
import { hexRunIsHostnameLabelFragment } from './sourceOccurrence.js';
import { validateUrlCandidate } from './observableTypeResolver.js';
import { annotateDocumentZones } from './documentZones.js';

const SOURCE = 'https://research.example/blog/overextraction/';
const HEX = crypto.createHash('md5').update('overextraction-bucket').digest('hex');
const SHA_A = crypto.createHash('sha256').update('overextraction-stager-a').digest('hex');
const SHA_B = crypto.createHash('sha256').update('overextraction-stager-b').digest('hex');
const BUCKET = `pub-${HEX}.store-cdn.dev`;

function htmlDoc(inner) {
  return `<!doctype html><html lang="en"><head><title>Over-extraction fixture</title></head><body><article>
<h1>Synthetic espionage campaign</h1>
<p>Background paragraph describing lure construction, delivery and operator tradecraft across several environments.</p>
${inner}
</article></body></html>`;
}

function extract(inner) {
  const r = extractCanonicalDocumentFromHtml(htmlDoc(inner), { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  return { ...extractCandidatesWithDiagnostics(r.document, { sourceUrl: SOURCE }), document: r.document };
}

const keyOf = (c) => `${c.candidate_type}:${c.normalized_value}`;
const find = (cands, type, value) => cands.find((c) => c.candidate_type === type && c.normalized_value === value) || null;
const isMember = (c) => Boolean(c) && isActionableReviewIndicator({ ...c, evidence: buildCandidateEvidenceRecord(c) });
const memberKeys = (cands) => cands.filter(isMember).map(keyOf).sort();

// Narrative sections (stage table, prose C2 topic, dead-drop prose), a curated
// IOC appendix, then a vendor "Integrated Coverage" sidebar.
const NARRATIVE = `
<h2>The infection chain</h2>
<h3>Stage 4: downloader and launcher</h3>
<p>The table below shows the files retrieved during one campaign.</p>
<table><thead><tr><th>CDN URL</th><th>Actual Content</th><th>Description</th></tr></thead><tbody>
<tr><td>${BUCKET}/AbCd[…].pdf</td><td>Lure-specific PDF</td><td>Decoy document opened for the victim</td></tr>
<tr><td>${BUCKET}/AbCdhost.exe.qqa</td><td>host.exe (legitimate signed binary)</td><td>Loads the sideloaded DLL</td></tr>
</tbody></table>
<h2>C2 infrastructure</h2>
<p>We also identified software-themed domains that directly hosted standalone backdoor executables. The domain “update-flash[.]com” served samples from “https://update-flash[.]com/download/setup_x.exe”. Similarly, “cdn-office[.]net” delivered a related build from “https://www.cdn-office[.]net/downloads/setup_x.exe”.</p>
<h2>The backdoor</h2>
<h3>Dead-drop C2 communication</h3>
<p>The implant blends into legitimate synchronization traffic. Outbound connections terminate at “graph.example-cloud.com” and “login.example-cloud.com”.</p>
<table><thead><tr><th>Path</th><th>Purpose</th></tr></thead><tbody>
<tr><td>/beacons/{id}.json</td><td>Check-in</td></tr>
</tbody></table>`;

const APPENDIX = `
<h2>Indicators of compromise (IOCs)</h2>
<p>IOCs for this research can also be found at our repository.</p>
<p>${SHA_A} (malicious HTA stager)</p>
<p>${SHA_B} (malicious WSF stager)</p>
<p>update-flash[.]com</p>
<p>cdn-office[.]net</p>
<p>pub-${HEX}[.]store-cdn[.]dev</p>
<p>hxxps://update-flash[.]com/download/setup_x.exe</p>
<p>hxxps://www.cdn-office[.]net/downloads/setup_x.exe</p>
<p>hxxps://pub-${HEX}[.]store-cdn[.]dev/AbCdhost.exe.qqa (signed host binary URL)</p>
<h3>Integrated Coverage</h3>
<h5>Web Security</h5>
<p>Vendor Intelligence</p>
<h5>Email Security</h5>
<p>Vendor Intelligence</p>
<p>Read more about our integrations in the data sheet on vendor-site.com.</p>`;

const DECLARED = [
  `sha256:${SHA_A}`,
  `sha256:${SHA_B}`,
  'domain:update-flash.com',
  'domain:cdn-office.net',
  `domain:${BUCKET}`,
  'url:https://update-flash.com/download/setup_x.exe',
  'url:https://www.cdn-office.net/downloads/setup_x.exe',
  `url:https://${BUCKET}/AbCdhost.exe.qqa`
].sort();

// ---------------------------------------------------------------------------
// End to end: curated appendix ⇒ Indicators == publisher-declared identities
// ---------------------------------------------------------------------------

test('curated IOC appendix: Indicators are exactly the publisher-declared identities', () => {
  const { candidates, diagnostics } = extract(`${NARRATIVE}${APPENDIX}`);
  assert.equal(diagnostics.document_scope.has_authoritative_indicator_scope, true);
  assert.deepEqual(memberKeys(candidates), DECLARED);
  // Table completeness stays consistent after the scheme-less fold.
  assert.equal(diagnostics.explicit_tables.inconsistent, false);
  assert.deepEqual(diagnostics.explicit_tables.missing_identities, []);
});

test('curated IOC appendix: AI maliciousness on narrative values does not change membership', () => {
  const { candidates, document } = extract(`${NARRATIVE}${APPENDIX}`);
  const narrative = candidates.filter((c) => c.ai_needed && !DECLARED.includes(keyOf(c)));
  assert.ok(narrative.some((c) => c.normalized_value === 'graph.example-cloud.com'), 'narrative values stay extracted for analysis');
  const after = mergeAiCandidateUpdates(
    candidates,
    {
      candidate_updates: narrative.map((c) => ({
        candidate_type: c.candidate_type,
        normalized_value: c.normalized_value,
        assessment: 'malicious',
        role: 'command_and_control',
        confidence: 0.9
      }))
    },
    { document }
  );
  assert.deepEqual(memberKeys(after), DECLARED);
});

test('no curated IOC section (MODE B): narrative values the model calls malicious remain Indicators', () => {
  const { candidates, document, diagnostics } = extract(`
<h2>C2 infrastructure</h2>
<p>The domain “update-flash[.]com” served samples from “https://update-flash[.]com/download/setup_x.exe”.</p>
<h2>Network activity</h2>
<p>The implant then beacons to relay-node-17[.]net every five minutes.</p>`);
  assert.equal(diagnostics.document_scope.has_authoritative_indicator_scope, false, 'a prose-only C2 topic is not a curated section');
  const after = mergeAiCandidateUpdates(
    candidates,
    {
      candidate_updates: [
        { candidate_type: 'domain', normalized_value: 'relay-node-17.net', assessment: 'malicious', role: 'command_and_control', confidence: 0.9 },
        { candidate_type: 'url', normalized_value: 'https://update-flash.com/download/setup_x.exe', assessment: 'malicious', role: 'malware_download', confidence: 0.9 }
      ]
    },
    { document }
  );
  assert.ok(isMember(find(after, 'domain', 'relay-node-17.net')));
  assert.ok(isMember(find(after, 'url', 'https://update-flash.com/download/setup_x.exe')));
});

// ---------------------------------------------------------------------------
// Membership: zone is evidence, not membership
// ---------------------------------------------------------------------------

test('a prose mention inside an IOC / C2 section zone is not a report Indicator', () => {
  const row = (occ) => ({
    candidate_type: 'domain',
    normalized_value: 'vendor-site.com',
    assessment: 'malicious',
    is_ioc: true,
    source_assertion: 'body_mention',
    evidence: { source_assertion: 'body_mention', document_has_authoritative_scope: true, occurrences: [occ] }
  });
  const prose = row({ zone: 'explicit_ioc_section', form: 'standalone', occurrence_kind: 'narrative_mention' });
  const c2Prose = row({ zone: 'c2_section', form: 'standalone', occurrence_kind: 'narrative_context' });
  const assertedRow = row({ zone: 'explicit_ioc_section', form: 'standalone', occurrence_kind: 'standalone_indicator_row', asserted: true });
  const legacy = row({ zone: 'explicit_ioc_section', form: 'standalone' });
  assert.equal(isPublisherAuthoritativeReportIocMember(prose), false);
  assert.equal(isPublisherAuthoritativeReportIocMember(c2Prose), false);
  assert.equal(isPublisherAuthoritativeReportIocMember(assertedRow), true);
  assert.equal(isPublisherAuthoritativeReportIocMember(legacy), true, 'pre-annotation extracts keep the zone reading');
  assert.match(publisherAuthoritativeIocMembershipSql('c'), /occ->>'asserted' = 'true'/);
  assert.match(publisherAuthoritativeIocMembershipSql('c'), /occurrence_kind/);
});

// ---------------------------------------------------------------------------
// Hash typing: a hex run of a hostname label is not a hash
// ---------------------------------------------------------------------------

test('hex run joined to a hostname label by "-" is a hostname fragment, not a hash', () => {
  const at = (text, hex) => {
    const i = text.indexOf(hex);
    return hexRunIsHostnameLabelFragment(text, i, i + hex.length);
  };
  assert.equal(at(`pub-${HEX}.store-cdn.dev (staging bucket)`, HEX), true);
  assert.equal(at(`https://pub-${HEX}.store-cdn.dev/x`, HEX), true);
  assert.equal(at(`${HEX}-cdn.example.net`, HEX), true);
  assert.equal(at(`MD5 ${HEX} of the dropper`, HEX), false);
  assert.equal(at(`${HEX}.exe was dropped`, HEX), false, 'hash-named file keeps its hash');
  assert.equal(at(`md5-${HEX} label`, HEX), false, 'no dotted hostname around it');

  const { candidates } = extract(`
<h2>Indicators of compromise</h2>
<p>pub-${HEX}[.]store-cdn[.]dev (staging bucket)</p>
<p>${SHA_A}</p>`);
  assert.equal(find(candidates, 'md5', HEX), null);
  assert.ok(isMember(find(candidates, 'domain', BUCKET)));

  const both = extract(`
<h2>Indicators of compromise</h2>
<p>pub-${HEX}[.]store-cdn[.]dev</p>
<p>${HEX}</p>`).candidates;
  const hash = find(both, 'md5', HEX);
  assert.ok(hash, 'a standalone spelling of the same hex is still a hash');
  assert.equal(hash.occurrences.length, 1);
});

// ---------------------------------------------------------------------------
// URL token boundaries / validity / identity
// ---------------------------------------------------------------------------

test('a closing typographic quote ends a URL: quoted prose URL is the listed identity', () => {
  const { candidates } = extract(`
<p>The sample was served from “https://update-flash[.]com/download/setup_x.exe”, and from «https://alt-flash[.]com/a.exe».</p>`);
  const urls = candidates.filter((c) => c.candidate_type === 'url').map((c) => c.normalized_value).sort();
  assert.deepEqual(urls, ['https://alt-flash.com/a.exe', 'https://update-flash.com/download/setup_x.exe']);
  assert.equal(candidates.some((c) => /%E2%80%9D|%C2%BB|[”»]/i.test(String(c.normalized_value))), false);
});

test('an elided value ("[…]", "[...]", "…") is not a URL', () => {
  for (const raw of [`${BUCKET}/AbCd[…].pdf`, `https://${BUCKET}/AbCd[...].pdf`, `https://${BUCKET}/AbCd…pdf`]) {
    const v = validateUrlCandidate(raw);
    assert.equal(v.ok, false, raw);
    assert.equal(v.reason, 'elided_value', raw);
  }
  assert.equal(validateUrlCandidate(`https://${BUCKET}/AbCd.pdf`).ok, true);
  const { candidates } = extract(NARRATIVE);
  assert.equal(candidates.some((c) => String(c.normalized_value).includes('[')), false);
});

test('scheme-less "host/path" joins the absolute URL the report lists; ambiguous scheme stays as written', () => {
  const { candidates } = extract(`
<h2>Indicators of compromise</h2>
<table><thead><tr><th>URL</th><th>Description</th></tr></thead><tbody>
<tr><td>${BUCKET}/AbCdhost.exe.qqa</td><td>host binary</td></tr>
<tr><td>dual-scheme[.]net/p/a.bin</td><td>payload</td></tr>
</tbody></table>
<p>hxxps://pub-${HEX}[.]store-cdn[.]dev/AbCdhost.exe.qqa</p>
<p>http://dual-scheme[.]net/p/a.bin</p>
<p>https://dual-scheme[.]net/p/a.bin</p>`);
  const folded = find(candidates, 'url', `https://${BUCKET}/AbCdhost.exe.qqa`);
  assert.ok(folded);
  assert.equal(find(candidates, 'url', `${BUCKET}/AbCdhost.exe.qqa`), null);
  assert.ok(folded.occurrences.some((o) => o.form === 'table_row'), 'table provenance kept on the folded identity');
  assert.deepEqual(folded.parsed.scheme_less_aliases, [`${BUCKET}/AbCdhost.exe.qqa`]);
  assert.ok(find(candidates, 'url', 'dual-scheme.net/p/a.bin'), 'http + https listed: scheme-less spelling is not guessed');
});

// ---------------------------------------------------------------------------
// Section scope
// ---------------------------------------------------------------------------

function zonesOf(inner) {
  const r = extractCanonicalDocumentFromHtml(htmlDoc(inner), { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  const d = annotateDocumentZones(r.document, { sourceUrl: SOURCE });
  return (re) => d.blocks.find((b) => re.test(String(b.text || '')))?.zone;
}

test('a vendor sidebar heading nested under a closing sub-topic never resumes the IOC section', () => {
  const zoneOf = zonesOf(APPENDIX);
  assert.equal(zoneOf(/^update-flash/), 'explicit_ioc_section');
  assert.equal(zoneOf(/^Email Security$/), 'report_body');
  assert.equal(zoneOf(/data sheet on vendor-site/), 'report_body');
});

test('a prose-only C2 topic heading is narrative; a C2 heading over indicator rows is curated', () => {
  const prose = zonesOf(`
<h2>C2 infrastructure</h2>
<p>The operators relied on cloud hosting; the domain “update-flash[.]com” served samples.</p>
<h2>Conclusion</h2><p>Done.</p>`);
  assert.equal(prose(/served samples/), 'report_body');
  const listed = zonesOf(`
<h2>C2 infrastructure</h2>
<p>The following servers were used:</p>
<h3>Servers</h3>
<ul><li>relay-node-17[.]net</li><li>relay-node-18[.]net</li></ul>
<h2>Conclusion</h2><p>Done.</p>`);
  assert.equal(listed(/^relay-node-17/), 'c2_section');
  assert.equal(listed(/following servers/), 'c2_section');
});

// ---------------------------------------------------------------------------
// Optional live acceptance: public article vs the publisher's own IOC file
// ---------------------------------------------------------------------------

test('live article: Indicators equal the publisher IOC file', async (t) => {
  const article = 'https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/';
  const iocFile = 'https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2026/09/uat-11587-targets-gov.txt';
  const get = async (url) => {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 20000);
    try {
      const res = await fetch(url, {
        signal: ac.signal,
        headers: {
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36',
          accept: 'text/html,text/plain'
        }
      });
      return res.ok ? await res.text() : { status: res.status };
    } finally {
      clearTimeout(timer);
    }
  };
  let html;
  let published;
  try {
    [html, published] = await Promise.all([get(article), get(iocFile)]);
  } catch (err) {
    t.skip(`live fetch unavailable: ${err?.cause?.code || err.message}`);
    return;
  }
  if (typeof html !== 'string' || typeof published !== 'string') {
    t.skip(`live fetch HTTP ${html?.status || published?.status}`);
    return;
  }
  const declared = new Set(published.split(/\r?\n/).map((s) => s.trim().toLowerCase()).filter(Boolean));
  const r = extractCanonicalDocumentFromHtml(html, { url: article, finalUrl: article, httpStatus: 200 });
  assert.equal(r.ok, true, r.code);
  const { candidates } = extractCandidatesWithDiagnostics(r.document, { sourceUrl: article });
  const members = candidates.filter(isMember).map((c) => String(c.normalized_value).toLowerCase());
  assert.deepEqual(members.filter((v) => !declared.has(v)), [], 'no Indicator outside the publisher file');
  assert.deepEqual([...declared].filter((v) => !members.includes(v)), [], 'every publisher IOC is an Indicator');
  assert.equal(members.length, declared.size);
});
