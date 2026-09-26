/**
 * Path segments and filename-shaped tokens are technical artifacts, not
 * domains, consistently across every occurrence of a value (tl-candidates-v10).
 * Synthetic documents only; explicit typed Domain rows must stay domains.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractCandidatesWithDiagnostics, THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { resolveDottedToken, isPathSegmentPosition, FILE_EXT_HINT } from './observableTypeResolver.js';

const URL = 'https://vendor.example/research/app-server-campaign';
const keyOf = (c) => `${c.candidate_type}:${String(c.normalized_value).toLowerCase()}`;

function extract(html) {
  const r = extractCanonicalDocumentFromHtml(html, { url: URL, finalUrl: URL, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  return extractCandidatesWithDiagnostics(r.document, { sourceUrl: URL });
}

const resolve = (value, surroundingText, ctx = {}) => resolveDottedToken(value, { surroundingText, ...ctx });

test('contract version bumped for the typing change', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v10');
});

test('deployable / server-page extensions are filename shapes, never DNS suffixes', () => {
  for (const ext of ['war', 'ear', 'jspx', 'jspf', 'ashx', 'asmx', 'ascx', 'axd', 'cshtml', 'phtml', 'shtml', 'cfm', 'jar', 'jsp', 'dll', 'exe']) {
    assert.ok(FILE_EXT_HINT.has(ext), ext);
    const r = resolve(`webhook.${ext}`, `the operator deployed webhook.${ext} and sent requests from external IP addresses`);
    assert.equal(r.kind, 'technical_artifact', ext);
  }
});

test('path-segment position: directory / file inside a Unix or Windows path is an artifact', () => {
  assert.equal(isPathSegmentPosition('<HOME>/applications/', '/x.jsp'), true);
  assert.equal(isPathSegmentPosition('applications\\portal\\', '\\stage.exe'), true);
  assert.equal(isPathSegmentPosition('Scan ', '\\x'), true);
  assert.equal(isPathSegmentPosition('beacon to https://', '/gate'), false, 'URL authority is not a path segment');
  assert.equal(isPathSegmentPosition('requests to ', '/gate.php'), false, 'scheme-less URL host position');
  assert.equal(isPathSegmentPosition('mounted the WebDAV share \\\\', '\\pub'), false, 'UNC host is a network host');
  assert.equal(resolve('dav-relay.srv', 'the loader mounted \\\\dav-relay.srv\\pub over WebDAV for C2').kind, 'domain');

  const unix = resolve('Console.srv', 'Inspect <HOME>/webserv/applications/Console.srv/ for unexpected files; requests from external IP addresses');
  assert.deepEqual([unix.kind, unix.reason], ['technical_artifact', 'path_segment']);
  const win = resolve('Console.srv', 'dir applications\\portal\\Console.srv\\stage.exe');
  assert.deepEqual([win.kind, win.reason], ['technical_artifact', 'path_segment']);
});

test('domains keep their reading: URL authority, scheme-less URL host, DNS-shaped suffix inside a path, declared Domain', () => {
  assert.equal(resolve('evil-cdn.top', 'the loader beacons to https://evil-cdn.top/gate').kind, 'domain');
  assert.equal(resolve('evil-cdn.top', 'the implant sent requests to evil-cdn.top/gate.php').kind, 'domain');
  assert.equal(resolve('evil-cdn.com', 'payloads were staged under downloads/evil-cdn.com/ and fetched from the C2').kind, 'domain');
  const declared = resolve('update.war', 'update.war', { typeLabel: 'Domain', declaredType: 'domain' });
  assert.deepEqual([declared.kind, declared.reason], ['domain', 'declared_network_type']);
});

test('one value never splits into a domain (body) and an artifact (File Name table); body path segments agree', () => {
  const html = `<html lang="en"><body><article>
<h2>Intrusion activity</h2>
<p>The operator sent requests from external IP addresses and deployed web shells into <APP_HOME>/applications/Console.war/ on the server.</p>
<p>Alongside the loader, the actor deployed the relay.jsp and relay.jspx servlets into victim web directories.</p>
<p>dir applications\\portal\\Console.war\\stage.exe</p>
<h2>Indicators of Compromise</h2>
<h3>File Indicators</h3>
<table>
<thead><tr><th>File Name</th><th>SHA-256</th><th>Description</th></tr></thead>
<tbody>
<tr><td>relay.jspx</td><td>${'a'.repeat(64)}</td><td>JSPX relay servlet</td></tr>
<tr><td>stage.exe</td><td>${'b'.repeat(64)}</td><td>Stager</td></tr>
</tbody>
</table>
<h3>Network Indicators</h3>
<table>
<thead><tr><th>Type</th><th>IOC</th><th>Note</th></tr></thead>
<tbody>
<tr><td>Domain</td><td>relay-panel[.]shop</td><td>Operator panel</td></tr>
<tr><td>Domain</td><td>archive-sync[.]war</td><td>Staging host</td></tr>
<tr><td>IP</td><td>203.0.113.77</td><td>C2</td></tr>
</tbody>
</table>
</article></body></html>`;
  const { candidates, diagnostics } = extract(html);
  const keys = new Set(candidates.map(keyOf));

  // File / directory names: artifacts only, one identity each, never AI-classified domains.
  assert.equal(keys.has('domain:relay.jspx'), false, 'no domain split for the table-typed file');
  assert.equal(keys.has('domain:console.war'), false, 'path segment is not a domain');
  const relay = candidates.filter((c) => String(c.normalized_value).toLowerCase() === 'relay.jspx');
  assert.equal(relay.length, 1, 'body and table occurrences merge into one candidate');
  assert.equal(relay[0].candidate_type, 'technical_artifact');
  assert.equal(relay[0].is_ioc, false);
  assert.ok(relay[0].occurrences.length >= 2, 'body mention joined the table identity');
  assert.equal(candidates.some((c) => c.candidate_type === 'domain' && c.ai_needed), false, 'no filename-shaped domain goes to the AI');

  // Explicit table completeness: typed Domain rows stay domains, even with a file-like suffix.
  assert.ok(keys.has('domain:relay-panel.shop'));
  assert.ok(keys.has('domain:archive-sync.war'), 'declared Domain row is never re-typed by a filename heuristic');
  assert.equal(candidates.find((c) => keyOf(c) === 'domain:archive-sync.war').source_assertion, 'explicit_ioc');
  assert.ok(keys.has(`sha256:${'a'.repeat(64)}`));
  assert.ok(keys.has(`sha256:${'b'.repeat(64)}`));
  assert.ok(keys.has('ip:203.0.113.77'));
  assert.equal(diagnostics.explicit_tables.inconsistent, false);
  assert.deepEqual(diagnostics.explicit_tables.missing_identities, []);
  assert.deepEqual(diagnostics.explicit_tables.dropped_asserted_identities, []);
});

test('a declared Domain row is not outvoted by artifact readings of the same value elsewhere', () => {
  const html = `<html lang="en"><body><article>
<p>The loader wrote its config under C:\\ProgramData\\sync-node.war\\cfg and read files from /opt/sync-node.war/ as well.</p>
<h2>Indicators of Compromise</h2>
<table>
<thead><tr><th>Type</th><th>IOC</th></tr></thead>
<tbody><tr><td>Domain</td><td>sync-node[.]war</td></tr></tbody>
</table>
</article></body></html>`;
  const { candidates, diagnostics } = extract(html);
  const hit = candidates.find((c) => keyOf(c) === 'domain:sync-node.war');
  assert.ok(hit, 'explicit Domain row survives');
  assert.equal(hit.source_assertion, 'explicit_ioc');
  assert.equal(diagnostics.explicit_tables.inconsistent, false);
});
