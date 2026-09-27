/**
 * URL-contained hash occurrences.
 *
 * A hex run inside a URL (path segment, query value, fragment — absolute,
 * defanged or scheme-less) is a component of that URL, not an independent
 * file-hash occurrence. Containment is per occurrence, never per identity: a
 * standalone spelling of the same value (prose, row, explicit table) still
 * creates the hash, with its evidence window anchored on that spelling.
 *
 * Synthetic values only.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractCandidatesWithDiagnostics, surroundingWindow } from './candidateExtraction.js';

const SRC = 'https://research.example/blog/synthetic-hash-containment/';
const MD5 = '0123456789abcdef0123456789abcdef';
const SHA1 = '0123456789abcdef0123456789abcdef01234567';
const SHA256 = `${MD5}${MD5}`;
const HASH_TYPES = new Set(['md5', 'sha1', 'sha256']);

function extract(body) {
  const html = `<!doctype html><html lang="en"><head><title>Synthetic</title></head><body><article>
<h1>Synthetic hash containment</h1>
<p>The synthetic analysis describes the delivery chain and the operator tradecraft observed across several environments.</p>
${body}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SRC, finalUrl: SRC, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  return { ...extractCandidatesWithDiagnostics(r.document, { sourceUrl: SRC }), document: r.document };
}

const find = (cands, type, value) => cands.find((c) => c.candidate_type === type && c.normalized_value === value) || null;
const hashes = (cands) => cands.filter((c) => HASH_TYPES.has(c.candidate_type));
const blockIdOf = (document, needle) => document.blocks.find((b) => String(b.text).includes(needle))?.id;

// ---------------------------------------------------------------------------
// URL-contained only → no independent hash occurrence (URL unchanged)
// ---------------------------------------------------------------------------

test('1. MD5 in a URL path segment is not an independent MD5', () => {
  const { candidates } = extract(`<p>The loader was retrieved from https://cdn.files-relay.com/download/${MD5}/file yesterday.</p>`);
  assert.deepEqual(hashes(candidates), []);
  assert.ok(find(candidates, 'url', `https://cdn.files-relay.com/download/${MD5}/file`), 'URL keeps its existing extraction');
});

test('2. MD5 in a URL query value is not an independent MD5', () => {
  const { candidates } = extract(`<p>The loader was retrieved from https://files-relay.com/download?id=${MD5} yesterday.</p>`);
  assert.deepEqual(hashes(candidates), []);
  assert.ok(candidates.some((c) => c.candidate_type === 'url' && c.normalized_value.includes(`id=${MD5}`)));
});

test('3. MD5 in a URL fragment is not an independent MD5', () => {
  const { candidates } = extract(`<p>The panel was reached at https://files-relay.com/#${MD5} during the session.</p>`);
  assert.deepEqual(hashes(candidates), []);
  assert.ok(candidates.some((c) => c.candidate_type === 'url'));
});

test('4. SHA1 in a URL path is suppressed', () => {
  const { candidates } = extract(`<p>The loader was retrieved from https://files-relay.com/s/${SHA1} yesterday.</p>`);
  assert.deepEqual(hashes(candidates), []);
});

test('5. SHA256 in a URL path is suppressed (no shorter hash carved out of it either)', () => {
  const { candidates } = extract(`<p>The loader was retrieved from https://files-relay.com/sample/${SHA256} yesterday.</p>`);
  assert.deepEqual(hashes(candidates), []);
});

test('11. defanged and scheme-less URLs contain their hash after refanging', () => {
  const { candidates } = extract(`
<p>The loader was retrieved from hxxps://files-relay[.]com/files/${MD5} yesterday.</p>
<p>A second copy sat at files-mirror[.]net/drop/${SHA1} for a day.</p>`);
  assert.deepEqual(hashes(candidates), []);
  assert.ok(find(candidates, 'url', `https://files-relay.com/files/${MD5}`));
  assert.ok(find(candidates, 'url', `files-mirror.net/drop/${SHA1}`));
});

// ---------------------------------------------------------------------------
// Standalone spellings are retained and keep the existing narrative path
// ---------------------------------------------------------------------------

test('6–8. standalone MD5 / SHA1 / SHA256 are retained on the narrative evidence path', () => {
  const { candidates } = extract(`
<p>The malicious attachment has MD5 ${MD5}.</p>
<p>The dropped loader has SHA1 ${SHA1}.</p>
<p>The final payload has SHA256 ${SHA256}.</p>`);
  for (const [type, v] of [['md5', MD5], ['sha1', SHA1], ['sha256', SHA256]]) {
    const c = find(candidates, type, v);
    assert.ok(c, `${type} retained`);
    assert.equal(c.is_ioc, true);
    assert.equal(c.ai_needed, true, `${type} follows the model path`);
    assert.equal(c.source_assertion, 'body_mention');
    assert.equal(c.occurrences.length, 1);
    assert.match(c.occurrences[0].surrounding_text, new RegExp(`has ${type.toUpperCase()} ${v}`));
  }
  assert.equal(hashes(candidates).length, 3);
});

test('12. punctuation-bounded standalone hashes are retained', () => {
  const { candidates } = extract(`
<p>Samples: (${MD5}), "${SHA1}", and MD5:${'f'.repeat(32)}; SHA256=${SHA256}.</p>`);
  for (const [type, v] of [['md5', MD5], ['sha1', SHA1], ['md5', 'f'.repeat(32)], ['sha256', SHA256]]) {
    assert.ok(find(candidates, type, v), `${type}:${v} retained`);
  }
});

// ---------------------------------------------------------------------------
// Containment is per occurrence, not per identity
// ---------------------------------------------------------------------------

test('9a. same block: URL copy + standalone assertion → one MD5 anchored on the standalone spelling', () => {
  const { candidates, document } = extract(
    `<p>The payload is available at https://files-relay.com/files/${MD5}. Its MD5 is ${MD5}.</p>`
  );
  const c = find(candidates, 'md5', MD5);
  assert.ok(c, 'the standalone assertion keeps the identity');
  assert.equal(hashes(candidates).length, 1);
  assert.equal(c.occurrences.length, 1);
  const o = c.occurrences[0];
  assert.equal(o.block_id, blockIdOf(document, 'Its MD5 is'));
  assert.equal(o.form, 'standalone');
  assert.match(o.surrounding_text, new RegExp(`Its MD5 is ${MD5}`));
  assert.doesNotMatch(o.surrounding_text, /https?:\/\//, 'the evidence window is not the URL copy');
  // The URL clause ("available at") does not become this hash's relation.
  const alone = find(extract(`<p>Its MD5 is ${MD5}.</p>`).candidates, 'md5', MD5);
  assert.equal(o.source_relation, alone.occurrences[0].source_relation);
  assert.equal(o.relation_marker, alone.occurrences[0].relation_marker);
});

test('9b. different blocks: only the standalone block is an MD5 occurrence', () => {
  const { candidates, document } = extract(`
<p>The payload is available at https://files-relay.com/files/${MD5} for download.</p>
<p>For analysis we examined the malicious attachment with MD5 hash: ${MD5}</p>`);
  const c = find(candidates, 'md5', MD5);
  assert.ok(c);
  assert.deepEqual(c.occurrences.map((o) => o.block_id), [blockIdOf(document, 'For analysis we examined')]);
  assert.equal(c.occurrence_count, 1);
  assert.equal(c.ai_needed, true);
});

test('9c. defanged same block: anchoring survives the refang offset shift', () => {
  const { candidates } = extract(
    `<p>Download hxxps://files-relay[.]com/a/${SHA256} then check it: SHA256 ${SHA256}.</p>`
  );
  const c = find(candidates, 'sha256', SHA256);
  assert.ok(c);
  const st = c.occurrences[0].surrounding_text;
  assert.match(st, new RegExp(`SHA256 ${SHA256}`));
  assert.doesNotMatch(st, /hxxps|files-relay/);
});

test('10. explicit IOC table hash wins over a URL copy elsewhere; table completeness unchanged', () => {
  const { candidates, diagnostics, document } = extract(`
<p>The loader was retrieved from https://files-relay.com/files/${MD5} yesterday.</p>
<h2>Indicators of Compromise</h2>
<table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>
<tr><td>MD5</td><td>${MD5}</td></tr>
<tr><td>Domain</td><td>files-relay[.]com</td></tr>
</tbody></table>`);
  const c = find(candidates, 'md5', MD5);
  assert.ok(c);
  assert.equal(c.policy_decision, 'explicit_report_assertion');
  assert.equal(c.assessment, 'malicious');
  assert.ok(Array.isArray(c.table_rows) && c.table_rows.some((r) => r.explicit));
  const table = document.blocks.find((b) => b.type === 'table');
  assert.deepEqual(c.occurrences.map((o) => o.block_id), [table.id], 'the URL paragraph adds no hash occurrence');
  const t = diagnostics.explicit_tables;
  assert.equal(t.inconsistent, false);
  assert.deepEqual(t.missing_identities, []);
  assert.equal(t.explicit_identities, 2);
});

// ---------------------------------------------------------------------------
// Unchanged behaviour
// ---------------------------------------------------------------------------

test('13. hex runs that are not hash-bounded stay unextracted; a hostless relative path is unchanged', () => {
  const { candidates } = extract(`
<p>The blob ${'a'.repeat(70)} and the key id_${MD5} are configuration values.</p>
<p>The module writes cache/${SHA1} to disk.</p>`);
  assert.equal(find(candidates, 'md5', MD5), null);
  assert.equal(candidates.some((c) => HASH_TYPES.has(c.candidate_type) && c.normalized_value.startsWith('aaaa')), false);
  // Not a URL span (no host): existing extraction is preserved, not broadened or narrowed.
  assert.ok(find(candidates, 'sha1', SHA1));
});

test('14. IPv4 prefix inside a hostname and IP inside a URL remain non-candidates', () => {
  const { candidates } = extract(`
<p>The redirector used 45.61.10.60.dyn-relay[.]net and fetched http://45.61.10.61/files/${MD5} afterwards.</p>`);
  assert.equal(find(candidates, 'ip', '45.61.10.60'), null);
  assert.equal(find(candidates, 'ip', '45.61.10.61'), null);
  assert.equal(find(candidates, 'md5', MD5), null);
  assert.ok(find(candidates, 'domain', '45.61.10.60.dyn-relay.net'));
});

test('surroundingWindow: ordinal anchors on that spelling and never reaches back over an earlier copy', () => {
  const text = `see https://h.example/${MD5} now. Hash ${MD5} here`;
  assert.equal(surroundingWindow(text, MD5, 140, 0), surroundingWindow(text, MD5));
  const w = surroundingWindow(text, MD5, 140, 1);
  assert.equal(w, ` now. Hash ${MD5} here`);
  assert.equal(surroundingWindow(text, MD5, 140, 5), surroundingWindow(text, MD5), 'unknown ordinal falls back to the first hit');
});
