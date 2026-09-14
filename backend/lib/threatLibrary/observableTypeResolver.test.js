/**
 * Central observable-type resolver: a string that looks domain-like or
 * URL-like is not automatically a network IOC. Syntax + source semantics +
 * provenance decide; no allowlists, no report-specific rules.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  OBSERVABLE_TYPE_RESOLVER_VERSION,
  resolveDottedToken,
  validateUrlCandidate,
  validateCanonicalIocValue,
  classifyPathLikeShape,
  classifyTypeLabel,
  parseArtifactTypeLabel,
  isHostnameSyntax,
  hasCodeIdentifierShape,
  suffixStrength,
  portFromProse,
  buildTypeResolutionRecord,
  NON_NETWORK_RESOLVED_TYPES
} from './observableTypeResolver.js';
import { normalizeCandidateValue } from './candidateValue.js';

test('resolver has its own internal contract version', () => {
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v1');
  assert.ok(NON_NETWORK_RESOLVED_TYPES.has('technical_artifact'));
  assert.ok(NON_NETWORK_RESOLVED_TYPES.has('relative_path'));
});

// ---------------------------------------------------------------------------
// Dotted technical identifiers vs hostnames
// ---------------------------------------------------------------------------

test('single-instance identifier context: dotted token is NOT a domain', () => {
  const r = resolveDottedToken('localfoo.client.singleinstance', {
    surroundingText: 'Single-instance identifier: localfoo.client.singleinstance'
  });
  assert.equal(r.kind, 'technical_artifact');
  assert.equal(r.reason, 'single_instance_identifier_context');
  assert.equal(r.artifact_kind, 'mutex');
  assert.equal(r.labelled, true);
});

test('same dotted token with an explicit network relation IS a domain (context decides, not the value)', () => {
  const r = resolveDottedToken('localfoo.client.singleinstance', {
    surroundingText: 'Malware connects to localfoo.client.singleinstance over TCP 443'
  });
  assert.equal(r.kind, 'domain');
  assert.equal(r.reason, 'network_relation');
});

test('named mutex in prose (original case) is a technical artifact', () => {
  for (const text of [
    'First it checks for a named mutex, LocalFoo.Client.SingleInstance, and exits if it already exists.',
    'The strongest host-based indicators are the static mutex LocalFoo.Client.SingleInstance, the presence of a JSON file',
    'Named mutex: hunt for LocalFoo.Client.SingleInstance. It has not changed across samples.'
  ]) {
    const r = resolveDottedToken('LocalFoo.Client.SingleInstance', { surroundingText: text });
    assert.equal(r.kind, 'technical_artifact', text);
    assert.equal(r.artifact_kind === 'mutex' || r.artifact_kind === 'code', true, `${text} → ${r.reason}`);
  }
});

test('Loader.Program.Main and other symbolic identifiers are not domains', () => {
  for (const [token, ctx] of [
    ['Loader.Program.Main', {}],
    ['Program.Main', {}],
    ['embed.FS', { surroundingText: "packaged into the executable through Go's embed.FS, so the hub needs no web server" }],
    ['bytes.Index', { surroundingText: 'The patcher locates each block with bytes.Index and overwrites it with memmove.' }],
    ['ApplyStubPE.ForceCheckSum', { surroundingText: 'recalculates the PE checksum through ApplyStubPE.ForceCheckSum and ApplyStubPE.WithAuthenticode' }],
    ['my_module.helper', {}]
  ]) {
    const r = resolveDottedToken(token, ctx);
    assert.equal(r.kind, 'technical_artifact', token);
    assert.equal(r.artifact_kind, 'code', `${token} → ${r.reason}`);
  }
});

test('agent.server.timeout in configuration context is not a domain', () => {
  const r = resolveDottedToken('agent.server.timeout', {
    surroundingText: 'The configuration key agent.server.timeout controls the beacon interval in seconds.'
  });
  assert.equal(r.kind, 'technical_artifact');
  assert.equal(r.reason, 'config_context');
  // Even without context the TLD-position label "timeout" is a code word, so syntax alone never promotes it.
  assert.equal(resolveDottedToken('agent.server.timeout').kind, 'technical_artifact');
});

test('malware connects to c2.evil-example.com → domain; typed row Domain | c2.evil-example.com → domain', () => {
  assert.equal(resolveDottedToken('c2.evil-example.com', { surroundingText: 'Malware connects to c2.evil-example.com' }).kind, 'domain');
  const typed = resolveDottedToken('c2.evil-example.com', { typeLabel: 'Domain', form: 'table_row' });
  assert.equal(typed.kind, 'domain');
  assert.equal(typed.reason, 'declared_network_type');
});

test('type labels are authoritative for the reading: Mutex | evil.com is not a network IOC, Domain | x.internal is', () => {
  assert.equal(resolveDottedToken('evil.com', { typeLabel: 'Mutex' }).kind, 'technical_artifact');
  assert.equal(resolveDottedToken('evil.com', { typeLabel: 'Class' }).artifact_kind, 'code');
  assert.equal(resolveDottedToken('evil.com', { typeLabel: 'Registry key' }).artifact_kind, 'registry');
  assert.equal(resolveDottedToken('update.corp.internal', { typeLabel: 'Hostname' }).kind, 'domain');
  assert.equal(resolveDottedToken('update.corp.internal', { typeLabel: 'C2 domain' }).kind, 'domain');
});

test('public suffix is only a signal: unusual suffix still promotes with network semantics or an explicit indicator row', () => {
  const internal = resolveDottedToken('update.corp.lan', { surroundingText: 'the implant resolves update.corp.lan through the internal DNS' });
  assert.equal(internal.kind, 'domain');
  const row = resolveDottedToken('c2.staging.corpnet', { strongZone: true, form: 'list_row' });
  assert.equal(row.kind, 'domain');
  assert.equal(row.reason, 'explicit_indicator_row');
  // plain unknown-but-plausible suffix with no signal either way stays a domain candidate (policy decides promotion)
  assert.equal(resolveDottedToken('verify-cloud.digital').kind, 'domain');
});

test('brand-style capitalisation on the first label is not a code signal (Exploit.in, Google.com)', () => {
  assert.equal(hasCodeIdentifierShape('Exploit.in', { suffixStrength: 'strong' }), false);
  assert.equal(hasCodeIdentifierShape('Google.com', { suffixStrength: 'strong' }), false);
  assert.equal(hasCodeIdentifierShape('EVIL.COM'), false);
  assert.equal(hasCodeIdentifierShape('embed.FS'), true);
  assert.equal(hasCodeIdentifierShape('LocalVectra.Client.SingleInstance'), true);
  assert.equal(hasCodeIdentifierShape('Loader.Program.Main', { suffixStrength: 'weak' }), true);
  assert.equal(resolveDottedToken('Exploit.in', { surroundingText: 'a parallel listing on Exploit.in and negotiation over Telegram' }).kind, 'domain');
});

test('code block context: weak suffix needs network evidence; strong suffix still passes (real C2 in code)', () => {
  assert.equal(resolveDottedToken('cfg.server.timeout', { blockType: 'code' }).kind, 'technical_artifact');
  assert.equal(resolveDottedToken('cfg.server.timeout', { blockType: 'code' }).reason, 'code_block_weak_suffix');
  assert.equal(resolveDottedToken('c2-panel.evil-example.net', { blockType: 'code' }).kind, 'domain');
  assert.equal(resolveDottedToken('cfg.server.timeout', { blockType: 'code', surroundingText: 'connects to cfg.server.timeout' }).kind, 'domain');
});

test('suffix strength: ccTLD/gTLD strong, code words / long labels weak, unknown short labels plausible', () => {
  assert.equal(suffixStrength(['evil', 'com']), 'strong');
  assert.equal(suffixStrength(['evil', 'co', 'uk']), 'strong');
  assert.equal(suffixStrength(['a', 'timeout']), 'weak');
  assert.equal(suffixStrength(['a', 'singleinstance']), 'weak');
  assert.equal(suffixStrength(['a', 'exe']), 'weak');
  assert.equal(suffixStrength(['verify-cloud', 'digital']), 'strong');
  assert.equal(suffixStrength(['c2', 'staging', 'corpnet']), 'plausible');
});

test('hostname syntax: labels, alphabetic / IDN TLD, no whitespace or symbols', () => {
  assert.equal(isHostnameSyntax('c2.evil-example.com'), true);
  assert.equal(isHostnameSyntax('xn--80ak6aa92e.com'), true);
  assert.equal(isHostnameSyntax('evil.xn--p1ai'), true);
  assert.equal(isHostnameSyntax('Product Vectra, Company Vectra'), false);
  assert.equal(isHostnameSyntax('%TEMP%callback.json'), false);
  assert.equal(isHostnameSyntax('a.1'), false);
  assert.equal(isHostnameSyntax('-bad.com'), false);
});

// ---------------------------------------------------------------------------
// Multi-language semantics (not English-keyword-only)
// ---------------------------------------------------------------------------

test('Turkish: bağlanır → domain, yapılandırma anahtarı → artifact, muteks → artifact', () => {
  assert.equal(resolveDottedToken('zararli.ornek-alan.com', { surroundingText: 'Zararlı yazılım zararli.ornek-alan.com adresine bağlanır' }).kind, 'domain');
  assert.equal(resolveDottedToken('ayar.sunucu.zamanasimi', { surroundingText: 'Yapılandırma anahtarı ayar.sunucu.zamanasimi değeri saniye cinsindendir' }).kind, 'technical_artifact');
  assert.equal(resolveDottedToken('tek.ornek.kilit', { surroundingText: 'Muteks adı tek.ornek.kilit sabittir' }).artifact_kind, 'mutex');
  assert.equal(resolveDottedToken('kotu.ornek.xyz', { typeLabel: 'Alan Adı' }).kind, 'domain');
  assert.equal(resolveDottedToken('kotu.ornek.xyz', { typeLabel: 'Muteks' }).kind, 'technical_artifact');
});

test('Chinese: 连接 / 域名 → domain, 互斥体 / 配置 → artifact', () => {
  assert.equal(resolveDottedToken('kotu.ornek.xyz', { surroundingText: '木马连接 kotu.ornek.xyz 域名' }).kind, 'domain');
  assert.equal(resolveDottedToken('tek.ornek.kilit', { surroundingText: '互斥体 tek.ornek.kilit 用于单实例检查' }).artifact_kind, 'mutex');
  assert.equal(resolveDottedToken('agent.server.timeout', { surroundingText: '配置项 agent.server.timeout 控制心跳间隔' }).kind, 'technical_artifact');
  assert.equal(resolveDottedToken('c2.evil-example.net', { typeLabel: '域名' }).kind, 'domain');
  assert.equal(resolveDottedToken('c2.evil-example.net', { typeLabel: '互斥体' }).kind, 'technical_artifact');
});

test('Russian / German / Spanish labels', () => {
  assert.equal(resolveDottedToken('c2.evil-example.net', { typeLabel: 'Домен' }).kind, 'domain');
  assert.equal(resolveDottedToken('c2.evil-example.net', { typeLabel: 'Мьютекс' }).kind, 'technical_artifact');
  assert.equal(resolveDottedToken('c2.evil-example.net', { typeLabel: 'Klasse' }).kind, 'technical_artifact');
  assert.equal(resolveDottedToken('c2.evil-example.net', { typeLabel: 'Dominio' }).kind, 'domain');
  assert.equal(resolveDottedToken('Foo.Bar.Baz', { surroundingText: 'El mutex Foo.Bar.Baz evita una segunda instancia' }).artifact_kind, 'mutex');
});

test('type-label classification is short-label only; section titles are neutral', () => {
  assert.equal(classifyTypeLabel('Mutex').semantics, 'artifact');
  assert.equal(classifyTypeLabel('ClickFix path').kind, 'path');
  assert.equal(classifyTypeLabel('Domain').semantics, 'network');
  assert.equal(classifyTypeLabel('C2 port').semantics, 'network');
  assert.equal(classifyTypeLabel('Host and Network Artifacts').semantics, 'neutral');
  assert.equal(classifyTypeLabel('The malware creates a mutex before it connects').semantics, 'neutral');
  assert.equal(parseArtifactTypeLabel('Default PE metadata')?.kind, 'metadata');
});

// ---------------------------------------------------------------------------
// URL vs relative path / filesystem path, candidate boundaries
// ---------------------------------------------------------------------------

test('relative paths and routes are never URL IOCs; path and prose-stated port are kept as context', () => {
  const r = validateUrlCandidate('/clickfix/abc/file on port 8081');
  assert.equal(r.ok, false);
  assert.equal(r.resolved_type, 'relative_path');
  assert.equal(r.normalized_path, '/clickfix/abc/file');
  assert.equal(r.port, 8081);
  assert.equal(r.trailing_text, 'on port 8081');
  for (const p of ['/clickfix/abc/file', '/api/v1/upload', '../payload', './stage2.bin']) {
    const x = validateUrlCandidate(p);
    assert.equal(x.ok, false, p);
    assert.equal(x.resolved_type, 'relative_path', p);
  }
});

test('filesystem paths are never URL IOCs', () => {
  for (const p of ['C:\\Users\\Public\\payload.exe', 'C:/Temp/payload.exe', '%TEMP%\\callback.json', '%APPDATA%\\svc.exe', '\\\\share\\drop\\x.dll', '/etc/cron.d/backdoor', '/tmp/.x/payload']) {
    const x = validateUrlCandidate(p);
    assert.equal(x.ok, false, p);
    assert.equal(x.resolved_type, 'file_path', p);
  }
  assert.equal(classifyPathLikeShape('C:\\Users\\Public\\payload.exe'), 'file_path');
});

test('absolute URLs (fanged or defanged) are URL IOCs with a validated host', () => {
  const a = validateUrlCandidate('http://154.58.204.15:8081/clickfix/abc/file');
  assert.equal(a.ok, true);
  assert.equal(a.host, '154.58.204.15');
  assert.equal(a.host_kind, 'ip');
  assert.equal(a.port, 8081);
  const b = validateUrlCandidate('hxxps://evil[.]example/a');
  assert.equal(b.ok, true);
  assert.equal(b.url, 'https://evil.example/a');
  assert.equal(validateUrlCandidate('https://[2001:db8::1]/x').ok, true);
  assert.equal(validateUrlCandidate('http://exa mple.com/x').ok, false);
  assert.equal(validateUrlCandidate('javascript:alert(1)').ok, false);
});

test('candidate boundary: a URL followed by prose is not absorbed; the port stays context', () => {
  const r = validateUrlCandidate('https://evil.example/a on port 8080');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'url_followed_by_prose');
  assert.equal(r.port, 8080);
  // normalizeCandidateValue rejects it, so cell/token parsers split at the boundary
  const n = normalizeCandidateValue('https://evil.example/a on port 8080', 'url');
  assert.equal(n.ok, false);
  const clean = normalizeCandidateValue('https://evil.example/a', 'url');
  assert.equal(clean.ok, true);
  assert.equal(clean.normalizedValue, 'https://evil.example/a');
});

test('normalizeCandidateValue: path shapes become non-IOC path candidates, never URLs or domains', () => {
  const rel = normalizeCandidateValue('/clickfix/abc/file on port 8081', 'url');
  assert.equal(rel.ok, true);
  assert.equal(rel.candidateType, 'relative_path');
  assert.equal(rel.isIoc, false);
  assert.equal(rel.normalizedValue, '/clickfix/abc/file');
  assert.equal(rel.parsed.port, 8081);
  const win = normalizeCandidateValue('C:\\Users\\Public\\payload.exe');
  assert.equal(win.candidateType, 'file_path');
  assert.equal(win.isIoc, false);
  const sentence = normalizeCandidateValue('Product Vectra, Company Vectra, version 0.2');
  assert.equal(sentence.ok, false);
});

test('prose port extraction is multilingual context, never a synthesised endpoint', () => {
  assert.equal(portFromProse('on port 8081'), 8081);
  assert.equal(portFromProse('over TCP port 443'), 443);
  assert.equal(portFromProse('8080 portu üzerinden'), 8080);
  assert.equal(portFromProse('端口 4444'), 4444);
  assert.equal(portFromProse('порт 9001'), 9001);
  assert.equal(portFromProse('no port here'), null);
  assert.equal(portFromProse('on port 99999'), null);
});

// ---------------------------------------------------------------------------
// Canonical IOC validity gate
// ---------------------------------------------------------------------------

test('canonical validity gate rejects syntactic guesses whatever the claimed type', () => {
  assert.equal(validateCanonicalIocValue('url', '/clickfix/abc/file on port 8081').ok, false);
  assert.equal(validateCanonicalIocValue('url', '/clickfix/abc/file').ok, false);
  assert.equal(validateCanonicalIocValue('url', 'https://evil.example/a').ok, true);
  assert.equal(validateCanonicalIocValue('domain', 'Product Vectra, Company').ok, false);
  assert.equal(validateCanonicalIocValue('domain', 'c2.evil-example.com').ok, true);
  assert.equal(validateCanonicalIocValue('ip', '154.58.204.15').ok, true);
  assert.equal(validateCanonicalIocValue('ip', '999.1.1.1').ok, false);
  assert.equal(validateCanonicalIocValue('cidr', '10.0.0.0/24').ok, true);
  assert.equal(validateCanonicalIocValue('sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855').ok, true);
  assert.equal(validateCanonicalIocValue('technical_artifact', 'LocalFoo.Client.SingleInstance').ok, false);
});

test('type resolution record is explainable (raw → syntax guess → resolved type → reason → promotion)', () => {
  const rec = buildTypeResolutionRecord({
    raw: 'localfoo.client.singleinstance',
    syntaxGuess: 'domain',
    resolvedType: 'technical_artifact',
    reason: 'single_instance_identifier_context',
    promotion: 'excluded'
  });
  assert.deepEqual(
    { raw: rec.raw, syntax_guess: rec.syntax_guess, resolved_type: rec.resolved_type, reason: rec.reason, promotion: rec.promotion },
    { raw: 'localfoo.client.singleinstance', syntax_guess: 'domain', resolved_type: 'technical_artifact', reason: 'single_instance_identifier_context', promotion: 'excluded' }
  );
  const path = buildTypeResolutionRecord({ raw: '/clickfix/abc/file on port 8081', syntaxGuess: 'url', resolvedType: 'relative_path', reason: 'relative_path_without_scheme_or_host', promotion: 'excluded', normalizedPath: '/clickfix/abc/file', port: 8081 });
  assert.equal(path.normalized_path, '/clickfix/abc/file');
  assert.equal(path.port, 8081);
});
