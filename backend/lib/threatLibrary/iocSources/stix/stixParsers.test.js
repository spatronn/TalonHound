import test from 'node:test';
import assert from 'node:assert/strict';
import { parseStixPattern, normalizePatternBrackets, unescapeStixString } from './pattern.js';
import { parseStixJsonSource, looksLikeStixJson } from './json.js';
import { parseStixXmlSource, looksLikeStixXml, extractIndicatorElements } from './xml.js';
import { candidatesFromStixEvidence } from './candidates.js';
import { EVIDENCE_MEMBERSHIP } from './evidence.js';
import { parseIocSourceContent, detectSourceFormat } from '../parseContent.js';
import { markdownToCanonicalDocument, selectCampaignScope } from '../campaignScope.js';

test('STIX pattern: simple hash and Elastic missing bracket', () => {
  const a = parseStixPattern(
    "[file:hashes.'SHA-256' = 'A4069AA29628E64EA63B4FB3E29D16DCC368C5ADD304358A47097EEDAFBBB565']"
  );
  assert.equal(a.ok, true);
  assert.equal(a.observables[0].type, 'sha256');

  const elastic = parseStixPattern(
    "file:hashes.'SHA256' = 'c865f24e4b9b0855b8b559fc3769239b0aa6e8d680406616a13d9a36fbbc2d30']"
  );
  assert.equal(elastic.ok, true);
  assert.equal(elastic.observables[0].type, 'sha256');
  assert.equal(normalizePatternBrackets("x']").startsWith('['), true);
});

test('STIX pattern: OR of SHA-1/SHA-256 flattens; AND across types does not', () => {
  const orPat = parseStixPattern(
    "[file:hashes.'SHA-1' = '61D585E0B849F2594D6AA1D7AF1C44FDEDC3C985' OR file:hashes.'SHA-256' = '1D04E33009BCD017898B9E1387E40B5C04279C02EBC110F12E4A724CCDB9E4FB']"
  );
  assert.equal(orPat.ok, true);
  assert.equal(orPat.observables.length, 2);

  const andCross = parseStixPattern(
    "[domain-name:value = 'evil.example' AND ipv4-addr:value = '203.0.113.10']"
  );
  assert.equal(andCross.ok, false);
  assert.equal(andCross.code, 'unsupported_pattern');
});

test('STIX pattern: CISA file digests narrowed by the file name flatten to the digests', () => {
  const sha1 = 'BB79502D301BA77745B7DBC5DF4269FC7B074CDA';
  const sha256 = 'A82E496B7B5279CB6B93393EC167DD3F50AFF1557366784B25F9E51CB23689D9';
  const md5 = '7DD26568049FAC1B87F676ECFAAC9B11';
  const p = parseStixPattern(
    `[(file:hashes.'SHA-1' = '${sha1}' OR file:hashes.'SHA-256' = '${sha256}' OR file:hashes.MD5 = '${md5}') AND file:name = 'msmp.exe']`
  );
  assert.equal(p.ok, true);
  assert.deepEqual(p.observables.map((o) => o.type).sort(), ['md5', 'sha1', 'sha256']);
  assert.deepEqual(p.dropped_properties, ['file:name']);

  const single = parseStixPattern(`[file:hashes.'SHA-256' = '${sha256}' AND file:name = 'msmp.exe']`);
  assert.equal(single.ok, true);
  assert.deepEqual(single.observables.map((o) => o.type), ['sha256']);

  // A name alternative (OR at the outer level) is not one narrowed file.
  const orName = parseStixPattern(`[file:hashes.'SHA-256' = '${sha256}' OR file:name = 'msmp.exe']`);
  assert.equal(orName.ok, false);
  // Two separately named files joined by AND are not flattened.
  const twoFiles = parseStixPattern(
    `[(file:hashes.MD5 = '${md5}' AND file:name = 'a.exe') AND (file:hashes.'SHA-1' = '${sha1}' AND file:name = 'b.exe')]`
  );
  assert.equal(twoFiles.ok, false);
  // A network value beside the file is never dropped as an attribute.
  const crossType = parseStixPattern(`[file:hashes.MD5 = '${md5}' AND domain-name:value = 'evil.example']`);
  assert.equal(crossType.ok, false);
});

test('STIX pattern: escaped quotes and MATCHES unsupported', () => {
  assert.equal(unescapeStixString("a\\'b\\\\c"), "a'b\\c");
  const bad = parseStixPattern("[domain-name:value MATCHES '.*\\.evil']");
  assert.equal(bad.ok, false);
});

test('STIX JSON: indicator bundle; observed-data is context; revoked excluded', () => {
  const bundle = {
    type: 'bundle',
    id: 'bundle--1',
    objects: [
      {
        type: 'indicator',
        id: 'indicator--1',
        pattern_type: 'stix',
        pattern: "[domain-name:value = 'bad.example']",
        valid_from: '2024-01-01T00:00:00.000Z'
      },
      {
        type: 'indicator',
        id: 'indicator--2',
        pattern_type: 'stix',
        pattern: "[ipv4-addr:value = '198.51.100.9']",
        revoked: true
      },
      {
        type: 'indicator',
        id: 'indicator--3',
        pattern_type: 'stix',
        pattern: "[url:value = 'http://old.example/path']",
        valid_from: '2020-01-01T00:00:00.000Z',
        valid_until: '2020-06-01T00:00:00.000Z'
      },
      {
        type: 'observed-data',
        id: 'observed-data--1',
        object_refs: ['domain-name--ctx']
      },
      {
        type: 'domain-name',
        id: 'domain-name--ctx',
        value: 'cdn.example'
      },
      {
        type: 'marking-definition',
        id: 'marking-definition--1',
        definition_type: 'tlp'
      }
    ]
  };
  const parsed = parseStixJsonSource(JSON.stringify(bundle), { now: new Date('2024-06-01T00:00:00Z') });
  assert.equal(parsed.ok, true);
  const byMem = Object.fromEntries(
    ['indicator', 'context_only', 'excluded', 'unsupported'].map((k) => [
      k,
      parsed.evidence.filter((e) => e.membership === k).map((e) => e.normalized_value)
    ])
  );
  assert.ok(byMem.indicator.includes('bad.example'));
  assert.ok(byMem.excluded.includes('198.51.100.9'));
  assert.ok(byMem.context_only.includes('http://old.example/path') || byMem.context_only.includes('old.example'));
  assert.ok(byMem.context_only.includes('cdn.example'));

  const cands = candidatesFromStixEvidence(parsed.evidence);
  assert.equal(cands.filter((c) => c.assessment === 'malicious').length, 1);
  assert.equal(cands[0].normalized_value, 'bad.example');
});

test('STIX JSON: unsupported compound yields diagnostic not guess', () => {
  const parsed = parseStixJsonSource(
    JSON.stringify({
      type: 'bundle',
      objects: [
        {
          type: 'indicator',
          id: 'indicator--x',
          pattern: "[domain-name:value = 'a.example' AND ipv4-addr:value = '1.2.3.4']"
        }
      ]
    })
  );
  assert.equal(parsed.ok, true);
  assert.equal(parsed.summary.classification.unsupported, 1);
  assert.equal(candidatesFromStixEvidence(parsed.evidence).length, 0);
});

test('STIX JSON: invalid schema / not STIX', () => {
  assert.equal(looksLikeStixJson('{"indicators":[{"value":"x"}]}'), false);
  const bad = parseStixJsonSource('{"foo":1}');
  assert.equal(bad.ok, false);
});

test('STIX XML: hashes and URL; email does not promote provider domains', () => {
  const xml = `<?xml version="1.0"?>
<stix:STIX_Package xmlns:stix="http://stix.mitre.org/stix-1"
  xmlns:indicator="http://stix.mitre.org/Indicator-2"
  xmlns:cybox="http://cybox.mitre.org/cybox-2"
  xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
  xmlns:FileObj="http://cybox.mitre.org/objects#FileObject-2"
  xmlns:URIObj="http://cybox.mitre.org/objects#URIObject-2"
  xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2"
  xmlns:EmailMessageObj="http://cybox.mitre.org/objects#EmailMessageObject-2"
  xmlns:DomainNameObj="http://cybox.mitre.org/objects#DomainNameObject-2"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <stix:Indicators>
    <stix:Indicator id="CISA:Indicator-1">
      <indicator:Title>Malicious File Indicator</indicator:Title>
      <indicator:Type>File Hash Watchlist</indicator:Type>
      <indicator:Observable>
        <cybox:Object>
          <cybox:Properties xsi:type="FileObj:FileObjectType">
            <FileObj:Hashes>
              <cyboxCommon:Hash>
                <cyboxCommon:Type>SHA256</cyboxCommon:Type>
                <cyboxCommon:Simple_Hash_Value>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</cyboxCommon:Simple_Hash_Value>
              </cyboxCommon:Hash>
            </FileObj:Hashes>
          </cybox:Properties>
        </cybox:Object>
      </indicator:Observable>
    </stix:Indicator>
    <stix:Indicator id="CISA:Indicator-2">
      <indicator:Title>Malicious URL Indicator</indicator:Title>
      <indicator:Observable>
        <cybox:Object>
          <cybox:Properties xsi:type="URIObj:URIObjectType" type="URL">
            <URIObj:Value>evil.example/path</URIObj:Value>
          </cybox:Properties>
        </cybox:Object>
      </indicator:Observable>
    </stix:Indicator>
    <stix:Indicator id="CISA:Indicator-3">
      <indicator:Title>Malicious E-mail Indicator</indicator:Title>
      <indicator:Type>Malicious E-mail</indicator:Type>
      <indicator:Observable>
        <cybox:Object>
          <cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">
            <EmailMessageObj:Header>
              <EmailMessageObj:From xsi:type="AddressObj:AddressObjectType" category="e-mail">
                <AddressObj:Address_Value>fortihooks@protonmail.com</AddressObj:Address_Value>
              </EmailMessageObj:From>
            </EmailMessageObj:Header>
          </cybox:Properties>
        </cybox:Object>
      </indicator:Observable>
    </stix:Indicator>
    <stix:Indicator id="CISA:Indicator-4">
      <indicator:Title>Domain</indicator:Title>
      <indicator:Observable>
        <cybox:Object>
          <cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType" type="FQDN">
            <DomainNameObj:Value>literoved.ru</DomainNameObj:Value>
          </cybox:Properties>
        </cybox:Object>
      </indicator:Observable>
    </stix:Indicator>
  </stix:Indicators>
</stix:STIX_Package>`;

  assert.equal(looksLikeStixXml(xml), true);
  assert.equal(extractIndicatorElements(xml).length, 4);
  const parsed = parseStixXmlSource(xml);
  assert.equal(parsed.ok, true);
  const vals = parsed.evidence.map((e) => `${e.membership}:${e.observable_type}:${e.normalized_value}`);
  assert.ok(vals.some((v) => v.startsWith('indicator:sha256:')));
  assert.ok(vals.some((v) => v.includes('indicator:url:') && v.includes('evil.example')));
  assert.ok(vals.some((v) => v === 'indicator:domain:literoved.ru'));
  assert.ok(vals.some((v) => v.includes('context_only:email:fortihooks@protonmail.com')));
  assert.ok(!vals.some((v) => v.includes('domain:protonmail.com')));

  const cands = candidatesFromStixEvidence(parsed.evidence);
  assert.ok(cands.every((c) => c.normalized_value !== 'protonmail.com'));
  assert.ok(cands.some((c) => c.candidate_type === 'domain' && c.normalized_value === 'literoved.ru'));
});

test('parseIocSourceContent routes STIX JSON and rejects text-scan of STIX XML mail domains', async () => {
  assert.equal(detectSourceFormat({ url: 'https://x/a.stix_.json', path: 'a.stix_.json' }), 'stix_json');
  const json = await parseIocSourceContent({
    body: JSON.stringify({
      type: 'bundle',
      objects: [
        {
          type: 'indicator',
          id: 'indicator--1',
          pattern: "[file:hashes.'SHA-256' = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb']"
        }
      ]
    }),
    url: 'https://example.com/pack.json',
    path: 'pack.json'
  });
  assert.equal(json.ok, true);
  assert.equal(json.format, 'stix_json');
  assert.equal(json.unique_count, 1);

  const xmlBody = `<?xml version="1.0"?>
<stix:STIX_Package xmlns:stix="http://stix.mitre.org/stix-1"
  xmlns:indicator="http://stix.mitre.org/Indicator-2"
  xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2"
  xmlns:EmailMessageObj="http://cybox.mitre.org/objects#EmailMessageObject-2"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <stix:Indicator id="i1">
    <indicator:Type>Malicious E-mail</indicator:Type>
    <indicator:Observable>
      <cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">
        <EmailMessageObj:From xsi:type="AddressObj:AddressObjectType" category="e-mail">
          <AddressObj:Address_Value>x@tutanota.com</AddressObj:Address_Value>
        </EmailMessageObj:From>
      </cybox:Properties>
    </indicator:Observable>
  </stix:Indicator>
</stix:STIX_Package>`;
  const xml = await parseIocSourceContent({
    body: xmlBody,
    url: 'https://example.com/a.stix_.xml',
    path: 'a.stix_.xml'
  });
  assert.equal(xml.ok, true);
  assert.equal(xml.format, 'stix_xml');
  assert.equal(xml.unique_count, 0);
  assert.ok((xml.classification?.context_only || 0) >= 1);
});

test('Markdown README campaign scope resolves Elastic-shaped Reference URL', () => {
  const md = `## Taking SHELLTER

Reference: https://www.elastic.co/security-labs/taking-shellter
`;
  const doc = markdownToCanonicalDocument(md, { title: 'README.md' });
  const scope = selectCampaignScope(doc, {
    reportUrl: 'https://elastic.co/security-labs/taking-shellter',
    reportTitle: 'Taking SHELLTER: a commercial evasion framework'
  });
  assert.equal(scope.status, 'single_campaign');
});

test('Elastic README Reference slug matches report URL under /threat-command/', () => {
  const md = `## Shelby malware

Reference: https://www.elastic.co/security-labs/the-shelby-strategy
`;
  const doc = markdownToCanonicalDocument(md, { title: 'README.md' });
  const scope = selectCampaignScope(doc, {
    reportUrl: 'https://www.elastic.co/security-labs/threat-command/the-shelby-strategy',
    reportTitle: 'The Shelby Strategy'
  });
  assert.equal(scope.status, 'single_campaign');
});

test('Elastic-shaped markdown README without tables yields zero IOC candidates', async () => {
  const body = `## Taking SHELLTER

Reference: https://www.elastic.co/security-labs/taking-shellter

evil.example should not become an indicator from prose.
`;
  const parsed = await parseIocSourceContent({
    body,
    path: 'indicators/shellter/README.md',
    url: 'https://raw.githubusercontent.com/elastic/labs-releases/main/indicators/shellter/README.md',
    reportScope: {
      reportUrl: 'https://www.elastic.co/security-labs/taking-shellter',
      reportTitle: 'Taking SHELLTER'
    }
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.unique_count, 0);
  assert.equal(parsed.scope?.status, 'single_campaign');
});

test('EVIDENCE_MEMBERSHIP constants stable', () => {
  assert.equal(EVIDENCE_MEMBERSHIP.INDICATOR, 'indicator');
  assert.equal(EVIDENCE_MEMBERSHIP.CONTEXT_ONLY, 'context_only');
});
