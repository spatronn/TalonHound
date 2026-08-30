import { describe, it, expect } from 'vitest';
import { parseNoteFields, normalizeFeedTags, buildFeedIntelligence } from './feedTagNormalization.js';

describe('parseNoteFields', () => {
  it('parses pipe-delimited key=value note', () => {
    const note = 'Auto-imported from URLHaus CSV | external_id=3880277 | url_status=online | tags=elf,mips';
    const fields = parseNoteFields(note);
    expect(fields.external_id).toBe('3880277');
    expect(fields.url_status).toBe('online');
    expect(fields.tags).toBe('elf,mips');
  });

  it('returns empty object for empty/null note', () => {
    expect(parseNoteFields('')).toEqual({});
    expect(parseNoteFields(null)).toEqual({});
  });

  it('skips segments without =', () => {
    const note = 'Header segment | key=value';
    const fields = parseNoteFields(note);
    expect(Object.keys(fields)).toEqual(['key']);
    expect(fields.key).toBe('value');
  });

  it('handles value containing = sign', () => {
    const note = 'reference=https://example.com/url?foo=bar';
    const fields = parseNoteFields(note);
    expect(fields.reference).toBe('https://example.com/url?foo=bar');
  });
});

describe('normalizeFeedTags', () => {
  const src = 'URLHaus:abuse.ch';

  it('maps malware_download tag to dropper_downloader classification', () => {
    const { classifications, tags } = normalizeFeedTags({ sourceName: src, rawTags: ['malware_download'] });
    expect(classifications).toHaveLength(1);
    expect(classifications[0].value).toBe('dropper_downloader');
    expect(classifications[0].origin).toBe('feed');
    expect(tags).toHaveLength(0);
  });

  it('maps c2 tag to command_and_control classification', () => {
    const { classifications } = normalizeFeedTags({ sourceName: src, rawTags: ['c2'] });
    expect(classifications[0].value).toBe('command_and_control');
  });

  it('keeps technical tags in tags array', () => {
    const { classifications, tags } = normalizeFeedTags({ sourceName: src, rawTags: ['elf', 'mips', '32-bit'] });
    expect(classifications).toHaveLength(0);
    expect(tags.map((t) => t.tag)).toEqual(['elf', 'mips', '32-bit']);
    expect(tags[0].origin).toBe('feed');
    expect(tags[0].source_name).toBe(src);
  });

  it('keeps malware family names in tags array (not threat actor)', () => {
    const { tags } = normalizeFeedTags({ sourceName: src, rawTags: ['Mozi'] });
    expect(tags[0].tag).toBe('Mozi');
    expect(tags[0].normalized).toBe('mozi');
  });

  it('deduplicates tags case-insensitively', () => {
    const { tags } = normalizeFeedTags({ sourceName: src, rawTags: ['ELF', 'elf', 'Elf'] });
    expect(tags).toHaveLength(1);
  });

  it('maps category to classification', () => {
    const { classifications } = normalizeFeedTags({ sourceName: src, rawTags: [], category: 'botnet_cc' });
    expect(classifications[0].value).toBe('command_and_control');
  });

  it('does not duplicate classification from both category and tag', () => {
    const { classifications } = normalizeFeedTags({ sourceName: src, rawTags: ['botnet'], category: 'botnet' });
    const vals = classifications.map((c) => c.value);
    const unique = [...new Set(vals)];
    expect(vals).toEqual(unique);
  });

  it('handles empty rawTags', () => {
    const { classifications, tags } = normalizeFeedTags({ sourceName: src, rawTags: [] });
    expect(classifications).toHaveLength(0);
    expect(tags).toHaveLength(0);
  });

  it('maps signature=Mirai to botnet classification', () => {
    const { classifications, tags } = normalizeFeedTags({ sourceName: 'MalwareBazaar:abuse.ch', rawTags: [], signature: 'Mirai' });
    expect(classifications).toHaveLength(1);
    expect(classifications[0].value).toBe('botnet');
    expect(classifications[0].origin).toBe('feed');
    expect(tags).toHaveLength(0);
  });

  it('maps signature=Gafgyt to botnet classification', () => {
    const { classifications } = normalizeFeedTags({ sourceName: 'MalwareBazaar:abuse.ch', rawTags: [], signature: 'Gafgyt' });
    expect(classifications[0].value).toBe('botnet');
  });

  it('maps signature=WannaCry to ransomware classification', () => {
    const { classifications } = normalizeFeedTags({ sourceName: 'MalwareBazaar:abuse.ch', rawTags: [], signature: 'WannaCry' });
    expect(classifications).toHaveLength(1);
    expect(classifications[0].value).toBe('ransomware');
  });

  it('unknown signature adds no extra classification', () => {
    const { classifications, tags } = normalizeFeedTags({ sourceName: src, rawTags: [], signature: 'UnknownFamily42' });
    expect(classifications).toHaveLength(0);
    expect(tags).toHaveLength(0);
  });

  it('signature does not duplicate an already-present classification', () => {
    // category=botnet_cc already produces command_and_control; Mirai signature adds botnet (different slug)
    const { classifications } = normalizeFeedTags({ sourceName: src, rawTags: [], category: 'botnet_cc', signature: 'Mirai' });
    const slugs = classifications.map((c) => c.value);
    expect(slugs).toContain('command_and_control');
    expect(slugs).toContain('botnet');
    expect(new Set(slugs).size).toBe(slugs.length);
  });

  it('tag Mozi stays in tags array (signature param drives classification, not raw tags)', () => {
    const { classifications, tags } = normalizeFeedTags({ sourceName: src, rawTags: ['Mozi'] });
    expect(classifications).toHaveLength(0);
    expect(tags[0].tag).toBe('Mozi');
    expect(tags[0].normalized).toBe('mozi');
  });
});

describe('buildFeedIntelligence', () => {
  it('returns empty arrays for no evidence rows', () => {
    const fi = buildFeedIntelligence([]);
    expect(fi.classifications).toHaveLength(0);
    expect(fi.tags).toHaveLength(0);
    expect(fi.source_metadata).toHaveLength(0);
  });

  it('parses URLHaus note into feed intelligence', () => {
    const evidenceRows = [{
      source_name: 'URLHaus:abuse.ch',
      feed_key: 'urlhaus-abusech',
      category: 'malware',
      note: 'Auto-imported from URLHaus CSV | external_id=3880277 | reference_url=https://urlhaus.abuse.ch/url/3880277/ | url_status=online | reporter=geenensp | tags=32-bit,elf,mips,Mozi,malware_download | last_online=2024-01-01T00:00:00.000Z | date_added=2024-01-01T00:00:00.000Z'
    }];
    const fi = buildFeedIntelligence(evidenceRows);

    // malware from category, dropper_downloader from tag
    const classValues = fi.classifications.map((c) => c.value);
    expect(classValues).toContain('malware');
    expect(classValues).toContain('dropper_downloader');

    // tags: 32-bit, elf, mips, Mozi (not malware_download which became a classification)
    const tagNames = fi.tags.map((t) => t.normalized);
    expect(tagNames).toContain('elf');
    expect(tagNames).toContain('mips');
    expect(tagNames).toContain('32-bit');
    expect(tagNames).toContain('mozi');
    expect(tagNames).not.toContain('malware_download');

    // structured metadata
    expect(fi.source_metadata[0].external_id).toBe('3880277');
    expect(fi.source_metadata[0].url_status).toBe('online');
    expect(fi.source_metadata[0].reporter).toBe('geenensp');
  });

  it('parses MalwareBazaar Mirai note into botnet + malware classifications', () => {
    const evidenceRows = [{
      source_name: 'MalwareBazaar:abuse.ch',
      feed_key: 'malwarebazaar-abusech',
      category: 'Mirai',
      note: 'Auto-imported from MalwareBazaar CSV | external_id=abc123 | reporter=abuse_ch | signature=Mirai | tags=Mirai,elf | date_added=2026-07-04T12:00:00.000Z'
    }];
    const fi = buildFeedIntelligence(evidenceRows);
    const classValues = fi.classifications.map((c) => c.value);
    expect(classValues).toContain('botnet');
    // Mirai tag stays as a tag (not mapped to classification from raw tags)
    const tagNorms = fi.tags.map((t) => t.normalized);
    expect(tagNorms).toContain('mirai');
    expect(tagNorms).toContain('elf');
  });

  it('keeps same tag from different sources as separate source-scoped entries', () => {
    const evidenceRows = [
      { source_name: 'URLHaus', feed_key: 'urlhaus', category: null, note: 'Auto | tags=elf,c2' },
      { source_name: 'ThreatFox', feed_key: 'threatfox', category: null, note: 'Auto | tags=elf,phishing' }
    ];
    const fi = buildFeedIntelligence(evidenceRows);

    const elfTags = fi.tags.filter((t) => t.normalized === 'elf');
    expect(elfTags).toHaveLength(2);
    expect(elfTags.map((t) => t.source_name).sort()).toEqual(['ThreatFox', 'URLHaus']);

    const classSlugs = fi.classifications.map((c) => c.value);
    expect(classSlugs.filter((v) => v === 'command_and_control')).toHaveLength(1);
    expect(classSlugs.filter((v) => v === 'phishing')).toHaveLength(1);
  });

  it('parses ThreatFox note tags into feed intelligence', () => {
    const evidenceRows = [{
      source_name: 'ThreatFox:abuse.ch',
      feed_key: 'threatfox-abusech',
      category: 'botnet_cc',
      note: 'Auto-imported from ThreatFox API | ioc_id=123 | threat_type=botnet_cc | malware=Mirai | confidence=high | tags=mirai,c2,elf'
    }];
    const fi = buildFeedIntelligence(evidenceRows);
    const classSlugs = fi.classifications.map((c) => c.value);
    // category=botnet_cc → command_and_control; tag c2 → command_and_control (deduped)
    expect(classSlugs).toContain('command_and_control');
    // technical tags not mapped to classifications stay as tags
    const tagNorms = fi.tags.map((t) => t.normalized);
    expect(tagNorms).toContain('mirai');
    expect(tagNorms).toContain('elf');
    // metadata fields
    expect(fi.source_metadata[0].threat_type).toBe('botnet_cc');
    expect(fi.source_metadata[0].malware).toBe('Mirai');
  });

  it('parses PhishTank evidence — category phishing produces phishing classification', () => {
    const evidenceRows = [{
      source_name: 'PhishTank:opendns',
      feed_key: 'phishtank-opendnsrr',
      category: 'phishing',
      note: 'Auto-imported from PhishTank online-valid.csv'
    }];
    const fi = buildFeedIntelligence(evidenceRows);
    const classSlugs = fi.classifications.map((c) => c.value);
    expect(classSlugs).toContain('phishing');
    expect(fi.tags).toHaveLength(0);
  });

  it('parses OTX note with pulse tags into classifications and tags', () => {
    const evidenceRows = [{
      source_name: 'AlienVault OTX',
      feed_key: 'alienvault-otx',
      category: 'threat-intel',
      note: 'Auto-imported from AlienVault OTX (subscribed pulses) | pulse_id=abc123 | pulse_name=Malware Campaign | pulse_author=analyst | adversary=APT28 | tlp=white | tags=phishing,windows,office | indicator_id=9999 | pulse_modified=2026-07-01T00:00:00.000Z | reference=https://otx.alienvault.com/pulse/abc123'
    }];
    const fi = buildFeedIntelligence(evidenceRows);
    const classSlugs = fi.classifications.map((c) => c.value);
    expect(classSlugs).toContain('phishing');
    // windows and office are technical tags, not classifications
    const tagNorms = fi.tags.map((t) => t.normalized);
    expect(tagNorms).toContain('windows');
    expect(tagNorms).toContain('office');
    // metadata fields surfaced
    const meta = fi.source_metadata[0];
    expect(meta.pulse_id).toBe('abc123');
    expect(meta.adversary).toBe('APT28');
    expect(meta.pulse_modified).toBe('2026-07-01T00:00:00.000Z');
  });

  it('OTX note with unknown-only tags produces no classifications', () => {
    const evidenceRows = [{
      source_name: 'AlienVault OTX',
      feed_key: 'alienvault-otx',
      category: 'threat-intel',
      note: 'Auto-imported from AlienVault OTX (subscribed pulses) | tags=APT28,russia,geopolitics'
    }];
    const fi = buildFeedIntelligence(evidenceRows);
    expect(fi.classifications).toHaveLength(0);
    const tagNorms = fi.tags.map((t) => t.normalized);
    expect(tagNorms).toContain('apt28');
    expect(tagNorms).toContain('russia');
  });
});
