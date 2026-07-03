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

  it('maps malware_download tag to classification', () => {
    const { classifications, tags } = normalizeFeedTags({ sourceName: src, rawTags: ['malware_download'] });
    expect(classifications).toHaveLength(1);
    expect(classifications[0].value).toBe('malware_download');
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

    // malware from category, malware_download from tag
    const classValues = fi.classifications.map((c) => c.value);
    expect(classValues).toContain('malware');
    expect(classValues).toContain('malware_download');

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

  it('deduplicates tags and classifications across multiple evidence rows', () => {
    const evidenceRows = [
      { source_name: 'URLHaus', feed_key: 'urlhaus', category: null, note: 'Auto | tags=elf,c2' },
      { source_name: 'ThreatFox', feed_key: 'threatfox', category: null, note: 'Auto | tags=elf,phishing' }
    ];
    const fi = buildFeedIntelligence(evidenceRows);

    const tagNorms = fi.tags.map((t) => t.normalized);
    expect(tagNorms.filter((n) => n === 'elf')).toHaveLength(1);

    const classSlugs = fi.classifications.map((c) => c.value);
    expect(classSlugs.filter((v) => v === 'command_and_control')).toHaveLength(1);
    expect(classSlugs.filter((v) => v === 'phishing')).toHaveLength(1);
  });
});
