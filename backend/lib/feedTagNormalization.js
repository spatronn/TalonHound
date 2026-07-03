/**
 * Parse feed evidence notes and normalize tags/classifications for IOC detail display.
 * Pure functions — no DB access. Called at API response time.
 */

// Feed tag → classification slug
const TAG_TO_CLASSIFICATION = new Map([
  ['malware_download', 'malware_download'],
  ['malware-download', 'malware_download'],
  ['malware_delivery', 'malware_download'],
  ['phishing', 'phishing'],
  ['botnet', 'botnet'],
  ['c2', 'command_and_control'],
  ['cc', 'command_and_control'],
  ['cnc', 'command_and_control'],
  ['command_and_control', 'command_and_control'],
  ['spam', 'spam'],
  ['ransomware', 'ransomware'],
  ['exploit', 'exploit'],
  ['trojan', 'trojan'],
  ['rat', 'remote_access_trojan'],
  ['remote_access_trojan', 'remote_access_trojan'],
  ['stealer', 'stealer'],
  ['infostealer', 'stealer'],
  ['dropper', 'dropper'],
  ['loader', 'loader'],
  ['cryptominer', 'cryptominer'],
  ['miner', 'cryptominer'],
]);

// IOC category field → classification slug
const CATEGORY_TO_CLASSIFICATION = new Map([
  ['malware', 'malware'],
  ['botnet_cc', 'command_and_control'],
  ['botnet_cc_url', 'command_and_control'],
  ['phishing', 'phishing'],
  ['ransomware', 'ransomware'],
  ['spam', 'spam'],
]);

function slugToLabel(slug) {
  return slug.split('_').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
}

/**
 * Parse a pipe-delimited key=value note string (URLHaus/ThreatFox/MalwareBazaar/OTX format).
 * Returns a plain object with the parsed fields. The leading description segment (no `=`) is skipped.
 */
export function parseNoteFields(note) {
  if (!note || typeof note !== 'string') return {};
  const result = {};
  for (const part of note.split(' | ')) {
    const eqIdx = part.indexOf('=');
    if (eqIdx <= 0) continue;
    const key = part.slice(0, eqIdx).trim();
    const val = part.slice(eqIdx + 1).trim();
    if (key) result[key] = val;
  }
  return result;
}

/**
 * Given a source name, raw tag list, and optional category, produce normalized
 * classification and tag arrays for display in IOC Detail Overview.
 *
 * Classifications: items matching TAG_TO_CLASSIFICATION or CATEGORY_TO_CLASSIFICATION.
 * Tags: everything else (technical tags, family names, unknown tags).
 */
export function normalizeFeedTags({ sourceName, rawTags = [], category = null }) {
  const classifications = [];
  const tags = [];
  const seenSlugs = new Set();
  const seenNorm = new Set();

  if (category) {
    const catSlug = CATEGORY_TO_CLASSIFICATION.get(category.toLowerCase());
    if (catSlug && !seenSlugs.has(catSlug)) {
      classifications.push({ value: catSlug, label: slugToLabel(catSlug), active: true, origin: 'feed', source_name: sourceName });
      seenSlugs.add(catSlug);
    }
  }

  for (const rawTag of rawTags) {
    const trimmed = String(rawTag || '').trim();
    if (!trimmed) continue;
    const normalized = trimmed.toLowerCase();

    const classSlug = TAG_TO_CLASSIFICATION.get(normalized);
    if (classSlug) {
      if (!seenSlugs.has(classSlug)) {
        classifications.push({ value: classSlug, label: slugToLabel(classSlug), active: true, origin: 'feed', source_name: sourceName });
        seenSlugs.add(classSlug);
      }
      continue;
    }

    if (!seenNorm.has(normalized)) {
      tags.push({ tag: trimmed, normalized, origin: 'feed', source_name: sourceName });
      seenNorm.add(normalized);
    }
  }

  return { classifications, tags };
}

const KNOWN_METADATA_FIELDS = [
  'external_id', 'reference_url', 'url_status', 'reporter', 'date_added', 'last_online',
  'ioc_id', 'threat_type', 'malware', 'malware_alias', 'confidence', 'reference',
  'first_seen', 'last_seen', 'file_name', 'file_type', 'signature', 'vtpercent',
  'pulse_id', 'pulse_name', 'adversary', 'tlp', 'pulse_author', 'indicator_id'
];

/**
 * Build the feed_intelligence payload from evidence rows returned by fetchFeedSourceEvidenceForItems.
 * Deduplicates classifications and tags across all sources.
 *
 * Returns:
 *   classifications — feed-derived classification entries (shape: { value, label, active, origin, source_name })
 *   tags            — feed-derived context tags ({ tag, normalized, origin, source_name })
 *   source_metadata — structured metadata per source for Source Evidence display
 */
export function buildFeedIntelligence(evidenceRows = []) {
  const allClassifications = [];
  const allTags = [];
  const sourceMetadata = [];
  const seenSlugs = new Set();
  const seenNorm = new Set();

  for (const row of (evidenceRows || [])) {
    const noteFields = parseNoteFields(row.note);
    const rawTagsStr = noteFields.tags || '';
    const rawTags = rawTagsStr ? rawTagsStr.split(',').map((t) => t.trim()).filter(Boolean) : [];

    const { classifications, tags } = normalizeFeedTags({
      sourceName: row.source_name,
      rawTags,
      category: row.category
    });

    for (const c of classifications) {
      if (!seenSlugs.has(c.value)) {
        allClassifications.push(c);
        seenSlugs.add(c.value);
      }
    }

    for (const t of tags) {
      if (!seenNorm.has(t.normalized)) {
        allTags.push(t);
        seenNorm.add(t.normalized);
      }
    }

    const meta = {};
    for (const f of KNOWN_METADATA_FIELDS) {
      if (noteFields[f]) meta[f] = noteFields[f];
    }

    if (rawTags.length > 0 || Object.keys(meta).length > 0) {
      sourceMetadata.push({
        source_name: row.source_name,
        feed_key: row.feed_key || null,
        raw_tags: rawTags,
        ...meta
      });
    }
  }

  return { classifications: allClassifications, tags: allTags, source_metadata: sourceMetadata };
}
