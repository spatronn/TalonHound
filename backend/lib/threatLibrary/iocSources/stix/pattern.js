/**
 * Conservative STIX 2.x pattern parser for IOC Source ingestion.
 * No eval. Unsupported / ambiguous compound expressions return typed diagnostics.
 */

/** @typedef {{ ok: true, observables: Array<{ type: string, value: string, property: string }>, compound: 'single'|'or_same_object'|'and_same_hashes', dropped_properties: string[] } | { ok: false, code: string, message: string }} PatternResult */

const HASH_PROP = {
  md5: 'md5',
  'sha-1': 'sha1',
  sha1: 'sha1',
  'sha-256': 'sha256',
  sha256: 'sha256'
};

/**
 * Unescape a STIX pattern string literal (\' \\).
 * @param {string} value
 */
export function unescapeStixString(value) {
  let out = '';
  const s = String(value || '');
  for (let i = 0; i < s.length; i += 1) {
    if (s[i] === '\\' && i + 1 < s.length) {
      out += s[i + 1];
      i += 1;
    } else {
      out += s[i];
    }
  }
  return out;
}

/**
 * Normalize Elastic/CISA bracket quirks: missing opening `[`, trailing noise.
 * @param {string} pattern
 */
export function normalizePatternBrackets(pattern) {
  let p = String(pattern || '').trim();
  if (!p) return p;
  // Elastic labs-releases sometimes emits `file:hashes...'...']` without `[`.
  if (!p.startsWith('[') && p.endsWith(']')) p = `[${p}`;
  if (p.startsWith('[') && !p.endsWith(']')) p = `${p}]`;
  return p;
}

/**
 * Map a STIX comparison LHS to TalonHound observable type.
 * @param {string} objectType
 * @param {string} property
 * @returns {string|null}
 */
export function mapStixPropertyToType(objectType, property) {
  const ot = String(objectType || '').toLowerCase();
  const prop = String(property || '').toLowerCase().replace(/^hashes\./, '').replace(/'/g, '');
  if (ot === 'ipv4-addr' || ot === 'ipv4_addr') return 'ip';
  if (ot === 'ipv6-addr' || ot === 'ipv6_addr') return 'ipv6';
  if (ot === 'domain-name' || ot === 'domain_name') return 'domain';
  if (ot === 'url') return 'url';
  if (ot === 'email-addr' || ot === 'email_addr') return 'email';
  if (ot === 'file') {
    const hashType = HASH_PROP[prop];
    return hashType || null;
  }
  return null;
}

const COMPARISON_RE =
  /([a-z0-9_-]+):((?:hashes\.(?:'[A-Za-z0-9_-]+'|[A-Za-z0-9_-]+)|[a-z0-9_.-]+))\s*(?:=|ISSUBSET|IN)\s*'((?:\\'|\\\\|[^'\\])*)'/gi;

/**
 * Extract comparison clauses from a pattern body (inside outer brackets).
 * @param {string} body
 */
function extractComparisons(body) {
  const out = [];
  COMPARISON_RE.lastIndex = 0;
  let m;
  while ((m = COMPARISON_RE.exec(body)) !== null) {
    const objectType = m[1];
    const property = m[2];
    const value = unescapeStixString(m[3]);
    const type = mapStixPropertyToType(objectType, property);
    out.push({
      objectType: objectType.toLowerCase(),
      property,
      value,
      type,
      raw: m[0]
    });
  }
  return out;
}

/**
 * Detect whether remaining operators are only OR (safe multi-hash) or include AND/FOLLOWEDBY.
 * @param {string} body
 * @param {number} comparisonCount
 */
function classifyCompound(body, comparisonCount) {
  if (comparisonCount <= 1) return 'single';
  const ops = String(body || '')
    .replace(COMPARISON_RE, ' # ')
    .replace(/[()[\]]/g, ' ')
    .toUpperCase()
    .split(/\s+/)
    .filter((t) => t === 'AND' || t === 'OR' || t === 'FOLLOWEDBY');
  const hasAnd = ops.includes('AND') || ops.includes('FOLLOWEDBY');
  const hasOr = ops.includes('OR');
  if (hasAnd && hasOr) return 'mixed';
  if (hasAnd) return 'and';
  if (hasOr) return 'or';
  return comparisonCount > 1 ? 'unknown' : 'single';
}

/** File attributes that only narrow which file the digests describe. */
const FILE_ATTRIBUTE_PROP_RE = /^(?:name|size|mime_type)$/i;

/**
 * The file digests are one parenthesised OR group (or a single digest), joined
 * to the file's attributes by AND only: `(h1 OR h2) AND file:name = 'x'`.
 * @param {string} body
 */
function sameFileHashAlternatives(body) {
  const masked = String(body || '').replace(COMPARISON_RE, (m) => (/:hashes\./i.test(m) ? ' H ' : ' A '));
  const groups = masked.match(/\(([^()]*)\)/g) || [];
  for (const g of groups) {
    if (/\bA\b/.test(g) || /\bAND\b/i.test(g)) return false;
  }
  const outer = masked.replace(/\([^()]*\)/g, ' G ').toUpperCase();
  if (/[()]/.test(outer) || /\bOR\b/.test(outer)) return false;
  const hashTerms = (outer.match(/\b[HG]\b/g) || []).length;
  return hashTerms === 1;
}

/**
 * Parse a STIX Indicator pattern into observables when semantics are preserved.
 * OR of hash alternatives for the same file → multiple hash observables (OK).
 * AND across different object types / non-hash properties → unsupported.
 *
 * @param {string} pattern
 * @returns {PatternResult}
 */
export function parseStixPattern(pattern) {
  const raw = String(pattern || '').trim();
  if (!raw) {
    return { ok: false, code: 'unsupported_pattern', message: 'Empty STIX pattern' };
  }

  const normalized = normalizePatternBrackets(raw);
  if (!normalized.startsWith('[') || !normalized.endsWith(']')) {
    return { ok: false, code: 'unsupported_pattern', message: 'Pattern is not a bracketed STIX comparison' };
  }

  const body = normalized.slice(1, -1).trim();
  // Reject MATCHES / LIKE / EXISTS / ISSUBSET-of-object-path complexity beyond value ISSUBSET.
  if (/\b(?:MATCHES|LIKE|EXISTS|FOLLOWEDBY)\b/i.test(body)) {
    return { ok: false, code: 'unsupported_pattern', message: 'Pattern uses MATCHES/LIKE/EXISTS/FOLLOWEDBY' };
  }

  const comparisons = extractComparisons(body);
  if (!comparisons.length) {
    return { ok: false, code: 'unsupported_pattern', message: 'No supported comparison expressions in pattern' };
  }

  // Reject if leftover alphanumeric tokens look like unparsed pattern syntax
  // (e.g. nested object paths we did not match).
  const residual = body
    .replace(COMPARISON_RE, ' ')
    .replace(/\b(?:AND|OR)\b/gi, ' ')
    .replace(/[()]/g, ' ')
    .trim();
  if (/[a-z0-9_:]/i.test(residual)) {
    return { ok: false, code: 'unsupported_pattern', message: `Unsupported pattern residue: ${residual.slice(0, 80)}` };
  }

  // One file described by several digests (`SHA-1 OR SHA-256 OR MD5 OR
  // SSDEEP`): an algorithm TalonHound does not index (SSDEEP, TLSH, SHA-512)
  // is an attribute of that file, not a reason to drop its supported hashes.
  const fileHashCompound = comparisons.length > 1
    && comparisons.every((c) => c.objectType === 'file' && /^hashes\./i.test(c.property));
  // One file whose digests are alternatives, narrowed by that file's own
  // attributes (CISA: `[(file:hashes.'SHA-1' = … OR file:hashes.MD5 = …) AND
  // file:name = 'x.exe']`): the name / size only narrow the same object, so the
  // supported digests are the file's Indicators and the attributes are dropped.
  const fileAttributes = comparisons.filter((c) => c.objectType === 'file' && FILE_ATTRIBUTE_PROP_RE.test(c.property));
  const fileHashes = comparisons.filter((c) => c.objectType === 'file' && /^hashes\./i.test(c.property) && c.type && c.value);
  if (
    fileAttributes.length && fileHashes.length &&
    fileAttributes.length + fileHashes.length === comparisons.length &&
    sameFileHashAlternatives(body)
  ) {
    return {
      ok: true,
      observables: fileHashes.map((c) => ({ type: c.type, value: c.value, property: `${c.objectType}:${c.property}` })),
      compound: fileHashes.length > 1 ? 'or_same_object' : 'single',
      dropped_properties: fileAttributes.map((c) => `${c.objectType}:${c.property}`)
    };
  }
  const droppedProperties = [];
  const usable = fileHashCompound
    ? comparisons.filter((c) => {
        if (c.type && c.value) return true;
        droppedProperties.push(`${c.objectType}:${c.property}`);
        return false;
      })
    : comparisons;
  if (!usable.length) {
    return { ok: false, code: 'unsupported_pattern', message: 'No supported file hash algorithm in pattern' };
  }

  const mapped = [];
  for (const c of usable) {
    if (!c.type || !c.value) {
      return {
        ok: false,
        code: 'unsupported_pattern',
        message: `Unsupported observable property ${c.objectType}:${c.property}`
      };
    }
    mapped.push({ type: c.type, value: c.value, property: `${c.objectType}:${c.property}` });
  }

  const compound = classifyCompound(body, mapped.length);
  if (compound === 'mixed' || compound === 'unknown') {
    return { ok: false, code: 'unsupported_pattern', message: 'Compound pattern mixes operators in an unsupported way' };
  }

  if (compound === 'and') {
    // Same-file multi-hash AND (MD5 AND SHA-256) → emit all hashes.
    const allFileHashes = mapped.every((o) => ['md5', 'sha1', 'sha256'].includes(o.type));
    const sameFile = mapped.every((o) => o.property.startsWith('file:'));
    if (allFileHashes && sameFile) {
      return { ok: true, observables: mapped, compound: 'and_same_hashes', dropped_properties: droppedProperties };
    }
    return {
      ok: false,
      code: 'unsupported_pattern',
      message: 'AND across distinct observables cannot be flattened into independent Indicators'
    };
  }

  if (compound === 'or') {
    // OR of hashes for one file, or OR of same-type values — emit each as alternate identity.
    const types = new Set(mapped.map((o) => o.type));
    const allHashes = mapped.every((o) => ['md5', 'sha1', 'sha256'].includes(o.type));
    const sameType = types.size === 1;
    if (allHashes || sameType) {
      return { ok: true, observables: mapped, compound: 'or_same_object', dropped_properties: droppedProperties };
    }
    return {
      ok: false,
      code: 'unsupported_pattern',
      message: 'OR across distinct observable types cannot be flattened into independent Indicators'
    };
  }

  return { ok: true, observables: mapped, compound: 'single', dropped_properties: droppedProperties };
}
