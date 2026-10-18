/**
 * Semantic reading of hexadecimal digest-shaped values.
 *
 * A 32 / 40 / 64-hex run is only a FILE hash Indicator when the publisher
 * labels (or leaves unlabelled) it as the digest of a file / sample. The same
 * shape is also used for identifiers that do not name a file: ELF GNU
 * build-ids (`BuildID[sha1]=…`), certificate thumbprints / fingerprints,
 * VirusTotal structural hashes (vhash), fuzzy / import hashes, cryptographic
 * keys / IVs / nonces, and digests of trivial well-known inputs
 * (sha256("123456"), md5("")). Treating those as malware samples puts
 * unrelated values into hash feeds.
 *
 * Reading is by the label that governs the value: the text between the
 * previous field separator ("," ";" "|" newline or another observable) and
 * the value. A non-file label noun wins over the digest-algorithm qualifier
 * it carries ("TLS certificate (SHA256 hash):", "APK signing certificate
 * (SHA-1 thumbprint):", "BuildID[sha1]="), unless a file noun follows it
 * ("certificate-signed sample SHA256: …").
 *
 * Deterministic; no vendor / value lists except the well-known trivial
 * digests, which are computed, not hardcoded.
 */

import crypto from 'node:crypto';
import { refangTextForExtraction } from './defang.js';

export const DIGEST_KINDS = Object.freeze({
  FILE: 'file_hash',
  BUILD_ID: 'build_id',
  CERTIFICATE: 'certificate_fingerprint',
  SIMILARITY: 'similarity_hash',
  CRYPTO_KEY: 'cryptographic_key',
  CREDENTIAL: 'credential',
  WELL_KNOWN: 'well_known_digest'
});

/** Non-file digest kinds: never md5 / sha1 / sha256 Indicators. */
export const NON_FILE_DIGEST_KINDS = Object.freeze(
  new Set([
    DIGEST_KINDS.BUILD_ID,
    DIGEST_KINDS.CERTIFICATE,
    DIGEST_KINDS.SIMILARITY,
    DIGEST_KINDS.CRYPTO_KEY,
    DIGEST_KINDS.CREDENTIAL,
    DIGEST_KINDS.WELL_KNOWN
  ])
);

const KIND_PATTERNS = [
  [DIGEST_KINDS.BUILD_ID, /(?:^|[^a-z0-9])(?:gnu[\s_-]*)?build[\s_-]*id(?:\[[^\]]*\])?(?:[^a-z0-9]|$)/i],
  [
    DIGEST_KINDS.CERTIFICATE,
    /(?:^|[^a-z0-9])(?:certificates?|certs?|x\.?509|thumbprints?|signing\s+(?:cert|key|identity)|code[\s-]*signing|ja[34]s?|jarm)(?:[^a-z0-9]|$)/i
  ],
  [
    DIGEST_KINDS.SIMILARITY,
    /(?:^|[^a-z0-9])(?:vhash|imphash|import\s+hash|ssdeep|tlsh|authentihash|pehash|rich\s*(?:header\s*)?hash|telfhash|dhash|icon\s+hash|fuzzy\s+hash)(?:[^a-z0-9]|$)/i
  ],
  [
    DIGEST_KINDS.CRYPTO_KEY,
    /(?:^|[^a-z0-9])(?:(?:aes|rc4|rsa|xor|chacha\d*|salsa\d*|des|3des|blowfish|hmac|encryption|decryption|session|symmetric|secret|private|public|master|shared|cipher|crypto)[\s_-]*(?:key|iv|nonce|secret)s?|keys?[\s_-]*(?:material|stream)|initiali[sz]ation\s+vector|iv|nonce|salt)(?:[^a-z0-9]|$)/i
  ],
  [
    DIGEST_KINDS.CREDENTIAL,
    /(?:^|[^a-z0-9])(?:auth(?:entication)?[\s_-]*token|access[\s_-]*token|refresh[\s_-]*token|api[\s_-]*key|bearer(?:\s+token)?|password|passwd|passphrase|credentials?|bot[\s_-]*token|token)(?:[^a-z0-9]|$)/i
  ]
];

/** File / sample nouns: a label that names the file keeps the hash reading. */
const FILE_NOUN_RE =
  /(?:^|[^a-z0-9])(?:files?|samples?|binar(?:y|ies)|executables?|payloads?|dlls?|exes?|loaders?|droppers?|implants?|scripts?|archives?|installers?|documents?|attachments?|malware|artifacts?|apks?|elfs?|modules?|components?|variants?|stagers?|backdoors?|trojans?|filename|file\s*name)(?:[^a-z0-9]|$)/i;

/** Field separators that end the label window before a value. */
const SEPARATOR_RE = /[,;|\n\r¶]|\s[-–—]\s/g;
const OTHER_DIGEST_RE = /\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi;

/** Trivial inputs whose digests identify no sample (computed once). */
const TRIVIAL_INPUTS = Object.freeze([
  '', '0', '1', '123', '1234', '12345', '123456', '1234567', '12345678', '123456789',
  'password', 'Password', 'admin', 'test', 'hello', 'hello world', 'Hello World', 'abc',
  'qwerty', 'secret', 'root', 'user', 'guest', 'changeme', 'letmein', 'default'
]);
const WELL_KNOWN_DIGESTS = (() => {
  const out = new Map();
  for (const input of TRIVIAL_INPUTS) {
    for (const alg of ['md5', 'sha1', 'sha256']) {
      const hex = crypto.createHash(alg).update(input, 'utf8').digest('hex');
      out.set(hex, { algorithm: alg, input });
    }
  }
  return out;
})();

/**
 * Digest of a trivial well-known input ("", "123456", "password", …).
 * @param {string} value hex
 * @returns {{ algorithm: string, input: string }|null}
 */
export function wellKnownDigest(value) {
  return WELL_KNOWN_DIGESTS.get(String(value || '').trim().toLowerCase()) || null;
}

/**
 * The label window that governs `value` inside `text`: the text after the
 * last separator / other digest before the value. For a table row whose value
 * cell is first after a separator ("SHA-256 hash | <v> | …"), the previous
 * cell is the label.
 * @param {string} text
 * @param {string} value
 */
export function digestLabelWindow(text, value) {
  const hay = refangTextForExtraction(String(text || ''));
  const v = String(value || '').trim().toLowerCase();
  if (!hay || !v) return '';
  const idx = hay.toLowerCase().indexOf(v);
  if (idx < 0) return '';
  let before = hay.slice(0, idx);
  // Another digest earlier on the line belongs to its own label.
  let cut = 0;
  for (const m of before.matchAll(OTHER_DIGEST_RE)) cut = m.index + m[0].length;
  before = before.slice(cut);
  const seps = [...before.matchAll(SEPARATOR_RE)];
  if (!seps.length) return before.slice(-120);
  const last = seps[seps.length - 1];
  const tail = before.slice(last.index + last[0].length);
  if (tail.trim()) return tail.slice(-120);
  // "<label> | <value>": the previous cell is the label.
  const prev = seps.length >= 2 ? seps[seps.length - 2] : null;
  return before.slice(prev ? prev.index + prev[0].length : 0, last.index).slice(-120);
}

/**
 * Semantic kind of a digest-shaped value from its governing label.
 * @param {string} text line / row / surrounding window that contains the value
 * @param {string} value hex value
 * @returns {{ kind: string, label: string, reason: string }}
 */
export function classifyHexDigest(text, value) {
  const known = wellKnownDigest(value);
  if (known) {
    return { kind: DIGEST_KINDS.WELL_KNOWN, label: '', reason: `digest_of_trivial_input_${known.algorithm}` };
  }
  const label = digestLabelWindow(text, value);
  if (!label.trim()) return { kind: DIGEST_KINDS.FILE, label, reason: 'unlabelled' };
  let best = null;
  for (const [kind, re] of KIND_PATTERNS) {
    const all = [...label.matchAll(new RegExp(re.source, 'gi'))];
    if (!all.length) continue;
    const at = all[all.length - 1].index;
    if (!best || at > best.at) best = { kind, at };
  }
  if (!best) return { kind: DIGEST_KINDS.FILE, label, reason: 'file_label' };
  // A file noun after the non-file noun names the file ("certificate-signed sample SHA256:").
  if (FILE_NOUN_RE.test(label.slice(best.at + 1))) return { kind: DIGEST_KINDS.FILE, label, reason: 'file_noun_after_label' };
  return { kind: best.kind, label, reason: `${best.kind}_label` };
}

/**
 * True when the value must not be typed as a file-hash Indicator.
 * @param {string} text
 * @param {string} value
 */
export function isNonFileDigest(text, value) {
  return NON_FILE_DIGEST_KINDS.has(classifyHexDigest(text, value).kind);
}
