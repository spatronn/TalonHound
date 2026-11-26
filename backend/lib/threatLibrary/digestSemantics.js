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
  WELL_KNOWN: 'well_known_digest',
  // Account / tunnel / tenant / device identifiers that merely share the hex
  // shape ("Cloudflare tunnel account tag", "bot ID") — tl-digest-v3.
  IDENTIFIER: 'account_identifier',
  // Content-addressed object names: a Git commit / blob / tree id or an OCI
  // container image index / manifest digest. They name a repository or
  // registry object, not a file sample a hash feed can match (tl-digest-v6).
  OBJECT_ID: 'object_identifier'
});

/** Non-file digest kinds: never md5 / sha1 / sha256 Indicators. */
export const NON_FILE_DIGEST_KINDS = Object.freeze(
  new Set([
    DIGEST_KINDS.BUILD_ID,
    DIGEST_KINDS.CERTIFICATE,
    DIGEST_KINDS.SIMILARITY,
    DIGEST_KINDS.CRYPTO_KEY,
    DIGEST_KINDS.CREDENTIAL,
    DIGEST_KINDS.WELL_KNOWN,
    DIGEST_KINDS.IDENTIFIER,
    DIGEST_KINDS.OBJECT_ID
  ])
);

const KIND_PATTERNS = [
  [DIGEST_KINDS.BUILD_ID, /(?:^|[^a-z0-9])(?:gnu[\s_-]*)?build[\s_-]*id(?:\[[^\]]*\])?(?:[^a-z0-9]|$)/i],
  [
    DIGEST_KINDS.CERTIFICATE,
    // An Apple code-directory hash ("CDHash") digests the code signature's
    // directory, never the file: a code-signing identity (tl-digest-v10).
    /(?:^|[^a-z0-9])(?:certificates?|certs?|x\.?509|thumbprints?|signing\s+(?:cert|key|identity)|code[\s-]*signing|cdhash(?:es)?|code[\s-]*directory(?:\s+hash(?:es)?)?|ja[34]s?|jarm|spki|subject\s+public\s+key\s+info|serial(?:\s*(?:number|no\.?|#))?)(?:[^a-z0-9]|$)/i
  ],
  [
    DIGEST_KINDS.SIMILARITY,
    /(?:^|[^a-z0-9])(?:vhash|imphash|import\s+hash|ssdeep|tlsh|authentihash|pehash|rich\s*(?:header\s*)?hash|telfhash|dhash|icon\s+hash|fuzzy\s+hash|(?:host[\s_-]*)?banner(?:[\s_-]*\d+)?[\s_-]*hash(?:es)?|favicon[\s_-]*hash|http[\s_-]*(?:header|title|body)[\s_-]*hash)(?:[^a-z0-9]|$)/i
  ],
  [
    DIGEST_KINDS.CRYPTO_KEY,
    // A key size / block mode may sit between the cipher and the key noun
    // ("AES-256-GCM key", "AES 128 CBC IV", "ChaCha20-Poly1305 key") —
    // tl-digest-v8.
    /(?:^|[^a-z0-9])(?:(?:aes|rc4|rsa|xor|chacha\d*|salsa\d*|des|3des|blowfish|hmac|encryption|decryption|session|symmetric|secret|private|public|master|shared|cipher|crypto)(?:[\s_-]*(?:\d{2,4}(?:[\s_-]*bits?)?|gcm|cbc|ctr|ecb|cfb|ofb|xts|ccm|siv|poly1305))*[\s_-]*(?:key|iv|nonce|secret)s?|(?:public|private|host|server|client|ssh)\s+(?:(?:rsa|dsa|ecdsa|ed25519|ed448|x25519|ssh|sftp|[a-z]{2,10}\d{0,5})\s+){1,2}keys?|ssh[\s_-]+(?:host[\s_-]+)?(?:key[\s_-]+)?fingerprints?|keys?[\s_-]*(?:material|stream)|initiali[sz]ation\s+vector|iv|nonce|salt)(?:[^a-z0-9]|$)/i
  ],
  [
    DIGEST_KINDS.IDENTIFIER,
    /(?:^|[^a-z0-9])(?:(?:account|tenant|tunnel|client|customer|user|device|machine|bot|victim|affiliate|campaign|session|install(?:ation)?|subscription|organi[sz]ation|org)[\s_-]*(?:account[\s_-]*)?(?:tags?|ids?|identifiers?|uuids?|guids?)|account[\s_-]*tags?)(?:[^a-z0-9]|$)/i
  ],
  [
    DIGEST_KINDS.OBJECT_ID,
    /(?:^|[^a-z0-9])(?:(?:git\s+)?commits?(?:\s+(?:hash(?:es)?|ids?|sha-?1?))?|git\s+(?:blob|tree|object)s?|(?:source|git|vcs)\s+revisions?|(?:container\s+|docker\s+|oci\s+)?image\s+(?:index(?:es)?|manifests?|digests?)|(?:container|docker|oci|registry)\s+digests?|(?:index|manifest)\s+digests?)(?:[^a-z0-9]|$)/i
  ],
  [
    DIGEST_KINDS.CREDENTIAL,
    /(?:^|[^a-z0-9])(?:auth(?:entication)?[\s_-]*token|access[\s_-]*token|refresh[\s_-]*token|api[\s_-]*key|bearer(?:\s+token)?|password|passwd|passphrase|credentials?|bot[\s_-]*token|token)(?:[^a-z0-9]|$)/i
  ]
];

/** A label that is only a digest algorithm / generic digest word ("SHA-256", "SHA1 hash:", "Fingerprint"). */
const ALGORITHM_ONLY_LABEL_RE =
  /^[\s|:=\-–—(]*(?:md5|sha-?(?:1|224|256|384|512)|sha-?3(?:-\d+)?|hash|digest|fingerprint|value)(?:\s+(?:hash|digest|value))?[\s|:=\-–—)]*$/i;

/** A key noun that closes the label right before the value ("with the key (", "Key:"). */
const BARE_KEY_LABEL_RE = /(?:^|[^a-z0-9])keys?\s*[(:=\[]?\s*$/i;
/** Registry / run keys name a location, not key material. */
const REGISTRY_KEY_LABEL_RE = /\b(?:run|runonce|registry|reg|hkcu|hklm|hkey_[a-z_]+|autorun|startup)\s+keys?\s*[(:=\[]?\s*$/i;

/** File / sample nouns: a label that names the file keeps the hash reading. */
const FILE_NOUN_RE =
  /(?:^|[^a-z0-9])(?:files?|samples?|binar(?:y|ies)|executables?|payloads?|dlls?|exes?|loaders?|droppers?|implants?|scripts?|archives?|installers?|documents?|attachments?|malware|artifacts?|apks?|elfs?|modules?|components?|variants?|stagers?|backdoors?|trojans?|filename|file\s*name)(?:[^a-z0-9]|$)/i;

/** "<digest word> of / for <subject>" in a row description: the digest's own subject. */
const DIGEST_SUBJECT_RE = /\b(?:hash(?:es)?|digests?|fingerprints?|thumbprints?|sha-?(?:1|256|384|512)|md5)\s+(?:value\s+)?(?:of|for)\s+(?:the\s+|an?\s+)?([^.;|¶]{2,120})/i;

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
    // A longer trivial digest cut to a hash-column width ("cf83e135…ce9ce", the
    // first 64 hex of SHA-512("") listed as a SHA-256) — tl-digest-v8.
    for (const alg of ['sha384', 'sha512']) {
      const hex = crypto.createHash(alg).update(input, 'utf8').digest('hex');
      for (const width of [64, 40, 32]) {
        if (!out.has(hex.slice(0, width))) out.set(hex.slice(0, width), { algorithm: `${alg}_prefix`, input });
      }
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

/** A label window that is only a list conjunction ("and", ",", "/"). */
const CONJUNCTION_ONLY_LABEL_RE = /^\s*(?:,|&|\/|and|or|,\s*and|,\s*or)\s*$/i;

/**
 * The digest written immediately before `value` on the same line, joined to
 * it by a conjunction only, else null.
 * @param {string} text
 * @param {string} value
 */
function previousDigestOnLine(text, value) {
  const hay = refangTextForExtraction(String(text || ''));
  const idx = hay.toLowerCase().indexOf(String(value || '').trim().toLowerCase());
  if (idx < 0) return null;
  let previous = null;
  for (const m of hay.slice(0, idx).matchAll(OTHER_DIGEST_RE)) previous = m;
  if (!previous) return null;
  const between = hay.slice(previous.index + previous[0].length, idx);
  return CONJUNCTION_ONLY_LABEL_RE.test(between) ? previous[0] : null;
}

/**
 * Semantic kind of a digest-shaped value from its governing label.
 * @param {string} text line / row / surrounding window that contains the value
 * @param {string} value hex value
 * @param {{ scopeLabel?: string|null, columnHeader?: string|null, rowDescription?: string|null }} [opts]
 * @returns {{ kind: string, label: string, reason: string }}
 */
export function classifyHexDigest(text, value, opts = {}) {
  const known = wellKnownDigest(value);
  if (known) {
    return { kind: DIGEST_KINDS.WELL_KNOWN, label: '', reason: `digest_of_trivial_input_${known.algorithm}` };
  }
  // OCI notation: "<index|manifest|config|layer> … sha256:<hex>" names a
  // registry object of a container image, not a file sample (tl-digest-v7).
  if (isOciObjectDigest(text, value)) {
    return { kind: DIGEST_KINDS.OBJECT_ID, label: 'oci', reason: 'oci_object_digest' };
  }
  let label = digestLabelWindow(text, value);
  // "commits <h1> and <h2>": a label that is only a conjunction after another
  // digest is that digest's label — the run shares one subject (tl-digest-v6).
  if (CONJUNCTION_ONLY_LABEL_RE.test(label)) {
    const previous = previousDigestOnLine(text, value);
    if (previous) label = digestLabelWindow(text, previous);
  }
  const own = classifyLabel(label, { bareKey: /^[0-9a-f]{16,}$/i.test(String(value || '').trim()) });
  if (own.kind !== DIGEST_KINDS.FILE || own.reason === 'file_noun_after_label') return own;
  // The column header of a table cell is that cell's label ("Imphash |
  // Cluster | Role"): a non-file digest kind there governs every row, whatever
  // file nouns the row's other cells use ("x64 EXE (26 samples)") (tl-digest-v4).
  const columnHeader = String(opts.columnHeader || '').trim();
  if (columnHeader) {
    const fromHeader = classifyLabel(columnHeader.slice(0, 120));
    if (fromHeader.kind !== DIGEST_KINDS.FILE && fromHeader.kind !== DIGEST_KINDS.CREDENTIAL) {
      return { kind: fromHeader.kind, label: columnHeader, reason: `${fromHeader.kind}_column_header` };
    }
  }
  // A table row labelled only by its algorithm ("SHA-256 | <v>") names no
  // subject itself; the table's caption / heading does ("Custom
  // certificate used for TLS communication"). A file noun on the row or in the
  // scope label keeps the file-hash reading.
  const scope = String(opts.scopeLabel || '').trim();
  // An unlabelled value (a bare list item) takes its subject from the scope
  // label the same way an algorithm-only row label does.
  const scopeGoverns = own.reason === 'unlabelled' || (own.reason === 'file_label' && ALGORITHM_ONLY_LABEL_RE.test(label));
  // The row's own label cell names the subject of every value the row lists
  // ("Commits (pre-rewrite) | Library: <h1>, <h2>", "SPKI SHA256 | <v1> <v2>",
  // "Docker digests | Infected: 2.10.82 sha256:<v>"): the label window only
  // reaches the value next to it, so a multi-value cell left the others
  // unlabelled (tl-digest-v9). A file noun on either label keeps the file reading.
  const rowLabel = String(opts.rowLabel || '').trim();
  if (rowLabel && !FILE_NOUN_RE.test(rowLabel) && !FILE_NOUN_RE.test(label)) {
    const fromRowLabel = classifyLabel(rowLabel.slice(0, 120));
    if (fromRowLabel.kind !== DIGEST_KINDS.FILE && fromRowLabel.kind !== DIGEST_KINDS.CREDENTIAL) {
      return { kind: fromRowLabel.kind, label: rowLabel, reason: `${fromRowLabel.kind}_row_label` };
    }
  }
  // A table row whose description cell, written AFTER the value, says what the
  // digest is of ("SHA-256 Hash of public ED25519 Key for WinSCP Server"):
  // that subject governs like a label (tl-digest-v2). Only a description that
  // names the digest itself counts — "Backdoor using an RC4 key" does not.
  // A description that names the digest kind without an of/for subject
  // ("HOST-BANNER_0_HASH from the exposed SSH service") also governs when it
  // is not a file-hash reading (tl-digest-v2 / 30-report RC-5).
  const rowDescription = String(opts.rowDescription || '').trim();
  if (rowDescription) {
    const subject = DIGEST_SUBJECT_RE.exec(rowDescription);
    if (subject && !FILE_NOUN_RE.test(subject[1])) {
      const fromDescription = classifyLabel(subject[1].slice(0, 120));
      if (fromDescription.kind !== DIGEST_KINDS.FILE && fromDescription.kind !== DIGEST_KINDS.CREDENTIAL) {
        return { kind: fromDescription.kind, label, reason: `${fromDescription.kind}_row_description` };
      }
    }
    if (!FILE_NOUN_RE.test(rowDescription)) {
      const fromRow = classifyLabel(rowDescription.slice(0, 160));
      if (fromRow.kind !== DIGEST_KINDS.FILE && fromRow.kind !== DIGEST_KINDS.CREDENTIAL) {
        return { kind: fromRow.kind, label, reason: `${fromRow.kind}_row_description` };
      }
    }
  }
  if (scope && scopeGoverns && !FILE_NOUN_RE.test(scope)) {
    const fromScope = classifyLabel(scope.slice(0, 160));
    if (fromScope.kind !== DIGEST_KINDS.FILE && fromScope.kind !== DIGEST_KINDS.CREDENTIAL) {
      return { kind: fromScope.kind, label, reason: `${fromScope.kind}_scope_label` };
    }
  }
  return own;
}

/**
 * Field-name spelling → words: camelCase / PascalCase humps and dotted keys
 * become separate words ("accessTokenHash" → "access Token Hash",
 * "fileSha256" → "file Sha256"), so label nouns read the same however the
 * publisher's JSON / config key spells them. snake_case and kebab-case are
 * already word-separated for the patterns.
 * @param {string} label
 */
export function labelWords(label) {
  return String(label || '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/(?<=[a-z])\.(?=[a-z])/gi, ' ');
}

/** Crypto nouns that are also ordinary name parts ("AppSalt", "OmniIV"). */
const WEAK_CRYPTO_NOUN_RE = /^(?:salt|iv|nonce)$/i;

/**
 * True when the split-word match is only a bare weak crypto noun that was the
 * trailing hump of a capitalised compound in the label as written ("AppSalt
 * SDK" → "App Salt"): a product / brand name, not key material. Field names
 * ("saltHex", "ivBytes") and multi-word key phrases from a structure name
 * ("SubjectPublicKeyInfo" → "Public Key") keep their reading (tl-digest-v5).
 * @param {string} label as written
 * @param {{ text: string }} best match in the split label
 */
function isNameHumpOnly(label, best) {
  const noun = String(best?.text || '').replace(/^[^a-z0-9]+|[^a-z0-9]+$/gi, '');
  if (!WEAK_CRYPTO_NOUN_RE.test(noun)) return false;
  const compound = new RegExp(`(?:^|[^A-Za-z0-9])[A-Z][A-Za-z0-9]*?[a-z0-9]${noun}(?![a-z])`);
  return compound.test(label) && !new RegExp(`(?:^|[^A-Za-z0-9])${noun}(?:[^A-Za-z0-9]|$)`, 'i').test(label);
}

/** "based on TLSH pivot", "via imphash": how a sample was found, not what the digest is. */
const SIMILARITY_METHOD_PHRASE_RE =
  /\b(?:based\s+on|via|using|through|found\s+(?:by|with)|pivot(?:ing|ed)?\s+(?:on|from))\s+(?:an?\s+|the\s+)?(?:vhash|imphash|ssdeep|tlsh|authentihash|telfhash)(?:\s+(?:pivot|similarity|match|cluster|overlap))?/gi;

function bestKindIn(rawText) {
  const text = String(rawText || '').replace(SIMILARITY_METHOD_PHRASE_RE, ' ');
  let best = null;
  for (const [kind, re] of KIND_PATTERNS) {
    const all = [...text.matchAll(new RegExp(re.source, 'gi'))];
    if (!all.length) continue;
    const last = all[all.length - 1];
    const at = last.index;
    if (!best || at > best.at) best = { kind, at, text: last[0] };
  }
  return best;
}

function classifyLabel(label, opts = {}) {
  if (!label.trim()) return { kind: DIGEST_KINDS.FILE, label, reason: 'unlabelled' };
  // The label as written decides first (`VHash`, `ImpHash`, `BuildID` are
  // single tokens there); only when it names no kind is the field-name
  // spelling split into words (`accessTokenHash`).
  let words = label;
  let best = bestKindIn(label);
  if (!best) {
    const split = labelWords(label);
    if (split !== label) {
      best = bestKindIn(split);
      if (best && best.kind === DIGEST_KINDS.CRYPTO_KEY && isNameHumpOnly(label, best)) best = null;
      if (best) words = split;
    }
  }
  if (!best) {
    // "… with the key (<hex>)", "Key: <hex>": a bare key noun closing the label.
    if (opts.bareKey === true && BARE_KEY_LABEL_RE.test(words) && !REGISTRY_KEY_LABEL_RE.test(words) && !FILE_NOUN_RE.test(words)) {
      return { kind: DIGEST_KINDS.CRYPTO_KEY, label, reason: `${DIGEST_KINDS.CRYPTO_KEY}_label` };
    }
    return { kind: DIGEST_KINDS.FILE, label, reason: 'file_label' };
  }
  // A file noun after the non-file noun names the file ("certificate-signed sample SHA256:").
  if (FILE_NOUN_RE.test(words.slice(best.at + 1))) return { kind: DIGEST_KINDS.FILE, label, reason: 'file_noun_after_label' };
  return { kind: best.kind, label, reason: `${best.kind}_label` };
}

/**
 * "Image index: sha256:<hex>", "(index sha256:<hex>", "amd64 manifest
 * sha256:<hex>": the OCI digest notation (algorithm glued to the hex) right
 * after an index / manifest / config / layer noun. Without the glued prefix
 * a "manifest" label is a file ("package.json | Malicious manifest | <hex>").
 */
const OCI_OBJECT_LABEL_RE = /(?:^|[^a-z0-9])(?:index|manifests?|config|layers?)\s*[:=]?\s*sha-?256:\s*$/i;

/**
 * @param {string} text
 * @param {string} value hex
 */
export function isOciObjectDigest(text, value) {
  const hay = refangTextForExtraction(String(text || ''));
  const v = String(value || '').trim().toLowerCase();
  if (!hay || !v) return false;
  const lower = hay.toLowerCase();
  for (let at = lower.indexOf(v); at >= 0; at = lower.indexOf(v, at + v.length)) {
    if (OCI_OBJECT_LABEL_RE.test(hay.slice(Math.max(0, at - 60), at))) return true;
  }
  return false;
}

/** A row label that names the certificates' public-key hash. */
const SPKI_ROW_LABEL_RE = /(?:^|[^a-z0-9])(?:spki|subject\s+public\s+key\s+info)(?:[^a-z0-9]|$)/i;

function tableRowCells(row) {
  return (Array.isArray(row) ? row : row?.cells || []).map((c) => String(c ?? '').trim());
}

/**
 * The label cell of the one table row that holds `value`, or null: the row's
 * first non-empty cell when it is a short label and not the value's own cell.
 * A bare algorithm row ("SHA256 | <v1> <v2>") of a table that also lists the
 * certificates' SPKI hashes, and whose every label is a certificate attribute
 * or an algorithm, is a list of certificate fingerprints (tl-digest-v9).
 * @param {{ type?: string, table?: { rows?: Array<string[]|{ cells?: string[] }> } }} block
 * @param {string} value hex
 * @returns {string|null}
 */
export function digestRowLabel(block, value) {
  const v = String(value || '').trim().toLowerCase();
  const rows = block?.type === 'table' ? block.table?.rows || [] : [];
  if (!v || !rows.length) return null;
  const hasDigest = (text) => new RegExp(OTHER_DIGEST_RE.source, 'i').test(text);
  const labelOf = (cells) => {
    const label = cells.find(Boolean) || '';
    return !label || label.length > 60 || cells.length < 2 || hasDigest(label) ? null : label;
  };
  const holding = rows.map(tableRowCells).filter((cells) => cells.some((c) => c.toLowerCase().includes(v)));
  if (holding.length !== 1) return null;
  const label = labelOf(holding[0]);
  if (!label) return null;
  if (ALGORITHM_ONLY_LABEL_RE.test(label)) {
    const labels = rows.map(tableRowCells).filter((cells) => cells.some(Boolean)).map(labelOf);
    const certificateTable =
      labels.every(Boolean) &&
      labels.some((l) => SPKI_ROW_LABEL_RE.test(l)) &&
      labels.every((l) => ALGORITHM_ONLY_LABEL_RE.test(l) || classifyLabel(l).kind === DIGEST_KINDS.CERTIFICATE);
    if (certificateTable) return 'Certificate fingerprint';
  }
  return label;
}

/** Reasons that only mean "no subject named\": the default file reading. */
const DEFAULT_FILE_REASONS = new Set(['unlabelled', 'file_label']);

/**
 * Hex values the document itself names as repository / registry objects
 * anywhere ("Commit 3eab…", "source revision 2053…", "manifest sha256:…").
 * A bare occurrence of the same value elsewhere (a table row "3eab… | Pushed
 * to … next branch") is that object, never a file sample (tl-digest-v7).
 * @param {Array<{ text?: string }>} blocks
 * @returns {Set<string>}
 */
export function documentObjectIdentifiers(blocks) {
  const out = new Set();
  for (const b of blocks || []) {
    const text = String(b?.text || '');
    if (!text) continue;
    for (const line of text.split(/\r?\n|\s¶\s/)) {
      for (const m of line.matchAll(OTHER_DIGEST_RE)) {
        const v = m[0].toLowerCase();
        if (out.has(v)) continue;
        if (classifyHexDigest(line, v).kind === DIGEST_KINDS.OBJECT_ID) out.add(v);
      }
    }
  }
  return out;
}

/**
 * The file-hash reading of `digest` only defaulted (no subject named, no file
 * noun in the label or row description) and the document names the value as
 * an object identifier elsewhere: read it as that object.
 * @param {{ kind: string, reason: string, label?: string }} digest
 * @param {string} value
 * @param {Set<string>|null|undefined} objectIdentifiers
 * @param {string|null} [rowDescription]
 */
export function coreferencedObjectDigest(digest, value, objectIdentifiers, rowDescription = null) {
  if (!objectIdentifiers || !objectIdentifiers.size) return null;
  if (digest?.kind !== DIGEST_KINDS.FILE || !DEFAULT_FILE_REASONS.has(digest.reason)) return null;
  if (!objectIdentifiers.has(String(value || '').trim().toLowerCase())) return null;
  if (FILE_NOUN_RE.test(String(digest.label || '')) || FILE_NOUN_RE.test(String(rowDescription || ''))) return null;
  return { kind: DIGEST_KINDS.OBJECT_ID, label: digest.label || '', reason: 'object_identifier_coreference' };
}

/**
 * True when the value must not be typed as a file-hash Indicator.
 * @param {string} text
 * @param {string} value
 */
export function isNonFileDigest(text, value) {
  return NON_FILE_DIGEST_KINDS.has(classifyHexDigest(text, value).kind);
}
