import crypto from 'node:crypto';

/**
 * One-time first-run setup code.
 *
 * installation.sh generates a code, shows it once on the operator's terminal, and passes
 * only its SHA-256 hash to the backend (env SETUP_CODE_HASH). The plaintext is never
 * written to disk, logs, the repository, or any normal API. The first Setup Wizard step
 * asks the operator to type the code; the backend verifies it (timing-safe) against the
 * stored hash and permanently invalidates it when setup completes.
 *
 * Format: 4 groups of 4 unambiguous characters, e.g. `H7QX-4KMP-9TWR-2NBY` (16 chars of
 * entropy from an unbiased CSPRNG ≈ 80 bits over a 32-symbol alphabet).
 */

// Crockford-style alphabet with ambiguous characters removed (no I, L, O, U, 0, 1).
const ALPHABET = 'ABCDEFGHJKMNPQRSTVWXYZ23456789';
const GROUPS = 4;
const GROUP_LEN = 4;
const CODE_LEN = GROUPS * GROUP_LEN;

export const SETUP_CODE_POLICY = Object.freeze({
  length: CODE_LEN,
  groups: GROUPS,
  groupLength: GROUP_LEN,
  separator: '-',
  alphabet: ALPHABET
});

/** Generate a cryptographically strong one-time setup code. */
export function generateSetupCode() {
  const chars = [];
  for (let i = 0; i < CODE_LEN; i += 1) {
    chars.push(ALPHABET[crypto.randomInt(ALPHABET.length)]);
  }
  const groups = [];
  for (let g = 0; g < GROUPS; g += 1) {
    groups.push(chars.slice(g * GROUP_LEN, (g + 1) * GROUP_LEN).join(''));
  }
  return groups.join(SETUP_CODE_POLICY.separator);
}

/**
 * Canonicalize operator input for comparison: uppercase, strip everything that is not an
 * allowed alphabet character (dashes, spaces, stray punctuation). Returns '' when the
 * result is empty so callers can reject it uniformly.
 */
export function normalizeSetupCode(input) {
  if (input == null) return '';
  const cleaned = String(input)
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '');
  return cleaned;
}

/** SHA-256 (lowercase hex) of the canonicalized code. Empty input → ''. */
export function hashSetupCode(input) {
  const normalized = normalizeSetupCode(input);
  if (!normalized) return '';
  return crypto.createHash('sha256').update(normalized, 'utf8').digest('hex');
}

/** True when `input` matches `expectedHash`, compared in constant time. */
export function verifySetupCode(input, expectedHash) {
  const expected = String(expectedHash || '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expected)) return false;
  const candidate = hashSetupCode(input);
  if (candidate.length !== expected.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(expected, 'hex'));
  } catch {
    return false;
  }
}

/** True when a value looks like a stored SHA-256 hex hash (for env validation). */
export function isSha256Hex(value) {
  return /^[0-9a-f]{64}$/i.test(String(value || '').trim());
}
