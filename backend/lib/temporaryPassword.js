import crypto from 'crypto';

/**
 * Cryptographically strong, human-readable temporary passwords for admin-initiated
 * resets. Uses Node's crypto (never Math.random) and an unambiguous alphabet so the
 * value can be read aloud / copied without confusing 0/O or 1/l/I.
 */

// Ambiguous characters removed: 0 O 1 l I. Guarantees at least one of each class.
const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const LOWER = 'abcdefghijkmnopqrstuvwxyz';
const DIGITS = '23456789';
const ALL = UPPER + LOWER + DIGITS;

const GROUPS = 4;
const GROUP_LEN = 4;

export const TEMP_PASSWORD_POLICY = Object.freeze({
  length: GROUPS * GROUP_LEN,
  groups: GROUPS,
  groupLength: GROUP_LEN,
  separator: '-',
  guarantees: ['uppercase', 'lowercase', 'digit'],
  unambiguous: true
});

/** Pick one character from `alphabet` using a uniform, unbiased CSPRNG draw. */
function pick(alphabet) {
  return alphabet[crypto.randomInt(alphabet.length)];
}

/** Fisher–Yates shuffle backed by crypto.randomInt (unbiased). */
function shuffle(chars) {
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars;
}

/**
 * Generate a temporary password such as `Abcd-Efgh-2345-Kmnp`.
 * Always includes >=1 uppercase, >=1 lowercase and >=1 digit; drops ambiguous chars.
 * @returns {string}
 */
export function generateTemporaryPassword() {
  const total = GROUPS * GROUP_LEN;
  const chars = [pick(UPPER), pick(LOWER), pick(DIGITS)];
  while (chars.length < total) {
    chars.push(pick(ALL));
  }
  shuffle(chars);

  const groups = [];
  for (let g = 0; g < GROUPS; g += 1) {
    groups.push(chars.slice(g * GROUP_LEN, (g + 1) * GROUP_LEN).join(''));
  }
  return groups.join(TEMP_PASSWORD_POLICY.separator);
}
