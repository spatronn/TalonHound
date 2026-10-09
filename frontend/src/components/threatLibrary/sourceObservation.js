/**
 * Presentation of a Threat Library claim's publisher observation
 * (`claim.source_observation`): when the publisher observed THIS value, read
 * from its own indicator row ("First Seen / Last Seen"). It is a different
 * fact from the report's publication date and from TalonHound's import time,
 * so it is labelled as the publisher's and never filled from either.
 */

import { formatCalendarDate } from '../../lib/formatDate.js';

/**
 * Display text, or null when the report gave no observation date for the value.
 * Labelled first/last-seen columns are named as such; unlabelled row dates
 * are shown as the window they span.
 * @param {{ earliest?: string|null, latest?: string|null, first_seen?: string|null, last_seen?: string|null }|null|undefined} obs
 * @returns {string|null}
 */
export function formatSourceObservation(obs) {
  if (!obs || typeof obs !== 'object') return null;
  const first = formatCalendarDate(obs.first_seen);
  const last = formatCalendarDate(obs.last_seen);
  if (first || last) {
    if (first && last && first !== last) return `Publisher first seen ${first} · last seen ${last}`;
    if (first && last) return `Publisher observed ${first}`;
    return first ? `Publisher first seen ${first}` : `Publisher last seen ${last}`;
  }
  const earliest = formatCalendarDate(obs.earliest);
  const latest = formatCalendarDate(obs.latest);
  if (!earliest && !latest) return null;
  if (earliest && latest && earliest !== latest) return `Publisher observed ${earliest} – ${latest}`;
  return `Publisher observed ${earliest || latest}`;
}

/** Tooltip: what the date is and what it is not. */
export const SOURCE_OBSERVATION_TITLE =
  'Date the report publisher observed this indicator (from its own row in the report). ' +
  'Not the report publication date and not the TalonHound import time; current reputation is shown separately.';
