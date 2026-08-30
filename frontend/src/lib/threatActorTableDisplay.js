import { formatThreatActorAliases } from './threatActorManagerList.js';

export const THREAT_ACTOR_PAGE_CLASS = 'threat-actors-page';
export const THREAT_ACTOR_TABLE_CLASS = 'threat-actors-table';
export const THREAT_ACTOR_DESCRIPTION_CLAMP_CLASS = 'ta-clamp-description';
export const THREAT_ACTOR_ALIASES_CLAMP_CLASS = 'ta-clamp-aliases';
export const THREAT_ACTOR_DESCRIPTION_TRUNCATE_MIN_CHARS = 140;

/**
 * @param {string|null|undefined} description
 * @returns {{ displayText: string, isPlaceholder: boolean, expandable: boolean, fullText: string|null }}
 */
export function formatThreatActorDescriptionCell(description) {
  const fullText = String(description || '').trim();
  if (!fullText) {
    return {
      displayText: '—',
      isPlaceholder: true,
      expandable: false,
      fullText: null
    };
  }

  const expandable = fullText.length >= THREAT_ACTOR_DESCRIPTION_TRUNCATE_MIN_CHARS || /\n/.test(fullText);
  return {
    displayText: fullText,
    isPlaceholder: false,
    expandable,
    fullText
  };
}

/**
 * @param {string[]|string|null|undefined} aliases
 * @returns {{ displayText: string, isPlaceholder: boolean, title?: string }}
 */
export function formatThreatActorAliasesCell(aliases) {
  const displayText = formatThreatActorAliases(aliases);
  if (displayText === '—') {
    return { displayText, isPlaceholder: true };
  }
  return { displayText, isPlaceholder: false, title: displayText };
}

/**
 * @param {string|null|undefined} actorName
 */
export function threatActorDescriptionModalTitle(actorName) {
  const name = String(actorName || '').trim();
  return name || 'Threat Actor';
}

/**
 * @param {{ name?: string, description?: string|null }} actor
 */
export function buildThreatActorDescriptionModalState(actor) {
  const cell = formatThreatActorDescriptionCell(actor?.description);
  if (!cell.expandable || !cell.fullText) return null;
  return {
    name: String(actor?.name || '').trim() || 'Threat Actor',
    description: cell.fullText
  };
}
