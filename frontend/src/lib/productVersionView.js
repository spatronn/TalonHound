/**
 * Product version display helpers for Administration / System UI.
 */

/** @param {{ product?: string, version?: string }|null|undefined} info */
export function formatProductVersionLabel(info) {
  const product = String(info?.product || 'TalonHound').trim() || 'TalonHound';
  const version = String(info?.version || '').trim();
  return version ? `${product} v${version}` : product;
}

/** @param {{ commit?: string }|null|undefined} info */
export function formatCommitDetail(info) {
  const commit = String(info?.commit || '').trim();
  if (!commit || commit === 'unknown' || commit === 'dev') return null;
  return commit.length > 7 ? commit.slice(0, 7) : commit;
}

/** @param {{ buildDate?: string }|null|undefined} info */
export function formatBuildDateDetail(info) {
  const buildDate = String(info?.buildDate || '').trim();
  if (!buildDate || buildDate === 'unknown') return null;
  return buildDate;
}
