export {
  SECTION_TREE_VERSION,
  SECTION_TREE_MEMBERSHIP_PREVIEW_VERSION,
  SECTION_TREE_SHADOW_VERSION,
  SECTION_TREE_SCOPE_ENGINE_VERSION,
  SCOPE_ENGINE_LEGACY,
  SCOPE_ENGINE_SECTION_TREE
} from './version.js';
export {
  isSectionTreeShadowEnabled,
  isSectionTreeFullRezonePreviewEnabled,
  getScopeEngine,
  isSectionTreeScopeAuthoritative
} from './flags.js';
export { annotateSectionTree } from './annotate.js';
export { previewMembershipAdditive, previewMembershipFullRezone } from './membershipPreview.js';
export { applySectionTreeAuthority } from './authority.js';
export { candidateMemberKeySet, compareMembershipSets } from './compare.js';
export {
  evaluateSectionTreeShadow,
  attachSectionTreeShadowDiagnostics,
  compactSectionTreeShadow
} from './shadow.js';
