/**
 * Public entry for File Artifact dual-write / services.
 */

export {
  EXACT_HASH_TYPES,
  EXACT_HASH_TYPE_SET,
  PRIMARY_HASH_PRIORITY,
  NON_IDENTITY_ATTR_TYPES,
  normalizeHashValue,
  normalizeHashType,
  normalizeExactHash,
  inferExactHashType,
  isExactFileHashIocType,
  selectPrimaryHash,
  shouldPromotePrimary,
  primaryPriorityRank,
  parseNoteKeyValues,
  extractExactHashesFromNote,
  extractExactHashesFromVtRaw,
  extractNonIdentityAttrsFromNote,
  isWeakMergeSignal
} from './hashNormalize.js';

export {
  isFileArtifactsDualWriteEnabled,
  isFileArtifactsReadEnabled
} from './flags.js';

export {
  mergeArtifactMetadata,
  selectCanonicalArtifact
} from './metadataPolicy.js';

export {
  recordMergeConflict,
  detectMultiArtifactConflict
} from './conflicts.js';

export {
  OBSERVATION_TYPE,
  RELATION_METHOD,
  upsertSourceObservation,
  formatObservationForApi
} from './observations.js';

export {
  findArtifactByHash,
  attachExactHash,
  linkIocToArtifact,
  recomputePrimaryHash,
  syncCanonicalIocFlag,
  ensureArtifactForFileHashIoc,
  attachProviderExactHashSet,
  upsertNonIdentityAttrs,
  exactHashAdvisoryLockKeys
} from './attach.js';

export { mergeFileArtifacts } from './merge.js';

export {
  findArtifactByIocPublicId,
  loadArtifactDetail,
  buildFileArtifactDetailBlock,
  mapPublicIdsToArtifactIds,
  dedupeListItemsByArtifact
} from './read.js';

export { applyFileArtifactListDedupe } from './listDedupe.js';

export {
  hashTypeRankSql,
  artifactAnnotateJoinSql,
  resolvedArtifactIdSql,
  identityKeySql,
  buildAnnotatedSelectSql,
  buildIdentityGroupedSelectSql,
  buildLegacyGroupedSelectSql,
  buildGroupedCteBody,
  buildCanonicalActiveBrowsePageSql,
  identityKeyForRow,
  canonicalizeRowsByIdentity,
  loadArtifactMapsForPublicIds
} from './canonicalListSql.js';

export { dualWriteFileArtifact, dualWriteFileArtifactForObservable } from './dualWrite.js';

export {
  EMPTY_ORPHAN_ARTIFACTS_SQL,
  countEmptyOrphanArtifacts,
  collectFileArtifactValidationMetrics
} from './validate.js';

export {
  withSavepoint,
  isControlledFileArtifactDbError,
  formatProviderError
} from './txSavepoint.js';
