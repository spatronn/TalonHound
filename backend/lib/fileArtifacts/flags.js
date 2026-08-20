/**
 * Feature flags for File Artifacts rollout.
 * Env pattern matches the existing IOC_LIST_* boolean-flag style.
 */

function parseBoolEnv(value, defaultValue = false) {
  if (value == null || value === '') return defaultValue;
  const v = String(value).trim().toLowerCase();
  if (v === '1' || v === 'true' || v === 'yes' || v === 'on') return true;
  if (v === '0' || v === 'false' || v === 'no' || v === 'off') return false;
  return defaultValue;
}

/** Dual-write on import paths (default off). */
export function isFileArtifactsDualWriteEnabled() {
  return parseBoolEnv(process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED, false);
}

/** Artifact-aware detail/list/search read path (default off). */
export function isFileArtifactsReadEnabled() {
  return parseBoolEnv(process.env.FILE_ARTIFACTS_READ_ENABLED, false);
}
