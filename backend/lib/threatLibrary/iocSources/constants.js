/**
 * Additional IOC Sources — shared constants and bounds.
 */

export const IOC_SOURCE_LIFECYCLE = Object.freeze({
  DISCOVERED: 'discovered',
  INSPECTING: 'inspecting',
  INSPECTED: 'inspected',
  ATTACHED: 'attached',
  EXTRACTING: 'extracting',
  EXTRACTED: 'extracted',
  DISMISSED: 'dismissed',
  BLOCKED: 'blocked',
  UNSUPPORTED: 'unsupported',
  FAILED: 'failed',
  STALE: 'stale'
});

export const IOC_SOURCE_TYPES = Object.freeze([
  'html',
  'txt',
  'csv',
  'json',
  'pdf',
  'github_dir',
  'github_file',
  'unknown'
]);

export const LINKED_SOURCE_IOC_ASSERTION = 'linked_source_ioc';

/** Job modes for source inspect / extract (threat_library_jobs.job_type). */
export const IOC_SOURCE_JOB_MODES = Object.freeze({
  INSPECT: 'inspect_ioc_source',
  EXTRACT: 'extract_ioc_source'
});

export const IOC_SOURCE_FETCH = Object.freeze({
  MAX_BYTES: Math.max(Number(process.env.THREAT_LIBRARY_IOC_SOURCE_MAX_BYTES || 4_194_304), 1024),
  TIMEOUT_MS: Math.max(Number(process.env.THREAT_LIBRARY_IOC_SOURCE_TIMEOUT_MS || 30_000), 1000),
  MAX_REDIRECTS: 5,
  GITHUB_MAX_FILES: Math.max(Number(process.env.THREAT_LIBRARY_IOC_SOURCE_GITHUB_MAX_FILES || 40), 1),
  GITHUB_MAX_DEPTH: 1,
  GITHUB_MAX_FILE_BYTES: Math.max(Number(process.env.THREAT_LIBRARY_IOC_SOURCE_GITHUB_FILE_BYTES || 1_048_576), 1024)
});

export const IOC_SOURCE_ELIGIBLE_EXTENSIONS = Object.freeze([
  '.txt',
  '.csv',
  '.json',
  '.html',
  '.htm',
  '.pdf',
  '.md',
  '.ioc',
  '.yml',
  '.yaml',
  // Publisher hash-list files (e.g. Gen Digital WardenStealer samples.sha256)
  '.sha256',
  '.sha1',
  '.md5'
]);

export const IOC_SOURCE_CONTENT_TYPES = Object.freeze([
  'text/plain',
  'text/csv',
  'text/html',
  'text/markdown',
  'application/json',
  'application/pdf',
  'application/octet-stream',
  'text/x-markdown',
  'application/yaml',
  'text/yaml'
]);

/** Link-text / surrounding-text cues for automatic discovery (case-insensitive). */
export const IOC_SOURCE_DISCOVERY_CUES = Object.freeze([
  'complete ioc',
  'full ioc',
  'ioc list',
  'iocs',
  'indicators of compromise',
  'additional indicators',
  'additional ioc',
  'supplementary indicators',
  'download ioc',
  'download indicators',
  'ioc appendix',
  'indicator appendix',
  'ioc repository',
  'ioc dataset',
  'indicator dataset',
  'host indicators',
  'network indicators',
  'sample hashes'
]);

export const IOC_SOURCE_DISCOVERY_URL_CUES = Object.freeze([
  '/ioc/',
  '/iocs/',
  '/indicators/',
  'ioc.',
  'indicators.',
  '.csv',
  '.txt',
  'github.com/'
]);
