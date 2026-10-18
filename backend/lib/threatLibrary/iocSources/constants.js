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

/**
 * Text / surrounding-text cues for automatic discovery (case-insensitive
 * substring match). These must describe a publisher IOC dataset — not ordinary
 * research citations or tooling links.
 *
 * IMPORTANT: do not put hostnames (e.g. "github.com/") here or in URL cues;
 * that previously self-reinforced every GitHub link to an accept score.
 */
export const IOC_SOURCE_DISCOVERY_CUES = Object.freeze([
  'complete ioc',
  'full ioc',
  'full ioc list',
  'ioc list',
  'iocs are available',
  'iocs can be found',
  'indicators of compromise can be found',
  'indicators of compromise',
  'indicators are published',
  'indicators are available',
  'additional indicators',
  'additional ioc',
  'supplementary indicators',
  'download ioc',
  'download indicators',
  'threat indicators csv',
  'ioc appendix',
  'indicator appendix',
  'ioc repository',
  'ioc dataset',
  'indicator dataset',
  'host indicators',
  'network indicators',
  'sample hashes',
  'see the following ioc',
  'ioc pack',
  'indicator pack'
]);

/**
 * Path / filename cues only. Never include bare hosts (github.com/) — host
 * relevance is scored separately and only when text evidence already exists.
 */
export const IOC_SOURCE_DISCOVERY_URL_CUES = Object.freeze([
  '/ioc/',
  '/iocs/',
  '/indicators/',
  '/indicator/',
  'ioc.',
  'indicators.'
]);

/** Minimum score to accept a discovered source (requires textual evidence). */
export const IOC_SOURCE_DISCOVERY_SCORE_THRESHOLD = 4;
