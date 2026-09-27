export const MAX_CONCURRENT_REPORT_ANALYSES_MIN = 1;
export const MAX_CONCURRENT_REPORT_ANALYSES_MAX = 4;
export const MAX_CONCURRENT_REPORT_ANALYSES_DEFAULT = 2;

export function parseConcurrentReportAnalyses(value) {
  const n = typeof value === 'number' ? value : Number(String(value).trim());
  if (!Number.isInteger(n) || n < MAX_CONCURRENT_REPORT_ANALYSES_MIN || n > MAX_CONCURRENT_REPORT_ANALYSES_MAX) {
    return null;
  }
  return n;
}
