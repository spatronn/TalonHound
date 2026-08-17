/** Analyst-friendly labels for BullMQ / queue job names (internal names stay unchanged). */

const DISPLAY_BY_INTEGRATION_KEY = {
  'et-blockrules': 'Blockrules IP import',
  'usom-trcert': 'Siber Güvenlik Başkanlığı / USOM API import',
  'urlhaus-abusech': 'Recent malicious URLs import',
  'threatfox-abusech': 'Recent IOCs import',
  'malwarebazaar-abusech': 'Recent malware samples import',
  'phishtank-opendnsrr': 'Online-valid phishing import'
};

const DISPLAY_BY_JOB_NAME = {
  'hourly-import': 'Blockrules IP import',
  'usom-import': 'Siber Güvenlik Başkanlığı / USOM API import',
  'urlhaus-import': 'Recent malicious URLs import',
  'threatfox-import': 'Recent IOCs import',
  'malwarebazaar-import': 'Recent malware samples import',
  'malwarebazaar-historical-recovery': 'MalwareBazaar historical recovery',
  'phishtank-import': 'Online-valid phishing import'
};

export function formatIntegrationJobDisplayName(jobName, integrationKey = null) {
  const name = String(jobName || '').trim();
  if (name === 'malwarebazaar-historical-recovery') {
    return 'MalwareBazaar historical recovery';
  }
  const key = String(integrationKey || '').trim();
  if (key && DISPLAY_BY_INTEGRATION_KEY[key]) {
    return DISPLAY_BY_INTEGRATION_KEY[key];
  }
  if (name && DISPLAY_BY_JOB_NAME[name]) {
    return DISPLAY_BY_JOB_NAME[name];
  }
  return name || '-';
}

export function withIntegrationJobDisplayName(row) {
  if (!row || typeof row !== 'object') return row;
  const displayName = formatIntegrationJobDisplayName(row.name, row.integration_key);
  return { ...row, job_name: row.name, name: displayName, display_name: displayName };
}
