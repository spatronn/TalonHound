/** Canonical threat classification enum (single source of truth). */

export const THREAT_CLASSIFICATIONS = Object.freeze([
  { value: 'unknown', label: 'Unknown' },
  { value: 'phishing', label: 'Phishing' },
  { value: 'credential_theft', label: 'Credential Theft' },
  { value: 'malware', label: 'Malware' },
  { value: 'ransomware', label: 'Ransomware' },
  { value: 'command_and_control', label: 'Command and Control (C2)' },
  { value: 'botnet', label: 'Botnet' },
  { value: 'exploit', label: 'Exploit / Exploitation' },
  { value: 'scanner_recon', label: 'Scanner / Reconnaissance' },
  { value: 'suspicious_infrastructure', label: 'Suspicious Infrastructure' },
  { value: 'spam_abuse', label: 'Spam / Abuse' },
  { value: 'dropper_downloader', label: 'Dropper / Downloader' },
  { value: 'payload_hosting', label: 'Payload Hosting' },
  { value: 'data_exfiltration', label: 'Data Exfiltration' },
  { value: 'cryptomining', label: 'Cryptomining' },
  { value: 'fraud_scam', label: 'Fraud / Scam' },
  { value: 'typosquatting_impersonation', label: 'Typosquatting / Impersonation' },
  { value: 'benign_test', label: 'Benign / Test' }
]);

const VALUE_SET = new Set(THREAT_CLASSIFICATIONS.map((x) => x.value));
const LABEL_BY_VALUE = new Map(THREAT_CLASSIFICATIONS.map((x) => [x.value, x.label]));

/** Legacy DB/API/tag values → canonical slug. */
const LEGACY_NORMALIZE_MAP = Object.freeze({
  c2: 'command_and_control',
  command_and_control: 'command_and_control',
  'command and control': 'command_and_control',
  scanner: 'scanner_recon',
  scanner_recon: 'scanner_recon',
  suspicious_infra: 'suspicious_infrastructure',
  suspicious_infrastructure: 'suspicious_infrastructure',
  test: 'benign_test',
  benign_test: 'benign_test',
  exploit_explitation: 'exploit',
  'exploit / explitation': 'exploit',
  'exploit / exploitation': 'exploit'
});

export function threatClassificationLabel(value) {
  const v = normalizeThreatClassification(value);
  return LABEL_BY_VALUE.get(v) || 'Unknown';
}

export function listThreatClassifications() {
  return THREAT_CLASSIFICATIONS.map(({ value, label }) => ({ value, label }));
}

export function normalizeThreatClassification(raw, { defaultValue = 'unknown' } = {}) {
  if (raw == null || raw === '') return defaultValue;
  let s = String(raw).trim().toLowerCase();
  s = s.replace(/[\s-]+/g, '_');
  if (LEGACY_NORMALIZE_MAP[s]) return LEGACY_NORMALIZE_MAP[s];
  if (VALUE_SET.has(s)) return s;
  return defaultValue;
}

export function validateThreatClassification(raw, { allowEmpty = false } = {}) {
  if (raw == null || raw === '') {
    if (allowEmpty) return { ok: true, value: 'unknown' };
    return { ok: true, value: 'unknown' };
  }
  const normalized = normalizeThreatClassification(raw, { defaultValue: null });
  if (!normalized || !VALUE_SET.has(normalized)) {
    return {
      ok: false,
      error: `threat_classification must be one of: ${[...VALUE_SET].join(', ')}`
    };
  }
  return { ok: true, value: normalized };
}

export function threatClassificationResponseFields(value) {
  const v = normalizeThreatClassification(value);
  return {
    threat_classification: v,
    threat_classification_label: threatClassificationLabel(v),
    primary_threat_classification: v
  };
}
