import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveClassificationFromFeed } from './iocClassificationMapping.js';

// --- urlhaus-abusech ---

test('urlhaus: maps botnet_cc to c2', () => {
  assert.equal(resolveClassificationFromFeed('urlhaus-abusech', 'botnet_cc'), 'c2');
});

test('urlhaus: maps malware_download to malware', () => {
  assert.equal(resolveClassificationFromFeed('urlhaus-abusech', 'malware_download'), 'malware');
});

test('urlhaus: maps phishing to phishing', () => {
  assert.equal(resolveClassificationFromFeed('urlhaus-abusech', 'phishing'), 'phishing');
});

test('urlhaus: returns null for unknown category', () => {
  assert.equal(resolveClassificationFromFeed('urlhaus-abusech', 'completely_unknown'), null);
});

// --- malwarebazaar-abusech ---

test('malwarebazaar: returns malware for any non-null value', () => {
  assert.equal(resolveClassificationFromFeed('malwarebazaar-abusech', 'Mirai'), 'malware');
  assert.equal(resolveClassificationFromFeed('malwarebazaar-abusech', 'malware'), 'malware');
  assert.equal(resolveClassificationFromFeed('malwarebazaar-abusech', 'WannaCry'), 'malware');
  assert.equal(resolveClassificationFromFeed('malwarebazaar-abusech', 'some_unknown_family'), 'malware');
});

test('malwarebazaar: returns null for null/empty', () => {
  assert.equal(resolveClassificationFromFeed('malwarebazaar-abusech', null), null);
  assert.equal(resolveClassificationFromFeed('malwarebazaar-abusech', ''), null);
  assert.equal(resolveClassificationFromFeed('malwarebazaar-abusech', undefined), null);
});

// --- threatfox-abusech ---

test('threatfox: maps botnet_cc to c2', () => {
  assert.equal(resolveClassificationFromFeed('threatfox-abusech', 'botnet_cc'), 'c2');
});

test('threatfox: maps payload_delivery to malware', () => {
  assert.equal(resolveClassificationFromFeed('threatfox-abusech', 'payload_delivery'), 'malware');
});

test('threatfox: maps ransomware to ransomware', () => {
  assert.equal(resolveClassificationFromFeed('threatfox-abusech', 'ransomware'), 'ransomware');
});

test('threatfox: returns null for null', () => {
  assert.equal(resolveClassificationFromFeed('threatfox-abusech', null), null);
});

test('threatfox: returns null for unknown type', () => {
  assert.equal(resolveClassificationFromFeed('threatfox-abusech', 'unknown_type'), null);
});

// --- phishtank-opendnsrr ---

test('phishtank: returns phishing for any non-null value', () => {
  assert.equal(resolveClassificationFromFeed('phishtank-opendnsrr', 'phishing'), 'phishing');
  assert.equal(resolveClassificationFromFeed('phishtank-opendnsrr', 'any'), 'phishing');
  assert.equal(resolveClassificationFromFeed('phishtank-opendnsrr', 'verified'), 'phishing');
});

test('phishtank: returns null for null', () => {
  assert.equal(resolveClassificationFromFeed('phishtank-opendnsrr', null), null);
});

test('phishtank: returns null for empty string', () => {
  assert.equal(resolveClassificationFromFeed('phishtank-opendnsrr', ''), null);
});

// --- alienvault-otx ---

test('otx: maps malware to malware', () => {
  assert.equal(resolveClassificationFromFeed('alienvault-otx', 'malware'), 'malware');
});

test('otx: maps phishing to phishing', () => {
  assert.equal(resolveClassificationFromFeed('alienvault-otx', 'phishing'), 'phishing');
});

test('otx: maps ransomware to ransomware', () => {
  assert.equal(resolveClassificationFromFeed('alienvault-otx', 'ransomware'), 'ransomware');
});

test('otx: maps botnet_cc to command_and_control', () => {
  assert.equal(resolveClassificationFromFeed('alienvault-otx', 'botnet_cc'), 'command_and_control');
});

test('otx: maps c2 to command_and_control', () => {
  assert.equal(resolveClassificationFromFeed('alienvault-otx', 'c2'), 'command_and_control');
});

test('otx: returns null for ambiguous tags', () => {
  assert.equal(resolveClassificationFromFeed('alienvault-otx', 'APT28'), null);
  assert.equal(resolveClassificationFromFeed('alienvault-otx', 'russia'), null);
  assert.equal(resolveClassificationFromFeed('alienvault-otx', 'unknown'), null);
});

test('otx: returns null for null', () => {
  assert.equal(resolveClassificationFromFeed('alienvault-otx', null), null);
});

// --- et-blockrules ---

test('et-blockrules: maps c2 to command_and_control', () => {
  assert.equal(resolveClassificationFromFeed('et-blockrules', 'c2'), 'command_and_control');
});

test('et-blockrules: maps botnet-c2 to command_and_control', () => {
  assert.equal(resolveClassificationFromFeed('et-blockrules', 'botnet-c2'), 'command_and_control');
});

test('et-blockrules: maps tor to suspicious_infrastructure', () => {
  assert.equal(resolveClassificationFromFeed('et-blockrules', 'tor'), 'suspicious_infrastructure');
});

test('et-blockrules: maps compromised-host to suspicious_infrastructure', () => {
  assert.equal(resolveClassificationFromFeed('et-blockrules', 'compromised-host'), 'suspicious_infrastructure');
});

test('et-blockrules: maps known-malicious to malware', () => {
  assert.equal(resolveClassificationFromFeed('et-blockrules', 'known-malicious'), 'malware');
});

test('et-blockrules: maps scanner to scanner_recon', () => {
  assert.equal(resolveClassificationFromFeed('et-blockrules', 'scanner'), 'scanner_recon');
});

test('et-blockrules: maps bruteforce to suspicious_infrastructure', () => {
  assert.equal(resolveClassificationFromFeed('et-blockrules', 'bruteforce'), 'suspicious_infrastructure');
});

test('et-blockrules: maps malicious-ip to suspicious_infrastructure', () => {
  assert.equal(resolveClassificationFromFeed('et-blockrules', 'malicious-ip'), 'suspicious_infrastructure');
});

test('et-blockrules: returns null for unknown category', () => {
  assert.equal(resolveClassificationFromFeed('et-blockrules', 'completely-unknown'), null);
});

test('et-blockrules: returns null for null', () => {
  assert.equal(resolveClassificationFromFeed('et-blockrules', null), null);
});

// --- unknown feed ---

test('unknown feed: returns null for unrecognized feed key', () => {
  assert.equal(resolveClassificationFromFeed('unknown-feed', 'malware'), null);
});

test('all feeds: returns null when rawValue is null', () => {
  for (const feedKey of ['urlhaus-abusech', 'threatfox-abusech', 'malwarebazaar-abusech', 'phishtank-opendnsrr', 'alienvault-otx', 'et-blockrules']) {
    assert.equal(resolveClassificationFromFeed(feedKey, null), null, `${feedKey} should return null for null rawValue`);
  }
});
