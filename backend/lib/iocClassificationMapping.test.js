import { describe, it, expect } from 'vitest';
import { resolveClassificationFromFeed } from './iocClassificationMapping.js';

describe('resolveClassificationFromFeed', () => {
  describe('urlhaus-abusech', () => {
    it('maps botnet_cc to c2', () => {
      expect(resolveClassificationFromFeed('urlhaus-abusech', 'botnet_cc')).toBe('c2');
    });

    it('maps malware_download to malware', () => {
      expect(resolveClassificationFromFeed('urlhaus-abusech', 'malware_download')).toBe('malware');
    });

    it('maps phishing to phishing', () => {
      expect(resolveClassificationFromFeed('urlhaus-abusech', 'phishing')).toBe('phishing');
    });

    it('returns null for unknown URLHaus category', () => {
      expect(resolveClassificationFromFeed('urlhaus-abusech', 'completely_unknown')).toBeNull();
    });
  });

  describe('malwarebazaar-abusech', () => {
    it('returns malware for any non-null value', () => {
      expect(resolveClassificationFromFeed('malwarebazaar-abusech', 'Mirai')).toBe('malware');
      expect(resolveClassificationFromFeed('malwarebazaar-abusech', 'malware')).toBe('malware');
      expect(resolveClassificationFromFeed('malwarebazaar-abusech', 'WannaCry')).toBe('malware');
      expect(resolveClassificationFromFeed('malwarebazaar-abusech', 'some_unknown_family')).toBe('malware');
    });

    it('returns null for null/empty value', () => {
      expect(resolveClassificationFromFeed('malwarebazaar-abusech', null)).toBeNull();
      expect(resolveClassificationFromFeed('malwarebazaar-abusech', '')).toBeNull();
      expect(resolveClassificationFromFeed('malwarebazaar-abusech', undefined)).toBeNull();
    });
  });

  describe('threatfox-abusech (regression)', () => {
    it('maps botnet_cc to c2', () => {
      expect(resolveClassificationFromFeed('threatfox-abusech', 'botnet_cc')).toBe('c2');
    });

    it('maps payload_delivery to malware', () => {
      expect(resolveClassificationFromFeed('threatfox-abusech', 'payload_delivery')).toBe('malware');
    });

    it('maps ransomware to ransomware', () => {
      expect(resolveClassificationFromFeed('threatfox-abusech', 'ransomware')).toBe('ransomware');
    });

    it('returns null for null threat type', () => {
      expect(resolveClassificationFromFeed('threatfox-abusech', null)).toBeNull();
    });

    it('returns null for unknown threat type', () => {
      expect(resolveClassificationFromFeed('threatfox-abusech', 'unknown_type')).toBeNull();
    });
  });

  describe('phishtank-opendnsrr', () => {
    it('returns phishing for any non-null value', () => {
      expect(resolveClassificationFromFeed('phishtank-opendnsrr', 'phishing')).toBe('phishing');
      expect(resolveClassificationFromFeed('phishtank-opendnsrr', 'any')).toBe('phishing');
      expect(resolveClassificationFromFeed('phishtank-opendnsrr', 'verified')).toBe('phishing');
    });

    it('returns null for null value', () => {
      expect(resolveClassificationFromFeed('phishtank-opendnsrr', null)).toBeNull();
    });

    it('returns null for empty string', () => {
      expect(resolveClassificationFromFeed('phishtank-opendnsrr', '')).toBeNull();
    });
  });

  describe('alienvault-otx', () => {
    it('maps malware tag to malware', () => {
      expect(resolveClassificationFromFeed('alienvault-otx', 'malware')).toBe('malware');
    });

    it('maps phishing tag to phishing', () => {
      expect(resolveClassificationFromFeed('alienvault-otx', 'phishing')).toBe('phishing');
    });

    it('maps ransomware tag to ransomware', () => {
      expect(resolveClassificationFromFeed('alienvault-otx', 'ransomware')).toBe('ransomware');
    });

    it('maps botnet_cc to command_and_control', () => {
      expect(resolveClassificationFromFeed('alienvault-otx', 'botnet_cc')).toBe('command_and_control');
    });

    it('maps c2 to command_and_control', () => {
      expect(resolveClassificationFromFeed('alienvault-otx', 'c2')).toBe('command_and_control');
    });

    it('returns null for unknown/ambiguous OTX tag', () => {
      expect(resolveClassificationFromFeed('alienvault-otx', 'APT28')).toBeNull();
      expect(resolveClassificationFromFeed('alienvault-otx', 'russia')).toBeNull();
      expect(resolveClassificationFromFeed('alienvault-otx', 'unknown')).toBeNull();
    });

    it('returns null for null value', () => {
      expect(resolveClassificationFromFeed('alienvault-otx', null)).toBeNull();
    });
  });

  describe('unknown feed', () => {
    it('returns null for unrecognized feed key', () => {
      expect(resolveClassificationFromFeed('unknown-feed', 'malware')).toBeNull();
    });
  });

  it('returns null when rawValue is null regardless of feed', () => {
    expect(resolveClassificationFromFeed('urlhaus-abusech', null)).toBeNull();
    expect(resolveClassificationFromFeed('threatfox-abusech', null)).toBeNull();
    expect(resolveClassificationFromFeed('malwarebazaar-abusech', null)).toBeNull();
    expect(resolveClassificationFromFeed('phishtank-opendnsrr', null)).toBeNull();
    expect(resolveClassificationFromFeed('alienvault-otx', null)).toBeNull();
  });
});
