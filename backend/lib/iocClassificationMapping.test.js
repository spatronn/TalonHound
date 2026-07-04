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

  describe('unknown feed', () => {
    it('returns null for unrecognized feed key', () => {
      expect(resolveClassificationFromFeed('unknown-feed', 'malware')).toBeNull();
    });
  });

  it('returns null when rawValue is null regardless of feed', () => {
    expect(resolveClassificationFromFeed('urlhaus-abusech', null)).toBeNull();
    expect(resolveClassificationFromFeed('threatfox-abusech', null)).toBeNull();
    expect(resolveClassificationFromFeed('malwarebazaar-abusech', null)).toBeNull();
  });
});
