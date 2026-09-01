import { FormatPreservingEncryptor } from '../../src/security/fpe';

describe('Format-Preserving Encryption (FPE) & Context-Aware Redaction Unit Suite', () => {
  let fpe: FormatPreservingEncryptor;

  beforeEach(() => {
    fpe = new FormatPreservingEncryptor({ secretKey: 'enterprise-test-fpe-key' });
  });

  describe('FPE-01: Structured Numeric Masking & Checksum Preservation', () => {
    it('Preserves exact length and formatting delimiters of SSNs and Tax IDs', () => {
      const ssn = '123-45-6789';
      const encrypted = fpe.encryptDigits(ssn);

      expect(encrypted).toHaveLength(ssn.length);
      expect(encrypted).toMatch(/^\d{3}-\d{2}-\d{4}$/);
      expect(encrypted).not.toBe(ssn);
    });

    it('Encrypts credit card numbers while preserving format and valid Luhn checksum', () => {
      const cc = '4532-7560-1234-5678';
      const encrypted = fpe.encryptDigits(cc, true);

      expect(encrypted).toHaveLength(cc.length);
      expect(encrypted).toMatch(/^\d{4}-\d{4}-\d{4}-\d{4}$/);
      expect(encrypted).not.toBe(cc);

      // Verify Luhn validity on encrypted output
      const rawDigits = encrypted.replace(/\D/g, '');
      let sum = 0;
      const parity = (rawDigits.length - 2) % 2;
      for (let i = 0; i < rawDigits.length; i++) {
        let digit = parseInt(rawDigits[i], 10);
        if (i % 2 === parity) {
          digit *= 2;
          if (digit > 9) digit -= 9;
        }
        sum += digit;
      }
      expect(sum % 10).toBe(0);
    });

    it('Is deterministic given identical encryption keys', () => {
      const input = '987-65-4321';
      const enc1 = fpe.encryptDigits(input);
      const enc2 = fpe.encryptDigits(input);
      expect(enc1).toBe(enc2);
    });
  });

  describe('FPE-02: Structured Email and Alphanumeric Token Masking', () => {
    it('Preserves email domain and syntactical structure', () => {
      const email = 'alice.smith@enterprise-corp.com';
      const encrypted = fpe.encryptEmail(email);

      expect(encrypted).toContain('@enterprise-corp.com');
      expect(encrypted.startsWith('fpe_')).toBe(true);
      expect(encrypted).not.toContain('alice.smith');
    });

    it('Preserves standard secret prefixes for client compatibility', () => {
      const apiKey = 'sk-proj-99998888777766665555444433332222';
      const encrypted = fpe.encryptAlphanumericToken(apiKey, 8); // 'sk-proj-' prefix

      expect(encrypted.startsWith('sk-proj-')).toBe(true);
      expect(encrypted).toHaveLength(apiKey.length);
      expect(encrypted).not.toBe(apiKey);
    });
  });
});
