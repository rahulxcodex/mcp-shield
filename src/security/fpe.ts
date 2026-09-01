import * as crypto from 'crypto';

export interface FpeOptions {
  secretKey?: string;
  tweak?: string;
}

export class FormatPreservingEncryptor {
  private key: Buffer;

  constructor(options?: FpeOptions) {
    const rawKey = options?.secretKey || process.env.MCP_SHIELD_FPE_KEY || 'default-mcp-shield-fpe-master-secret-key-32b';
    this.key = crypto.createHash('sha256').update(rawKey).digest();
  }

  /**
   * Generates a deterministic pseudorandom permutation of digits preserving length and Luhn checksum if applicable
   */
  public encryptDigits(digits: string, preserveLuhn: boolean = false): string {
    const cleaned = digits.replace(/\D/g, '');
    if (cleaned.length === 0) return digits;

    const hmac = crypto.createHmac('sha256', this.key).update(cleaned).digest('hex');
    let result = '';
    for (let i = 0; i < cleaned.length; i++) {
      const shift = parseInt(hmac[i % hmac.length], 16) % 10;
      const originalDigit = parseInt(cleaned[i], 10);
      result += ((originalDigit + shift) % 10).toString();
    }

    if (preserveLuhn && result.length >= 13) {
      result = this.fixLuhnChecksum(result);
    }

    // Reconstruct with original non-digit characters if any
    let digitIdx = 0;
    let formatted = '';
    for (let i = 0; i < digits.length; i++) {
      if (/\d/.test(digits[i])) {
        formatted += result[digitIdx++];
      } else {
        formatted += digits[i];
      }
    }
    return formatted;
  }

  /**
   * Format-preserving masking for email addresses (preserves domain and username length structure)
   */
  public encryptEmail(email: string): string {
    const parts = email.split('@');
    if (parts.length !== 2) return this.encryptDigits(email);
    const [user, domain] = parts;
    const hmac = crypto.createHmac('sha256', this.key).update(user).digest('hex').substring(0, Math.max(user.length, 6));
    return `fpe_${hmac}@${domain}`;
  }

  /**
   * Format-preserving encryption for structured alphanumeric tokens (e.g. sk-proj-..., ghp_...)
   */
  public encryptAlphanumericToken(token: string, prefixLength: number = 7): string {
    if (token.length <= prefixLength) return token;
    const prefix = token.slice(0, prefixLength);
    const secretPart = token.slice(prefixLength);
    const hmac = crypto.createHmac('sha256', this.key).update(secretPart).digest('base64url').substring(0, secretPart.length);
    return `${prefix}${hmac}`;
  }

  private fixLuhnChecksum(digits: string): string {
    const chars = digits.split('').map(Number);
    // Calculate current Luhn sum excluding last digit
    let sum = 0;
    const nDigits = chars.length;
    const parity = (nDigits - 2) % 2;

    for (let i = 0; i < nDigits - 1; i++) {
      let val = chars[i];
      if (i % 2 === parity) {
        val *= 2;
        if (val > 9) val -= 9;
      }
      sum += val;
    }

    const checkDigit = (10 - (sum % 10)) % 10;
    chars[chars.length - 1] = checkDigit;
    return chars.join('');
  }
}
