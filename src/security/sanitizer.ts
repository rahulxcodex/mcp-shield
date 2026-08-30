import * as crypto from 'crypto';

export const SECRET_PATTERNS = [
  { name: 'AWS_ACCESS_KEY', regex: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g },
  { name: 'GITHUB_PAT', regex: /ghp_[a-zA-Z0-9]{36}/g },
  { name: 'OPENAI_KEY', regex: /sk-(?:proj-)?[a-zA-Z0-9]{20,}/g },
  { name: 'SSH_PRIVATE_KEY', regex: /-----BEGIN [A-Z]+ PRIVATE KEY-----[a-zA-Z0-9+/\s=]+-----END [A-Z]+ PRIVATE KEY-----/g }
];

export class SecretSanitizer {
  private secretToToken = new Map<string, string>();
  private tokenToSecret = new Map<string, string>();
  private readonly MAX_CACHE_SIZE = 1000;

  private calculateEntropy(str: string): number {
    const len = str.length;
    if (len === 0) return 0;
    const frequencies: Record<string, number> = {};
    for (let i = 0; i < len; i++) {
      const char = str[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    for (const key in frequencies) {
      const p = frequencies[key] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  private registerSecret(secret: string): string {
    if (this.secretToToken.has(secret)) {
      return this.secretToToken.get(secret)!;
    }

    if (this.secretToToken.size >= this.MAX_CACHE_SIZE) {
      const firstKey = this.secretToToken.keys().next().value;
      if (firstKey) {
        const token = this.secretToToken.get(firstKey)!;
        this.secretToToken.delete(firstKey);
        this.tokenToSecret.delete(token);
      }
    }

    const token = `[[SHIELD_SECRET_${crypto.randomUUID()}]]`;
    this.secretToToken.set(secret, token);
    this.tokenToSecret.set(token, secret);
    return token;
  }

  public sanitize(payload: string): string {
    let sanitized = payload;
    
    for (const pattern of SECRET_PATTERNS) {
      sanitized = sanitized.replace(pattern.regex, (match) => {
        return this.registerSecret(match);
      });
    }

    // High Entropy check for long strings (e.g., base64 tokens)
    const longWordsRegex = /[a-zA-Z0-9+/=]{20,}/g;
    sanitized = sanitized.replace(longWordsRegex, (match) => {
      if (match.startsWith('[[SHIELD_SECRET_')) return match;
      
      const entropy = this.calculateEntropy(match);
      if (entropy > 4.2) {
        return this.registerSecret(match);
      }
      return match;
    });

    return sanitized;
  }

  public restore(payload: string): string {
    let restored = payload;
    const tokenRegex = /\[\[SHIELD_SECRET_[0-9a-fA-F-]{36}\]\]/g;
    restored = restored.replace(tokenRegex, (match) => {
      if (this.tokenToSecret.has(match)) {
        return this.tokenToSecret.get(match)!;
      }
      return match;
    });

    return restored;
  }
}
