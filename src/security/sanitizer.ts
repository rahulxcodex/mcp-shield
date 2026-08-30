import * as crypto from 'crypto';

export const SECRET_PATTERNS = [
  { name: 'AWS_ACCESS_KEY', regex: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g },
  { name: 'GITHUB_PAT', regex: /ghp_[a-zA-Z0-9]{36}/g },
  { name: 'OPENAI_KEY', regex: /sk-(?:proj-)?[a-zA-Z0-9]{20,}/g },
  { name: 'SSH_PRIVATE_KEY', regex: /-----BEGIN [A-Z]+ PRIVATE KEY-----[a-zA-Z0-9+/\s=]+-----END [A-Z]+ PRIVATE KEY-----/g }
];

export const HONEY_TOKENS = [
  'AKIA_HONEY_TOKEN_DO_NOT_USE_123',
  'ghp_honey_token_do_not_use_12345678901'
];

// Combine all patterns into a single Regex. Capture groups map to patterns.
// Group 1: AWS
// Group 2: GitHub
// Group 3: OpenAI
// Group 4: SSH
// Group 5: High Entropy fallback
const COMPOUND_REGEX = /((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})|(ghp_[a-zA-Z0-9]{36})|(sk-(?:proj-)?[a-zA-Z0-9]{20,})|(-----BEGIN [A-Z]+ PRIVATE KEY-----[a-zA-Z0-9+/\s=]+-----END [A-Z]+ PRIVATE KEY-----)|([a-zA-Z0-9+/=]{20,})/g;

export class SecretSanitizer {
  private secretToToken = new Map<string, string>();
  private tokenToSecret = new Map<string, string>();
  private readonly MAX_CACHE_SIZE = 1000;
  
  // Eviction Ring Buffer (Replaces iterator allocations)
  private evictionRing = new Array<string>(1000);
  private ringIndex = 0;
  private currentSize = 0;

  // Pre-allocated array for entropy calculation (0 allocations per check)
  private charFrequencies = new Uint32Array(256);

  public checkHoneyTokens(payload: string): boolean {
    for (const token of HONEY_TOKENS) {
      if (payload.includes(token)) return true;
    }
    return false;
  }

  private calculateEntropy(str: string): number {
    const len = str.length;
    if (len === 0) return 0;
    
    // Count frequencies using pre-allocated typed array
    for (let i = 0; i < len; i++) {
      this.charFrequencies[str.charCodeAt(i) & 0xFF]++;
    }
    
    let entropy = 0;
    // Calculate entropy and clear array in the same pass
    for (let i = 0; i < 256; i++) {
      const count = this.charFrequencies[i];
      if (count > 0) {
        const p = count / len;
        entropy -= p * Math.log2(p);
        this.charFrequencies[i] = 0; // Reset for next use without reallocating
      }
    }
    
    return entropy;
  }

  private registerSecret(secret: string): string {
    if (this.secretToToken.has(secret)) {
      return this.secretToToken.get(secret)!;
    }

    if (this.currentSize >= this.MAX_CACHE_SIZE) {
      // Evict oldest using ring buffer
      const oldestSecret = this.evictionRing[this.ringIndex];
      const oldToken = this.secretToToken.get(oldestSecret)!;
      this.secretToToken.delete(oldestSecret);
      this.tokenToSecret.delete(oldToken);
    } else {
      this.currentSize++;
    }

    const token = `[[SHIELD_SECRET_${crypto.randomUUID()}]]`;
    this.secretToToken.set(secret, token);
    this.tokenToSecret.set(token, secret);
    
    // Store in ring buffer and advance
    this.evictionRing[this.ringIndex] = secret;
    this.ringIndex = (this.ringIndex + 1) % this.MAX_CACHE_SIZE;

    return token;
  }

  public sanitize(payload: string): string {
    // Single-pass Lexer for all patterns and entropy! Time complexity reduced from O(K*N) to O(N)
    return payload.replace(COMPOUND_REGEX, (match, aws, github, openai, ssh, highEntropy) => {
      // If it matched a known pattern (groups 1-4), register immediately
      if (aws || github || openai || ssh) {
        return this.registerSecret(match);
      }
      
      // If it matched the high entropy fallback (group 5)
      if (highEntropy) {
        // Skip already tokenized sections (avoids recursive matching edge cases)
        if (match.startsWith('[[SHIELD_SECRET_')) return match;
        
        const entropy = this.calculateEntropy(match);
        if (entropy > 4.2) {
          return this.registerSecret(match);
        }
      }
      return match;
    });
  }

  public restore(payload: string): string {
    const tokenRegex = /\[\[SHIELD_SECRET_[0-9a-fA-F-]{36}\]\]/g;
    return payload.replace(tokenRegex, (match) => {
      if (this.tokenToSecret.has(match)) {
        return this.tokenToSecret.get(match)!;
      }
      return match;
    });
  }
}
