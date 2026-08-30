import * as crypto from 'crypto';
import { SecretVault } from './vault';

export const SECRET_PATTERNS = [
  { name: 'AWS_ACCESS_KEY', regex: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g },
  { name: 'ANTHROPIC_KEY', regex: /sk-ant-api03-[a-zA-Z0-9\-_]{20,}/g },
  { name: 'OPENAI_KEY', regex: /sk-(?:proj-)?[a-zA-Z0-9]{20,}/g },
  { name: 'SLACK_TOKEN', regex: /xox[baprs]-[a-zA-Z0-9]{10,}/g },
  { name: 'GITHUB_PAT', regex: /ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{82}/g },
  { name: 'GOOGLE_API_KEY', regex: /AIza[0-9A-Za-z\-_]{35}/g },
  { name: 'STRIPE_KEY', regex: /sk_(?:live|test)_[0-9a-zA-Z]{24,}/g },
  { name: 'HUGGINGFACE_TOKEN', regex: /hf_[a-zA-Z0-9]{34,}/g },
  { name: 'GITLAB_PAT', regex: /glpat-[0-9a-zA-Z\-_]{20,}/g },
  { name: 'JWT_TOKEN', regex: /ey[A-Za-z0-9\-_=]{10,}\.ey[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}/g },
  { name: 'SSH_PRIVATE_KEY', regex: /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----/g }
];

// Load honey tokens from environment, as hardcoding them in an OSS repo defeats their purpose
export const HONEY_TOKENS = process.env.MCP_SHIELD_HONEY_TOKENS ? process.env.MCP_SHIELD_HONEY_TOKENS.split(',') : [];

// Combine all patterns into a single Regex. Capture groups map to patterns.
const COMPOUND_REGEX = /((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})|(sk-ant-api03-[a-zA-Z0-9\-_]{20,})|(sk-(?:proj-)?[a-zA-Z0-9]{20,})|(xox[baprs]-[a-zA-Z0-9]{10,})|(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{82})|(AIza[0-9A-Za-z\-_]{35})|(sk_(?:live|test)_[0-9a-zA-Z]{24,})|(hf_[a-zA-Z0-9]{34,})|(glpat-[0-9a-zA-Z\-_]{20,})|(ey[A-Za-z0-9\-_=]{10,}\.ey[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,})|(-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----)|([a-zA-Z0-9+\/=\-_]{40,})/g;

export class SecretSanitizer {
  private vault = new SecretVault();

  // Pre-allocated array for entropy calculation (0 allocations per check)
  private charFrequencies = new Uint32Array(256);

  public checkHoneyTokens(payload: string): boolean {
    if (!payload) return false;
    const envTokens = process.env.MCP_SHIELD_HONEY_TOKENS ? process.env.MCP_SHIELD_HONEY_TOKENS.split(',') : [];
    const allTokens = [...HONEY_TOKENS, ...envTokens];
    for (const token of allTokens) {
      const trimmed = (token || '').trim();
      if (trimmed.length > 0 && payload.includes(trimmed)) return true;
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
    return this.vault.store(secret);
  }

  public sanitize(payload: string): string {
    // Single-pass Lexer for all patterns and entropy! Time complexity reduced from O(K*N) to O(N)
    return payload.replace(COMPOUND_REGEX, (match, aws, anthropic, openai, slack, github, google, stripe, hf, gitlab, jwt, ssh, highEntropy) => {
      // If it matched a known pattern (groups 1-11), register immediately
      if (aws || anthropic || openai || slack || github || google || stripe || hf || gitlab || jwt || ssh) {
        return this.registerSecret(match);
      }
      
      // If it matched the high entropy fallback (group 12)
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
      const secret = this.vault.retrieve(match);
      if (secret) {
        return secret;
      }
      return match;
    });
  }
}
