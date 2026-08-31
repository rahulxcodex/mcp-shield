import * as crypto from 'crypto';
import { SecretVault } from './vault';

export const SECRET_PATTERNS = [
  { name: 'AWS_ACCESS_KEY', regex: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g },
  { name: 'ANTHROPIC_KEY', regex: /sk-ant-api03-[a-zA-Z0-9\-_]{20,}/g },
  { name: 'OPENAI_KEY', regex: /sk-(?:proj-)?[a-zA-Z0-9\-_]{20,}/g },
  { name: 'SLACK_TOKEN', regex: /xox[baprs]-[a-zA-Z0-9\-_]{10,}/g },
  { name: 'GITHUB_PAT', regex: /ghp_[a-zA-Z0-9]{30,40}|github_pat_[a-zA-Z0-9_]{30,}|gho_[a-zA-Z0-9]{30,40}|ghu_[a-zA-Z0-9]{30,40}|ghs_[a-zA-Z0-9]{30,40}|ghr_[a-zA-Z0-9]{30,40}/g },
  { name: 'GOOGLE_API_KEY', regex: /AIza[0-9A-Za-z\-_]{35}/g },
  { name: 'STRIPE_KEY', regex: /sk_(?:live|test)_[0-9a-zA-Z]{24,}|rk_(?:live|test)_[0-9a-zA-Z]{24,}/g },
  { name: 'HUGGINGFACE_TOKEN', regex: /hf_[a-zA-Z0-9]{34,}/g },
  { name: 'GITLAB_PAT', regex: /glpat-[0-9a-zA-Z\-_]{20,}/g },
  { name: 'JWT_TOKEN', regex: /ey[A-Za-z0-9\-_=]{10,}\.ey[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}/g },
  { name: 'SSH_PRIVATE_KEY', regex: /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----/g }
];

// Load honey tokens from environment
export const HONEY_TOKENS = process.env.MCP_SHIELD_HONEY_TOKENS ? process.env.MCP_SHIELD_HONEY_TOKENS.split(',') : [];

// Combine all patterns into a single Regex. Capture groups map to patterns.
const COMPOUND_REGEX = /((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})|(sk-ant-api03-[a-zA-Z0-9\-_]{20,})|(sk-(?:proj-)?[a-zA-Z0-9\-_]{20,})|(xox[baprs]-[a-zA-Z0-9\-_]{10,})|(ghp_[a-zA-Z0-9]{30,40}|github_pat_[a-zA-Z0-9_]{30,}|gho_[a-zA-Z0-9]{30,40}|ghu_[a-zA-Z0-9]{30,40}|ghs_[a-zA-Z0-9]{30,40}|ghr_[a-zA-Z0-9]{30,40})|(AIza[0-9A-Za-z\-_]{35})|(sk_(?:live|test)_[0-9a-zA-Z]{24,}|rk_(?:live|test)_[0-9a-zA-Z]{24,})|(hf_[a-zA-Z0-9]{34,})|(glpat-[0-9a-zA-Z\-_]{20,})|(ey[A-Za-z0-9\-_=]{10,}\.ey[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,})|(-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----)|\b([a-zA-Z0-9+\/_\-]{40,}={0,2})\b/g;

export class SecretSanitizer {
  private vault = new SecretVault();
  private config?: any;

  constructor(config?: any) {
    this.config = config;
  }

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

  public calculateEntropy(str: string): number {
    const buf = Buffer.from(str, 'utf8');
    const len = buf.length;
    if (len === 0) return 0;
    
    const freqs = this.charFrequencies;
    freqs.fill(0);
    for (let i = 0; i < len; i++) {
      freqs[buf[i]]++;
    }
    
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      const count = freqs[i];
      if (count > 0) {
        const p = count / len;
        entropy -= p * Math.log2(p);
      }
    }
    
    return entropy;
  }

  private isFalsePositiveStructure(candidate: string, prefixContext: string): boolean {
    // 1. UUID standard format: 8-4-4-4-12
    if (/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(candidate)) {
      // UUIDs are IDs, not secret keys unless explicitly in a secret context
      if (!/(key|secret|token|password|auth|credential|api|bearer)/i.test(prefixContext)) {
        return true;
      }
    }

    // 2. Pure Hex Hashes & Checkpoints (Git SHAs, SHA1, SHA256, MD5, SHA512) without secret context
    if (/^[0-9a-fA-F]{32,128}$/.test(candidate) || /^(?:b64|sha|hash|chk)_[0-9a-fA-F]{32,}$/i.test(candidate) || /^(?:b64)?[0-9a-fA-F]{40,}$/i.test(candidate)) {
      if (!/(key|secret|token|password|auth|credential|api|bearer|private)/i.test(prefixContext)) {
        return true;
      }
    }

    // 3. Repeated character or trivial sequences
    const uniqueChars = new Set(candidate).size;
    if (uniqueChars < 8) return true;

    return false;
  }

  public registerSecret(secret: string): string {
    return this.vault.store(secret);
  }

  public sanitize(payload: string): string {
    return payload.replace(COMPOUND_REGEX, (match, aws, anthropic, openai, slack, github, google, stripe, hf, gitlab, jwt, ssh, highEntropy, offset, fullString) => {
      // If it matched a known pattern (groups 1-11), register immediately
      if (aws || anthropic || openai || slack || github || google || stripe || hf || gitlab || jwt || ssh) {
        return this.registerSecret(match);
      }
      
      // If it matched the high entropy fallback (group 12)
      if (highEntropy) {
        if (match.startsWith('[[SHIELD_SECRET_')) return match;
        
        const rawPrefix = fullString.substring(Math.max(0, offset - 50), offset);
        const statementBoundary = Math.max(rawPrefix.lastIndexOf('\n'), rawPrefix.lastIndexOf(';'));
        const prefix = (statementBoundary >= 0 ? rawPrefix.substring(statementBoundary + 1) : rawPrefix).toLowerCase();
        
        // Filter out non-secret structures like hashes and UUIDs in neutral contexts
        if (this.isFalsePositiveStructure(match, prefix)) {
          return match;
        }

        let score = 0;
        const entropy = this.calculateEntropy(match);
        
        if (entropy > 3.8) score += 10;
        if (entropy > 4.2) score += 20;
        if (entropy > 4.6) score += 15;
        if (match.length >= 40) score += 10;
        
        // Context analysis
        if (/(key|secret|token|password|auth|credential|api|bearer|private)[^a-z0-9]/i.test(prefix)) {
           score += 45;
        }

        const threshold = this.config?.confidenceThreshold || 60;
        if (score >= threshold) {
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
