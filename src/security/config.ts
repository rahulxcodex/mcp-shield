import * as fs from 'fs';
import * as yaml from 'js-yaml';
import { ShieldConfig, ShieldConfigSchema } from './policy-engine';

import * as path from 'path';
import * as crypto from 'crypto';

export class ConfigLoader {
  public static resolveConfigPath(customPath?: string): string {
    if (customPath && customPath.trim().length > 0) {
      return path.isAbsolute(customPath) ? customPath : path.resolve(process.cwd(), customPath);
    }
    if (process.env.MCP_SHIELD_CONFIG_PATH) {
      return path.resolve(process.env.MCP_SHIELD_CONFIG_PATH);
    }
    return path.resolve(process.cwd(), 'shield.config.default.yaml');
  }

  public static load(configPath: string = 'shield.config.default.yaml'): ShieldConfig {
    const resolvedPath = this.resolveConfigPath(configPath);
    if (!fs.existsSync(resolvedPath)) {
      console.warn(
        `[MCP-SHIELD] ⚠️  Config file not found at "${resolvedPath}". Active profile: HARDENED_FALLBACK (strict fail-closed enforcement active).`
      );
      return this.getHardenedProfile();
    }
    const fileContents = fs.readFileSync(resolvedPath, 'utf8');

    // Enterprise Tamper-Evident Integrity Check
    const expectedHash = process.env.MCP_SHIELD_CONFIG_SHA256;
    if (expectedHash) {
      const actualHash = crypto.createHash('sha256').update(fileContents).digest('hex');
      if (actualHash.toLowerCase() !== expectedHash.trim().toLowerCase()) {
        throw new Error(
          `[MCP-SHIELD] CONFIG INTEGRITY VIOLATION: File at "${resolvedPath}" was modified. Expected SHA-256 ${expectedHash} but got ${actualHash}.`
        );
      }
    }

    const parsedYaml = yaml.load(fileContents);
    const validatedConfig = ShieldConfigSchema.parse(parsedYaml);
    this.validatePolicySafety(validatedConfig);
    return validatedConfig;
  }

  public static validatePolicySafety(config: ShieldConfig): { isSafe: boolean; warnings: string[] } {
    const warnings: string[] = [];
    const seenRules = new Set<string>();

    for (let i = 0; i < (config.rules || []).length; i++) {
      const rule = config.rules[i];
      if (seenRules.has(rule.id)) {
        warnings.push(`Duplicate rule ID detected: "${rule.id}".`);
      }
      seenRules.add(rule.id);

      // Detect unsafe catch-all allow rule interaction
      const isCatchAll = !rule.targetTools || rule.targetTools.length === 0 || rule.targetTools.includes('*');
      if (isCatchAll && rule.action === 'allow' && rule.priority >= 50) {
        warnings.push(
          `Unsafe rule structure: Catch-all allow rule "${rule.id}" has high priority (${rule.priority}), potentially shadowing subsequent security blocks.`
        );
      }
    }

    return { isSafe: warnings.length === 0, warnings };
  }

  public static getProfile(name: 'developer' | 'secure' | 'enterprise' | 'hardened' | string): ShieldConfig {
    switch ((name || '').toLowerCase()) {
      case 'developer':
        return this.getDeveloperProfile();
      case 'secure':
        return this.getSecureProfile();
      case 'enterprise':
        return this.getEnterpriseProfile();
      default:
        return this.getHardenedProfile();
    }
  }

  public static getDeveloperProfile(): ShieldConfig {
    return {
      version: '1.0',
      profile: 'developer',
      mode: 'enforce',
      onError: 'block',
      redaction: { enabled: true, maskStyle: 'token', highEntropyCheck: true, entropyThreshold: 4.5 },
      sandbox: { cowEnabled: true, cowStagingDir: '.mcp-shield/cow', autoCommitOnApproval: true, readOnlyWorkspace: false },
      egress: { enabled: true, allowMode: 'allow', allowPrivateNetworks: false, blockLoopback: true, blockLinkLocal: true, blockMetadataEndpoints: true },
      rules: [
        { id: 'allow-safe', name: 'Allow safe tools', priority: 10, targetTools: ['*read*', '*list*', '*search*'], riskLevel: 'LOW', action: 'allow' },
        { id: 'block-destructive-rm', name: 'Block Recursive Root Deletion', priority: 100, targetTools: ['*bash*', '*terminal*', '*exec*'], riskLevel: 'CRITICAL', action: 'block' }
      ],
      audit: { enabled: true, logDir: '.mcp-shield/logs', tamperEvidentHashing: true }
    };
  }

  public static getSecureProfile(): ShieldConfig {
    return {
      version: '1.0',
      profile: 'secure',
      mode: 'enforce',
      onError: 'block',
      redaction: { enabled: true, maskStyle: 'token', highEntropyCheck: true, entropyThreshold: 4.0 },
      sandbox: { cowEnabled: true, cowStagingDir: '.mcp-shield/cow', autoCommitOnApproval: false, readOnlyWorkspace: true },
      egress: { enabled: true, allowMode: 'deny', allowedDomains: [], blockedDomains: [], allowPrivateNetworks: false, blockLoopback: true, blockLinkLocal: true, blockMetadataEndpoints: true },
      rules: [
        { id: 'allow-read-only', name: 'Allow read-only queries', priority: 10, targetTools: ['*read*', '*list*', '*search*'], riskLevel: 'LOW', action: 'allow' },
        { id: 'block-all-shell', name: 'Block shell execution', priority: 90, targetTools: ['*bash*', '*terminal*', '*exec*'], riskLevel: 'HIGH', action: 'block' }
      ],
      audit: { enabled: true, logDir: '.mcp-shield/logs', tamperEvidentHashing: true }
    };
  }

  public static getEnterpriseProfile(): ShieldConfig {
    return {
      version: '1.0',
      profile: 'enterprise',
      mode: 'enforce',
      onError: 'block',
      redaction: { enabled: true, maskStyle: 'hash', highEntropyCheck: true, entropyThreshold: 3.8 },
      sandbox: { cowEnabled: true, cowStagingDir: '.mcp-shield/cow', autoCommitOnApproval: false, readOnlyWorkspace: true },
      egress: { enabled: true, allowMode: 'deny', allowedDomains: [], blockedDomains: [], allowPrivateNetworks: false, blockLoopback: true, blockLinkLocal: true, blockMetadataEndpoints: true },
      rules: [
        { id: 'allow-verified', name: 'Allow verified tools', priority: 10, targetTools: ['*read*', '*list*'], riskLevel: 'LOW', action: 'allow' },
        { id: 'quarantine-unknown', name: 'Quarantine high risk', priority: 100, targetTools: ['*bash*', '*terminal*', '*exec*'], riskLevel: 'CRITICAL', action: 'block' }
      ],
      audit: { enabled: true, logDir: '.mcp-shield/logs', tamperEvidentHashing: true }
    };
  }

  public static getHardenedProfile(): ShieldConfig {
    return this.getSecureProfile();
  }
}
