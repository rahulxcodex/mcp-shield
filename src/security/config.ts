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

  public static getHardenedProfile(): ShieldConfig {
    return {
      version: '1.1',
      profile: 'hardened',
      mode: 'enforce',
      onError: 'block',
      redaction: { enabled: true, maskStyle: 'hash', highEntropyCheck: true, entropyThreshold: 4.0 },
      sandbox: { cowEnabled: true, cowStagingDir: '.mcp-shield/cow', autoCommitOnApproval: false },
      egress: { 
         enabled: true, 
         allowMode: 'deny', 
         allowedDomains: [], 
         blockedDomains: [],
         allowPrivateNetworks: false, 
         blockLoopback: true, 
         blockLinkLocal: true, 
         blockMetadataEndpoints: true 
      },
      rules: [
        { id: "allow-read-only", name: "Allow read-only queries", priority: 10, targetTools: ["*read*", "*list*", "*search*", "*get*", "*describe*", "*info*"], riskLevel: "LOW", action: "allow" },
        { id: "block-destructive", name: "Block Destructive", priority: 100, targetTools: ["*bash*", "*terminal*"], riskLevel: "CRITICAL", action: "block" }
      ],
      audit: { enabled: true, logDir: '.mcp-shield/logs', tamperEvidentHashing: true }
    };
  }
}
