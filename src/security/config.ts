import * as fs from 'fs';
import * as yaml from 'js-yaml';
import { ShieldConfig, ShieldConfigSchema } from './policy-engine';

export class ConfigLoader {
  public static load(configPath: string = 'shield.config.default.yaml'): ShieldConfig {
    if (!fs.existsSync(configPath)) {
      console.warn(`[MCP-SHIELD] Config file not found at ${configPath}. Falling back to 'hardened' profile.`);
      return this.getHardenedProfile();
    }
    const fileContents = fs.readFileSync(configPath, 'utf8');
    const parsedYaml = yaml.load(fileContents);
    return ShieldConfigSchema.parse(parsedYaml);
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
        { id: "allow-safe", name: "Allow safe tools", priority: 10, riskLevel: "LOW", action: "sandbox" },
        { id: "block-destructive", name: "Block Destructive", priority: 100, targetTools: ["*bash*", "*terminal*"], riskLevel: "CRITICAL", action: "block" }
      ],
      audit: { enabled: true, logDir: '.mcp-shield/logs', tamperEvidentHashing: true }
    };
  }
}
