import * as fs from 'fs';
import * as yaml from 'js-yaml';
import { ShieldConfig, ShieldConfigSchema } from './policy-engine';

export class ConfigLoader {
  public static load(configPath: string = 'shield.config.default.yaml'): ShieldConfig {
    if (!fs.existsSync(configPath)) {
      throw new Error(`[MCP-SHIELD] Config file not found: ${configPath}`);
    }
    const fileContents = fs.readFileSync(configPath, 'utf8');
    const parsedYaml = yaml.load(fileContents);
    return ShieldConfigSchema.parse(parsedYaml);
  }
}
