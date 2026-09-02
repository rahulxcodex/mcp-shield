import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { LicenseManager } from '../../security/license-manager';

export class LicenseCommand {
  public static run(key: string) {
    if (!key) {
      console.error('❌ Please provide a license key. Usage: mcp-shield license <key>');
      console.log('To obtain a key, visit your Vercel Enterprise Control Plane.');
      process.exit(1);
    }

    const licenseManager = new LicenseManager();
    try {
      licenseManager.verifyLicense(key);
      
      const configDir = path.join(os.homedir(), '.mcp-shield');
      if (!fs.existsSync(configDir)) {
        fs.mkdirSync(configDir, { recursive: true });
      }
      
      fs.writeFileSync(path.join(configDir, 'license.key'), key.trim());
      console.log('✅ License key installed successfully! MCP Shield is now activated.');
    } catch (e: any) {
      console.error('❌ Invalid or expired license key:', e.message);
      process.exit(1);
    }
  }
}
