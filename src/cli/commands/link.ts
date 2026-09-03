import * as readline from 'readline';
import { CloudTelemetryPublisher } from '../../cloud/telemetry';

export class LinkCommand {
  public static async run(args: string[] = []): Promise<void> {
    console.log('='.repeat(70));
    console.log('🛡️  MCP-SHIELD CLOUD DASHBOARD PAIRING');
    console.log('   Connect this device to your free MCP-Shield Cloud Console');
    console.log('='.repeat(70));

    let apiKey = '';
    const keyIdx = args.indexOf('--key');
    if (keyIdx !== -1 && args[keyIdx + 1]) {
      apiKey = args[keyIdx + 1].trim();
    }

    let endpoint = process.env.MCP_SHIELD_CLOUD_URL || 'https://mcp-shield-dashboard-d6jyrwkny-rahulsahgupta24-8925.vercel.app/api/v1/telemetry/ingest';
    const urlIdx = args.indexOf('--url');
    if (urlIdx !== -1 && args[urlIdx + 1]) {
      endpoint = args[urlIdx + 1].trim();
    }

    if (!apiKey) {
      apiKey = await this.promptUser('🔑 Enter your MCP-Shield Project API Key (e.g. mcp_live_...): ');
    }

    if (!apiKey) {
      console.error('❌ Error: API Key is required to pair device.');
      process.exit(1);
    }

    const publisher = new CloudTelemetryPublisher();
    publisher.saveConfig({
      enabled: true,
      apiKey,
      cloudEndpoint: endpoint
    });

    console.log('\n✅ [SUCCESS] MCP-Shield paired successfully!');
    console.log(`   Endpoint: ${endpoint}`);
    console.log(`   Key:      ${apiKey.substring(0, 12)}********`);
    console.log('\n💡 Your agent security events & audit logs will now stream live to your dashboard.');
    console.log('   Run: "mcp-shield wrap -- <command>" or "mcp-shield protect" to start.');
  }

  private static promptUser(query: string): Promise<string> {
    const rl = readline.createInterface({
      input: process.stdin as any,
      output: process.stdout as any
    });

    return new Promise((resolve) => {
      rl.question(query, (ans) => {
        rl.close();
        resolve(ans.trim());
      });
    });
  }
}
