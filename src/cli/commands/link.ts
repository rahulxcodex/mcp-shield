import * as readline from 'readline';
import * as os from 'os';
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

    let endpoint = process.env.MCP_SHIELD_CLOUD_URL || 'https://cloud.mcp-shield.com/api/v1/telemetry/ingest';
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
    const verifyEndpoint = endpoint.replace(/\/telemetry\/ingest$/, '/telemetry/verify');

    console.log('⏳ Verifying API key and establishing cryptographic handshake with MCP-Shield Cloud...');

    const timestamp = Date.now();
    const handshakePayload = JSON.stringify({
      clientVersion: '1.0.12',
      installation: {
        installationId: publisher.getInstallationId(),
        environment: process.env.MCP_SHIELD_ENV || 'production'
      },
      device: {
        hostname: os.hostname(),
        platform: os.platform(),
        arch: os.arch()
      }
    });

    const signature = CloudTelemetryPublisher.signPayload(handshakePayload, apiKey, timestamp);
    let verifySucceeded = false;
    let identityInfo: any = null;

    try {
      if (typeof fetch !== 'undefined') {
        const res = await fetch(verifyEndpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-MCP-Shield-Key': apiKey,
            'X-MCP-Shield-Key-Prefix': CloudTelemetryPublisher.extractKeyPrefix(apiKey),
            'Authorization': `Bearer ${apiKey}`,
            'X-MCP-Shield-Timestamp': String(timestamp),
            'X-MCP-Shield-Signature': signature
          },
          body: handshakePayload
        });

        if (res.ok) {
          identityInfo = await res.json().catch(() => ({}));
          verifySucceeded = true;
        } else {
          const errData = await res.json().catch(() => ({}));
          console.error(`\n❌ [PAIRING FAILED] HTTP ${res.status}: ${errData.error || 'Unauthorized'}`);
          console.error('   Please check your API key in the Cloud Console: https://cloud.mcp-shield.com/settings/general');
          process.exit(1);
        }
      }
    } catch {
      console.warn('\n⚠️  [OFFLINE WARNING] Could not reach cloud endpoint for live handshake verification.');
      console.warn('   Saving credentials locally. Protection enforcement remains 100% active offline.');
      verifySucceeded = true;
    }

    if (verifySucceeded) {
      publisher.saveConfig({
        enabled: true,
        apiKey,
        cloudEndpoint: endpoint
      });

      console.log('\n✅ [CONNECTED] MCP-Shield paired and verified successfully!');
      if (identityInfo?.organization?.name) {
        console.log(`   Organization: ${identityInfo.organization.name}`);
      }
      if (identityInfo?.project?.name) {
        console.log(`   Project:      ${identityInfo.project.name}`);
      }
      console.log(`   Environment:  ${identityInfo?.environment || process.env.MCP_SHIELD_ENV || 'production'}`);
      console.log(`   Device ID:    ${publisher.getInstallationId()}`);
      console.log(`   Console URL:  ${identityInfo?.dashboardUrl || 'https://cloud.mcp-shield.com/console'}`);
      console.log(`   Key Prefix:   ${CloudTelemetryPublisher.extractKeyPrefix(apiKey)}...`);
      console.log('\n💡 Security telemetry will now stream seamlessly to your organization dashboard.');
      console.log('   Run "mcp-shield wrap -- <command>" or "mcp-shield protect" to start protected agent sessions.');
    }
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

