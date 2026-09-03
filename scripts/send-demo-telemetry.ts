import { CloudTelemetryPublisher, SecurityTelemetryPayload } from '../src/cloud/telemetry';

async function main() {
  console.log('='.repeat(70));
  console.log('🛡️  MCP-SHIELD LIVE TELEMETRY STREAM GENERATOR');
  console.log('='.repeat(70));

  const targetUrl = process.env.MCP_SHIELD_CLOUD_URL || 'http://localhost:3000/api/v1/telemetry/ingest';
  const apiKey = process.env.MCP_SHIELD_API_KEY || 'mcp_live_sec_89b21a_mock';

  console.log(`📡 Ingest Endpoint: ${targetUrl}`);
  console.log(`🔑 Key Prefix:      ${apiKey.substring(0, 12)}...`);

  const publisher = new CloudTelemetryPublisher({
    enabled: true,
    cloudEndpoint: targetUrl,
    apiKey: apiKey,
    batchIntervalMs: 1000,
    maxBatchSize: 5
  });

  const demoEvents: SecurityTelemetryPayload[] = [
    {
      sessionId: `sess-${Date.now()}-1`,
      eventType: 'BLOCK',
      detector: 'Tree-sitter AST',
      riskLevel: 'CRITICAL',
      toolName: 'bash_exec',
      reason: 'Root deletion sequence rm -rf / intercepted in AST syntax node',
      clientTimestamp: new Date().toISOString()
    },
    {
      sessionId: `sess-${Date.now()}-2`,
      eventType: 'SANITIZE',
      detector: 'Bijective FPE DLP',
      riskLevel: 'HIGH',
      toolName: 'read_config',
      reason: 'AWS Access Key AKIAIOSFODNN7EXAMPLE tokenized with format-preserving surrogate',
      clientTimestamp: new Date().toISOString()
    },
    {
      sessionId: `sess-${Date.now()}-3`,
      eventType: 'BLOCK',
      detector: 'SSRF / Cloud Metadata',
      riskLevel: 'CRITICAL',
      toolName: 'http_request',
      reason: 'Prohibited connection attempt to 169.254.169.254 (AWS IMDS)',
      clientTimestamp: new Date().toISOString()
    },
    {
      sessionId: `sess-${Date.now()}-4`,
      eventType: 'QUARANTINE',
      detector: 'Canary Honeytoken',
      riskLevel: 'CRITICAL',
      toolName: 'database_query',
      reason: 'Prompt injection attempted to exfiltrate decoy honeytoken mcp_honey_decoy_k8s',
      clientTimestamp: new Date().toISOString()
    }
  ];

  console.log(`\n🚀 Dispatching ${demoEvents.length} simulated security events...`);

  for (const event of demoEvents) {
    publisher.trackEvent(event);
    console.log(`   ⚡ Tracked [${event.eventType}] - ${event.toolName} (${event.detector})`);
  }

  const flushed = await publisher.flush();
  if (flushed) {
    console.log('\n✅ Telemetry payload successfully signed and sent to console.');
  } else {
    console.log('\n⚠️ Could not connect to endpoint (server may not be running yet). Events cached locally.');
  }

  publisher.stop();
  process.exit(0);
}

main().catch((err) => {
  console.error('Error generating telemetry:', err.message);
  process.exit(1);
});
