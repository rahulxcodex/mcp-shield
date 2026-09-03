import { NextRequest, NextResponse } from 'next/server';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { serverId = 'sim-mcp-server', toolName = 'execute_action', payload, activeTier = 'enterprise_strict' } = body;

    const payloadStr = typeof payload === 'string' ? payload : JSON.stringify(payload || {});
    const rationale: string[] = [];
    const triggeredRules: string[] = [];
    let decision: 'ALLOW' | 'BLOCK' | 'SANITIZE' | 'QUARANTINE' = 'ALLOW';

    let capabilityRisk = 15;
    let credentialExposure = 0;
    let destinationRisk = 0;
    let behaviorAnomaly = 0;

    // Check SSRF
    if (payloadStr.includes('169.254') || payloadStr.includes('127.0.0.1') || payloadStr.includes('localhost')) {
      destinationRisk = 40;
      triggeredRules.push('RULE-NET-001: Cloud Metadata / Localhost SSRF Prevention');
      rationale.push('Payload targets private link-local or loopback network interface');
      decision = 'BLOCK';
    }

    // Check Credentials
    if (payloadStr.includes('AKIA') || payloadStr.includes('ghp_') || payloadStr.includes('BEGIN PRIVATE KEY')) {
      credentialExposure = 40;
      triggeredRules.push('RULE-DLP-002: Bijective Tokenizer Canary Mask');
      rationale.push('Payload contains cleartext API/private keys; bijective tokenization required');
      decision = decision === 'BLOCK' ? 'BLOCK' : 'SANITIZE';
    }

    // Check Destructive commands
    if (payloadStr.includes('rm -rf') || payloadStr.includes('Format-Volume') || payloadStr.includes('bash -i')) {
      capabilityRisk += 45;
      triggeredRules.push('RULE-SHELL-003: Destructive Command / Interactive Reverse Shell');
      rationale.push('Destructive host deletion or reverse shell invocation detected');
      decision = 'BLOCK';
    }

    const compositeScore = Math.min(100, capabilityRisk + credentialExposure + destinationRisk + behaviorAnomaly);

    return NextResponse.json({
      success: true,
      simulation: {
        decision,
        compositeRiskScore: compositeScore,
        tier: activeTier,
        triggeredRules,
        rationale,
        executionLatencyEstimateUs: 48,
        alternativeOutcomes: {
          permissive: decision === 'BLOCK' && credentialExposure > 0 ? 'SANITIZE' : decision,
          strict: decision === 'ALLOW' ? 'QUARANTINE' : decision,
        },
      },
      simulatedAt: new Date().toISOString(),
    });
  } catch {
    return NextResponse.json({ error: 'Invalid JSON request payload' }, { status: 400 });
  }
}
