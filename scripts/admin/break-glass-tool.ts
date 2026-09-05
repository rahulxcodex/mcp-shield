#!/usr/bin/env node
/**
 * MCP-Shield Internal Administrative Break-Glass Tool
 * 
 * Internal-only tool for emergency master-key operations.
 * Operates strictly over internal administrative channels with individual
 * operator attribution, pre-audit logging, and IP allowlist enforcement.
 */

import * as crypto from 'crypto';

interface BreakGlassOptions {
  action: 'key_revoke' | 'customer_suspend' | 'billing_correct' | 'policy_rollback';
  targetId: string;
  reason: string;
  operatorId: string;
  operatorName?: string;
  adminKey?: string;
  endpoint?: string;
  confirm?: boolean;
}

function parseArgs(): BreakGlassOptions {
  const args = process.argv.slice(2);
  const options: Partial<BreakGlassOptions> = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--action' && args[i + 1]) options.action = args[++i] as any;
    else if (arg === '--target' && args[i + 1]) options.targetId = args[++i];
    else if (arg === '--reason' && args[i + 1]) options.reason = args[++i];
    else if (arg === '--operator' && args[i + 1]) options.operatorId = args[++i];
    else if (arg === '--name' && args[i + 1]) options.operatorName = args[++i];
    else if (arg === '--key' && args[i + 1]) options.adminKey = args[++i];
    else if (arg === '--endpoint' && args[i + 1]) options.endpoint = args[++i];
    else if (arg === '--confirm') options.confirm = true;
  }

  if (!options.action || !options.targetId || !options.reason || !options.operatorId) {
    console.error(`
Error: Missing required parameters.

Usage:
  npx ts-node scripts/admin/break-glass-tool.ts \
    --action <key_revoke|customer_suspend|billing_correct|policy_rollback> \
    --target <targetId> \
    --reason "<mandatory audit rationale (min 5 chars)>" \
    --operator <operatorId> \
    [--name <operatorName>] \
    [--endpoint <adminEndpointUrl>] \
    --confirm
`);
    process.exit(1);
  }

  if (!options.confirm) {
    console.error('Error: Break-glass operations require explicit --confirm flag to execute.');
    process.exit(1);
  }

  return options as BreakGlassOptions;
}

export async function executeBreakGlass(opts: BreakGlassOptions): Promise<void> {
  const adminKey = opts.adminKey || process.env.ADMIN_MASTER_KEY || process.env.MCP_SHIELD_ADMIN_KEY;
  if (!adminKey) {
    console.error('Error: Administrative key required via --key or ADMIN_MASTER_KEY environment variable.');
    process.exit(1);
  }

  const endpoint = opts.endpoint || process.env.ADMIN_BREAK_GLASS_ENDPOINT || 'http://127.0.0.1:3000/api/v1/admin/break-glass';

  console.log('============================================================');
  console.log(' 🚨 INITIATING EMERGENCY BREAK-GLASS OPERATION');
  console.log('============================================================');
  console.log(`Action:       ${opts.action}`);
  console.log(`Target:       ${opts.targetId}`);
  console.log(`Operator:     ${opts.operatorId} (${opts.operatorName || 'Authorized Operator'})`);
  console.log(`Reason:       ${opts.reason}`);
  console.log(`Endpoint:     ${endpoint}`);
  console.log('------------------------------------------------------------');

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${adminKey}`,
    'x-admin-operator': opts.operatorId,
    'x-admin-name': opts.operatorName || `Operator (${opts.operatorId})`,
    'x-request-id': `bg-${crypto.randomUUID()}`,
  };

  const payload = {
    action: opts.action,
    targetId: opts.targetId,
    reason: opts.reason,
    confirmation: 'CONFIRM_BREAK_GLASS',
    params: {
      invokedVia: 'break-glass-cli-tool',
      timestamp: new Date().toISOString(),
    },
  };

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });

    const body = await response.json().catch(() => ({}));

    if (!response.ok) {
      console.error(`❌ Break-glass execution failed [HTTP ${response.status}]:`, body);
      process.exit(1);
    }

    console.log('✅ Break-glass operation executed successfully!');
    console.log(`Audit Record ID: ${body.data?.auditId || body.auditId}`);
    console.log(`Details:         `, body.data?.details || body.details);
    console.log('============================================================');
  } catch (err: any) {
    console.error('❌ Network or connectivity error during break-glass invocation:', err.message);
    process.exit(1);
  }
}

if (require.main === module) {
  const options = parseArgs();
  executeBreakGlass(options);
}
