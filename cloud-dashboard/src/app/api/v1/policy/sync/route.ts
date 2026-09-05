import { createAdminSupabaseClient } from '@/lib/supabase';
import { jsonSuccess, jsonError } from '@/lib/errors';
import * as crypto from 'crypto';

export const runtime = 'nodejs';

export interface PolicyRule {
  id: string;
  name: string;
  action: 'BLOCK' | 'SANITIZE' | 'QUARANTINE' | 'PROMPT';
  target: 'tool_call' | 'tool_output' | 'system_command' | 'network_egress';
  condition: string;
  message: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

export interface SignedPolicyManifest {
  manifestVersion: string;
  policyVersion: string;
  organizationId: string;
  projectId?: string;
  issuedAt: number;
  expiresAt: number;
  algorithm: 'Ed25519';
  rules: PolicyRule[];
  signature: string;
}

const BASELINE_PRODUCTION_RULES: PolicyRule[] = [
  {
    id: 'SEC-POL-001',
    name: 'Block Destructive Filesystem Execution',
    action: 'BLOCK',
    target: 'system_command',
    condition: 'cmd.matches("(rm\\s+-rf|del\\s+/s|format\\s+[a-z]:|mkfs)")',
    message: 'Destructive filesystem manipulation commands are strictly blocked by security policy.',
    severity: 'CRITICAL',
  },
  {
    id: 'SEC-POL-002',
    name: 'Bijective Secret DLP Sanitization',
    action: 'SANITIZE',
    target: 'tool_output',
    condition: 'output.containsPattern("SECRET_OR_API_KEY")',
    message: 'Cryptographic secret pattern detected and sanitized via format-preserving DLP vault.',
    severity: 'HIGH',
  },
  {
    id: 'SEC-POL-003',
    name: 'Prevent Untrusted Egress on Secret Read',
    action: 'QUARANTINE',
    target: 'network_egress',
    condition: 'session.hasReadLocalSecrets && egress.isUntrusted',
    message: 'Unverified outbound network egress quarantined following access to local credentials.',
    severity: 'CRITICAL',
  },
  {
    id: 'SEC-POL-004',
    name: 'Database Mutation Step-up Prompt',
    action: 'PROMPT',
    target: 'tool_call',
    condition: 'tool.name.matches("(sql_execute|query_db)") && args.query.matches("(DROP|ALTER|TRUNCATE)")',
    message: 'Irreversible database schema mutation requires human-in-the-loop authorization.',
    severity: 'HIGH',
  },
  {
    id: 'SEC-POL-005',
    name: 'Dynamic Code Evaluation Containment',
    action: 'BLOCK',
    target: 'tool_call',
    condition: 'tool.name == "eval" || args.command.matches("(eval|exec)\\s*\\(")',
    message: 'Dynamic in-memory code evaluation is prohibited under zero-trust enterprise posture.',
    severity: 'CRITICAL',
  },
];

const POLICY_VERSION = '2026.09.4';

function signPolicyBundle(payloadString: string, privateKeyPem?: string): string {
  if (!privateKeyPem) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('ED25519_SIGNING_KEY_REQUIRED: LICENSE_PRIVATE_KEY is required in production.');
    }
    return crypto.createHash('sha256').update(payloadString).digest('base64');
  }
  try {
    const formattedKey = privateKeyPem.replace(/\\n/g, '\n').trim();
    const signature = crypto.sign(null, Buffer.from(payloadString), formattedKey);
    return signature.toString('base64');
  } catch (err) {
    console.error('Ed25519 Policy Signing Error:', err);
    if (process.env.NODE_ENV === 'production') {
      throw new Error('POLICY_SIGNING_FAILED: Failed to sign policy manifest with Ed25519 key.');
    }
    return crypto.createHash('sha256').update(payloadString).digest('base64');
  }
}

export async function GET(req: Request) {
  const url = new URL(req.url);
  const organizationIdParam = url.searchParams.get('organization_id') || 'org-global';
  const projectIdParam = url.searchParams.get('project_id') || undefined;

  const etag = `W/"policy-${POLICY_VERSION}-${organizationIdParam}-${projectIdParam || 'all'}"`;
  const ifNoneMatch = req.headers.get('if-none-match');
  if (ifNoneMatch === etag) {
    return new Response(null, { status: 304, headers: { ETag: etag } });
  }

  const now = Date.now();
  const expiresAt = now + 60 * 60 * 1000;

  const unsignedManifest = {
    manifestVersion: '2.0.0',
    policyVersion: POLICY_VERSION,
    organizationId: organizationIdParam,
    projectId: projectIdParam,
    issuedAt: now,
    expiresAt,
    algorithm: 'Ed25519' as const,
    rules: BASELINE_PRODUCTION_RULES,
  };

  const payloadString = JSON.stringify(unsignedManifest);
  const signature = signPolicyBundle(payloadString, process.env.LICENSE_PRIVATE_KEY);

  const signedManifest: SignedPolicyManifest = {
    ...unsignedManifest,
    signature,
  };

  return jsonSuccess(signedManifest, 200, {
    ETag: etag,
    'Cache-Control': 'public, max-age=3600, must-revalidate',
  });
}
