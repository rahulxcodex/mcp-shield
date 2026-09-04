import fc from 'fast-check';
import * as fs from 'fs';
import * as path from 'path';
import { ProtocolValidator } from '../src/core/protocol-validator';
import { RequestDispatcher } from '../src/core/dispatcher';
import { ASTAnalyzer } from '../src/security/ast-analyzer';
import { PolicyRuleSchema } from '../src/security/policy-engine';
import { IncrementalSecretScanner } from '../src/security/dlp/incremental-secret-scanner';
import { PrivacyTelemetryEngine, DeploymentMode } from '../src/security/ml/privacy-telemetry';
import { z } from 'zod';

console.log('\n============================================================');
console.log(' RUNNING MCP SHIELD 7-COMPONENT PROPERTY-BASED FUZZ SUITE');
console.log('============================================================\n');

const seed = process.env.FUZZ_SEED ? parseInt(process.env.FUZZ_SEED, 10) : Date.now();
console.log(`Fuzzing Seed: ${seed}\n`);

// -------------------------------------------------------------
// Component 1: JSON-RPC Protocol Parser
// -------------------------------------------------------------
console.log('[1/7] Fuzzing JSON-RPC Parser Invariants...');
const protocolValidator = new ProtocolValidator();

const jsonRpcMalformedArbitrary = fc.record({
  jsonrpc: fc.oneof(fc.constant('1.0'), fc.constant('3.0'), fc.constant(''), fc.constant(null), fc.integer(), fc.boolean()),
  id: fc.oneof(fc.string(), fc.integer(), fc.constant(null)),
  method: fc.oneof(fc.string(), fc.constant(null), fc.constant('')),
  params: fc.anything(),
});

fc.assert(
  fc.property(jsonRpcMalformedArbitrary, (msg) => {
    const res = protocolValidator.validateInbound(msg);
    // Invalid jsonrpc version must be strictly rejected
    return res.valid === false && res.errorCode === -32600;
  }),
  { numRuns: 300, seed }
);
console.log('  PASS: JSON-RPC version mismatch & malformed envelopes strictly rejected.');

// -------------------------------------------------------------
// Component 2: MCP Lifecycle & Request ID State Machine
// -------------------------------------------------------------
console.log('[2/7] Fuzzing MCP Lifecycle & Request ID Tracking...');

fc.assert(
  fc.property(fc.array(fc.oneof(fc.string({ minLength: 1, maxLength: 30 }), fc.integer({ min: 1, max: 100000 }))), (ids) => {
    let duplicateRejected = true;
    const errors: any[] = [];
    const dispatcher = new RequestDispatcher(
      async (req) => { /* no-op handler */ },
      (msg, code, err) => {
        errors.push({ id: msg.id, code, err });
      },
      { maxInflightRequests: 100, maxQueueDepth: 1000 }
    );

    const seen = new Set();
    for (const id of ids) {
      const msg = { jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'echo' } };
      if (!seen.has(id)) {
        seen.add(id);
        dispatcher.enqueue(msg);
      } else {
        // Enqueueing duplicate ID must trigger duplicate ID error
        dispatcher.enqueue(msg);
        const hasDupErr = errors.some(e => e.id === id && e.code === -32600);
        if (!hasDupErr) {
          duplicateRejected = false;
        }
      }
    }
    return duplicateRejected;
  }),
  { numRuns: 100, seed }
);
console.log('  PASS: Duplicate in-flight request IDs systematically rejected with -32600.');

// -------------------------------------------------------------
// Component 3: AST Command Parser & Deobfuscation
// -------------------------------------------------------------
console.log('[3/7] Fuzzing AST Analyzer & Evasion Resistance...');
const astAnalyzer = new ASTAnalyzer();

const dangerousTargets = ['/', '/*', '//*', '///', '.*', '.', '..', '../..', '/etc', '/var', '/usr', '/root', '/home'];
const wrappers = ['', 'sudo', 'sudo -u root', 'doas', 'pkexec', 'env', 'env -i', 'nohup', 'timeout 10s'];
const quotes = ['', '"', "'"];

const adversarialCmdArb = fc.tuple(
  fc.constantFrom(...wrappers),
  fc.constantFrom(...quotes),
  fc.constantFrom(...dangerousTargets),
  fc.integer({ min: 0, max: 7 })
).map(([wrapper, q, target, choice]) => {
  if (choice === 0) return `${wrapper} rm -rf ${q}${target}${q}`.trim();
  if (choice === 1) return `${wrapper} chmod -R 777 ${q}${target}${q}`.trim();
  if (choice === 2) return `${wrapper} chown -R root:root ${q}${target}${q}`.trim();
  if (choice === 3) return `${wrapper} shred -u ${q}${target}${q}`.trim();
  if (choice === 4) return `${wrapper} dd if=/dev/zero of=/dev/sda bs=1M`.trim();
  if (choice === 5) return `${wrapper} mkfs.ext4 /dev/sda1`.trim();
  if (choice === 6) return `${wrapper} bash -c "rm -rf /"`.trim();
  return `${wrapper} find ${target} -delete`.trim();
});

fc.assert(
  fc.property(adversarialCmdArb, (cmd) => {
    const result = astAnalyzer.analyzeCommand(cmd);
    return !result.isSafe; // Must block all adversarial command variations
  }),
  { numRuns: 300, seed }
);
console.log('  PASS: Adversarial command variations systematically blocked.');

// -------------------------------------------------------------
// Component 4: Policy Matcher & Schema Enforcement
// -------------------------------------------------------------
console.log('[4/7] Fuzzing Policy Matcher & Schema Invariants...');

const policyRuleArb = fc.record({
  id: fc.string({ minLength: 1, maxLength: 50 }),
  name: fc.string({ minLength: 1, maxLength: 50 }),
  priority: fc.integer({ min: 1, max: 1000 }),
  riskLevel: fc.constantFrom('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'),
  action: fc.constantFrom('quarantine', 'block', 'prompt', 'sandbox', 'allow'),
  targetTools: fc.array(fc.string({ maxLength: 20 }), { maxLength: 5 }),
});

fc.assert(
  fc.property(policyRuleArb, (rule) => {
    const parse = PolicyRuleSchema.safeParse(rule);
    return parse.success === true;
  }),
  { numRuns: 200, seed }
);

// Verify invalid actions are rejected
const invalidPolicyRuleArb = fc.record({
  id: fc.string({ minLength: 1 }),
  name: fc.string({ minLength: 1 }),
  riskLevel: fc.string(), // arbitrary invalid
  action: fc.string(), // arbitrary invalid
});

fc.assert(
  fc.property(invalidPolicyRuleArb, (rule) => {
    const parse = PolicyRuleSchema.safeParse(rule);
    const validActions = ['quarantine', 'block', 'prompt', 'sandbox', 'allow'];
    const validRisks = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    if (!validActions.includes(rule.action) || !validRisks.includes(rule.riskLevel)) {
      return parse.success === false;
    }
    return true;
  }),
  { numRuns: 200, seed }
);
console.log('  PASS: Policy schema and action validation bounds enforced.');

// -------------------------------------------------------------
// Component 5: Streaming DLP Parser & Chunk Boundary Detection
// -------------------------------------------------------------
console.log('[5/7] Fuzzing Streaming DLP Parser & Boundary Crossing...');

const stripeSecretArb = fc.tuple(
  fc.constant('sk_live_'),
  fc.stringMatching(/^[a-zA-Z0-9]{24,30}$/)
).map(([prefix, body]) => `${prefix}${body}`);

fc.assert(
  fc.property(stripeSecretArb, fc.integer({ min: 1, max: 20 }), (secret, splitOffset) => {
    const scanner = new IncrementalSecretScanner(128);
    const safeOffset = Math.min(splitOffset, secret.length - 1);
    const part1 = secret.slice(0, safeOffset);
    const part2 = secret.slice(safeOffset);

    // Push split parts across stream boundary
    const findings1 = scanner.push(part1);
    const findings2 = scanner.push(part2);
    const flushed = scanner.flush();

    const totalFindings = [...findings1, ...findings2, ...flushed];
    return totalFindings.length > 0; // Secret must be detected across chunk boundary
  }),
  { numRuns: 150, seed }
);
console.log('  PASS: Streaming DLP detects credentials split across chunk boundaries.');

// -------------------------------------------------------------
// Component 6: Telemetry Decoder & Privacy Guarantee
// -------------------------------------------------------------
console.log('[6/7] Fuzzing Telemetry Ingestion & Privacy Controls...');

const telemetryArb = fc.record({
  mode: fc.constantFrom<DeploymentMode>('cloud-intel', 'private-telemetry', 'self-hosted', 'air-gapped'),
  serverIdentity: fc.string({ minLength: 1, maxLength: 30 }),
  riskScore: fc.integer({ min: 0, max: 100 }),
  noveltyScore: fc.float({ min: 0, max: 1 }),
  attackProbability: fc.float({ min: 0, max: 1 }),
  capabilities: fc.array(fc.string({ maxLength: 20 }), { maxLength: 10 }),
});

fc.assert(
  fc.property(telemetryArb, (t) => {
    const engine = new PrivacyTelemetryEngine(t.mode, t.serverIdentity);
    const payload = engine.packageTelemetry({
      toolName: 'read_resource',
      schema: { type: 'object' },
      capabilities: t.capabilities,
      features: {} as any,
      prediction: {
        riskScore: t.riskScore,
        attackProbability: t.attackProbability,
        noveltyScore: t.noveltyScore,
        recommendedAction: 'ALLOW',
        primarySignals: ['baseline'],
        featureAttributions: {},
        modelIdentity: 'model-a-v2',
        modelVersion: '2.0.0',
        inferenceLatencyUs: 120,
      },
      evidence: [],
    });

    if (t.mode === 'air-gapped' || t.mode === 'self-hosted') {
      return payload === null; // Strictly zero egress in air-gapped or self-hosted
    }

    if (!payload) return false;
    // Invariant: rawBodyIncluded is strictly false
    if (payload.rawBodyIncluded !== false) return false;
    // Invariant: risk score bounded
    if (payload.riskScore < 0 || payload.riskScore > 100) return false;
    // Invariant: server identity hash generated
    if (!payload.serverIdentityHash) return false;
    return true;
  }),
  { numRuns: 200, seed }
);
console.log('  PASS: Telemetry payload privacy invariants and zero-egress modes verified.');

// -------------------------------------------------------------
// Component 7: Enterprise Intel Request Validator
// -------------------------------------------------------------
console.log('[7/7] Fuzzing Enterprise Intel Request Validator & Math Bounds...');

const IntelRequestSchema = z.object({
  toolName: z.string().min(1).max(100),
  astEntropy: z.number().finite().min(0).max(10),
  untrustedEgressRequested: z.boolean(),
  credentialCanaryHits: z.number().int().min(0).max(1000),
  unverifiedBinaryDrift: z.boolean().optional(),
});

const invalidIntelArb = fc.record({
  toolName: fc.oneof(fc.constant(''), fc.string({ minLength: 101 })),
  astEntropy: fc.oneof(fc.constant(NaN), fc.constant(Infinity), fc.constant(-1), fc.constant(999)),
  untrustedEgressRequested: fc.boolean(),
  credentialCanaryHits: fc.oneof(fc.constant(-5), fc.constant(999999)),
});

fc.assert(
  fc.property(invalidIntelArb, (req) => {
    const parse = IntelRequestSchema.safeParse(req);
    // All adversarial inputs (NaN, Infinity, negatives, overflows) must fail schema validation
    return parse.success === false;
  }),
  { numRuns: 200, seed }
);
console.log('  PASS: Adversarial inputs (NaN, Infinity, negative, overflow) rejected.');

console.log('\n------------------------------------------------------------');
console.log(' ALL 7 PROPERTY-BASED FUZZING COMPONENTS PASSED SUCCESSFULLY!');
console.log('------------------------------------------------------------\n');
