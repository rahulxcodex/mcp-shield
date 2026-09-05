import { SecurityMutationEngine } from '../src/security/mutation/mutation-engine';
import { ASTAnalyzer } from '../src/security/ast-analyzer';
import { CapabilityManifestRegistry } from '../src/security/capability-manifest';
import { PathSecurityResolver } from '../src/security/path-resolver';
import { Sanitizer } from '../src/security/sanitizer';
import { IpClassifier, EgressSecurityConfig } from '../src/security/ip-utils';
import { PolicyEngine } from '../src/security/policy-engine';
import { UnicodeNormalizer } from '../src/security/unicode-normalizer';
import { PolicyRoutingEngine } from '../src/security/policy-routing';
import { AuthorizationModule } from '../src/security/authorization';
import * as crypto from 'crypto';

export interface MutationReport {
  totalMutants: number;
  killedMutants: number;
  survivedMutants: number;
  mutationScore: number;
  results: Array<{
    id: string;
    type: string;
    target: string;
    killed: boolean;
    reason: string;
  }>;
}

export function runSecurityMutationSuite(): MutationReport {
  const mutants = SecurityMutationEngine.createSecurityMutants();
  const results: MutationReport['results'] = [];

  for (const mutant of mutants) {
    const revert = mutant.applyMutation();
    let killed = false;
    let killerReason = '';

    try {
      switch (mutant.type) {
        case 'SEVERITY_DECREASE': {
          const res = new ASTAnalyzer().analyzeCommand('rm -rf /');
          // If the mutated code returns safe=true, our test detector catches it!
          if (res.isSafe === true) {
            killed = true;
            killerReason = 'Caught by destructive command invariant check';
          }
          break;
        }
        case 'BLOCK_TO_ALLOW': {
          const reg = new CapabilityManifestRegistry(true);
          const dec = reg.verifyInvocation('unregistered_tool', {}, { shellExecution: true });
          if (dec.authorized === true) {
            killed = true;
            killerReason = 'Caught by capability default-deny invariant check';
          }
          break;
        }
        case 'ALLOW_TO_BLOCK': {
          const res = new ASTAnalyzer().analyzeCommand('git status');
          if (res.isSafe === false) {
            killed = true;
            killerReason = 'Caught by benign command allowance invariant check';
          }
          break;
        }
        case 'PATH_COMPARISON_INVERSION': {
          const ok = PathSecurityResolver.isWithin('/workspace/docs/file.txt', '/workspace');
          if (!ok) {
            killed = true;
            killerReason = 'Caught by path containment invariant check';
          }
          break;
        }
        case 'REGEX_REMOVAL': {
          const token = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz123456';
          const out = new Sanitizer().sanitize(`API key: ${token}`);
          if (out.includes(token)) {
            killed = true;
            killerReason = 'Caught by secret leak invariant check';
          }
          break;
        }
        case 'CAPABILITY_REMOVAL': {
          const config: EgressSecurityConfig = {
            enabled: true,
            allowMode: 'deny',
            allowedDomains: [],
            blockedDomains: [],
            allowPrivateNetworks: false,
            blockLoopback: true,
            blockLinkLocal: true,
            blockMetadataEndpoints: true
          };
          const res = IpClassifier.checkEgressViolation('127.0.0.1', config);
          if (!res.isBlocked) {
            killed = true;
            killerReason = 'Caught by loopback egress filter invariant check';
          }
          break;
        }
        case 'POLICY_PRECEDENCE_MUTATION': {
          const engine = new PolicyEngine();
          const dec = engine.evaluate({
            toolName: 'bash',
            args: { command: 'rm -rf /' },
            evidence: [{ detector: 'ast', finding: 'DESTRUCTIVE', risk: 'CRITICAL' }]
          });
          if (dec.decision === 'allow') {
            killed = true;
            killerReason = 'Caught by policy block precedence invariant check';
          }
          break;
        }
        case 'UNICODE_NORMALIZATION_DISABLE': {
          const norm = UnicodeNormalizer.normalize('ｃｕｒｌ');
          if (norm === 'ｃｕｒｌ') {
            killed = true;
            killerReason = 'Caught by Unicode confusable normalization invariant check';
          }
          break;
        }
        case 'SIGNATURE_VERIFICATION_BYPASS': {
          const res = PathSecurityResolver.resolveForPolicy('../../../etc/passwd');
          if (!res.hasTraversalAttempt) {
            killed = true;
            killerReason = 'Caught by path traversal signature invariant check';
          }
          break;
        }
        case 'MUTATE_IS_BLOCKED': {
          const res = IpClassifier.checkEgressViolation('127.0.0.1', {
            enabled: true,
            allowMode: 'deny',
            allowedDomains: [],
            blockedDomains: [],
            allowPrivateNetworks: false,
            blockLoopback: true,
            blockLinkLocal: true,
            blockMetadataEndpoints: true
          });
          if (!res.isBlocked) {
            killed = true;
            killerReason = 'Caught by isBlocked egress enforcement invariant check';
          }
          break;
        }
        case 'MUTATE_AUTHORIZATION': {
          const reg = new CapabilityManifestRegistry(true);
          const dec = reg.verifyInvocation('unauthorized_admin_tool', {}, { shellExecution: true });
          if (dec.authorized === true) {
            killed = true;
            killerReason = 'Caught by authorization enforcement invariant check';
          }
          break;
        }
        case 'REMOVE_TENANT_FILTER': {
          const engine = new PolicyRoutingEngine();
          let threw = false;
          try {
            engine.enforceIsolation({ tenantId: 'tenant-a', geoRegion: 'US', maxBlastRadius: 100 }, 'tenant-b');
          } catch {
            threw = true;
          }
          if (!threw) {
            killed = true;
            killerReason = 'Caught by cross-tenant isolation enforcement invariant check';
          }
          break;
        }
        case 'DISABLE_SIGNATURE_VERIFICATION': {
          const authMod = new AuthorizationModule();
          authMod.registerApprover('alice', 'fake-public-key-pem', 'org-default');
          const reqId = authMod.initiateQuorumApproval('admin:mutate', 'org-default');
          let threw = false;
          try {
            authMod.recordApproval(reqId, 'alice', 'totally-invalid-signature-hex-123456');
          } catch {
            threw = true;
          }
          if (!threw) {
            killed = true;
            killerReason = 'Caught by cryptographic signature verification invariant check';
          }
          break;
        }
        case 'REMOVE_SSRF_CHECKS': {
          const cLoopback = IpClassifier.classify('127.0.0.1');
          const cMetadata = IpClassifier.classify('169.254.169.254');
          if (!cLoopback.isLoopback || !cMetadata.isMetadata) {
            killed = true;
            killerReason = 'Caught by SSRF loopback & cloud metadata invariant check';
          }
          break;
        }
        case 'BYPASS_DLP': {
          const secret = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
          const out = new Sanitizer().sanitize(`Secret token: ${secret}`);
          if (out.includes(secret)) {
            killed = true;
            killerReason = 'Caught by DLP secret leak detection invariant check';
          }
          break;
        }
        case 'BREAK_REPLAY_PROTECTION': {
          const authMod = new AuthorizationModule();
          authMod.registerApprover('bob', 'shared-secret-key-123', 'org-default');
          const reqId1 = authMod.initiateQuorumApproval('tool:exec', 'org-default');
          const data = `${reqId1}:bob:tool:exec`;
          const validSig = crypto.createHmac('sha256', 'shared-secret-key-123').update(data).digest('hex');
          
          let threwOnReplay = false;
          try {
            authMod.recordApproval(reqId1, 'bob', validSig);
            const reqId2 = authMod.initiateQuorumApproval('tool:exec', 'org-default');
            authMod.recordApproval(reqId2, 'bob', validSig);
          } catch (e: any) {
            if (e.message?.includes('Replay attack detected') || e.message?.includes('already')) {
              threwOnReplay = true;
            }
          }
          if (!threwOnReplay) {
            killed = true;
            killerReason = 'Caught by nonce replay protection invariant check';
          }
          break;
        }
      }
    } finally {
      revert();
    }

    results.push({
      id: mutant.id,
      type: mutant.type,
      target: mutant.targetComponent,
      killed,
      reason: killerReason || 'Mutant survived undetected!'
    });
  }

  const killedMutants = results.filter(r => r.killed).length;
  const survivedMutants = results.length - killedMutants;
  const mutationScore = Math.round((killedMutants / results.length) * 100);

  return {
    totalMutants: results.length,
    killedMutants,
    survivedMutants,
    mutationScore,
    results
  };
}

if (require.main === module) {
  console.log('\n=== MCP-SHIELD SECURITY MUTATION TESTING SUITE ===');
  const report = runSecurityMutationSuite();
  for (const r of report.results) {
    console.log(`[${r.killed ? 'KILLED' : 'SURVIVED'}] ${r.id} (${r.type}): ${r.reason}`);
  }
  console.log(`\nMutation Score: ${report.mutationScore}% (${report.killedMutants}/${report.totalMutants} mutants killed)`);
  if (report.survivedMutants > 0) {
    console.error(`FAILURE: ${report.survivedMutants} critical mutants survived!`);
    process.exit(1);
  } else {
    console.log('SUCCESS: All security-critical mutants successfully detected and killed.');
    process.exit(0);
  }
}
