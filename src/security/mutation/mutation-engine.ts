import { ASTAnalyzer } from '../ast-analyzer';
import { PathSecurityResolver } from '../path-resolver';
import { CapabilityManifestRegistry } from '../capability-manifest';
import { UnicodeNormalizer } from '../unicode-normalizer';
import { IpClassifier, EgressSecurityConfig } from '../ip-utils';
import { Sanitizer } from '../sanitizer';
import { PolicyEngine } from '../policy-engine';
import { PolicyRoutingEngine, TenantContext } from '../policy-routing';
import { AuthorizationModule } from '../authorization';

export type MutationType =
  | 'SEVERITY_DECREASE'
  | 'BLOCK_TO_ALLOW'
  | 'ALLOW_TO_BLOCK'
  | 'PATH_COMPARISON_INVERSION'
  | 'REGEX_REMOVAL'
  | 'CAPABILITY_REMOVAL'
  | 'POLICY_PRECEDENCE_MUTATION'
  | 'UNICODE_NORMALIZATION_DISABLE'
  | 'SIGNATURE_VERIFICATION_BYPASS'
  | 'MUTATE_IS_BLOCKED'
  | 'MUTATE_AUTHORIZATION'
  | 'REMOVE_TENANT_FILTER'
  | 'DISABLE_SIGNATURE_VERIFICATION'
  | 'REMOVE_SSRF_CHECKS'
  | 'BYPASS_DLP'
  | 'BREAK_REPLAY_PROTECTION';

export interface SecurityMutant {
  id: string;
  type: MutationType;
  description: string;
  targetComponent: string;
  applyMutation: () => () => void; // Returns a revert function
}

export interface MutantEvaluationResult {
  mutantId: string;
  type: MutationType;
  targetComponent: string;
  killed: boolean;
  killerDetector?: string;
  details?: string;
}

export class SecurityMutationEngine {
  /**
   * Generates comprehensive suite of mutations against critical security primitives
   */
  public static createSecurityMutants(): SecurityMutant[] {
    return [
      // 1. Severity Decrease Mutation
      {
        id: 'MUT-SEV-001',
        type: 'SEVERITY_DECREASE',
        targetComponent: 'ASTAnalyzer',
        description: 'Mutates destructive command detection severity from CRITICAL (0.9) to LOW (0.1)',
        applyMutation: () => {
          const orig = ASTAnalyzer.prototype.analyzeCommand;
          ASTAnalyzer.prototype.analyzeCommand = function (cmd: string) {
            const res = orig.call(this, cmd);
            if (!res.isSafe) {
              return { ...res, isSafe: true, reason: 'MUTATED: Severity downgraded to low' };
            }
            return res;
          };
          return () => {
            ASTAnalyzer.prototype.analyzeCommand = orig;
          };
        }
      },

      // 2. Decision Flip: BLOCK -> ALLOW
      {
        id: 'MUT-FLIP-001',
        type: 'BLOCK_TO_ALLOW',
        targetComponent: 'CapabilityManifestRegistry',
        description: 'Mutates default-deny policy for unregistered tools into default-allow',
        applyMutation: () => {
          const orig = CapabilityManifestRegistry.prototype.verifyInvocation;
          CapabilityManifestRegistry.prototype.verifyInvocation = function (name: string, args: any, caps: any) {
            const res = orig.call(this, name, args, caps);
            if (!res.authorized && res.reasonCode === 'UNKNOWN_TOOL_BLOCKED') {
              return { authorized: true, reasonCode: 'AUTHORIZED' };
            }
            return res;
          };
          return () => {
            CapabilityManifestRegistry.prototype.verifyInvocation = orig;
          };
        }
      },

      // 3. Decision Flip: ALLOW -> BLOCK (False Positive / Invariant Break)
      {
        id: 'MUT-FLIP-002',
        type: 'ALLOW_TO_BLOCK',
        targetComponent: 'ASTAnalyzer',
        description: 'Mutates benign read commands to block arbitrarily',
        applyMutation: () => {
          const orig = ASTAnalyzer.prototype.analyzeCommand;
          ASTAnalyzer.prototype.analyzeCommand = function (cmd: string) {
            if (cmd.trim() === 'git status' || cmd.trim() === 'pwd') {
              return { isSafe: false, reason: 'MUTATED: Inverted safe command' };
            }
            return orig.call(this, cmd);
          };
          return () => {
            ASTAnalyzer.prototype.analyzeCommand = orig;
          };
        }
      },

      // 4. Path Comparison Inversion
      {
        id: 'MUT-PATH-001',
        type: 'PATH_COMPARISON_INVERSION',
        targetComponent: 'PathSecurityResolver',
        description: 'Inverts directory containment check `isWithin`',
        applyMutation: () => {
          const orig = PathSecurityResolver.isWithin;
          PathSecurityResolver.isWithin = function (candidate: string, parent: string) {
            const result = orig.call(this, candidate, parent);
            return !result; // Inverted
          };
          return () => {
            PathSecurityResolver.isWithin = orig;
          };
        }
      },

      // 5. Regex Removal / Weakening
      {
        id: 'MUT-REGEX-001',
        type: 'REGEX_REMOVAL',
        targetComponent: 'Sanitizer',
        description: 'Disables secret pattern matching regexes in Sanitizer',
        applyMutation: () => {
          const orig = Sanitizer.prototype.sanitize;
          Sanitizer.prototype.sanitize = function (text: string) {
            // Nullify token replacement
            return text;
          };
          return () => {
            Sanitizer.prototype.sanitize = orig;
          };
        }
      },

      // 6. Capability Removal / Elevation
      {
        id: 'MUT-CAP-001',
        type: 'CAPABILITY_REMOVAL',
        targetComponent: 'IpClassifier',
        description: 'Removes loopback and metadata endpoint restrictions from egress filter',
        applyMutation: () => {
          const orig = IpClassifier.checkEgressViolation;
          IpClassifier.checkEgressViolation = function (host: string, config: EgressSecurityConfig) {
            const mutatedConfig: EgressSecurityConfig = {
              ...config,
              allowMode: 'allow',
              blockLoopback: false,
              blockMetadataEndpoints: false
            };
            return orig.call(this, host, mutatedConfig);
          };
          return () => {
            IpClassifier.checkEgressViolation = orig;
          };
        }
      },

      // 7. Policy Precedence Mutation
      {
        id: 'MUT-POL-001',
        type: 'POLICY_PRECEDENCE_MUTATION',
        targetComponent: 'PolicyEngine',
        description: 'Inverts block precedence allowing permitted overrides to supersede hard blocks',
        applyMutation: () => {
          const orig = PolicyEngine.prototype.evaluate;
          PolicyEngine.prototype.evaluate = function (context: any) {
            const res = orig.call(this, context);
            if (res.decision === 'block' || res.decision === 'quarantine') {
              return { ...res, decision: 'allow' as any, reasonCode: 'MUTATED: Overridden block' };
            }
            return res;
          };
          return () => {
            PolicyEngine.prototype.evaluate = orig;
          };
        }
      },

      // 8. Unicode Normalization Disabled
      {
        id: 'MUT-UNI-001',
        type: 'UNICODE_NORMALIZATION_DISABLE',
        targetComponent: 'UnicodeNormalizer',
        description: 'Bypasses Unicode NFKC homoglyph normalization',
        applyMutation: () => {
          const orig = UnicodeNormalizer.normalize;
          UnicodeNormalizer.normalize = function (input: string) {
            // Skips normalization, returning raw confusable characters
            return input;
          };
          return () => {
            UnicodeNormalizer.normalize = orig;
          };
        }
      },

      // 9. Signature Verification Bypass
      {
        id: 'MUT-SIG-001',
        type: 'SIGNATURE_VERIFICATION_BYPASS',
        targetComponent: 'PathSecurityResolver',
        description: 'Bypasses path traversal sequence detection',
        applyMutation: () => {
          const orig = PathSecurityResolver.resolveForPolicy;
          PathSecurityResolver.resolveForPolicy = function (p: string) {
            const res = orig.call(this, p);
            return { ...res, hasTraversalAttempt: false };
          };
          return () => {
            PathSecurityResolver.resolveForPolicy = orig;
          };
        }
      },

      // 10. Mutate isBlocked -> false
      {
        id: 'MUT-BLOCK-001',
        type: 'MUTATE_IS_BLOCKED',
        targetComponent: 'IpClassifier',
        description: 'Mutates IpClassifier.checkEgressViolation to unconditionally return isBlocked: false',
        applyMutation: () => {
          const orig = IpClassifier.checkEgressViolation;
          IpClassifier.checkEgressViolation = function () {
            return { isBlocked: false, reason: 'MUTATED: isBlocked bypassed' };
          };
          return () => {
            IpClassifier.checkEgressViolation = orig;
          };
        }
      },

      // 11. Mutate Authorization Checks -> authorized: true
      {
        id: 'MUT-AUTHZ-001',
        type: 'MUTATE_AUTHORIZATION',
        targetComponent: 'CapabilityManifestRegistry',
        description: 'Mutates capability authorization check to unconditionally return authorized: true',
        applyMutation: () => {
          const orig = CapabilityManifestRegistry.prototype.verifyInvocation;
          CapabilityManifestRegistry.prototype.verifyInvocation = function () {
            return { authorized: true, reasonCode: 'AUTHORIZED' as any };
          };
          return () => {
            CapabilityManifestRegistry.prototype.verifyInvocation = orig;
          };
        }
      },

      // 12. Remove Tenant Filters
      {
        id: 'MUT-TENANT-001',
        type: 'REMOVE_TENANT_FILTER',
        targetComponent: 'PolicyRoutingEngine',
        description: 'Mutates PolicyRoutingEngine to omit cross-tenant isolation enforcement',
        applyMutation: () => {
          const orig = PolicyRoutingEngine.prototype.enforceIsolation;
          PolicyRoutingEngine.prototype.enforceIsolation = function () {
            // MUTATED: No-op, removes tenant isolation filter
          };
          return () => {
            PolicyRoutingEngine.prototype.enforceIsolation = orig;
          };
        }
      },

      // 13. Disable Signature Verification
      {
        id: 'MUT-SIG-002',
        type: 'DISABLE_SIGNATURE_VERIFICATION',
        targetComponent: 'AuthorizationModule',
        description: 'Mutates AuthorizationModule signature verification to unconditionally accept invalid signatures',
        applyMutation: () => {
          const orig = (AuthorizationModule.prototype as any).verifySignature;
          (AuthorizationModule.prototype as any).verifySignature = function () {
            return true; // MUTATED: Always valid signature
          };
          return () => {
            (AuthorizationModule.prototype as any).verifySignature = orig;
          };
        }
      },

      // 14. Remove SSRF Checks
      {
        id: 'MUT-SSRF-001',
        type: 'REMOVE_SSRF_CHECKS',
        targetComponent: 'IpClassifier',
        description: 'Mutates IpClassifier SSRF detection to treat internal and metadata IPs as benign public IPs',
        applyMutation: () => {
          const origClassify = IpClassifier.classify;
          IpClassifier.classify = function (raw: string) {
            const res = origClassify.call(this, raw);
            return {
              ...res,
              isLoopback: false,
              isPrivate: false,
              isMetadata: false,
              isLinkLocal: false
            };
          };
          return () => {
            IpClassifier.classify = origClassify;
          };
        }
      },

      // 15. Bypass DLP
      {
        id: 'MUT-DLP-001',
        type: 'BYPASS_DLP',
        targetComponent: 'Sanitizer',
        description: 'Mutates DLP Sanitizer to return original payload without secret redaction',
        applyMutation: () => {
          const orig = Sanitizer.prototype.sanitize;
          Sanitizer.prototype.sanitize = function (text: string) {
            return text; // MUTATED: Zero redaction
          };
          return () => {
            Sanitizer.prototype.sanitize = orig;
          };
        }
      },

      // 16. Break Replay Protection
      {
        id: 'MUT-REPLAY-001',
        type: 'BREAK_REPLAY_PROTECTION',
        targetComponent: 'AuthorizationModule',
        description: 'Mutates AuthorizationModule to bypass consumed nonce tracking, allowing replay attacks',
        applyMutation: () => {
          const origRecord = AuthorizationModule.prototype.recordApproval;
          AuthorizationModule.prototype.recordApproval = function (id: string, approverId: string, signature: string, payload?: any) {
            (this as any).consumedNonces.clear(); // MUTATED: Clear nonces before approval to allow replay
            return origRecord.call(this, id, approverId, signature, payload);
          };
          return () => {
            AuthorizationModule.prototype.recordApproval = origRecord;
          };
        }
      }
    ];
  }
}
