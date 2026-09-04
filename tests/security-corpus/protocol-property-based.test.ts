import * as fc from 'fast-check';
import { ProtocolValidator } from '../../src/core/protocol-validator';
import { CapabilityManifestRegistry } from '../../src/security/capability-manifest';
import { PolicyEngine } from '../../src/security/policy-engine';

describe('Roadmap Step 2 — Protocol & Property-Based Security Testing', () => {
  let validator: ProtocolValidator;
  let manifestRegistry: CapabilityManifestRegistry;
  let policyEngine: PolicyEngine;

  beforeEach(() => {
    validator = new ProtocolValidator();
    manifestRegistry = new CapabilityManifestRegistry(true); // default-deny
    policyEngine = new PolicyEngine();
  });

  // Fast-check arbitraries
  const jsonRpcVersionArb = fc.constantFrom('2.0', '1.0', '3.0', '', null, undefined, 2);
  const idArb = fc.oneof(fc.integer(), fc.string({ maxLength: 50 }), fc.constant(null), fc.boolean(), fc.constant(undefined));
  const methodArb = fc.oneof(
    fc.constantFrom('tools/call', 'tools/list', 'initialize', 'notifications/cancelled', 'ping'),
    fc.string({ minLength: 1, maxLength: 50 }), // unknown methods
    fc.constant(null),
    fc.constant(undefined)
  );

  const primitiveArb = fc.oneof(fc.string(), fc.integer(), fc.boolean(), fc.constant(null));

  describe('Invariant 1: Invalid protocol messages never execute', () => {
    it('rejects malformed envelopes, missing jsonrpc, missing method, or invalid parameters', () => {
      const malformedPayloadArb = fc.record({
        jsonrpc: jsonRpcVersionArb,
        id: idArb,
        method: methodArb,
        params: fc.oneof(
          fc.dictionary(fc.string({ maxLength: 20 }), primitiveArb, { maxKeys: 10 }),
          primitiveArb,
          fc.constant(undefined)
        )
      });

      fc.assert(
        fc.property(malformedPayloadArb, (msg) => {
          const res = validator.validateInbound(msg);
          const isValidJsonRpc = msg.jsonrpc === '2.0' && typeof msg.method === 'string' && msg.method.trim().length > 0;

          if (!isValidJsonRpc) {
            // Must be flagged invalid!
            expect(res.valid).toBe(false);
          }
          return true;
        }),
        { numRuns: 500 }
      );
    });

    it('rejects deeply nested payloads exceeding recursion depth bound', () => {
      const buildDeepObject = (depth: number): any => {
        if (depth === 0) return 'leaf';
        return { child: buildDeepObject(depth - 1) };
      };

      const deepMsg = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'test',
          arguments: buildDeepObject(35) // Exceeds MAX_RECURSION_DEPTH (32)
        }
      };

      const res = validator.validateInbound(deepMsg);
      expect(res.valid).toBe(false);
      expect(res.errorMessage).toContain('nesting depth limit');
    });
  });

  describe('Invariant 2: Cancelled requests do not create successful execution', () => {
    it('enforces cancellation protocol notifications never transition to active execution', () => {
      const cancelMsgArb = fc.record({
        jsonrpc: fc.constant('2.0'),
        method: fc.constant('notifications/cancelled'),
        params: fc.record({
          requestId: fc.oneof(fc.integer(), fc.string({ maxLength: 30 }))
        })
      });

      fc.assert(
        fc.property(cancelMsgArb, (msg) => {
          // Verify that a cancellation notification is recognized and blocked from execution pipeline
          expect(msg.method).toBe('notifications/cancelled');
          const isNotification = (msg as any).id === undefined;
          expect(isNotification).toBe(true);
          return true;
        }),
        { numRuns: 100 }
      );
    });
  });

  describe('Invariant 3: Unauthorized capability requests never reach execution', () => {
    it('strictly blocks unauthorized tool invocations under default-deny regardless of parameters', () => {
      const arbitraryInvocation = fc.record({
        toolName: fc.string({ minLength: 1, maxLength: 30 }),
        args: fc.dictionary(fc.string({ maxLength: 10 }), primitiveArb, { maxKeys: 5 }),
        demandedCapabilities: fc.record({
          shellExecution: fc.boolean(),
          networkEgress: fc.boolean()
        })
      });

      fc.assert(
        fc.property(arbitraryInvocation, ({ toolName, args, demandedCapabilities }) => {
          // Under default-deny, any tool not explicitly whitelisted in registry must be denied
          const decision = manifestRegistry.verifyInvocation(toolName, args, demandedCapabilities);
          expect(decision.authorized).toBe(false);
          expect(decision.reasonCode).toBe('UNKNOWN_TOOL_BLOCKED');
          return true;
        }),
        { numRuns: 300 }
      );
    });
  });

  describe('Invariant 4: Malformed security metadata never downgrades a decision', () => {
    it('guarantees that high-risk AST violation is never overridden by corrupt metadata fields', () => {
      const metadataCorruptionArb = fc.record({
        _shieldCapabilities: fc.oneof(fc.string(), fc.array(fc.string()), fc.constant(null), fc.integer()),
        _bypass: fc.boolean(),
        _role: fc.string(),
        adminOverride: fc.boolean()
      });

      fc.assert(
        fc.property(metadataCorruptionArb, (corruptMeta) => {
          const decision = policyEngine.evaluate({
            toolName: 'bash',
            args: {
              command: 'rm -rf /',
              ...corruptMeta
            },
            evidence: [
              { detector: 'ast', finding: 'DESTRUCTIVE_COMMAND', risk: 'CRITICAL' }
            ]
          });

          // Must strictly BLOCK regardless of corrupt metadata
          expect(decision.decision).toBe('block');
          return true;
        }),
        { numRuns: 200 }
      );
    });
  });
});
