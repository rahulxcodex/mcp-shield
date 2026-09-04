import { AttackPathEngine } from '../../src/security/attack-path/attack-path-engine';
import { AttackPath } from '../../src/security/attack-path/attack-path-types';

describe('Roadmap Step 2 — Attack Path Testing Framework', () => {
  let engine: AttackPathEngine;

  beforeEach(() => {
    engine = new AttackPathEngine();
  });

  describe('Declarative Attack Path Evaluation', () => {
    it('detects and blocks dangerous multi-tool exfiltration sequence', () => {
      const exfilPath: AttackPath = {
        id: 'PATH-EXFIL-001',
        name: 'Database Exfiltration Chain',
        objective: 'exfiltration',
        expectedDecision: 'BLOCK',
        nodes: [
          { id: 'n1', toolName: 'read_database', capabilities: ['database', 'read'] },
          { id: 'n2', toolName: 'export_data', capabilities: ['export', 'transform'] },
          { id: 'n3', toolName: 'transform', capabilities: ['transform'] },
          { id: 'n4', toolName: 'compress', capabilities: ['compression'] },
          { id: 'n5', toolName: 'upload', capabilities: ['network', 'upload'] }
        ],
        edges: [
          { from: 'n1', to: 'n2', dataFlow: 'records' },
          { from: 'n2', to: 'n3', dataFlow: 'table' },
          { from: 'n3', to: 'n4', dataFlow: 'encoded' },
          { from: 'n4', to: 'n5', dataFlow: 'zip' }
        ]
      };

      const decision = engine.evaluateDeclarativePath(exfilPath);
      expect(decision.action).toBe('BLOCK');
      expect(decision.riskScore).toBeGreaterThanOrEqual(0.9);
      expect(decision.dangerousChainIdentified).toBe(true);
      expect(decision.chainExplanation).toContain('DANGEROUS MULTI-TOOL CHAIN');
    });

    it('allows benign multi-tool development workflow', () => {
      const benignPath: AttackPath = {
        id: 'PATH-DEV-001',
        name: 'Local Build and Lint Sequence',
        objective: 'persistence',
        expectedDecision: 'ALLOW',
        nodes: [
          { id: 'n1', toolName: 'git_status', capabilities: ['local'] },
          { id: 'n2', toolName: 'npm_run_lint', capabilities: ['local'] },
          { id: 'n3', toolName: 'npm_run_test', capabilities: ['local'] }
        ],
        edges: [
          { from: 'n1', to: 'n2' },
          { from: 'n2', to: 'n3' }
        ]
      };

      const decision = engine.evaluateDeclarativePath(benignPath);
      expect(decision.action).toBe('ALLOW');
      expect(decision.dangerousChainIdentified).toBe(false);
    });
  });

  describe('Sequential Stateful Chain Detection', () => {
    it('allows individual read tool, but blocks subsequent egress in the same session', () => {
      // 1. Initial read
      const dec1 = engine.evaluateStep('query_database', ['read', 'database']);
      expect(dec1.action).toBe('ALLOW');

      // 2. Intermediate transform
      const dec2 = engine.evaluateStep('compress_payload', ['transform', 'compress']);
      expect(dec2.action).toBe('ALLOW');

      // 3. Outbound exfiltration attempt completes the kill chain -> BLOCK
      const dec3 = engine.evaluateStep('http_post_webhook', ['network', 'upload']);
      expect(dec3.action).toBe('BLOCK');
      expect(dec3.riskScore).toBeGreaterThanOrEqual(0.9);
      expect(dec3.dangerousChainIdentified).toBe(true);
      expect(dec3.chainExplanation).toContain('Kill chain detected');
    });
  });
});
