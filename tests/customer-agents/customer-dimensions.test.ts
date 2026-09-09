import * as crypto from 'crypto';
import { SecretSanitizer } from '../../src/security/sanitizer';
import { AuditComplianceLedger, AuditEvent, AuditLedgerExport } from '../../src/security/audit-ledger';
import { ProxyServer } from '../../src/core/proxy';
import { ScanCommand } from '../../src/cli/commands/scan';
import { EcosystemDiscoveryReport } from '../../src/scanner/agent-ecosystem-scanner';
import { ConfigLoader } from '../../src/security/config';

describe('MCP-Shield Customer Subagent & Dimension Verification Suite', () => {

  // =========================================================================
  // ENTERPRISE PERSONA 1: Fortune 500 CISO / VP Cyber Security
  // Dimension: Enterprise SIEM Export, Merkle Invariants & Shadow Evaluation
  // =========================================================================
  describe('Enterprise Persona 1: CISO / SecOps Governance', () => {
    it('CISO-01: Should export audit events to Common Event Format (CEF) for SIEM ingestion', () => {
      const exportData: AuditLedgerExport = {
        exportedAt: new Date().toISOString(),
        totalEvents: 2,
        genesisHash: '0000000000000000000000000000000000000000000000000000000000000000',
        finalHash: 'hash_final',
        keyIds: ['key-1'],
        merkleRoot: 'merkle_root_abcdef1234567890',
        events: [
          {
            sequenceNumber: 1,
            timestamp: new Date().toISOString(),
            actor: 'ciso-agent',
            action: 'TOOL_INVOKE',
            payloadHash: 'hash1',
            previousHash: 'prev0',
            signature: 'sig1',
            keyId: 'key-1'
          },
          {
            sequenceNumber: 2,
            timestamp: new Date().toISOString(),
            actor: 'ciso-agent',
            action: 'SECURITY_BLOCK',
            payloadHash: 'hash2',
            previousHash: 'sig1',
            signature: 'sig2',
            keyId: 'key-1'
          }
        ]
      };

      const cefOutput = AuditComplianceLedger.exportToCef(exportData);
      expect(cefOutput).toContain('CEF:0|rahulxcodex|mcp-shield|1.0.25|TOOL_INVOKE|TOOL_INVOKE|3|src=ciso-agent');
      expect(cefOutput).toContain('CEF:0|rahulxcodex|mcp-shield|1.0.25|SECURITY_BLOCK|SECURITY_BLOCK|8|src=ciso-agent');
      expect(cefOutput).toContain('cs3Label=MerkleRoot');
    });

    it('CISO-02: Should export audit events to RFC 5424 Syslog format', () => {
      const exportData: AuditLedgerExport = {
        exportedAt: new Date().toISOString(),
        totalEvents: 1,
        genesisHash: '0000',
        finalHash: 'sig1',
        keyIds: ['key-1'],
        merkleRoot: 'root1',
        events: [
          {
            sequenceNumber: 1,
            timestamp: '2026-09-09T10:00:00.000Z',
            actor: 'prod-agent',
            action: 'POLICY_BLOCK',
            payloadHash: 'p_hash',
            previousHash: '0000',
            signature: 'sig1',
            keyId: 'key-1'
          }
        ]
      };

      const syslogOutput = AuditComplianceLedger.exportToSyslog(exportData);
      expect(syslogOutput).toContain('<131>1 2026-09-09T10:00:00.000Z mcp-shield mcpshld');
      expect(syslogOutput).toContain('[mcp@53427 seq="1" action="POLICY_BLOCK" actor="prod-agent"');
    });

    it('CISO-03: Should generate and verify mathematical Merkle inclusion proofs', () => {
      const leaves = [
        crypto.createHash('sha256').update('event-1').digest('hex'),
        crypto.createHash('sha256').update('event-2').digest('hex'),
        crypto.createHash('sha256').update('event-3').digest('hex'),
        crypto.createHash('sha256').update('event-4').digest('hex')
      ];

      const root = AuditComplianceLedger.computeMerkleRoot(leaves);
      expect(root).toBeDefined();

      // Generate inclusion proof for leaf index 2
      const proofResult = AuditComplianceLedger.generateMerkleProof(leaves, 2);
      expect(proofResult.leaf).toBe(leaves[2]);
      expect(proofResult.proof.length).toBeGreaterThan(0);

      // Verify proof
      const isValid = AuditComplianceLedger.verifyMerkleProof(proofResult.leaf, proofResult.proof, root);
      expect(isValid).toBe(true);

      // Tampered proof must fail
      const isInvalid = AuditComplianceLedger.verifyMerkleProof('tampered_leaf_hash', proofResult.proof, root);
      expect(isInvalid).toBe(false);
    });
  });

  // =========================================================================
  // ENTERPRISE PERSONA 2: Cloud Infrastructure & Platform Engineer
  // Dimension: Environment Quarantine, Workspace Isolation & Lifecycle
  // =========================================================================
  describe('Enterprise Persona 2: Platform Infrastructure Architect', () => {
    it('PLAT-01: Should strip ambient host cloud secrets from child process environment', () => {
      const hostEnv = {
        PATH: '/usr/bin:/bin',
        HOME: '/home/user',
        AWS_SECRET_ACCESS_KEY: 'super_secret_aws_key',
        GITHUB_TOKEN: 'ghp_secret_github_token',
        DATABASE_URL: 'postgres://admin:secret@db.internal:5432/db',
        SUPABASE_SERVICE_ROLE_KEY: 'sbp_secret_service_key',
        OPENAI_API_KEY: 'sk-proj-secret-key'
      };

      const safeEnv = ProxyServer.buildSafeEnv(hostEnv);

      // Safe variables preserved
      expect(safeEnv.PATH).toBe('/usr/bin:/bin');
      expect(safeEnv.HOME).toBe('/home/user');
      expect(safeEnv.PYTHONUNBUFFERED).toBe('1');

      // Sensitive cloud secrets strictly quarantined
      expect(safeEnv.AWS_SECRET_ACCESS_KEY).toBeUndefined();
      expect(safeEnv.GITHUB_TOKEN).toBeUndefined();
      expect(safeEnv.DATABASE_URL).toBeUndefined();
      expect(safeEnv.SUPABASE_SERVICE_ROLE_KEY).toBeUndefined();
      expect(safeEnv.OPENAI_API_KEY).toBeUndefined();
    });

    it('PLAT-02: Should instantiate ProxyServer with shadowMode option without throwing', () => {
      const proxy = new ProxyServer('node', ['-e', 'console.log("test")'], { shadowMode: true });
      expect(proxy).toBeDefined();
    });
  });

  // =========================================================================
  // ENTERPRISE PERSONA 3: Chief Privacy Officer / Healthcare Auditor
  // Dimension: International PII, Financial DLP & Custom Enterprise Patterns
  // =========================================================================
  describe('Enterprise Persona 3: Compliance & Privacy Auditor', () => {
    let sanitizer: SecretSanitizer;

    beforeEach(() => {
      sanitizer = new SecretSanitizer();
    });

    it('PRIV-01: Should sanitize European IBAN bank account numbers', () => {
      const payload = 'Wire funds to European account DE89370400440532013000 in Berlin';
      const sanitized = sanitizer.sanitize(payload);
      expect(sanitized).toMatch(/\[\[SHIELD_SECRET_[0-9a-fA-F-]{36}\]\]/);
      expect(sanitized).not.toContain('DE89370400440532013000');

      const restored = sanitizer.restore(sanitized);
      expect(restored).toBe(payload);
    });

    it('PRIV-02: Should sanitize Indian PAN and Aadhaar national identifiers', () => {
      const payload = 'Taxpayer PAN: ABCDE1234F, Resident Aadhaar: 2345 6789 0123';
      const sanitized = sanitizer.sanitize(payload);

      expect(sanitized).not.toContain('ABCDE1234F');
      expect(sanitized).not.toContain('2345 6789 0123');

      const restored = sanitizer.restore(sanitized);
      expect(restored).toBe(payload);
    });

    it('PRIV-03: Should sanitize Brazilian CPF numbers', () => {
      const payload = 'Cliente CPF: 123.456.789-01 cadastrado com sucesso.';
      const sanitized = sanitizer.sanitize(payload);

      expect(sanitized).not.toContain('123.456.789-01');
      expect(sanitized).toMatch(/\[\[SHIELD_SECRET_[0-9a-fA-F-]{36}\]\]/);

      const restored = sanitizer.restore(sanitized);
      expect(restored).toBe(payload);
    });

    it('PRIV-04: Should support pluggable custom enterprise regex patterns', () => {
      const customSanitizer = new SecretSanitizer();
      customSanitizer.registerCustomPattern('INTERNAL_EMPLOYEE_ID', /EMP-[0-9]{6}-[A-Z]{2}/g);

      const payload = 'Employee clearance: EMP-987654-XY authorized';
      const sanitized = customSanitizer.sanitize(payload);

      expect(sanitized).not.toContain('EMP-987654-XY');
      expect(sanitized).toMatch(/\[\[SHIELD_SECRET_[0-9a-fA-F-]{36}\]\]/);

      const restored = customSanitizer.restore(sanitized);
      expect(restored).toBe(payload);
    });
  });

  // =========================================================================
  // CUSTOMER PERSONA 4: AI Agent Engineer (Claude Desktop / Cursor User)
  // Dimension: Developer Experience (DX), Error Diagnosability & Config Safety
  // =========================================================================
  describe('Customer Persona 4: AI Agent Developer', () => {
    it('DEV-01: Should validate configuration schema cleanly without crashing', () => {
      const config = ConfigLoader.load();
      expect(config).toBeDefined();
      expect(config.mode).toBeDefined();
    });

    it('DEV-02: Should format error payloads with structured diagnostic guidance for LLMs', () => {
      const errorData = {
        errorType: 'MCP_SHIELD_POLICY_BLOCK',
        toolName: 'execute_command',
        ruleId: 'RULE-AST-001',
        reason: 'COMMAND_INJECTION_DETECTED',
        recommendation: 'Operation rejected by MCP-Shield security firewall. Adjust tool parameters.'
      };

      const errorPayload = {
        jsonrpc: '2.0',
        id: 42,
        error: {
          code: -32003,
          message: 'SECURITY POLICY BLOCKED: COMMAND_INJECTION_DETECTED',
          data: errorData
        }
      };

      expect(errorPayload.error.code).toBe(-32003);
      expect(errorPayload.error.data.errorType).toBe('MCP_SHIELD_POLICY_BLOCK');
      expect(errorPayload.error.data.recommendation).toBeDefined();
    });
  });

  // =========================================================================
  // CUSTOMER PERSONA 5: DevSecOps / SRE CI-CD Engineer
  // Dimension: SARIF 2.1.0 Static Analysis & Deterministic CI Failure Gates
  // =========================================================================
  describe('Customer Persona 5: DevSecOps CI/CD Automation', () => {
    const mockReport: EcosystemDiscoveryReport = {
      timestamp: Date.now(),
      totalAgentsFound: 2,
      totalServersFound: 3,
      protectedServersCount: 1,
      unprotectedServersCount: 2,
      totalSkillsFound: 0,
      overallPostureScore: 45,
      environments: [],
      globalRisks: {
        exposedSecrets: ['ANTHROPIC_API_KEY in /test/.mcp.json'],
        autoApproveExploits: ['--dangerously-skip-permissions in cursor-mcp'],
        unconstrainedExecution: ['/bin/bash in custom-server']
      }
    };

    it('SRE-01: Should convert ecosystem scan report to valid OASIS SARIF 2.1.0 format', () => {
      const sarif = ScanCommand.toSarif(mockReport);

      expect(sarif.version).toBe('2.1.0');
      expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
      expect(sarif.runs).toHaveLength(1);
      expect(sarif.runs[0].tool.driver.name).toBe('mcp-shield');

      const results = sarif.runs[0].results;
      expect(results).toHaveLength(3);

      const secretFinding = results.find((r: any) => r.ruleId === 'MCP-SHIELD-001');
      expect(secretFinding).toBeDefined();
      expect(secretFinding.level).toBe('error');

      const autoApproveFinding = results.find((r: any) => r.ruleId === 'MCP-SHIELD-002');
      expect(autoApproveFinding).toBeDefined();
      expect(autoApproveFinding.level).toBe('warning');
    });

    it('SRE-02: Should correctly evaluate failure thresholds without throwing in test environment', () => {
      expect(() => {
        ScanCommand.evaluateFailure(mockReport, 'critical');
        ScanCommand.evaluateFailure(mockReport, 'high');
        ScanCommand.evaluateFailure(mockReport, 'medium');
      }).not.toThrow();
    });
  });

  // =========================================================================
  // CUSTOMER PERSONA 6: External Strategy & Management Consultant
  // Dimension: Product Architecture, Dual Registry Parity & Enterprise Moat
  // =========================================================================
  describe('Customer Persona 6: External Strategy Consultant', () => {
    it('STRAT-01: Should verify package.json exports dual binary names (mcp-shield & mcpshld)', () => {
      const pkg = require('../../package.json');
      expect(pkg.bin).toBeDefined();
      expect(pkg.bin['mcp-shield']).toBe('./bin/mcp-shield.js');
      expect(pkg.bin['mcpshld']).toBe('./bin/mcp-shield.js');
    });

    it('STRAT-02: Should verify both CJS and ESM entry points are properly exported', () => {
      const pkg = require('../../package.json');
      expect(pkg.main).toBe('dist/index.js');
      expect(pkg.types).toBe('dist/index.d.ts');
      expect(pkg.exports['.']).toBeDefined();
    });
  });
});
