import { ASTAnalyzer } from '../../src/security/ast-analyzer';
import { SecretSanitizer } from '../../src/security/sanitizer';
import { PolicyEngine } from '../../src/security/policy-engine';
import { RateLimiter } from '../../src/security/rate-limiter';
import { COWFileSystem } from '../../src/sandbox/cow-fs';

/**
 * ============================================================================
 * MCP-SHIELD RED-TEAM VALIDATION TEST SUITE
 * ============================================================================
 * This test suite serves as the official regression harness for red-team security
 * researchers to submit, validate, and track adversarial bypass techniques.
 *
 * Guidelines for Contributors:
 * 1. Submit reproducible PoCs under the appropriate challenge category.
 * 2. Ensure each test asserts the gateway's expected hardened defensive posture.
 * 3. Run with: `npm run test:redteam`
 * ============================================================================
 */

describe('Red-Team Validation: Security Bypass Challenges', () => {
  let astAnalyzer: ASTAnalyzer;
  let sanitizer: SecretSanitizer;
  let policyEngine: PolicyEngine;
  let rateLimiter: RateLimiter;
  let cowFs: COWFileSystem;

  beforeEach(() => {
    astAnalyzer = new ASTAnalyzer();
    sanitizer = new SecretSanitizer();
    policyEngine = new PolicyEngine();
    rateLimiter = new RateLimiter(5, 60000);
    cowFs = new COWFileSystem();
  });

  afterEach(() => {
    policyEngine.close();
  });

  describe('RT-CAT-01: AST & Shell Evasion Defenses', () => {
    it('RT-0101: Blocks chained invocation wrappers (sudo + env + nice + rm)', () => {
      const payload = 'sudo env nice -n 19 rm -rf /';
      const res = astAnalyzer.analyzeCommand(payload);
      expect(res.isSafe).toBe(false);
      expect(res.reason).toBeDefined();
    });

    it('RT-0102: Blocks obfuscated command names with embedded quotes and backslashes', () => {
      const bypass1 = '\\r\\m -rf /';
      const bypass2 = 'r""m -rf /etc';
      const bypass3 = '"r"\'m\' -rf /var';

      expect(astAnalyzer.analyzeCommand(bypass1).isSafe).toBe(false);
      expect(astAnalyzer.analyzeCommand(bypass2).isSafe).toBe(false);
      expect(astAnalyzer.analyzeCommand(bypass3).isSafe).toBe(false);
    });

    it('RT-0103: Blocks dangerous path traversal resolving to root or system directories', () => {
      const traversals = [
        'rm -rf /var/log/../../etc',
        'rm -rf /././etc',
        'rm -rf ////',
        'rm -rf /etc/..',
        'rm -rf ~root'
      ];

      for (const cmd of traversals) {
        expect(astAnalyzer.analyzeCommand(cmd).isSafe).toBe(false);
      }
    });

    it('RT-0104: Blocks interpreter inline execution and redirection feeding', () => {
      const attacks = [
        'python3 -c "import os; os.system(\'rm -rf /\')"',
        'bash -c "rm -rf /"',
        'bash <<< "rm -rf /"',
        'sh < /tmp/payload.sh',
        'source /dev/shm/script.sh'
      ];

      for (const cmd of attacks) {
        expect(astAnalyzer.analyzeCommand(cmd).isSafe).toBe(false);
      }
    });

    it('RT-0105: Blocks raw block device writes and disk destruction', () => {
      const attacks = [
        'dd if=/dev/zero of=/dev/sda bs=1M',
        'dd if=/dev/urandom of=/dev/nvme0n1',
        'shred -u /etc/shadow',
        'mkfs.ext4 /dev/sda1'
      ];

      for (const cmd of attacks) {
        expect(astAnalyzer.analyzeCommand(cmd).isSafe).toBe(false);
      }
    });
  });

  describe('RT-CAT-02: Secret Leakage & Honey-Token Access', () => {
    it('RT-0201: Detects and quarantines decoy honey-token access', () => {
      process.env.MCP_SHIELD_HONEY_TOKENS = 'mcp_honey_sec_9948271a8f902b';
      const honeyPayload = 'Authorization: Bearer mcp_honey_sec_9948271a8f902b';
      const isTriggered = sanitizer.checkHoneyTokens(honeyPayload);
      expect(isTriggered).toBe(true);
    });

    it('RT-0202: Redacts standard cloud provider API keys from tool arguments', () => {
      const sensitiveArg = JSON.stringify({
        apiKey: 'AKIAIOSFODNN7EXAMPLE',
        openAiKey: 'sk-proj-1234567890abcdef1234567890abcdef1234567890',
        githubToken: 'ghp_1234567890abcdefghijklmnopqrstuvwxyz'
      });

      const sanitized = sanitizer.sanitize(sensitiveArg);
      expect(sanitized).not.toContain('AKIAIOSFODNN7EXAMPLE');
      expect(sanitized).not.toContain('sk-proj-1234567890abcdef1234567890abcdef1234567890');
      expect(sanitized).not.toContain('ghp_1234567890abcdefghijklmnopqrstuvwxyz');
      expect(sanitized).toContain('[[SHIELD_SECRET_');
    });

    it('RT-0203: Accurately restores tokenized secrets downstream without data corruption', () => {
      const original = 'key: sk-proj-1234567890abcdef1234567890abcdef1234567890';
      const sanitized = sanitizer.sanitize(original);
      const restored = sanitizer.restore(sanitized);
      expect(restored).toBe(original);
    });
  });

  describe('RT-CAT-03: Egress Exfiltration & Network Firewall', () => {
    it('RT-0301: Blocks egress requests to blacklisted exfiltration domains and wildcards', () => {
      const blockedPayloads = [
        { url: 'https://tunnel.ngrok.io/exfiltrate' },
        { endpoint: 'http://c2.evil.com/leak' },
        { target: 'https://evil.com/webhook' }
      ];

      for (const payload of blockedPayloads) {
        const res = policyEngine.checkEgress(payload);
        expect(res.isBlocked).toBe(true);
        expect(res.domain).toBeDefined();
      }
    });

    it('RT-0302: Allows egress requests to legitimate developer endpoints', () => {
      const safePayloads = [
        { url: 'https://api.github.com/repos/owner/repo' },
        { url: 'https://registry.npmjs.org/mcp-shield' },
        { url: 'https://crates.io/api/v1/crates' }
      ];

      for (const payload of safePayloads) {
        const res = policyEngine.checkEgress(payload);
        expect(res.isBlocked).toBe(false);
      }
    });
  });

  describe('RT-CAT-04: Rate-Limiting & Runaway Agent Loops', () => {
    it('RT-0401: Throttles runaway tool calling loops after reaching threshold', () => {
      const tool = 'bash_exec';
      // Max 5 calls allowed
      for (let i = 0; i < 5; i++) {
        expect(rateLimiter.checkLimit(tool)).toBe(true);
      }

      // 6th call must be blocked
      expect(rateLimiter.checkLimit(tool)).toBe(false);
    });

    it('RT-0402: Separately tracks rate limits across distinct tool names', () => {
      for (let i = 0; i < 5; i++) {
        rateLimiter.checkLimit('tool_a');
      }

      expect(rateLimiter.checkLimit('tool_a')).toBe(false);
      expect(rateLimiter.checkLimit('tool_b')).toBe(true);
    });
  });

  describe('RT-CAT-05: Copy-on-Write (COW) Staging & Path Isolation', () => {
    it('RT-0501: Stages file writes to isolated directory without mutating host files directly', () => {
      const testFile = 'tests/fixtures/sample.txt';
      const staged = cowFs.stageWrite(testFile, 'MODIFIED_CONTENT_FOR_REVIEW');

      expect(staged.stagingPath).toBeDefined();
      expect(staged.diff).toContain('MODIFIED_CONTENT_FOR_REVIEW');

      // Discard staged write
      cowFs.discard(staged.stagingPath);
    });
  });
});
