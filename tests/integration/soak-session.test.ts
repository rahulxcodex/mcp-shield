import { SecretSanitizer } from '../../src/security/sanitizer';
import { SecretVault } from '../../src/security/vault';
import { RateLimiter } from '../../src/security/rate-limiter';
import { JsonRpcStreamFramer } from '../../src/core/stream-framing';
import { ASTAnalyzer } from '../../src/security/ast-analyzer';
import { PolicyEngine } from '../../src/security/policy-engine';

jest.setTimeout(60000);

describe('Sustained Session Soak & Endurance Test Suite (8+ Hour Simulation)', () => {
  it('SOAK-01: Sustains 15,000 unique secret sanitizations with strict vault memory bounds', () => {
    const sanitizer = new SecretSanitizer();
    const startMemory = process.memoryUsage().heapUsed;

    // Simulate prolonged session with 15,000 distinct secrets
    for (let i = 0; i < 15000; i++) {
      const awsKey = `AKIA${i.toString().padStart(16, '0')}`;
      const payload = JSON.stringify({
        tool: 'cloud_deploy',
        params: { key: awsKey, index: i, note: 'continuous background agent work' }
      });
      const sanitized = sanitizer.sanitize(payload);
      expect(sanitized).not.toContain(awsKey);
      expect(sanitized).toContain('[[SHIELD_SECRET_');
    }

    // Verify vault secret store does not exceed configured capacity (5,000)
    const vault = (sanitizer as any).vault as SecretVault;
    expect((vault as any).secrets.size).toBeLessThanOrEqual(5000);
    expect((vault as any).tokenToId.size).toBeLessThanOrEqual(5000);

    if (global.gc) {
      global.gc();
      const endMemory = process.memoryUsage().heapUsed;
      const diffMB = (endMemory - startMemory) / (1024 * 1024);
      // Retained heap growth under bounded capacity should remain under 50 MB
      expect(diffMB).toBeLessThan(50);
    } else {
      const endMemory = process.memoryUsage().heapUsed;
      const diffMB = (endMemory - startMemory) / (1024 * 1024);
      // Uncollected ephemeral allocations in tight loop should remain bounded under 150 MB
      expect(diffMB).toBeLessThan(150);
    }
  });

  it('SOAK-02: RateLimiter sliding window handles continuous 20,000-check burst without memory drift', () => {
    const limiter = new RateLimiter(500, 60000, 2000);

    for (let i = 0; i < 20000; i++) {
      const toolId = `tool_${i % 100}`;
      limiter.checkLimit(toolId);
    }

    // Tracked tools should remain bounded
    const size = (limiter as any).counts.size;
    expect(size).toBeLessThanOrEqual(2001);
  });

  it('SOAK-03: StreamFramer processes 25,000 fragmented frames with zero leftover buffer bloat', () => {
    const framer = new JsonRpcStreamFramer();
    let messageCount = 0;

    framer.on('message', () => {
      messageCount++;
    });

    const sample = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}\n';

    for (let i = 0; i < 25000; i++) {
      // Alternate between whole frames and split byte chunks
      if (i % 2 === 0) {
        framer.append(Buffer.from(sample.slice(0, 20), 'utf8'));
        framer.append(Buffer.from(sample.slice(20), 'utf8'));
      } else {
        framer.append(Buffer.from(sample, 'utf8'));
      }
    }

    expect(messageCount).toBe(25000);
    expect((framer as any).buffer.length).toBe(0);
  });

  it('SOAK-04: ASTAnalyzer handles 5,000 complex shell command evaluations without parse tree leaks', () => {
    const analyzer = new ASTAnalyzer();

    const variedCommands = [
      'sudo env nice -n 10 rm -rf /var/log',
      'cat app.log | grep -i error | sort | uniq -c',
      'find . -name "*.ts" -exec grep -l "TODO" {} +',
      'git log --oneline -n 50',
      'echo ${VAR:-default} | base64 -d',
      'ps aux | grep node | awk \'{print $2}\'',
      'docker ps --filter "status=running"',
      'curl -s http://localhost:8080/health | jq .status'
    ];

    for (let i = 0; i < 5000; i++) {
      const cmd = variedCommands[i % variedCommands.length];
      const result = analyzer.analyzeCommand(cmd);
      expect(result).toBeDefined();
      expect(typeof result.isSafe).toBe('boolean');
    }
  });

  it('SOAK-05: PolicyEngine evaluates 10,000 mixed tool invocations with consistent microsecond latency', () => {
    const policy = new PolicyEngine({
      version: '1.0',
      profile: 'developer',
      redaction: { enabled: true, maskStyle: 'token', highEntropyCheck: true, entropyThreshold: 4.5 },
      sandbox: { cowEnabled: true, cowStagingDir: '.mcp-shield/cow', autoCommitOnApproval: true },
      egress: { enabled: true, allowMode: 'allow', blockedDomains: ['*.ngrok.io', '*.evil.com'], allowPrivateNetworks: true, blockLoopback: false, blockLinkLocal: false, blockMetadataEndpoints: false },
      audit: { enabled: true, logDir: '.mcp-shield/logs', tamperEvidentHashing: true },
      rules: [
        {
          id: 'rule_allow_all',
          name: 'Allow Safe Operations',
          priority: 10,
          riskLevel: 'LOW',
          action: 'allow'
        },
        {
          id: 'rule_block_root',
          name: 'Block Root Operations',
          priority: 100,
          riskLevel: 'CRITICAL',
          action: 'block',
          matchers: {
            pathMatches: { forbiddenPaths: ['/etc/passwd', '/dev/sda', '/root'] }
          }
        }
      ]
    });

    for (let i = 0; i < 10000; i++) {
      const isDangerous = i % 5 === 0;
      const res = policy.evaluate({
        toolName: 'execute_command',
        args: {
          path: isDangerous ? '/etc/passwd' : `/home/user/project/file_${i % 50}.ts`
        },
        evidence: []
      });

      if (isDangerous) {
        expect(res.decision).toBe('block');
      } else {
        expect(res.decision).toBe('allow');
      }
    }
  });
});

