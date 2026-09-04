import * as fs from 'fs';
import * as path from 'path';

export interface SourceVulnerabilityFinding {
  filePath: string;
  lineNumber: number;
  threatType: 'COMMAND_INJECTION' | 'PATH_TRAVERSAL' | 'HARDCODED_SECRET' | 'UNSAFE_EVAL' | 'UNCHECKED_SSRF';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  codeSnippet: string;
  explanation: string;
  remediation: string;
}

export interface McpSourceScanReport {
  scannedFilesCount: number;
  findings: SourceVulnerabilityFinding[];
  isSecure: boolean;
}

export class McpServerSourceScanner {
  private static SCAN_EXTENSIONS = new Set(['.ts', '.js', '.mjs', '.cjs', '.py']);
  private static IGNORE_DIRS = new Set(['node_modules', 'dist', 'build', '.git', 'coverage', '.next', '__pycache__', 'venv', '.venv']);

  /**
   * Recursively scans an MCP server repository or directory for source code vulnerabilities.
   */
  public scanSource(targetDir: string, maxFiles: number = 250): McpSourceScanReport {
    const findings: SourceVulnerabilityFinding[] = [];
    const filesToScan = this.collectSourceFiles(targetDir, maxFiles);

    for (const filePath of filesToScan) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        this.auditFileContent(filePath, content, findings);
      } catch {}
    }

    return {
      scannedFilesCount: filesToScan.length,
      findings,
      isSecure: findings.length === 0,
    };
  }

  public auditFileContent(
    filePath: string,
    content: string,
    findings: SourceVulnerabilityFinding[]
  ): void {
    const lines = content.split(/\r?\n/);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      const trimmed = line.trim();

      // Skip pure comment lines
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('/*')) {
        continue;
      }

      // 1. Command Injection: exec / spawn with shell or direct string concatenation
      if (
        /(?:exec|execSync)\s*\(\s*[`"'].*\$\{|(?:exec|execSync)\s*\(\s*args\b|child_process\.exec\s*\(/i.test(line) ||
        /os\.system\s*\(.*(?:\+|%|format|\{)/i.test(line) ||
        /subprocess\.(?:call|Popen|run)\s*\(.*shell\s*=\s*True/i.test(line)
      ) {
        findings.push({
          filePath,
          lineNumber: lineNum,
          threatType: 'COMMAND_INJECTION',
          severity: 'CRITICAL',
          codeSnippet: trimmed.slice(0, 120),
          explanation: 'Unsanitized tool argument or template interpolation passed directly to shell execution',
          remediation: 'Use execFile or spawn with argument arrays and shell: false, or validate arguments with ASTAnalyzer',
        });
      }

      // 2. Unsafe Dynamic Code Evaluation
      if (
        /\beval\s*\([^\)]+\)/i.test(line) ||
        /new\s+Function\s*\([^\)]+\)/i.test(line) ||
        /vm\.runIn(?:ThisContext|Context|NewContext)\s*\(/i.test(line)
      ) {
        findings.push({
          filePath,
          lineNumber: lineNum,
          threatType: 'UNSAFE_EVAL',
          severity: 'HIGH',
          codeSnippet: trimmed.slice(0, 120),
          explanation: 'Dynamic code execution (eval/Function) enables arbitrary execution escapes',
          remediation: 'Avoid dynamic string evaluation; use declarative schemas and strict AST interpretation',
        });
      }

      // 3. Path Traversal in File Operations
      if (
        /path\.join\s*\([^)]*(?:req|args|params|userInput)/i.test(line) ||
        /os\.path\.join\s*\([^)]*(?:args|params|request)/i.test(line) ||
        /(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream)\s*\(\s*path\.join/i.test(line)
      ) {
        findings.push({
          filePath,
          lineNumber: lineNum,
          threatType: 'PATH_TRAVERSAL',
          severity: 'HIGH',
          codeSnippet: trimmed.slice(0, 120),
          explanation: 'File access using user-supplied relative path without canonical root containment check',
          remediation: 'Enforce PathSecurityResolver.isWithin(jailRoot, targetPath) before file access',
        });
      }

      // 4. Hardcoded Secrets
      if (
        /(?:AKIA[0-9A-Z]{16})|(?:ghp_[a-zA-Z0-9]{36})|(?:sk-proj-[a-zA-Z0-9]{20,})|(?:-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)/i.test(line)
      ) {
        findings.push({
          filePath,
          lineNumber: lineNum,
          threatType: 'HARDCODED_SECRET',
          severity: 'CRITICAL',
          codeSnippet: trimmed.slice(0, 100).replace(/[A-Za-z0-9+/=]{10,}/, '***REDACTED***'),
          explanation: 'Hardcoded API credential or private key detected in source code',
          remediation: 'Store credentials in environment variables or load via SecretVault',
        });
      }

      // 5. Unchecked SSRF in HTTP Client Calls
      if (
        /(?:axios|fetch|http\.get|requests\.get)\s*\(\s*(?:args|params|req\.query)\./i.test(line)
      ) {
        findings.push({
          filePath,
          lineNumber: lineNum,
          threatType: 'UNCHECKED_SSRF',
          severity: 'HIGH',
          codeSnippet: trimmed.slice(0, 120),
          explanation: 'Network request targeting unvalidated user/agent URL without DNS or SSRF pinning',
          remediation: 'Pass destination URLs through AuthoritativeEgressEngine.evaluateDestination()',
        });
      }
    }
  }

  private collectSourceFiles(dir: string, maxFiles: number): string[] {
    const results: string[] = [];

    const walk = (current: string) => {
      if (results.length >= maxFiles) return;
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(current, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        if (results.length >= maxFiles) break;
        const fullPath = path.join(current, entry.name);

        if (entry.isDirectory()) {
          if (!McpServerSourceScanner.IGNORE_DIRS.has(entry.name)) {
            walk(fullPath);
          }
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          if (McpServerSourceScanner.SCAN_EXTENSIONS.has(ext)) {
            results.push(fullPath);
          }
        }
      }
    };

    if (fs.existsSync(dir)) {
      walk(dir);
    }

    return results;
  }
}
