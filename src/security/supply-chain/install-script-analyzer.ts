import * as fs from 'fs';
import * as path from 'path';

export interface MaliciousScriptFinding {
  stage: string; // e.g. 'preinstall', 'postinstall', 'install', 'setup.py'
  threatCategory: 'REVERSE_SHELL' | 'CURL_PIPE_EXEC' | 'CREDENTIAL_EXFILTRATION' | 'OBFUSCATED_PAYLOAD' | 'SUSPICIOUS_EXECUTION';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  snippet: string;
  explanation: string;
  sourceFile: string;
}

export interface InstallScriptAuditReport {
  scannedScriptsCount: number;
  maliciousFindings: MaliciousScriptFinding[];
  isClean: boolean;
}

export class InstallScriptAnalyzer {
  /**
   * Scans package.json scripts and Python setup/build files for dangerous install-time lifecycle execution.
   */
  public analyzePackage(packageDir: string, parsedPackage?: any): InstallScriptAuditReport {
    const findings: MaliciousScriptFinding[] = [];
    let scriptCount = 0;

    // 1. Check package.json scripts
    const pkgPath = path.join(packageDir, 'package.json');
    const pkg = parsedPackage || (fs.existsSync(pkgPath) ? this.safeReadJson(pkgPath) : null);
    if (pkg && pkg.scripts && typeof pkg.scripts === 'object') {
        const dangerousLifecycleHooks = [
          'preinstall',
          'install',
          'postinstall',
          'preuninstall',
          'postuninstall',
          'prepare',
        ];

        for (const hook of dangerousLifecycleHooks) {
          if (pkg.scripts[hook]) {
            scriptCount++;
            const cmd = String(pkg.scripts[hook]);
            this.inspectCommand(hook, cmd, pkgPath, findings);
          }
        }
      }

    // 2. Check setup.py or pyproject.toml
    const setupPyPath = path.join(packageDir, 'setup.py');
    if (fs.existsSync(setupPyPath)) {
      scriptCount++;
      try {
        const content = fs.readFileSync(setupPyPath, 'utf8');
        this.inspectPythonSetup(content, setupPyPath, findings);
      } catch {}
    }

    return {
      scannedScriptsCount: scriptCount,
      maliciousFindings: findings,
      isClean: findings.length === 0,
    };
  }

  public inspectCommand(
    stage: string,
    command: string,
    sourceFile: string,
    findings: MaliciousScriptFinding[]
  ): void {
    const lower = command.toLowerCase();

    // 1. Reverse Shell Patterns
    if (
      /nc(?:\.traditional)?\s+-[e|c]\b/i.test(command) ||
      /bash\s+-i\s+>&\s*\/dev\/tcp\//i.test(command) ||
      /\/dev\/udp\/[0-9\.]+\//i.test(command) ||
      /mknod\s+\w+\s+p/i.test(command) ||
      /socket\.socket.*connect/i.test(command)
    ) {
      findings.push({
        stage,
        threatCategory: 'REVERSE_SHELL',
        severity: 'CRITICAL',
        snippet: command.slice(0, 150),
        explanation: 'Active reverse shell payload detected in install lifecycle script',
        sourceFile,
      });
    }

    // 2. Curl/Wget pipe execution
    if (
      /(?:curl|wget)\s+[^\n|;&]+\|\s*(?:ba|z|da|k|t?c)?sh\b/i.test(command) ||
      /(?:curl|wget)\s+[^\n|;&]+\|\s*python\b/i.test(command) ||
      /(?:curl|wget)\s+[^\n|;&]+\|\s*node\b/i.test(command) ||
      /Invoke-Expression\s*\(?.*(?:Invoke-WebRequest|DownloadString)/i.test(command) ||
      /iwr\s+[^\n|;&]+\|\s*iex\b/i.test(command)
    ) {
      findings.push({
        stage,
        threatCategory: 'CURL_PIPE_EXEC',
        severity: 'CRITICAL',
        snippet: command.slice(0, 150),
        explanation: 'Unverified remote code download piped directly into interpreter shell',
        sourceFile,
      });
    }

    // 3. Credential Exfiltration
    if (
      /(?:cat|type|Get-Content)\s+[^\n;&|]*(?:\.ssh|\.aws|\.npmrc|\.netrc|\.env)/i.test(command) ||
      /(?:curl|wget|nc)\s+[^\n;&|]*\$(?:AWS_|GITHUB_|NPM_|OPENAI_|ANTHROPIC_)/i.test(command) ||
      /printenv\s*\|\s*(?:curl|wget|nc)/i.test(command) ||
      /env\s*\|\s*(?:curl|wget|nc)/i.test(command)
    ) {
      findings.push({
        stage,
        threatCategory: 'CREDENTIAL_EXFILTRATION',
        severity: 'CRITICAL',
        snippet: command.slice(0, 150),
        explanation: 'Install script reads sensitive user tokens or environment keys for outbound transmission',
        sourceFile,
      });
    }

    // 4. Obfuscated Payloads
    if (
      /(?:base64\s+-d|atob\s*\(|from_base64|Buffer\.from\(.*'base64'\))\s*\|\s*(?:ba|z|da|k)?sh\b/i.test(command) ||
      /powershell\s+-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/i.test(command) ||
      /eval\s*\(\s*Buffer\.from/i.test(command)
    ) {
      findings.push({
        stage,
        threatCategory: 'OBFUSCATED_PAYLOAD',
        severity: 'HIGH',
        snippet: command.slice(0, 150),
        explanation: 'Heavily obfuscated / encoded payload execution during package installation',
        sourceFile,
      });
    }

    // 5. Suspicious Process Spawns
    if (
      /\b(?:rm\s+-rf\s+\/|del\s+\/f\s+\/s\s+[a-zA-Z]:\\)/i.test(command) ||
      /\bchmod\s+(?:\+x|777)\s+/i.test(command)
    ) {
      findings.push({
        stage,
        threatCategory: 'SUSPICIOUS_EXECUTION',
        severity: 'MEDIUM',
        snippet: command.slice(0, 150),
        explanation: 'Potentially destructive filesystem command executed in install script',
        sourceFile,
      });
    }
  }

  public inspectPythonSetup(content: string, sourceFile: string, findings: MaliciousScriptFinding[]): void {
    if (
      /class\s+(?:PostInstallCommand|CustomInstall|install)\s*\(/i.test(content) &&
      /(?:os\.system|subprocess\.call|subprocess\.Popen|urllib\.request)/i.test(content)
    ) {
      findings.push({
        stage: 'setup.py:custom_cmdclass',
        threatCategory: 'SUSPICIOUS_EXECUTION',
        severity: 'HIGH',
        snippet: content.slice(0, 200).replace(/\s+/g, ' '),
        explanation: 'Custom Python cmdclass hook executing system subprocesses or network requests during install',
        sourceFile,
      });
    }

    if (/os\.environ\[.*(?:AWS|TOKEN|KEY|SECRET)/i.test(content) && /urllib|requests|socket/i.test(content)) {
      findings.push({
        stage: 'setup.py:credential_harvest',
        threatCategory: 'CREDENTIAL_EXFILTRATION',
        severity: 'CRITICAL',
        snippet: 'Environment variable harvesting connected to network module in setup.py',
        explanation: 'Python setup.py accessing secret environment variables alongside outbound networking',
        sourceFile,
      });
    }
  }

  private safeReadJson(filePath: string): any {
    for (let attempt = 0; attempt < 15; attempt++) {
      try {
        const raw = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(raw);
      } catch (e: any) {
        if (attempt === 14) {
          return null;
        }
        // Wait for Windows Defender to finish scanning the temp file
        const start = Date.now();
        while (Date.now() - start < 100) {}
      }
    }
    return null;
  }
}
