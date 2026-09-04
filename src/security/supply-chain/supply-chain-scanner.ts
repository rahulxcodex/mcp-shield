import { DependencyVulnerabilityScanner, DependencyScanResult } from './dependency-scanner';
import { InstallScriptAnalyzer, InstallScriptAuditReport } from './install-script-analyzer';
import { McpServerSourceScanner, McpSourceScanReport } from './mcp-source-scanner';
import { SbomProvenanceVerifier, SbomValidationReport } from './sbom-provenance';

export interface UnifiedSupplyChainReport {
  targetDirectory: string;
  timestamp: number;
  dependencies: DependencyScanResult;
  installScripts: InstallScriptAuditReport;
  sourceAudit: McpSourceScanReport;
  sbomProvenance: SbomValidationReport;
  criticalIssuesCount: number;
  highIssuesCount: number;
  supplyChainSecurityScore: number; // 0 to 100
  passed: boolean;
}

export class SupplyChainScanner {
  private depScanner = new DependencyVulnerabilityScanner();
  private scriptAnalyzer = new InstallScriptAnalyzer();
  private sourceScanner = new McpServerSourceScanner();
  private sbomVerifier = new SbomProvenanceVerifier();

  /**
   * Performs an authoritative 4-vector supply-chain security scan:
   * 1. Dependency CVEs & typo-squats
   * 2. Install-time lifecycle script analysis
   * 3. Static MCP server source code vulnerability scan
   * 4. SBOM & SLSA provenance verification
   */
  public scan(targetDir: string = process.cwd()): UnifiedSupplyChainReport {
    const dependencies = this.depScanner.scanDirectory(targetDir);
    const installScripts = this.scriptAnalyzer.analyzePackage(targetDir);
    const sourceAudit = this.sourceScanner.scanSource(targetDir);
    const sbomProvenance = this.sbomVerifier.verify(targetDir);

    let criticalCount = dependencies.riskSummary.critical;
    let highCount = dependencies.riskSummary.high;

    for (const f of installScripts.maliciousFindings) {
      if (f.severity === 'CRITICAL') criticalCount++;
      if (f.severity === 'HIGH') highCount++;
    }

    for (const s of sourceAudit.findings) {
      if (s.severity === 'CRITICAL') criticalCount++;
      if (s.severity === 'HIGH') highCount++;
    }

    // Compute composite supply chain security score (0 - 100)
    let score = 100;
    score -= criticalCount * 25;
    score -= highCount * 10;
    score -= dependencies.riskSummary.medium * 3;
    score -= dependencies.typoSquats.length * 15;

    // Weight in SBOM & provenance
    const sbomAdjustment = (sbomProvenance.reputationScore - 70) * 0.2;
    score = Math.round(score + sbomAdjustment);
    score = Math.max(0, Math.min(100, score));

    return {
      targetDirectory: targetDir,
      timestamp: Date.now(),
      dependencies,
      installScripts,
      sourceAudit,
      sbomProvenance,
      criticalIssuesCount: criticalCount,
      highIssuesCount: highCount,
      supplyChainSecurityScore: score,
      passed: criticalCount === 0 && highCount === 0 && dependencies.typoSquats.length === 0,
    };
  }
}
