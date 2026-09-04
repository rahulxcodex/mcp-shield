import * as fs from 'fs';
import * as path from 'path';

export interface SbomValidationReport {
  sbomFound: boolean;
  sbomPath?: string;
  format?: 'CycloneDX' | 'SPDX' | 'UNKNOWN';
  totalComponents: number;
  componentsWithoutLicense: number;
  untrustedPublishers: string[];
  provenanceVerified: boolean;
  slsaLevel: 'SLSA_L0' | 'SLSA_L1' | 'SLSA_L2' | 'SLSA_L3';
  reputationScore: number; // 0 to 100
}

export class SbomProvenanceVerifier {
  /**
   * Evaluates local SBOM files and provenance attestations for an MCP server project.
   */
  public verify(projectDir: string): SbomValidationReport {
    const candidates = [
      path.join(projectDir, 'mcp-shield.sbom.json'),
      path.join(projectDir, 'bom.json'),
      path.join(projectDir, 'sbom.json'),
      path.join(projectDir, 'cyclonedx.json'),
    ];

    let sbomPath: string | undefined;
    for (const c of candidates) {
      if (fs.existsSync(c)) {
        sbomPath = c;
        break;
      }
    }

    if (!sbomPath) {
      return {
        sbomFound: false,
        totalComponents: 0,
        componentsWithoutLicense: 0,
        untrustedPublishers: [],
        provenanceVerified: false,
        slsaLevel: 'SLSA_L0',
        reputationScore: 40, // Base score when no SBOM provided
      };
    }

    try {
      const raw = fs.readFileSync(sbomPath, 'utf8');
      const data = JSON.parse(raw);

      let format: 'CycloneDX' | 'SPDX' | 'UNKNOWN' = 'UNKNOWN';
      let components: any[] = [];

      if (data.bomFormat === 'CycloneDX' || data.specVersion) {
        format = 'CycloneDX';
        components = Array.isArray(data.components) ? data.components : [];
      } else if (data.spdxVersion) {
        format = 'SPDX';
        components = Array.isArray(data.packages) ? data.packages : [];
      }

      let missingLicense = 0;
      const untrustedPublishers: string[] = [];

      for (const comp of components) {
        // License checks
        const hasLicense =
          (comp.licenses && comp.licenses.length > 0) ||
          comp.licenseConcluded ||
          comp.licenseDeclared;
        if (!hasLicense) {
          missingLicense++;
        }

        // Publisher check
        const publisher = comp.publisher || comp.group || comp.supplier;
        if (typeof publisher === 'string') {
          if (publisher.includes('anonymous') || publisher.includes('unverified')) {
            untrustedPublishers.push(`${comp.name} (${publisher})`);
          }
        }
      }

      // Check SLSA provenance
      const provenanceFile = path.join(projectDir, 'provenance.json');
      const hasProvenance = fs.existsSync(provenanceFile);

      let slsaLevel: 'SLSA_L0' | 'SLSA_L1' | 'SLSA_L2' | 'SLSA_L3' = 'SLSA_L1';
      if (hasProvenance) {
        slsaLevel = 'SLSA_L2';
      }

      let score = 85;
      if (missingLicense > 0) score -= Math.min(20, missingLicense * 2);
      if (untrustedPublishers.length > 0) score -= Math.min(25, untrustedPublishers.length * 5);
      if (hasProvenance) score += 15;
      score = Math.max(20, Math.min(100, score));

      return {
        sbomFound: true,
        sbomPath,
        format,
        totalComponents: components.length,
        componentsWithoutLicense: missingLicense,
        untrustedPublishers,
        provenanceVerified: hasProvenance,
        slsaLevel,
        reputationScore: score,
      };
    } catch {
      return {
        sbomFound: true,
        sbomPath,
        format: 'UNKNOWN',
        totalComponents: 0,
        componentsWithoutLicense: 0,
        untrustedPublishers: [],
        provenanceVerified: false,
        slsaLevel: 'SLSA_L0',
        reputationScore: 30,
      };
    }
  }
}
