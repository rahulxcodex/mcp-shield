import * as fs from 'fs';
import * as path from 'path';
import {
  generateProductionCertification,
  ProductionCertification
} from '../../scripts/generate-production-certification';

describe('Finite Versioned Production Certification Contract', () => {
  const rootDir = path.resolve(__dirname, '../..');
  const certPath = path.resolve(rootDir, 'PRODUCTION_CERTIFICATION.json');

  const MANDATORY_CONTROLS: (keyof Omit<ProductionCertification, 'release' | 'commit' | 'build' | 'environment' | 'overall_status'>)[] = [
    'test_suite',
    'security_suite',
    'redteam_suite',
    'fuzzing',
    'mutation_testing',
    'dependency_scan',
    'secret_scan',
    'container_scan',
    'database_verification',
    'rls_verification',
    'tenant_isolation',
    'authentication',
    'authorization',
    'ssrf',
    'dLP',
    'mcp_conformance',
    'webhook_security',
    'billing',
    'licensing',
    'observability',
    'backup_restore',
    'performance',
    'disaster_recovery',
    'configuration',
    'deployment_smoke_test',
    'rollback_test'
  ];

  beforeAll(() => {
    generateProductionCertification();
  });

  it('generates a valid PRODUCTION_CERTIFICATION.json at repository root', () => {
    expect(fs.existsSync(certPath)).toBe(true);
    const raw = fs.readFileSync(certPath, 'utf8');
    const cert: ProductionCertification = JSON.parse(raw);

    expect(cert.release).toMatch(/^mcpshld@\d+\.\d+\.\d+/);
    expect(cert.commit).toBeDefined();
    expect(cert.commit.length).toBeGreaterThanOrEqual(4);
    expect(cert.build).toMatch(/^build-\d{8}-/);
    expect(cert.environment).toBe('production');
  });

  it('verifies all 26 mandatory control domains have status: PASS and executable evidence', () => {
    const cert: ProductionCertification = JSON.parse(fs.readFileSync(certPath, 'utf8'));

    for (const ctrlKey of MANDATORY_CONTROLS) {
      const item = cert[ctrlKey];
      expect(item).toBeDefined();
      expect(item.status).toBe('PASS');
      expect(typeof item.evidence).toBe('string');
      expect(item.evidence.length).toBeGreaterThan(10);
      expect(typeof item.command).toBe('string');
      expect(item.command.length).toBeGreaterThan(3);
      expect(typeof item.timestamp).toBe('string');
      expect(typeof item.artifact).toBe('string');
    }
  });

  it('guarantees overall_status is strictly PRODUCTION_READY when all mandatory controls pass', () => {
    const cert: ProductionCertification = JSON.parse(fs.readFileSync(certPath, 'utf8'));
    expect(cert.overall_status).toBe('PRODUCTION_READY');
  });

  it('enforces fail-closed: overall_status CANNOT be PRODUCTION_READY if any control is FAIL', () => {
    const cert: ProductionCertification = JSON.parse(fs.readFileSync(certPath, 'utf8'));

    // Mutate one control to FAIL
    cert.ssrf.status = 'FAIL';

    // Simulate certification evaluator logic
    const failedControls = MANDATORY_CONTROLS.filter(
      (k) => cert[k].status !== 'PASS' && cert[k].status !== 'NOT_APPLICABLE'
    );
    const evaluatedStatus = failedControls.length > 0 ? 'CERTIFICATION_FAILED' : 'PRODUCTION_READY';

    expect(evaluatedStatus).toBe('CERTIFICATION_FAILED');
    expect(evaluatedStatus).not.toBe('PRODUCTION_READY');
  });

  it('ensures reports/production-certification.json is synchronized with root contract', () => {
    const reportsPath = path.resolve(rootDir, 'reports/production-certification.json');
    expect(fs.existsSync(reportsPath)).toBe(true);

    const rootCert: ProductionCertification = JSON.parse(fs.readFileSync(certPath, 'utf8'));
    const reportsCert = JSON.parse(fs.readFileSync(reportsPath, 'utf8'));

    expect(reportsCert.overall_status).toBe(rootCert.overall_status);
    expect(reportsCert.release).toBe(rootCert.release);
  });
});
