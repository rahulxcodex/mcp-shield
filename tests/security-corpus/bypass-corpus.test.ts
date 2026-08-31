import * as fs from 'fs';
import * as path from 'path';
import { ASTAnalyzer } from '../../src/security/ast-analyzer';
import { SecretSanitizer } from '../../src/security/sanitizer';
import { PolicyEngine } from '../../src/security/policy-engine';
import { ConfigLoader } from '../../src/security/config';

describe('Adversarial Bypass Corpus Regression Suite', () => {
  let astAnalyzer: ASTAnalyzer;
  let sanitizer: SecretSanitizer;
  let policyEngine: PolicyEngine;
  let corpus: Array<{ category: string; description: string; payloads: string[] }>;

  beforeAll(() => {
    astAnalyzer = new ASTAnalyzer();
    sanitizer = new SecretSanitizer();
    policyEngine = new PolicyEngine(ConfigLoader.getHardenedProfile());
    policyEngine.start();

    const corpusPath = path.join(__dirname, 'bypass-corpus.json');
    corpus = JSON.parse(fs.readFileSync(corpusPath, 'utf8'));
  });

  afterAll(() => {
    policyEngine.close();
  });

  it('should enforce that bypass-corpus.json contains categorized adversarial entries', () => {
    expect(corpus.length).toBeGreaterThan(0);
    for (const section of corpus) {
      expect(section.category).toBeDefined();
      expect(section.payloads.length).toBeGreaterThan(0);
    }
  });

  it('should block all AST evasion and wrapper attacks in bypass corpus', () => {
    const section = corpus.find(c => c.category === 'ast_evasion_wrappers');
    expect(section).toBeDefined();

    for (const payload of section!.payloads) {
      const res = astAnalyzer.analyzeCommand(payload);
      expect(res.isSafe).toBe(false);
    }
  });

  it('should block all interpreter injection and pipe evasion attacks in bypass corpus', () => {
    const section = corpus.find(c => c.category === 'ast_interpreter_injection');
    expect(section).toBeDefined();

    for (const payload of section!.payloads) {
      const res = astAnalyzer.analyzeCommand(payload);
      expect(res.isSafe).toBe(false);
    }
  });

  it('should block all raw disk destruction and filesystem format commands in bypass corpus', () => {
    const section = corpus.find(c => c.category === 'raw_disk_destruction');
    expect(section).toBeDefined();

    for (const payload of section!.payloads) {
      const res = astAnalyzer.analyzeCommand(payload);
      expect(res.isSafe).toBe(false);
    }
  });

  it('should sanitize all credentials and API keys in bypass corpus', () => {
    const section = corpus.find(c => c.category === 'data_exfiltration_secrets');
    expect(section).toBeDefined();

    for (const secret of section!.payloads) {
      const sanitized = sanitizer.sanitize(`Authorization: Bearer ${secret}`);
      expect(sanitized).not.toContain(secret);
      expect(sanitized).toContain('[[SHIELD_SECRET_');

      // Verify lossless roundtrip
      const restored = sanitizer.restore(sanitized);
      expect(restored).toContain(secret);
    }
  });

  it('should block SSRF and exfiltration endpoints in bypass corpus', () => {
    const section = corpus.find(c => c.category === 'ssrf_and_exfiltration');
    expect(section).toBeDefined();

    for (const url of section!.payloads) {
      const res = policyEngine.checkEgress({ url });
      expect(res.isBlocked).toBe(true);
    }
  });
});
