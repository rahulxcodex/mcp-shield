import { SecretSanitizer } from '../../src/security/sanitizer';

interface LabeledSample {
  id: string;
  category: string;
  input: string;
  isSecret: boolean;
  expectedPatternOrName?: string;
}

const EVALUATION_DATASET: LabeledSample[] = [
  // === TRUE POSITIVES (Real Credentials / Secrets) ===
  { id: 'SEC-01', category: 'AWS', input: 'aws_key = "' + ['AKIA', 'IOSFODNN7EXAMPLE'].join('') + '"', isSecret: true },
  { id: 'SEC-02', category: 'AWS', input: 'export ' + ['ASIA', 'IOSFODNN7EXAMPLE'].join('') + '=xyz', isSecret: true },
  { id: 'SEC-03', category: 'GitHub', input: ['ghp', '1234567890abcdefghijklmnopqrstuvwx'].join('_'), isSecret: true },
  { id: 'SEC-04', category: 'GitHub', input: ['github', 'pat', '11AAAAAAA0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz'].join('_'), isSecret: true },
  { id: 'SEC-05', category: 'Anthropic', input: ['sk', 'ant', 'api03', 'abcdef1234567890abcdef1234567890abcdef'].join('-'), isSecret: true },
  { id: 'SEC-06', category: 'OpenAI', input: ['sk', '1234567890abcdefghijklmnopqrstuvwxyzAB'].join('-'), isSecret: true },
  { id: 'SEC-07', category: 'OpenAI', input: ['sk', 'proj', '1234567890abcdefghijklmnopqrstuvwxyzABCD123456'].join('-'), isSecret: true },
  { id: 'SEC-08', category: 'Slack', input: ['xoxb', '123456789012', '1234567890123', 'abcdefghijklmnopqrstuvwx'].join('-'), isSecret: true },
  { id: 'SEC-09', category: 'Slack', input: ['xoxp', '123456789012', '1234567890123', 'abcdefghijklmnopqrstuvwx'].join('-'), isSecret: true },
  { id: 'SEC-10', category: 'Google', input: ['AIzaSyA', '1234567890abcdefghijklmnopqrstuv'].join(''), isSecret: true },
  { id: 'SEC-11', category: 'Stripe', input: ['sk', 'live', '1234567890abcdefghijklmnopqrstuvwx'].join('_'), isSecret: true },
  { id: 'SEC-12', category: 'Stripe', input: ['sk', 'test', '1234567890abcdefghijklmnopqrstuvwx'].join('_'), isSecret: true },
  { id: 'SEC-13', category: 'HuggingFace', input: ['hf', '1234567890abcdefghijklmnopqrstuvwxyzAB'].join('_'), isSecret: true },
  { id: 'SEC-14', category: 'GitLab', input: ['glpat', '1234567890abcdefghijklmnopqrst'].join('-'), isSecret: true },
  { id: 'SEC-15', category: 'JWT', input: 'Bearer ' + ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ', 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'].join('.'), isSecret: true },
  { id: 'SEC-16', category: 'SSH', input: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y1p...fake...rsa...key\n-----END RSA PRIVATE KEY-----', isSecret: true },
  { id: 'SEC-17', category: 'Custom Token Context', input: 'const api_secret = "qW9xP7mK2vL5jN8bV1cZ4xX6yT3rE9wQ0aB7cD8eF2gH1iJ4kL";', isSecret: true },
  { id: 'SEC-18', category: 'Custom Token Context', input: 'auth_token: "vM8kP3xZ9wL2jN7bQ1cR4xT6yV3rE8wA0aB5cD6eF7gH9iJ1kL"', isSecret: true },
  { id: 'SEC-19', category: 'Custom Password', input: 'db_password="Kj8mP2vL9xQ1cR4yT6wA0cD7eF9iJ2kL0123456789abcdef"', isSecret: true },
  { id: 'SEC-20', category: 'Bearer Token', input: 'Authorization: Bearer dXNlcjpwYXNzd29yZF9leGFtcGxlXzEyMzQ1Njc4OTA1NmJhc2U2NA==', isSecret: true },

  // === NEGATIVE SAMPLES (False Positives / Non-Secrets) ===
  { id: 'NEG-01', category: 'UUID', input: 'session_id = "550e8400-e29b-41d4-a716-446655440000"', isSecret: false },
  { id: 'NEG-02', category: 'UUID', input: 'request_id = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"', isSecret: false },
  { id: 'NEG-03', category: 'Git Commit SHA', input: 'commit 7b520448103d334972e3d93f70d9ded6f87a84d1', isSecret: false },
  { id: 'NEG-04', category: 'SHA256 Hash', input: 'checksum: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', isSecret: false },
  { id: 'NEG-05', category: 'MD5 Hash', input: 'etag: "d41d8cd98f00b204e9800998ecf8427e"', isSecret: false },
  { id: 'NEG-06', category: 'Minified JS Code', input: 'function t(e,n){return e.filter((function(e){return e.id===n}))}', isSecret: false },
  { id: 'NEG-07', category: 'Source Identifier', input: 'const MCPShieldContainerRuntimeSandboxEnvironmentVariable = true;', isSecret: false },
  { id: 'NEG-08', category: 'Log Line', input: '[INFO] 2026-08-31T12:00:00.000Z Connection established on port 8080 successfully.', isSecret: false },
  { id: 'NEG-09', category: 'URL', input: 'Visit https://github.com/rahulxcodex/mcp-shield/blob/main/README.md for docs', isSecret: false },
  { id: 'NEG-10', category: 'CSS Colors', input: 'background-color: #f8f9fa; border: 1px solid #dee2e6; color: #212529;', isSecret: false },
  { id: 'NEG-11', category: 'Math Equation', input: 'e^(i*pi) + 1 = 0; derivative = (f(x+h) - f(x)) / h; sum = n*(n+1)/2;', isSecret: false },
  { id: 'NEG-12', category: 'Base64 Non-Secret Data', input: 'const placeholder = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";', isSecret: false },
  { id: 'NEG-13', category: 'JSON Data', input: '{"user_id": 12345, "name": "Alice Developer", "role": "admin"}', isSecret: false },
  { id: 'NEG-14', category: 'Path', input: '/usr/local/bin/node /home/user/projects/mcp-shield/dist/index.js', isSecret: false },
  { id: 'NEG-15', category: 'Package Name', input: 'npm install --save-dev @types/node @types/jest @types/express typescript', isSecret: false }
];

describe('SecretSanitizer Ground-Truth Evaluation Suite', () => {
  let sanitizer: SecretSanitizer;

  beforeEach(() => {
    sanitizer = new SecretSanitizer({ confidenceThreshold: 60 });
  });

  it('evaluates Precision, Recall, F1 Score, and False Positive Rate against labeled dataset', () => {
    let tp = 0; // True Positive: Actual secret, Sanitized
    let fp = 0; // False Positive: Not a secret, Sanitized
    let tn = 0; // True Negative: Not a secret, Unchanged
    let fn = 0; // False Negative: Actual secret, Unchanged

    for (const sample of EVALUATION_DATASET) {
      const sanitized = sanitizer.sanitize(sample.input);
      const isRedacted = sanitized.includes('[[SHIELD_SECRET_');

      if (sample.isSecret) {
        if (isRedacted) {
          tp++;
        } else {
          fn++;
          console.warn(`[FALSE NEGATIVE] ID: ${sample.id}, Category: ${sample.category}, Input: ${sample.input}`);
        }
      } else {
        if (isRedacted) {
          fp++;
          console.warn(`[FALSE POSITIVE] ID: ${sample.id}, Category: ${sample.category}, Input: ${sample.input}`);
        } else {
          tn++;
        }
      }
    }

    const precision = tp / (tp + fp);
    const recall = tp / (tp + fn);
    const f1 = (2 * precision * recall) / (precision + recall);
    const fpr = fp / (fp + tn);

    console.log('\n================ SECRET SANITIZER EVALUATION RESULTS ================');
    console.log(`Total Samples:       ${EVALUATION_DATASET.length}`);
    console.log(`True Positives (TP): ${tp}`);
    console.log(`True Negatives (TN): ${tn}`);
    console.log(`False Positives(FP): ${fp}`);
    console.log(`False Negatives(FN): ${fn}`);
    console.log(`---------------------------------------------------------------------`);
    console.log(`Precision:           ${(precision * 100).toFixed(2)}%`);
    console.log(`Recall:              ${(recall * 100).toFixed(2)}%`);
    console.log(`F1 Score:            ${(f1 * 100).toFixed(2)}%`);
    console.log(`False Positive Rate: ${(fpr * 100).toFixed(2)}%`);
    console.log('=====================================================================\n');

    // Strict assertions for production DLP
    expect(recall).toBeGreaterThanOrEqual(0.95);
    expect(precision).toBeGreaterThanOrEqual(0.95);
    expect(f1).toBeGreaterThanOrEqual(0.95);
    expect(fpr).toBeLessThanOrEqual(0.05);
  });
});
