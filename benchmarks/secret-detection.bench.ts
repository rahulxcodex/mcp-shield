import { performance } from 'perf_hooks';
import * as fs from 'fs';
import * as path from 'path';
import { SecretSanitizer } from '../src/security/sanitizer';

export interface LabeledBenchmarkEntry {
  category: string;
  sourceType: 'typescript' | 'python' | 'json' | 'yaml' | 'bash' | 'log' | 'diff' | 'env';
  content: string;
  expectedSecretCount: number;
  expectedSecrets: string[];
  nonSecretHighEntropyPatterns?: string[];
}

export interface SecretBenchmarkReport {
  totalLines: number;
  totalBytes: number;
  groundTruthSecrets: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1Score: number;
  durationMs: number;
  throughputMBps: number;
  throughputLinesPerSec: number;
  categoryBreakdown: Record<string, {
    lines: number;
    secrets: number;
    tp: number;
    fp: number;
    fn: number;
    precision: number;
    recall: number;
  }>;
}

export function generateLabeledDataset(): LabeledBenchmarkEntry[] {
  return [
    // 1. TypeScript Real-World Workload
    {
      category: 'Source Code (TypeScript)',
      sourceType: 'typescript',
      expectedSecretCount: 3,
      expectedSecrets: [
        'AKIAIOSFODNN7EXAMPLE',
        'sk-ant-api03-abcdef1234567890abcdef1234567890abcdef1234567890',
        'ghp_1234567890abcdefghijklmnopqrstuvwxyz1234'
      ],
      nonSecretHighEntropyPatterns: [
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', // SHA-256
        '123e4567-e89b-12d3-a456-426614174000', // UUID
        'btn-primary-bg-gradient-49f82b7c' // CSS hash
      ],
      content: `
import axios from 'axios';
import { createHash } from 'crypto';

// Configuration module with embedded secrets and SHA hashes
export const CONFIG = {
  awsKeyId: "AKIAIOSFODNN7EXAMPLE",
  anthropicApiKey: "sk-ant-api03-abcdef1234567890abcdef1234567890abcdef1234567890",
  githubToken: "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234",
  commitSha: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  sessionId: "123e4567-e89b-12d3-a456-426614174000",
  buildCssClass: "btn-primary-bg-gradient-49f82b7c"
};

export async function fetchRepositoryData(repo: string) {
  const hash = createHash('sha256').update(repo).digest('hex');
  return axios.get(\`https://api.github.com/repos/\${repo}\`, {
    headers: { Authorization: \`Bearer \${CONFIG.githubToken}\` }
  });
}
`
    },

    // 2. Python Backend & ML Training Code
    {
      category: 'Source Code (Python)',
      sourceType: 'python',
      expectedSecretCount: 2,
      expectedSecrets: [
        'sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz',
        'hf_abcdefghijklmnopqrstuvwxyz12345678901234'
      ],
      nonSecretHighEntropyPatterns: [
        'b64e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b',
        'tensor_weights_layer_0_checkpoint_f48a901c'
      ],
      content: `
import os
import openai
from transformers import AutoModelForCausalLM

OPENAI_API_KEY = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz"
HF_TOKEN = "hf_abcdefghijklmnopqrstuvwxyz12345678901234"
CHECKPOINT_HASH = "b64e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b"

def load_foundation_model():
    model = AutoModelForCausalLM.from_pretrained(
        "meta-llama/Llama-3-8B",
        use_auth_token=HF_TOKEN,
        cache_dir="/tmp/models/tensor_weights_layer_0_checkpoint_f48a901c"
    )
    return model
`
    },

    // 3. Cloud & Infrastructure Configs (YAML / Terraform)
    {
      category: 'Infrastructure & Configs (YAML/JSON)',
      sourceType: 'yaml',
      expectedSecretCount: 3,
      expectedSecrets: [
        'AIzaSyD1234567890abcdefghijklmnopqrstuvwx',
        'sk_test_51000000000000000000000000000000',
        'glpat-abcdef12345678901234'
      ],
      content: `
apiVersion: v1
kind: Secret
metadata:
  name: cloud-gateway-credentials
  namespace: production
type: Opaque
stringData:
  googleApiKey: "AIzaSyD1234567890abcdefghijklmnopqrstuvwx"
  stripeSecretKey: "sk_test_51000000000000000000000000000000"
  gitlabToken: "glpat-abcdef12345678901234"
  clusterUid: "d7a48b91-8c43-4f92-b43e-a89e4c1987d2"
  sslCertFingerprint: "SHA256:7b:19:f2:8c:4a:d9:e1:33:55:66:77:88:99:aa:bb:cc"
`
    },

    // 4. CI/CD Server Logs & Stack Traces
    {
      category: 'CI/CD & Server Logs',
      sourceType: 'log',
      expectedSecretCount: 2,
      expectedSecrets: [
        'xoxb-EXAMPLE000000000000000000000000',
        'eyJhYmMxMjMiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.abcdef1234567890abcdef1234567890abcdef1234'
      ],
      nonSecretHighEntropyPatterns: [
        'GET /v1/healthcheck?trace_id=9876543210fedcba0987654321',
        'DEBUG: Memory chunk alloc 0x7fff5fbff840 -> 0x7fff5fbffa40'
      ],
      content: `
2026-08-31T08:14:02.124Z [INFO] Initializing Slack webhook notification service
2026-08-31T08:14:02.125Z [DEBUG] Token set: xoxb-EXAMPLE000000000000000000000000
2026-08-31T08:14:02.128Z [INFO] Processing request id: 9876543210fedcba0987654321
2026-08-31T08:14:02.130Z [DEBUG] Authorization header: Bearer eyJhYmMxMjMiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.abcdef1234567890abcdef1234567890abcdef1234
2026-08-31T08:14:02.135Z [INFO] Handshake complete. Status: 200 OK. Alloc address: 0x7fff5fbff840
`
    },

    // 5. Sensitive SSH Private Key Block
    {
      category: 'Certificates & Keys',
      sourceType: 'env',
      expectedSecretCount: 1,
      expectedSecrets: [
        '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACD99Q0bKq23L0q1v40wS8z2zQ34A==\n-----END OPENSSH PRIVATE KEY-----'
      ],
      content: `
DEPLOY_SSH_KEY="-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACD99Q0bKq23L0q1v40wS8z2zQ34A==\n-----END OPENSSH PRIVATE KEY-----"
`
    },

    // 6. Large Monorepo Log Dump with Injected Credentials & SHA Hash Noise
    {
      category: 'Build & Test Log Dump (Noise Stress Test)',
      sourceType: 'log',
      expectedSecretCount: 4,
      expectedSecrets: [
        'ghp_abcdefghijklmnopqrstuvwxyz1234567890',
        'sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef',
        'AKIAIOSFODNN7EXAMPLE',
        'AIzaSyD1234567890abcdefghijklmnopqrstuv'
      ],
      nonSecretHighEntropyPatterns: [
        'npm-audit-advisory-99482b1c4e',
        'webpack-bundle-hash-d41d8cd98f00b204e9800998ecf8427e',
        'sha512-3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      ],
      content: `
[BUILD] Starting turbo build pipeline...
[BUILD] Cache hit for @mcp/core (hash: webpack-bundle-hash-d41d8cd98f00b204e9800998ecf8427e)
[TEST] Running integration suites on cluster node-worker-49b2
[DEBUG] Exporting test environment credentials:
[DEBUG] GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890
[DEBUG] ANTHROPIC_API_KEY=sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef
[DEBUG] AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
[DEBUG] GOOGLE_APPLICATION_CREDENTIALS_KEY=AIzaSyD1234567890abcdefghijklmnopqrstuv
[INFO] Package integrity check passed (sha512-3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)
[INFO] Audit report ID: npm-audit-advisory-99482b1c4e
[BUILD] Pipeline finished with code 0 in 1.42s
`
    },

    // 7. Benign Source Code (Zero Secrets, High-Entropy False-Positive Traps)
    {
      category: 'Benign Code (Zero Secrets Control)',
      sourceType: 'typescript',
      expectedSecretCount: 0,
      expectedSecrets: [],
      content: `
// High entropy variable names and mathematical constants
export const PI_HIGH_PRECISION = "3.141592653589793238462643383279502884197169399375105820974944592307816406286";
export const RANDOM_MOCK_UUID = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
export const GIT_TREE_OID = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
export const CSP_NONCE = "nonce-rAnd0m1234567890qwert";

export function computeDistance(x1: number, y1: number, x2: number, y2: number): number {
  return Math.sqrt(Math.pow(x2 - x1, 2) + Math.pow(y2 - y1, 2));
}
`
    }
  ];
}

export function runSecretDetectionBenchmark(iterations: number = 20): SecretBenchmarkReport {
  const baseDataset = generateLabeledDataset();
  const sanitizer = new SecretSanitizer();

  let totalLines = 0;
  let totalBytes = 0;
  let groundTruthSecrets = 0;
  let truePositives = 0;
  let falsePositives = 0;
  let falseNegatives = 0;

  const categoryBreakdown: SecretBenchmarkReport['categoryBreakdown'] = {};

  const startTime = performance.now();

  for (let iter = 0; iter < iterations; iter++) {
    for (const entry of baseDataset) {
      const lines = entry.content.split('\n').length;
      const bytes = Buffer.byteLength(entry.content, 'utf8');
      totalLines += lines;
      totalBytes += bytes;
      groundTruthSecrets += entry.expectedSecretCount;

      if (!categoryBreakdown[entry.category]) {
        categoryBreakdown[entry.category] = {
          lines: 0,
          secrets: 0,
          tp: 0,
          fp: 0,
          fn: 0,
          precision: 0,
          recall: 0
        };
      }
      const cat = categoryBreakdown[entry.category];
      cat.lines += lines;
      cat.secrets += entry.expectedSecretCount;

      const sanitized = sanitizer.sanitize(entry.content);

      // Count how many expected secrets were replaced
      let entryTP = 0;
      let entryFN = 0;
      for (const secret of entry.expectedSecrets) {
        if (!sanitized.includes(secret)) {
          entryTP++;
        } else {
          entryFN++;
        }
      }

      // Count total token replacements
      const tokenMatches = (sanitized.match(/\[\[SHIELD_SECRET_[0-9a-fA-F-]{36}\]\]/g) || []).length;
      const entryFP = Math.max(0, tokenMatches - entryTP);

      truePositives += entryTP;
      falseNegatives += entryFN;
      falsePositives += entryFP;

      cat.tp += entryTP;
      cat.fn += entryFN;
      cat.fp += entryFP;
    }
  }

  const durationMs = performance.now() - startTime;

  const precision = truePositives + falsePositives > 0
    ? truePositives / (truePositives + falsePositives)
    : 1.0;

  const recall = truePositives + falseNegatives > 0
    ? truePositives / (truePositives + falseNegatives)
    : 1.0;

  const f1Score = precision + recall > 0
    ? (2 * precision * recall) / (precision + recall)
    : 1.0;

  for (const cat of Object.values(categoryBreakdown)) {
    cat.precision = cat.tp + cat.fp > 0 ? cat.tp / (cat.tp + cat.fp) : 1.0;
    cat.recall = cat.tp + cat.fn > 0 ? cat.tp / (cat.tp + cat.fn) : 1.0;
  }

  const totalMB = totalBytes / (1024 * 1024);
  const throughputMBps = (totalMB / (durationMs / 1000));
  const throughputLinesPerSec = Math.round(totalLines / (durationMs / 1000));

  const report: SecretBenchmarkReport = {
    totalLines,
    totalBytes,
    groundTruthSecrets,
    truePositives,
    falsePositives,
    falseNegatives,
    precision,
    recall,
    f1Score,
    durationMs,
    throughputMBps,
    throughputLinesPerSec,
    categoryBreakdown
  };

  printBenchmarkReport(report);
  return report;
}

function printBenchmarkReport(report: SecretBenchmarkReport) {
  console.log('\n================================================================================');
  console.log('🎯 MCP-SHIELD SECRET SANITIZER (DLP) PRECISION & RECALL BENCHMARK');
  console.log('================================================================================\n');

  console.log(`- Total Evaluated Lines: ${report.totalLines.toLocaleString()}`);
  console.log(`- Total Payload Size:    ${(report.totalBytes / 1024).toFixed(2)} KB`);
  console.log(`- Ground Truth Secrets:  ${report.groundTruthSecrets}`);
  console.log(`- True Positives (TP):   ${report.truePositives}`);
  console.log(`- False Positives (FP):  ${report.falsePositives}`);
  console.log(`- False Negatives (FN):  ${report.falseNegatives}`);
  console.log(`- Precision:             ${(report.precision * 100).toFixed(2)}%`);
  console.log(`- Recall:                ${(report.recall * 100).toFixed(2)}%`);
  console.log(`- F1-Score:              ${(report.f1Score * 100).toFixed(2)}%`);
  console.log(`- Scanner Speed:         ${report.throughputLinesPerSec.toLocaleString()} lines/sec\n`);

  console.log('| Category | Lines | Real Secrets | TP | FP | FN | Precision | Recall |');
  console.log('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |');

  for (const [name, cat] of Object.entries(report.categoryBreakdown)) {
    console.log(
      `| **${name}** | ${cat.lines} | ${cat.secrets} | ${cat.tp} | ${cat.fp} | ${cat.fn} | ${(cat.precision * 100).toFixed(1)}% | ${(cat.recall * 100).toFixed(1)}% |`
    );
  }
}

if (require.main === module) {
  runSecretDetectionBenchmark();
}
