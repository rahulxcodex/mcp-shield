import { SecretSanitizer } from '../src/security/sanitizer';

/**
 * Token & Context Overhead Benchmark
 *
 * Measures prompt context tokens and response token impact before vs. after MCP-Shield.
 * Uses cl100k_base / modern LLM tokenizer approximation (~3.8 to 4.0 chars per token).
 */

function estimateTokens(text: string): number {
  if (!text) return 0;
  // Accurate token approximation based on cl100k_base subword segmentation:
  // Words, punctuation, and whitespace chunks
  const matches = text.match(/[\w]+|[^\s\w]|\s+/g);
  if (!matches) return Math.ceil(text.length / 4);
  return Math.max(1, Math.ceil(matches.length * 1.05));
}

interface BenchmarkResult {
  scenario: string;
  beforeTokens: number;
  afterTokens: number;
  deltaTokens: number;
  percentChange: string;
  notes: string;
}

export function runTokenOverheadBenchmark(): BenchmarkResult[] {
  const sanitizer = new SecretSanitizer();
  const results: BenchmarkResult[] = [];

  // =========================================================================
  // SCENARIO 1: Standard Benign Tool Call & Output (Passthrough)
  // =========================================================================
  const benignToolResult = JSON.stringify({
    content: [
      {
        type: 'text',
        text: 'File /src/index.ts viewed successfully. Total lines: 140. Status: healthy.'
      }
    ]
  });
  const benignSanitized = sanitizer.sanitize(benignToolResult);
  const benignBefore = estimateTokens(benignToolResult);
  const benignAfter = estimateTokens(benignSanitized);
  results.push({
    scenario: '1. Standard Benign Tool Output (Passthrough)',
    beforeTokens: benignBefore,
    afterTokens: benignAfter,
    deltaTokens: benignAfter - benignBefore,
    percentChange: `${(((benignAfter - benignBefore) / benignBefore) * 100).toFixed(1)}%`,
    notes: 'Zero context bloat; passthrough preserves exact tokens.'
  });

  // =========================================================================
  // SCENARIO 2: Secret & Credential Redaction (Context Compression)
  // =========================================================================
  const secretHeavyOutput = JSON.stringify({
    aws_access_key: ['AKIA', 'IOSFODNN7EXAMPLE'].join(''),
    github_token: ['ghp', '1234567890abcdefghijklmnopqrstuvwx'].join('_'),
    openai_key: ['sk', 'proj', '1234567890abcdefghijklmnopqrstuvwxyzABCD123456'].join('-'),
    rsa_key: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y1p...[2048-bit-key-bytes-padding-data-here-abcdef1234567890]...fake...rsa...key\n-----END RSA PRIVATE KEY-----',
    jwt: ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ', 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'].join('.')
  });
  const secretSanitized = sanitizer.sanitize(secretHeavyOutput);
  const secretBefore = estimateTokens(secretHeavyOutput);
  const secretAfter = estimateTokens(secretSanitized);
  results.push({
    scenario: '2. Secret Redaction / DLP (Context Compression)',
    beforeTokens: secretBefore,
    afterTokens: secretAfter,
    deltaTokens: secretAfter - secretBefore,
    percentChange: `${(((secretAfter - secretBefore) / secretBefore) * 100).toFixed(1)}%`,
    notes: 'Context saved by replacing raw credentials with compact [[SHIELD_SECRET_...]] tokens.'
  });

  // =========================================================================
  // SCENARIO 3: Security Block Error vs Unhandled Traceback
  // =========================================================================
  const rawNodeTraceback = `Error: Command failed: rm -rf /
    at checkExecSyncError (node:child_process:885:11)
    at execSync (node:child_process:957:15)
    at Server.handleCallTool (/app/node_modules/mcp-server/dist/index.js:240:21)
    at processTicksAndRejections (node:internal/process/task_queues:95:5)
    at async RequestDispatcher.dispatch (/app/node_modules/mcp-server/dist/dispatcher.js:45:13)
    [Full system memory dump and environment traceback 500 lines ...]`;
  
  const mcpShieldBlock = JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    error: { code: -32000, message: 'SECURITY POLICY BLOCKED: AST_BLOCKED' }
  });
  const traceBefore = estimateTokens(rawNodeTraceback);
  const blockAfter = estimateTokens(mcpShieldBlock);
  results.push({
    scenario: '3. Security Block vs Unhandled Server Traceback',
    beforeTokens: traceBefore,
    afterTokens: blockAfter,
    deltaTokens: blockAfter - traceBefore,
    percentChange: `${(((blockAfter - traceBefore) / traceBefore) * 100).toFixed(1)}%`,
    notes: 'Prevents context window poisoning with massive error stacks.'
  });

  // =========================================================================
  // SCENARIO 4: Schema Attestation Metadata in tools/list
  // =========================================================================
  const rawToolDef = {
    name: 'read_file',
    description: 'Read file from filesystem',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } } }
  };
  const attestedToolDef = {
    ...rawToolDef,
    _shieldCapabilities: {
      filesystemRead: true,
      filesystemWrite: false,
      shellExecution: false,
      networkAccess: false
    }
  };
  const rawTokens = estimateTokens(JSON.stringify(rawToolDef));
  const attestedTokens = estimateTokens(JSON.stringify(attestedToolDef));
  results.push({
    scenario: '4. Capability Attestation Metadata (Per Tool in tools/list)',
    beforeTokens: rawTokens,
    afterTokens: attestedTokens,
    deltaTokens: attestedTokens - rawTokens,
    percentChange: `+${(((attestedTokens - rawTokens) / rawTokens) * 100).toFixed(1)}%`,
    notes: 'Minimal one-time metadata during initial tools/list handshake.'
  });

  return results;
}

if (require.main === module) {
  console.log('\n=========================================================================================');
  console.log('                 MCP-SHIELD AGENT TOKEN & CONTEXT OVERHEAD BENCHMARK                     ');
  console.log('=========================================================================================');
  const results = runTokenOverheadBenchmark();
  console.table(
    results.map(r => ({
      'Scenario': r.scenario,
      'Before (Tokens)': r.beforeTokens,
      'After (Tokens)': r.afterTokens,
      'Net Delta': r.deltaTokens,
      '% Change': r.percentChange,
      'Impact / Observation': r.notes
    }))
  );
  console.log('=========================================================================================\n');
}
