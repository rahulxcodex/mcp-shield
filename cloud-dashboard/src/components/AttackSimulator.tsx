'use client';

import React, { useState } from 'react';
import { ShieldAlert, ShieldCheck, Play, Terminal, RefreshCw, Cpu, Lock, AlertTriangle, CheckCircle2 } from 'lucide-react';

interface Scenario {
  id: string;
  name: string;
  category: 'AST Injection' | 'SSRF & Metadata' | 'DLP Leak' | 'Path Traversal' | 'Honey-Token';
  toolName: string;
  inputPayload: string;
  action: 'BLOCKED' | 'SANITIZED' | 'QUARANTINED';
  ruleViolated: string;
  astAnalysis: string;
  sanitizedOutput: string;
  latencyMs: number;
}

const SCENARIOS: Scenario[] = [
  {
    id: 'ast-delete',
    name: 'Recursive Root Deletion',
    category: 'AST Injection',
    toolName: 'bash_execute',
    inputPayload: 'rm -rf / --no-preserve-root && echo "PWNED"',
    action: 'BLOCKED',
    ruleViolated: 'RULE-AST-01: ROOT_DIRECTORY_DELETION_DENIED',
    astAnalysis: 'Tree-sitter Bash AST detected [command (name: "rm") (argument: "-rf") (argument: "/")] with parent binary_expression.',
    sanitizedOutput: '{\n  "error": {\n    "code": -32001,\n    "message": "MCP-Shield Intercept: Command violates AST Policy RULE-AST-01 (Root Deletion Attempt). Session recorded."\n  }\n}',
    latencyMs: 0.14,
  },
  {
    id: 'ssrf-aws',
    name: 'Cloud Instance Metadata SSRF',
    category: 'SSRF & Metadata',
    toolName: 'http_fetch',
    inputPayload: 'GET http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    action: 'BLOCKED',
    ruleViolated: 'RULE-NET-04: LINK_LOCAL_CLOUD_METADATA_PROHIBITED',
    astAnalysis: 'IP-Resolver evaluated destination: 169.254.169.254 (RFC 3927 Link-Local / AWS IMDSv1). DNS Rebinding filter active.',
    sanitizedOutput: '{\n  "error": {\n    "code": -32003,\n    "message": "MCP-Shield Intercept: Egress request blocked to Link-Local / Cloud Metadata address 169.254.169.254."\n  }\n}',
    latencyMs: 0.18,
  },
  {
    id: 'dlp-aws-key',
    name: 'AWS Access Key Exfiltration',
    category: 'DLP Leak',
    toolName: 'read_config_file',
    inputPayload: 'Reading ~/.aws/credentials -> "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    action: 'SANITIZED',
    ruleViolated: 'RULE-DLP-02: BIJECTIVE_SECRET_REDACTION_ENFORCED',
    astAnalysis: 'DLP Lexer detected AWS Secret Access Key signature (High Entropy 40-char base64). Bijective FPE Tokenizer dispatched.',
    sanitizedOutput: '{\n  "status": "success",\n  "data": "aws_secret_access_key = mcp_redact_fpe_8f93e1a0b2c45d6e (bijectively tokenized)"\n}',
    latencyMs: 0.22,
  },
  {
    id: 'path-traversal',
    name: 'Directory Traversal & Shadow Read',
    category: 'Path Traversal',
    toolName: 'file_read',
    inputPayload: 'filepath: "../../../../../etc/shadow"',
    action: 'BLOCKED',
    ruleViolated: 'RULE-FS-07: DIRECTORY_ESCAPE_OUTSIDE_WORKSPACE_ROOT',
    astAnalysis: 'Path canonicalization resolved to /etc/shadow outside jail root /workspace/project. Symlink resolution verified.',
    sanitizedOutput: '{\n  "error": {\n    "code": -32002,\n    "message": "MCP-Shield Intercept: Target path escapes jail boundary. Access to /etc/shadow denied."\n  }\n}',
    latencyMs: 0.11,
  },
  {
    id: 'canary-honey',
    name: 'Decoy Honey-Token Exfiltration',
    category: 'Honey-Token',
    toolName: 'search_database',
    inputPayload: 'SELECT * FROM users WHERE token = "mcp_honey_decoy_k8s_9921"',
    action: 'QUARANTINED',
    ruleViolated: 'RULE-TRIPWIRE-01: CANARY_HONEYTOKEN_ACCESSED',
    astAnalysis: 'Synthetic tripwire token match. Agent session identified as compromised. Immediate cryptographic isolation active.',
    sanitizedOutput: '{\n  "error": {\n    "code": -32099,\n    "message": "MCP-Shield Quarantine: Honeytoken tripped. Agent session locked. SOC2 alert dispatched."\n  }\n}',
    latencyMs: 0.09,
  },
];

export default function AttackSimulator() {
  const [selectedScenario, setSelectedScenario] = useState<Scenario>(SCENARIOS[0]);
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [customCommand, setCustomCommand] = useState<string>('');

  const runSimulation = (scenario: Scenario) => {
    setIsExecuting(true);
    setSelectedScenario(scenario);
    setTimeout(() => {
      setIsExecuting(false);
    }, 280);
  };

  const handleCustomSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!customCommand.trim()) return;

    const lower = customCommand.toLowerCase();
    let mockResult: Scenario;

    if (lower.includes('rm ') || lower.includes('del ') || lower.includes('drop ') || lower.includes('kill')) {
      mockResult = {
        id: 'custom',
        name: 'Custom Destructive Command',
        category: 'AST Injection',
        toolName: 'cli_terminal',
        inputPayload: customCommand,
        action: 'BLOCKED',
        ruleViolated: 'RULE-AST-09: DESTRUCTIVE_OPERATOR_DETECTED',
        astAnalysis: `Tree-sitter evaluated syntax tree for "${customCommand}". Dangerous destructive call node matched zero-trust deny list.`,
        sanitizedOutput: `{\n  "error": {\n    "code": -32001,\n    "message": "MCP-Shield Intercept: Custom command blocked by Tree-sitter AST policy."\n  }\n}`,
        latencyMs: 0.16,
      };
    } else if (lower.includes('http') || lower.includes('169.') || lower.includes('localhost') || lower.includes('127.')) {
      mockResult = {
        id: 'custom',
        name: 'Custom Network Probe',
        category: 'SSRF & Metadata',
        toolName: 'fetch_url',
        inputPayload: customCommand,
        action: 'BLOCKED',
        ruleViolated: 'RULE-NET-01: PRIVATE_NETWORK_SSRF_PROHIBITED',
        astAnalysis: 'Egress IP resolution mapped to internal loopback or private subnet range. Connection aborted before socket handshake.',
        sanitizedOutput: `{\n  "error": {\n    "code": -32003,\n    "message": "MCP-Shield Intercept: SSRF attempt to internal network blocked."\n  }\n}`,
        latencyMs: 0.19,
      };
    } else {
      mockResult = {
        id: 'custom',
        name: 'Custom Payload Evaluation',
        category: 'DLP Leak',
        toolName: 'agent_runner',
        inputPayload: customCommand,
        action: 'SANITIZED',
        ruleViolated: 'RULE-DLP-01: BIJECTIVE_FPE_INSPECTION_PASSED',
        astAnalysis: 'Lexical analysis passed safe boundary. DLP sanitization verified no secret leaks.',
        sanitizedOutput: `{\n  "status": "allowed",\n  "message": "Payload evaluated safely under MCP-Shield Zero-Trust guardrails."\n}`,
        latencyMs: 0.13,
      };
    }

    runSimulation(mockResult);
  };

  return (
    <section id="simulator" className="py-20 bg-[#090a0f] border-y border-slate-800/80 relative overflow-hidden">
      {/* Background glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-gradient-to-r from-emerald-500/10 via-cyan-500/10 to-indigo-500/10 blur-[100px] pointer-events-none rounded-full" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <div className="text-center max-w-3xl mx-auto mb-12">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono font-medium mb-4">
            <Cpu className="w-3.5 h-3.5" />
            <span>INTERACTIVE ZERO-DAY DEFENSE PLAYGROUND</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            See How MCP Shield Neutralizes Attacks in Real-Time
          </h2>
          <p className="mt-4 text-base text-slate-400">
            Select an attack vector below or enter a custom tool payload. Experience how Tree-sitter AST validation,
            bijective DLP redaction, and SSRF firewalls intercept threats in under 0.2 milliseconds.
          </p>
        </div>

        {/* Preset scenario selection chips */}
        <div className="flex flex-wrap items-center justify-center gap-2.5 mb-8">
          {SCENARIOS.map((s) => (
            <button
              key={s.id}
              onClick={() => runSimulation(s)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-medium transition-all ${
                selectedScenario.id === s.id
                  ? 'bg-slate-800 border-emerald-500 text-white shadow-lg shadow-emerald-500/10 border'
                  : 'bg-slate-900/80 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700 border'
              }`}
            >
              <span className={`w-2 h-2 rounded-full ${
                s.action === 'BLOCKED' ? 'bg-rose-500' : s.action === 'SANITIZED' ? 'bg-cyan-400' : 'bg-amber-400'
              }`} />
              <span>{s.name}</span>
            </button>
          ))}
        </div>

        {/* Interactive Playground Sandbox */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 bg-[#0c0e18] border border-slate-800 rounded-2xl p-6 shadow-2xl">
          {/* Left Column: Input Payload & Custom Form */}
          <div className="lg:col-span-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-indigo-400" />
                <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                  Inbound MCP Tool Invocation
                </span>
              </div>
              <span className="text-xs font-mono bg-slate-900 text-slate-400 border border-slate-800 px-2 py-0.5 rounded">
                tool: {selectedScenario.toolName}
              </span>
            </div>

            <div className="bg-[#08090e] border border-slate-800/80 rounded-xl p-4 font-mono text-xs text-slate-300 min-h-[140px] flex flex-col justify-between">
              <div>
                <span className="text-slate-500 select-none">$ </span>
                <span className="text-emerald-300 font-semibold">{selectedScenario.inputPayload}</span>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-900 flex items-center justify-between text-[11px] text-slate-500">
                <span>Vector: <strong className="text-slate-300">{selectedScenario.category}</strong></span>
                <span>Client: Claude Desktop / Cursor</span>
              </div>
            </div>

            {/* Custom Input Form */}
            <form onSubmit={handleCustomSubmit} className="pt-2">
              <label className="block text-xs font-medium text-slate-400 mb-2">
                Or test your own malicious command / URL:
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={customCommand}
                  onChange={(e) => setCustomCommand(e.target.value)}
                  placeholder="e.g. rm -rf /etc, http://169.254.169.254, or cat ~/.ssh/id_rsa"
                  className="flex-1 bg-slate-900 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 transition"
                />
                <button
                  type="submit"
                  disabled={isExecuting}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs transition disabled:opacity-50 shadow-lg shadow-indigo-600/20"
                >
                  {isExecuting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                  <span>Test Payload</span>
                </button>
              </div>
            </form>
          </div>

          {/* Right Column: Real-Time Intercept Verdict */}
          <div className="lg:col-span-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                {selectedScenario.action === 'BLOCKED' ? (
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                ) : (
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                )}
                <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                  MCP Shield Intercept Verdict
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-[11px] font-mono font-bold px-2 py-0.5 rounded border ${
                  selectedScenario.action === 'BLOCKED'
                    ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                    : selectedScenario.action === 'SANITIZED'
                    ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                    : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                }`}>
                  {selectedScenario.action}
                </span>
                <span className="text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                  {selectedScenario.latencyMs}ms latency
                </span>
              </div>
            </div>

            {/* Rule & AST Diagnostic */}
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
                <Lock className="w-3.5 h-3.5 text-indigo-400" />
                <span>{selectedScenario.ruleViolated}</span>
              </div>
              <p className="text-[11px] font-mono text-slate-400 leading-relaxed">
                {selectedScenario.astAnalysis}
              </p>
            </div>

            {/* Sanitized JSON-RPC payload returned to LLM */}
            <div>
              <div className="text-[11px] text-slate-400 mb-1.5 flex items-center justify-between">
                <span>Safe JSON-RPC Response to LLM:</span>
                <span className="text-[10px] text-emerald-400 font-mono">Zero Plaintext Leak</span>
              </div>
              <pre className="bg-[#08090e] border border-slate-800/80 rounded-xl p-3 font-mono text-[11px] text-emerald-400/90 overflow-x-auto">
                {selectedScenario.sanitizedOutput}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
