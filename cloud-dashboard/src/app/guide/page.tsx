'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  ShieldAlert,
  Terminal,
  Key,
  Copy,
  Check,
  CheckCircle2,
  Lock,
  Zap,
  Sliders,
  Sparkles,
  ArrowLeft,
  Search,
  ExternalLink,
  Server,
  Layers,
  FileCode,
  BookOpen
} from 'lucide-react';

export default function GuidePage() {
  const [activeClientTab, setActiveClientTab] = useState<'claude' | 'cursor' | 'antigravity' | 'cline' | 'windsurf'>('claude');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="bg-[#090a0f] text-slate-100 min-h-screen flex flex-col font-sans">
      {/* Guide Header */}
      <header className="border-b border-slate-800 bg-[#0d0e15]/90 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/" className="flex items-center gap-2.5 group">
              <div className="h-9 w-9 rounded-xl bg-gradient-to-tr from-emerald-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-emerald-500/20 group-hover:scale-105 transition">
                <ShieldCheck className="w-5 h-5 text-black stroke-[2.5]" />
              </div>
              <div>
                <div className="font-bold text-lg leading-tight flex items-center gap-2">
                  <span>MCP-SHIELD</span>
                  <span className="text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded-full font-mono font-medium">
                    USER GUIDE
                  </span>
                </div>
                <div className="text-[11px] text-slate-400">Complete Integration & Administrator Documentation</div>
              </div>
            </Link>
          </div>

          <div className="flex items-center gap-3">
            <Link
              href="/console"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-black text-xs font-bold transition shadow-lg shadow-emerald-600/20"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Open Console</span>
            </Link>
            <Link
              href="/"
              className="text-slate-400 hover:text-white transition p-1.5"
              title="Return to Homepage"
            >
              <ArrowLeft className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </header>

      {/* Main Guide Content */}
      <div className="max-w-7xl mx-auto px-4 py-8 flex-1 w-full grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Sticky Sidebar Navigation */}
        <aside className="lg:col-span-3 space-y-6">
          <div className="bg-[#0f111a] border border-slate-800 rounded-xl p-4 sticky top-24 space-y-3 text-xs">
            <div className="font-semibold text-slate-200 uppercase tracking-wider text-[11px] flex items-center gap-2 border-b border-slate-800 pb-2">
              <BookOpen className="w-4 h-4 text-emerald-400" />
              <span>Guide Navigation</span>
            </div>
            <nav className="space-y-1.5 text-slate-400">
              <a href="#quickstart" className="block p-1.5 rounded hover:bg-slate-900 hover:text-emerald-400 transition">
                1. Quickstart in 60s
              </a>
              <a href="#master-license" className="block p-1.5 rounded hover:bg-slate-900 hover:text-emerald-400 transition font-medium text-emerald-300">
                2. Master License Activation
              </a>
              <a href="#clients" className="block p-1.5 rounded hover:bg-slate-900 hover:text-emerald-400 transition">
                3. Client Integrations
              </a>
              <a href="#threat-engine" className="block p-1.5 rounded hover:bg-slate-900 hover:text-emerald-400 transition">
                4. Security Guardrails & AST
              </a>
              <a href="#console-pairing" className="block p-1.5 rounded hover:bg-slate-900 hover:text-emerald-400 transition">
                5. Cloud Console & Pairing
              </a>
              <a href="#compliance" className="block p-1.5 rounded hover:bg-slate-900 hover:text-emerald-400 transition">
                6. SOC2 Compliance & Audits
              </a>
              <a href="#cli-ref" className="block p-1.5 rounded hover:bg-slate-900 hover:text-emerald-400 transition">
                7. CLI Command Reference
              </a>
            </nav>

            <div className="pt-3 border-t border-slate-800/80">
              <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-[11px]">
                <strong>Need Support?</strong> Check our GitHub repo or deploy on Vercel/Render.
              </div>
            </div>
          </div>
        </aside>

        {/* Main Document Body */}
        <main className="lg:col-span-9 space-y-10">
          {/* Hero Banner */}
          <div className="p-6 rounded-2xl bg-gradient-to-br from-[#121524] to-[#0a0c14] border border-slate-800 space-y-3">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono">
              <ShieldCheck className="w-3.5 h-3.5" /> ZERO-TRUST MODEL CONTEXT PROTOCOL FIREWALL
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              MCP Shield Integration & Administration Guide
            </h1>
            <p className="text-sm text-slate-300 leading-relaxed max-w-3xl">
              Complete setup manual for securing AI agent workflows (Claude Desktop, Cursor, Antigravity, VSCode Cline, Windsurf).
              Eliminate prompt-injection RCEs, SSRF cloud metadata attacks, and credential leaks with sub-millisecond AST evaluation.
            </p>
          </div>

          {/* Section 1: Quickstart */}
          <section id="quickstart" className="space-y-4">
            <h2 className="text-xl font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-2">
              <span className="text-emerald-400 font-mono">01.</span> Quickstart in 60 Seconds
            </h2>
            <p className="text-xs text-slate-300 leading-relaxed">
              Install the MCP Shield binary globally on your workstation, or run it directly using npx:
            </p>
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between font-mono text-xs text-emerald-300">
              <span>npm install -g mcp-shield</span>
              <button
                onClick={() => copyToClipboard('npm install -g mcp-shield', 'install-cmd')}
                className="p-1.5 text-slate-400 hover:text-white transition"
              >
                {copiedId === 'install-cmd' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-xs space-y-2">
              <div className="font-semibold text-slate-200">Auto-Detect & Protect Installed Clients:</div>
              <p className="text-slate-400">
                Run the auto-discovery engine. It locates Claude Desktop, Cursor, Cline, and Windsurf configurations, and non-invasively wraps servers with the security proxy:
              </p>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between font-mono text-slate-200">
                <span>mcp-shield protect</span>
                <button
                  onClick={() => copyToClipboard('mcp-shield protect', 'protect-cmd')}
                  className="p-1.5 text-slate-400 hover:text-white transition"
                >
                  {copiedId === 'protect-cmd' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>
          </section>

          {/* Section 2: Master License Key Activation */}
          <section id="master-license" className="space-y-4">
            <h2 className="text-xl font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-2">
              <span className="text-emerald-400 font-mono">02.</span> Enterprise Master License Activation
            </h2>
            <div className="p-5 rounded-2xl bg-gradient-to-tr from-emerald-950/30 to-cyan-950/20 border border-emerald-500/30 space-y-4 shadow-xl">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="h-8 w-8 rounded-lg bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center">
                    <Key className="w-4 h-4 text-emerald-400" />
                  </div>
                  <div>
                    <h3 className="font-bold text-sm text-white">Your Pre-Configured Master License Key</h3>
                    <p className="text-xs text-slate-400">Permanently activates enterprise AST guardrails & unlimited hotpath evaluations</p>
                  </div>
                </div>
                <span className="text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 px-2 py-0.5 rounded-full font-mono font-bold">
                  MASTER TIER
                </span>
              </div>

              <p className="text-xs text-slate-300">
                Execute this command in your terminal to write your authenticated master license credential to <code className="bg-black px-1.5 py-0.5 rounded text-emerald-400 font-mono">~/.mcp-shield/license.key</code>:
              </p>

              <div className="p-3.5 rounded-xl bg-slate-950 border border-emerald-500/30 flex items-center justify-between font-mono text-xs text-emerald-300">
                <span className="truncate mr-2">mcp-shield license MASTER_RGX_SHIELD_9999_OMEGA_SECURE_KEY</span>
                <button
                  onClick={() => copyToClipboard('mcp-shield license MASTER_RGX_SHIELD_9999_OMEGA_SECURE_KEY', 'master-key-cmd')}
                  className="p-1.5 text-slate-400 hover:text-white transition shrink-0"
                  title="Copy Master Key Activation Command"
                >
                  {copiedId === 'master-key-cmd' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-[11px] text-slate-400 pt-1">
                <div className="flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span>Bypasses 14-day trial limit</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span>Full AST & FPE DLP unlocked</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span>Unlimited cloud telemetry nodes</span>
                </div>
              </div>
            </div>
          </section>

          {/* Section 3: Client Configurations */}
          <section id="clients" className="space-y-4">
            <h2 className="text-xl font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-2">
              <span className="text-emerald-400 font-mono">03.</span> Client Configuration Guides
            </h2>
            <p className="text-xs text-slate-300">
              Select your AI client or IDE to view the exact JSON configuration block:
            </p>

            {/* Client Tabs */}
            <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-2">
              {[
                { id: 'claude', label: 'Claude Desktop' },
                { id: 'cursor', label: 'Cursor IDE' },
                { id: 'antigravity', label: 'Google Antigravity' },
                { id: 'cline', label: 'VSCode Cline' },
                { id: 'windsurf', label: 'Windsurf' },
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveClientTab(tab.id as any)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                    activeClientTab === tab.id
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      : 'bg-slate-900/60 text-slate-400 hover:text-white border border-slate-800'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Tab Contents */}
            <div className="p-4 rounded-xl bg-[#0f111a] border border-slate-800 space-y-3 text-xs">
              {activeClientTab === 'claude' && (
                <>
                  <div className="text-slate-300 font-semibold">Config Location:</div>
                  <div className="font-mono text-[11px] text-slate-400">
                    macOS: ~/Library/Application Support/Claude/claude_desktop_config.json<br />
                    Windows: %APPDATA%\Claude\claude_desktop_config.json
                  </div>
                  <div className="relative">
                    <pre className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-slate-200 overflow-x-auto">
{`{
  "mcpServers": {
    "shielded-filesystem": {
      "command": "mcp-shield",
      "args": [
        "wrap",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/username/Desktop"
      ]
    }
  }
}`}
                    </pre>
                    <button
                      onClick={() => copyToClipboard(`{
  "mcpServers": {
    "shielded-filesystem": {
      "command": "mcp-shield",
      "args": [
        "wrap",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/username/Desktop"
      ]
    }
  }
}`, 'claude-cfg')}
                      className="absolute top-2.5 right-2.5 p-1.5 rounded bg-slate-800 text-slate-300 hover:text-white"
                    >
                      {copiedId === 'claude-cfg' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </>
              )}

              {activeClientTab === 'cursor' && (
                <>
                  <div className="text-slate-300 font-semibold">Config Location:</div>
                  <div className="font-mono text-[11px] text-slate-400">~/.cursor/mcp.json or Cursor Settings &gt; Features &gt; MCP</div>
                  <div className="relative">
                    <pre className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-slate-200 overflow-x-auto">
{`{
  "mcpServers": {
    "terminal-tools": {
      "command": "mcp-shield",
      "args": [
        "wrap",
        "--",
        "node",
        "./mcp-server-terminal/dist/index.js"
      ]
    }
  }
}`}
                    </pre>
                    <button
                      onClick={() => copyToClipboard(`{
  "mcpServers": {
    "terminal-tools": {
      "command": "mcp-shield",
      "args": [
        "wrap",
        "--",
        "node",
        "./mcp-server-terminal/dist/index.js"
      ]
    }
  }
}`, 'cursor-cfg')}
                      className="absolute top-2.5 right-2.5 p-1.5 rounded bg-slate-800 text-slate-300 hover:text-white"
                    >
                      {copiedId === 'cursor-cfg' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </>
              )}

              {activeClientTab === 'antigravity' && (
                <>
                  <div className="text-slate-300 font-semibold">Config Location:</div>
                  <div className="font-mono text-[11px] text-slate-400">Workspace root or ~/.gemini/antigravity/mcp/</div>
                  <div className="relative">
                    <pre className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-slate-200 overflow-x-auto">
{`{
  "mcpServers": {
    "shielded-shell": {
      "command": "mcp-shield",
      "args": [
        "wrap",
        "--",
        "mcp-server-commands"
      ]
    }
  }
}`}
                    </pre>
                    <button
                      onClick={() => copyToClipboard(`{
  "mcpServers": {
    "shielded-shell": {
      "command": "mcp-shield",
      "args": [
        "wrap",
        "--",
        "mcp-server-commands"
      ]
    }
  }
}`, 'ag-cfg')}
                      className="absolute top-2.5 right-2.5 p-1.5 rounded bg-slate-800 text-slate-300 hover:text-white"
                    >
                      {copiedId === 'ag-cfg' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </>
              )}

              {activeClientTab === 'cline' && (
                <>
                  <div className="text-slate-300 font-semibold">Config Location:</div>
                  <div className="font-mono text-[11px] text-slate-400">%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json</div>
                  <div className="relative">
                    <pre className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-slate-200 overflow-x-auto">
{`{
  "mcpServers": {
    "cline-shielded": {
      "command": "mcp-shield",
      "args": ["wrap", "--", "npx", "@modelcontextprotocol/server-postgres", "postgresql://user:pass@localhost:5432/db"]
    }
  }
}`}
                    </pre>
                    <button
                      onClick={() => copyToClipboard(`{
  "mcpServers": {
    "cline-shielded": {
      "command": "mcp-shield",
      "args": ["wrap", "--", "npx", "@modelcontextprotocol/server-postgres", "postgresql://user:pass@localhost:5432/db"]
    }
  }
}`, 'cline-cfg')}
                      className="absolute top-2.5 right-2.5 p-1.5 rounded bg-slate-800 text-slate-300 hover:text-white"
                    >
                      {copiedId === 'cline-cfg' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </>
              )}

              {activeClientTab === 'windsurf' && (
                <>
                  <div className="text-slate-300 font-semibold">Config Location:</div>
                  <div className="font-mono text-[11px] text-slate-400">~/.codeium/windsurf/mcp_config.json</div>
                  <div className="relative">
                    <pre className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-slate-200 overflow-x-auto">
{`{
  "mcpServers": {
    "windsurf-shield": {
      "command": "mcp-shield",
      "args": ["wrap", "--", "python", "-m", "mcp_server_filesystem"]
    }
  }
}`}
                    </pre>
                    <button
                      onClick={() => copyToClipboard(`{
  "mcpServers": {
    "windsurf-shield": {
      "command": "mcp-shield",
      "args": ["wrap", "--", "python", "-m", "mcp_server_filesystem"]
    }
  }
}`, 'windsurf-cfg')}
                      className="absolute top-2.5 right-2.5 p-1.5 rounded bg-slate-800 text-slate-300 hover:text-white"
                    >
                      {copiedId === 'windsurf-cfg' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </>
              )}
            </div>
          </section>

          {/* Section 4: Threat Engine */}
          <section id="threat-engine" className="space-y-4">
            <h2 className="text-xl font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-2">
              <span className="text-emerald-400 font-mono">04.</span> Security Guardrails & AST Engine
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="p-4 rounded-xl bg-[#0f111a] border border-slate-800 space-y-2">
                <div className="font-bold text-slate-100 flex items-center gap-2">
                  <Sliders className="w-4 h-4 text-rose-400" /> Tree-sitter AST Syntax Firewall
                </div>
                <p className="text-slate-400 leading-relaxed">
                  Unlike naive regex filters, commands are parsed into Abstract Syntax Trees for Bash, PowerShell, and Cmd. Block recursive deletions, obfuscated pipes, and parameter injection before OS execution.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-[#0f111a] border border-slate-800 space-y-2">
                <div className="font-bold text-slate-100 flex items-center gap-2">
                  <Lock className="w-4 h-4 text-cyan-400" /> Bijective Format-Preserving DLP
                </div>
                <p className="text-slate-400 leading-relaxed">
                  Replaces sensitive credentials (AWS, Stripe, OpenAI, SSH keys) with deterministic surrogate tokens. If an approved downstream tool needs the secret, it is restored transparently without ever exposing it to LLM prompt context.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-[#0f111a] border border-slate-800 space-y-2">
                <div className="font-bold text-slate-100 flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-amber-400" /> SSRF & Cloud IMDS Protection
                </div>
                <p className="text-slate-400 leading-relaxed">
                  Blocks agent egress requests targeting link-local metadata endpoints (AWS 169.254.169.254, GCP metadata.google.internal) and localhost loops.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-[#0f111a] border border-slate-800 space-y-2">
                <div className="font-bold text-slate-100 flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-yellow-400" /> Canary Honey-Token Tripwires
                </div>
                <p className="text-slate-400 leading-relaxed">
                  Injects synthetic decoy tools into the MCP catalog. Any tool call targeting a decoy instantly flags model prompt-injection compromise and isolates the process.
                </p>
              </div>
            </div>
          </section>

          {/* Section 5: Console & Pairing */}
          <section id="console-pairing" className="space-y-4">
            <h2 className="text-xl font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-2">
              <span className="text-emerald-400 font-mono">05.</span> Cloud Console & Device Pairing
            </h2>
            <p className="text-xs text-slate-300">
              Pair your local MCP agent with the cloud telemetry dashboard:
            </p>

            <div className="p-4 rounded-xl bg-[#0f111a] border border-slate-800 space-y-3 text-xs">
              <div className="space-y-1">
                <div className="font-semibold text-slate-200">1. Generate an API Key in the Console:</div>
                <p className="text-slate-400">
                  Open <Link href="/console" className="text-emerald-400 underline">Console</Link> and click <strong>&ldquo;New Key&rdquo;</strong> in the API Keys sidebar to generate a unique lookup token (<code className="text-emerald-300">mcp_live_...</code>).
                </p>
              </div>

              <div className="space-y-1">
                <div className="font-semibold text-slate-200">2. Link Your Machine:</div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between font-mono text-emerald-300">
                  <span>mcp-shield link --key &lt;your_unique_api_key&gt;</span>
                  <button
                    onClick={() => copyToClipboard('mcp-shield link --key mcp_live_your_key', 'link-cmd')}
                    className="p-1.5 text-slate-400 hover:text-white transition"
                  >
                    {copiedId === 'link-cmd' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div className="space-y-1">
                <div className="font-semibold text-slate-200">3. Real-Time Telemetry:</div>
                <p className="text-slate-400">
                  Tool invocations, AST verdicts, and tokenization events stream live to your dashboard authenticated via HMAC-SHA256 signatures.
                </p>
              </div>
            </div>
          </section>

          {/* Section 6: Compliance */}
          <section id="compliance" className="space-y-4">
            <h2 className="text-xl font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-2">
              <span className="text-emerald-400 font-mono">06.</span> SOC2 Type II Compliance & Audit Reports
            </h2>
            <p className="text-xs text-slate-300 leading-relaxed">
              MCP Shield provides out-of-the-box audit ledgering conforming to SOC2 Trust Services Criteria (CC6.1, CC6.6, CC6.7).
              Download an audit JSON report at any time by clicking <strong>&ldquo;Export SOC2 Log&rdquo;</strong> in the top header of the <Link href="/console" className="text-emerald-400 underline">Console</Link>.
            </p>
          </section>

          {/* Section 7: CLI Reference */}
          <section id="cli-ref" className="space-y-4">
            <h2 className="text-xl font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-2">
              <span className="text-emerald-400 font-mono">07.</span> Complete CLI Reference
            </h2>
            <div className="overflow-x-auto rounded-xl border border-slate-800">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#121420] text-slate-300 border-b border-slate-800">
                  <tr>
                    <th className="p-3">Command</th>
                    <th className="p-3 font-sans">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-slate-400 bg-slate-950/40">
                  <tr>
                    <td className="p-3 text-emerald-400 font-semibold">mcp-shield license &lt;key&gt;</td>
                    <td className="p-3 font-sans">Activates enterprise license credential (e.g. MASTER_RGX_SHIELD_9999_OMEGA_SECURE_KEY).</td>
                  </tr>
                  <tr>
                    <td className="p-3 text-emerald-400 font-semibold">mcp-shield protect</td>
                    <td className="p-3 font-sans">Auto-discovers and wraps Claude, Cursor, Cline, and Windsurf configurations.</td>
                  </tr>
                  <tr>
                    <td className="p-3 text-emerald-400 font-semibold">mcp-shield wrap -- &lt;cmd&gt;</td>
                    <td className="p-3 font-sans">Wraps and executes any MCP server inside the zero-trust AST sandbox.</td>
                  </tr>
                  <tr>
                    <td className="p-3 text-emerald-400 font-semibold">mcp-shield link --key &lt;key&gt;</td>
                    <td className="p-3 font-sans">Pairs workstation with Cloud Console for real-time threat telemetry.</td>
                  </tr>
                  <tr>
                    <td className="p-3 text-emerald-400 font-semibold">mcp-shield scan</td>
                    <td className="p-3 font-sans">Scans existing MCP configurations for plaintext secrets and unsafe privileges.</td>
                  </tr>
                  <tr>
                    <td className="p-3 text-emerald-400 font-semibold">mcp-shield stats</td>
                    <td className="p-3 font-sans">Displays summary table of intercepted threats and tokenized secrets.</td>
                  </tr>
                  <tr>
                    <td className="p-3 text-emerald-400 font-semibold">mcp-shield demo</td>
                    <td className="p-3 font-sans">Spawns an interactive local playground to simulate attacks safely.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}
