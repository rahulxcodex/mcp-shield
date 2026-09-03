'use client';

import React, { useState } from 'react';
import { Copy, Check, Terminal, FileCode, CheckCircle2 } from 'lucide-react';

interface TabItem {
  id: string;
  name: string;
  filePath: string;
  codeSnippet: string;
  instructions: string;
}

const TABS: TabItem[] = [
  {
    id: 'claude',
    name: 'Claude Desktop',
    filePath: '~/Library/Application Support/Claude/claude_desktop_config.json',
    instructions: 'Add MCP Shield as a proxy layer wrapping your target MCP servers:',
    codeSnippet: `{
  "mcpServers": {
    "shielded-filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@rahulxcodex/mcp-shield",
        "proxy",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/username/Desktop"
      ]
    }
  }
}`,
  },
  {
    id: 'cursor',
    name: 'Cursor IDE',
    filePath: '.cursor/mcp.json',
    instructions: 'Configure Cursor to wrap MCP servers with zero-trust AST inspection:',
    codeSnippet: `{
  "mcpServers": {
    "shielded-terminal": {
      "command": "mcp-shield",
      "args": [
        "proxy",
        "--enforce-ast",
        "--block-ssrf",
        "--",
        "node",
        "./servers/terminal-mcp.js"
      ]
    }
  }
}`,
  },
  {
    id: 'antigravity',
    name: 'Antigravity / Gemini CLI',
    filePath: '~/.gemini/antigravity/mcp.json',
    instructions: 'Secure autonomous subagents and MCP servers within Google Antigravity:',
    codeSnippet: `{
  "servers": {
    "shielded-cloud-ops": {
      "command": "npx",
      "args": [
        "@rahulxcodex/mcp-shield",
        "proxy",
        "--cloud-telemetry",
        "--policy",
        "strict",
        "--",
        "npx",
        "cloud-ops-mcp"
      ]
    }
  }
}`,
  },
  {
    id: 'cline',
    name: 'VSCode Cline / Roo-Code',
    filePath: '~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json',
    instructions: 'Drop-in proxy for all autonomous VSCode agent tasks:',
    codeSnippet: `{
  "mcpServers": {
    "github-shielded": {
      "command": "npx",
      "args": [
        "-y",
        "@rahulxcodex/mcp-shield",
        "proxy",
        "--redact-secrets",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-github"
      ],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_your_token_here"
      }
    }
  }
}`,
  },
  {
    id: 'sdk',
    name: 'Python & Node.js SDK',
    filePath: 'agent.py / index.ts',
    instructions: 'Programmatic client wrapping in your custom agent scripts:',
    codeSnippet: `# Python FastMCP integration
from mcp_shield import ShieldProxy

shield = ShieldProxy(
    policy="zero-trust",
    cloud_telemetry=True,
    dlp_bijective=True
)

# Seamlessly wrap your existing server client
client = shield.wrap_mcp_client(upstream_server_cmd=["python", "my_server.py"])
await client.call_tool("execute_query", {"query": "SELECT * FROM users"})`,
  },
];

export default function InstallationTabs() {
  const [activeTab, setActiveTab] = useState<string>(TABS[0].id);
  const [copied, setCopied] = useState<boolean>(false);

  const current = TABS.find((t) => t.id === activeTab) || TABS[0];

  const handleCopy = () => {
    navigator.clipboard.writeText(current.codeSnippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="install" className="py-20 bg-[#0c0e18] border-b border-slate-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-12">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-mono font-medium mb-4">
            <Terminal className="w-3.5 h-3.5" />
            <span>DROP-IN INTEGRATION WITH ALL AGENT RUNTIMES</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            Install Once. Protect Every Tool Call.
          </h2>
          <p className="mt-4 text-base text-slate-400">
            Zero code rewrites. MCP Shield wraps standard Model Context Protocol servers transparently via STDIO or SSE,
            immediately enabling AST command inspection, bijective DLP, and SSRF prevention.
          </p>
        </div>

        {/* Global Quickstart Command */}
        <div className="max-w-2xl mx-auto mb-10 p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4 shadow-xl">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <div className="text-xs text-slate-400 font-mono">Global CLI Quickstart</div>
              <div className="text-sm font-mono font-semibold text-emerald-300">npx @rahulxcodex/mcp-shield setup</div>
            </div>
          </div>
          <button
            onClick={() => {
              navigator.clipboard.writeText('npx @rahulxcodex/mcp-shield setup');
              setCopied(true);
              setTimeout(() => setCopied(false), 2000);
            }}
            className="w-full sm:w-auto px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center justify-center gap-2 transition"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            <span>{copied ? 'Copied CLI Command!' : 'Copy Command'}</span>
          </button>
        </div>

        {/* Tab Selection */}
        <div className="flex items-center justify-start sm:justify-center overflow-x-auto gap-2 pb-4 mb-6">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 rounded-xl text-xs font-medium whitespace-nowrap transition-all ${
                activeTab === tab.id
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/40 shadow-lg shadow-emerald-500/10'
                  : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab.name}
            </button>
          ))}
        </div>

        {/* Tab Code Box */}
        <div className="max-w-4xl mx-auto bg-[#08090e] border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
          <div className="px-5 py-3.5 bg-[#0f111d] border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-mono text-slate-300">{current.filePath}</span>
            </div>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied!' : 'Copy Config'}</span>
            </button>
          </div>

          <div className="p-4 sm:p-6">
            <p className="text-xs text-slate-400 mb-4 font-sans">{current.instructions}</p>
            <pre className="font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed p-4 rounded-xl bg-slate-950 border border-slate-900">
              {current.codeSnippet}
            </pre>
          </div>

          <div className="px-6 py-3 bg-[#0c0e18] border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
            <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
              <CheckCircle2 className="w-4 h-4" /> Ready for production agent deployment
            </span>
            <span className="font-mono text-[11px] text-slate-500">Supports STDIO and SSE</span>
          </div>
        </div>
      </div>
    </section>
  );
}
