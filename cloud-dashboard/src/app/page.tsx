import React from 'react';
import { Activity, Ban, Github, Key, Radio, Shield, ShieldCheck, Sliders, Sparkles, Zap } from 'lucide-react';

export default function Dashboard() {
  return (
    <div className="bg-[#090a0f] text-slate-100 min-h-screen flex flex-col font-sans">
      <header className="border-b border-slate-800 bg-[#0d0e15]/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-xl bg-gradient-to-tr from-emerald-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-emerald-500/20">
              <ShieldCheck className="w-5 h-5 text-black" />
            </div>
            <div>
              <div className="font-bold text-lg leading-tight flex items-center gap-2">
                <span>MCP-SHIELD</span>
                <span className="text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded-full font-mono font-medium">LIVE PROXY</span>
              </div>
              <div className="text-xs text-slate-400">Zero-Trust AI Agent Security Gateway</div>
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300">
              <span className="h-2.5 w-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>Connected (Port 8000)</span>
            </div>
            <a href="https://github.com/rahulxcodex/mcp-shield" target="_blank" rel="noreferrer" className="text-slate-400 hover:text-white transition">
              <Github className="w-5 h-5" />
            </a>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6 flex-1 w-full space-y-6">
        {/* Top KPI Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-[#0f111a] border border-slate-800/80 p-4 rounded-xl relative overflow-hidden flex flex-col">
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Security Health Score</div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-emerald-400">98</span>
              <span className="text-xs text-slate-500 font-mono">/ 100</span>
            </div>
            <div className="mt-2 text-xs text-emerald-400/80 flex items-center gap-1">
              <Shield className="w-3.5 h-3.5" /> Zero-Trust Firewall Enforced
            </div>
          </div>

          <div className="bg-[#0f111a] border border-slate-800/80 p-4 rounded-xl relative overflow-hidden flex flex-col">
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Attacks Neutralized</div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-rose-400">0</span>
              <span className="text-xs text-rose-500 font-mono">threats blocked</span>
            </div>
            <div className="mt-2 text-xs text-slate-400 flex items-center gap-1">
              <Ban className="w-3.5 h-3.5 text-rose-400" /> AST, SSRF, & Shell Evasions
            </div>
          </div>

          <div className="bg-[#0f111a] border border-slate-800/80 p-4 rounded-xl relative overflow-hidden flex flex-col">
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Secrets Tokenized (DLP)</div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-cyan-400">0</span>
              <span className="text-xs text-cyan-500 font-mono">keys redacted</span>
            </div>
            <div className="mt-2 text-xs text-slate-400 flex items-center gap-1">
              <Key className="w-3.5 h-3.5 text-cyan-400" /> Zero-Plaintext Storage
            </div>
          </div>

          <div className="bg-[#0f111a] border border-slate-800/80 p-4 rounded-xl relative overflow-hidden flex flex-col">
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Evaluated Invocations</div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-indigo-400">0</span>
              <span className="text-xs text-indigo-500 font-mono">hot-path calls</span>
            </div>
            <div className="mt-2 text-xs text-slate-400 flex items-center gap-1">
              <Zap className="w-3.5 h-3.5 text-indigo-400" /> <span>&lt; 0.2 ms</span> mean latency
            </div>
          </div>
        </div>

        {/* Live Threat Stream & Policy Center */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 bg-[#0f111a] border border-slate-800 rounded-xl flex flex-col h-[560px]">
            <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between bg-[#131522]/50 rounded-t-xl">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-emerald-400" />
                <span className="font-semibold text-sm text-slate-100">Live Intercept Stream</span>
                <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded-full text-xs font-mono">0 events</span>
              </div>
              <button className="text-xs text-slate-400 hover:text-white bg-slate-900 border border-slate-800 rounded px-2 py-1 transition">
                Clear Feed
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs">
              <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-2">
                <Radio className="w-8 h-8 text-slate-600 animate-pulse" />
                <p>Listening for agent MCP tool calls...</p>
                <p className="text-[11px] text-slate-600">Run an MCP tool via Claude Desktop, Cursor, or CLI.</p>
              </div>
            </div>
          </div>

          <div className="space-y-6">
            <div className="bg-[#0f111a] border border-slate-800 rounded-xl p-4 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <div className="font-semibold text-sm flex items-center gap-2 text-slate-100">
                  <Sliders className="w-4 h-4 text-cyan-400" /> Active Gateway Guardrails
                </div>
                <span className="text-xs text-emerald-400 font-mono">ACTIVE</span>
              </div>

              <div className="space-y-2.5 text-xs">
                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800/60">
                  <span className="text-slate-300">AST Root Deletion Block</span>
                  <span className="text-emerald-400 font-semibold font-mono">ENFORCED</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800/60">
                  <span className="text-slate-300">SSRF & Cloud Metadata Guard</span>
                  <span className="text-emerald-400 font-semibold font-mono">ENFORCED</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800/60">
                  <span className="text-slate-300">DLP Secret Tokenizer</span>
                  <span className="text-cyan-400 font-semibold font-mono">BIJECTIVE</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800/60">
                  <span className="text-slate-300">Rate Ceiling Throttler</span>
                  <span className="text-indigo-400 font-semibold font-mono">15 calls/min</span>
                </div>
              </div>
            </div>

            <div className="bg-[#0f111a] border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="font-semibold text-sm flex items-center gap-2 border-b border-slate-800/80 pb-3 text-slate-100">
                <Sparkles className="w-4 h-4 text-amber-400" /> Decoy Honey-Token Tripwire
              </div>
              <p className="text-xs text-slate-400">
                Active decoy canary tokens deployed in LLM context. Any exfiltration attempt triggers immediate session quarantine.
              </p>
              <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-xs text-amber-300 font-mono flex items-center justify-between">
                <span>mcp_honey_decoy_***</span>
                <span className="text-[10px] bg-amber-500/20 px-1.5 py-0.5 rounded font-bold">ARMED</span>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
