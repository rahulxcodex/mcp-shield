'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Shield,
  Bot,
  Terminal,
  Globe,
  Layers,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Lock,
  ArrowRight,
  Database,
  Search,
  ExternalLink,
} from 'lucide-react';

interface RuntimeSession {
  sessionId: string;
  agentType: 'mcp' | 'coding_agent' | 'browser_agent' | 'multi_agent';
  agentName: string;
  status: 'ACTIVE' | 'ISOLATED' | 'COMPLETED' | 'TERMINATED';
  delegationDepth: number;
  threatsNeutralized: number;
  lastAction: string;
  startedAt: string;
}

export default function AIRuntimeConsole() {
  const [sessions, setSessions] = useState<RuntimeSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'all' | 'mcp' | 'coding' | 'browser' | 'multi'>('all');

  useEffect(() => {
    fetch('/api/v1/control-plane/runtime')
      .then((res) => res.json())
      .then((data) => {
        if (data.sessions) {
          setSessions(data.sessions);
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const filteredSessions = sessions.filter((s) => {
    if (activeTab === 'mcp') return s.agentType === 'mcp';
    if (activeTab === 'coding') return s.agentType === 'coding_agent';
    if (activeTab === 'browser') return s.agentType === 'browser_agent';
    if (activeTab === 'multi') return s.agentType === 'multi_agent';
    return true;
  });

  return (
    <div className="min-h-screen bg-[#07080c] text-slate-100 p-6 md:p-10">
      {/* Header */}
      <div className="max-w-7xl mx-auto space-y-8">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
          <div>
            <div className="flex items-center gap-3">
              <div className="p-2.5 bg-blue-500/10 border border-blue-500/20 rounded-xl">
                <Bot className="w-6 h-6 text-blue-400" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-2xl font-bold tracking-tight text-white">AI Agent Runtime Security Platform</h1>
                  <span className="px-2.5 py-0.5 text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full">
                    Step 10 Moat Live
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Unified execution security boundary for MCP servers, coding agents, browser bots & multi-agent swarms.
                </p>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Link
              href="/console"
              className="px-3.5 py-2 text-xs font-medium text-slate-300 bg-slate-800/80 hover:bg-slate-700 rounded-lg border border-slate-700 transition flex items-center gap-1.5"
            >
              <span>Console Dashboard</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>

        {/* Runtime Overview Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">MCP Servers</span>
              <Shield className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white mt-2">Active Gateway</div>
            <p className="text-xs text-slate-500 mt-1">JSON-RPC, AST filter, Bijective DLP</p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Coding Agents</span>
              <Terminal className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold text-white mt-2">Protected</div>
            <p className="text-xs text-slate-500 mt-1">Cursor, Cline, Aider host guardrails</p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Browser Agents</span>
              <Globe className="w-4 h-4 text-blue-400" />
            </div>
            <div className="text-2xl font-bold text-white mt-2">Sandbox Bound</div>
            <p className="text-xs text-slate-500 mt-1">Playwright & DOM SSRF interception</p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Multi-Agent Swarms</span>
              <Layers className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-white mt-2">Depth Capped (≤ 5)</div>
            <p className="text-xs text-slate-500 mt-1">Delegation loop & privilege escalation</p>
          </div>
        </div>

        {/* Runtime Sessions Stream */}
        <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <h2 className="text-sm font-semibold text-slate-200">Active AI Runtime Sessions</h2>
            <div className="flex items-center gap-1.5 p-1 bg-slate-950/60 border border-slate-800 rounded-lg text-xs">
              <button
                type="button"
                onClick={() => setActiveTab('all')}
                className={`px-3 py-1 rounded-md transition ${activeTab === 'all' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'}`}
              >
                All Runtimes
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('mcp')}
                className={`px-3 py-1 rounded-md transition ${activeTab === 'mcp' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'}`}
              >
                MCP
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('coding')}
                className={`px-3 py-1 rounded-md transition ${activeTab === 'coding' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'}`}
              >
                Coding Agents
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('browser')}
                className={`px-3 py-1 rounded-md transition ${activeTab === 'browser' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'}`}
              >
                Browser Agents
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('multi')}
                className={`px-3 py-1 rounded-md transition ${activeTab === 'multi' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'}`}
              >
                Multi-Agent
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-3 px-4 font-medium">Session ID</th>
                  <th className="py-3 px-4 font-medium">Runtime Type</th>
                  <th className="py-3 px-4 font-medium">Agent Name</th>
                  <th className="py-3 px-4 font-medium">Delegation Depth</th>
                  <th className="py-3 px-4 font-medium">Threats Neutralized</th>
                  <th className="py-3 px-4 font-medium">Status</th>
                  <th className="py-3 px-4 font-medium">Last Monitored Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredSessions.map((s) => (
                  <tr key={s.sessionId} className="hover:bg-slate-800/30 transition">
                    <td className="py-3 px-4 font-mono text-slate-300">{s.sessionId}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-medium">
                        {s.agentType}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-medium text-slate-200">{s.agentName}</td>
                    <td className="py-3 px-4 text-slate-300">Depth {s.delegationDepth} / 5</td>
                    <td className="py-3 px-4">
                      <span className="text-emerald-400 font-semibold">{s.threatsNeutralized} blocked</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="flex items-center gap-1.5 text-emerald-400">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                        {s.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px] truncate max-w-xs">{s.lastAction}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
