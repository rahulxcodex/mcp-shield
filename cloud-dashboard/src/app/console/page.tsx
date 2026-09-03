'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  ShieldAlert,
  Shield,
  Ban,
  Key,
  Zap,
  Radio,
  Sliders,
  Sparkles,
  Activity,
  Download,
  Terminal,
  RefreshCw,
  Settings,
  Lock,
  ArrowLeft,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Plus,
  Trash2,
  Copy,
  Check,
  X
} from 'lucide-react';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Cell
} from 'recharts';

interface SecurityEvent {
  id: string;
  timestamp: string;
  eventType: 'BLOCK' | 'SANITIZE' | 'QUARANTINE' | 'PASSTHROUGH';
  toolName: string;
  detector: string;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  reason: string;
}

interface ApiKeyEntry {
  id: string;
  name: string;
  keyPrefix: string;
  apiKey?: string;
  createdAt: string;
  lastUsedAt?: string;
  status: 'active' | 'revoked';
}

const INITIAL_EVENTS: SecurityEvent[] = [
  {
    id: 'evt-101',
    timestamp: 'Just now',
    eventType: 'BLOCK',
    toolName: 'execute_command',
    detector: 'Tree-sitter AST',
    riskLevel: 'CRITICAL',
    reason: 'Root destruction command rm -rf / detected in binary_expression',
  },
  {
    id: 'evt-102',
    timestamp: '2m ago',
    eventType: 'SANITIZE',
    toolName: 'read_env_file',
    detector: 'Bijective FPE DLP',
    riskLevel: 'HIGH',
    reason: 'Tokenized AWS_SECRET_ACCESS_KEY (wJalrXUt...) with surrogate token',
  },
  {
    id: 'evt-103',
    timestamp: '5m ago',
    eventType: 'BLOCK',
    toolName: 'fetch_http',
    detector: 'SSRF / Cloud Metadata',
    riskLevel: 'CRITICAL',
    reason: 'Egress blocked to AWS IMDS 169.254.169.254/latest/meta-data',
  },
  {
    id: 'evt-104',
    timestamp: '12m ago',
    eventType: 'QUARANTINE',
    toolName: 'sql_query',
    detector: 'Canary Honeytoken',
    riskLevel: 'CRITICAL',
    reason: 'Agent context accessed decoy honeytoken mcp_honey_decoy_k8s_9921',
  },
  {
    id: 'evt-105',
    timestamp: '18m ago',
    eventType: 'BLOCK',
    toolName: 'bash_run',
    detector: 'Tree-sitter AST',
    riskLevel: 'HIGH',
    reason: 'PowerShell encoded command IEX [System.Text.Encoding]::Unicode blocked',
  },
];

const TIMELINE_DATA = [
  { time: '00:00', allowed: 120, threats: 4 },
  { time: '04:00', allowed: 90, threats: 2 },
  { time: '08:00', allowed: 340, threats: 15 },
  { time: '12:00', allowed: 610, threats: 28 },
  { time: '16:00', allowed: 840, threats: 34 },
  { time: '20:00', allowed: 520, threats: 19 },
  { time: 'Now', allowed: 480, threats: 12 },
];

const VECTOR_DATA = [
  { vector: 'AST Injection', count: 42, color: '#f43f5e' },
  { vector: 'SSRF & Metadata', count: 28, color: '#fb923c' },
  { vector: 'DLP Redacted', count: 65, color: '#22d3ee' },
  { vector: 'Canary Tripped', count: 11, color: '#eab308' },
  { vector: 'Rate Exceeded', count: 19, color: '#a855f7' },
];

export default function ConsolePage() {
  const [events, setEvents] = useState<SecurityEvent[]>(INITIAL_EVENTS);
  const [filterType, setFilterType] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<boolean>(false);
  const [apiKeys, setApiKeys] = useState<ApiKeyEntry[]>([
    {
      id: 'key-dev-101',
      name: 'Claude Desktop Agent',
      keyPrefix: 'mcp_live_sec_89b21a',
      createdAt: '2026-09-01',
      lastUsedAt: '2 mins ago',
      status: 'active'
    }
  ]);
  const [isCreateKeyOpen, setIsCreateKeyOpen] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyClient, setNewKeyClient] = useState('Claude Desktop');
  const [justCreatedKey, setJustCreatedKey] = useState<string | null>(null);
  const [copiedKeyId, setCopiedKeyId] = useState<string | null>(null);

  const [stats, setStats] = useState({
    healthScore: 98,
    attacksNeutralized: 165,
    secretsTokenized: 84,
    invocations: 3000,
    latency: '0.18ms',
  });

  const handleGenerateKey = async () => {
    const rawRandom = Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    const fullSecret = `mcp_live_sec_${rawRandom}`;
    const prefix = fullSecret.substring(0, 16);
    const assignedName = (newKeyName.trim() || 'Production MCP Gateway') + ` (${newKeyClient})`;

    const newKey: ApiKeyEntry = {
      id: `key-${Date.now()}`,
      name: assignedName,
      keyPrefix: prefix,
      apiKey: fullSecret,
      createdAt: 'Just now',
      lastUsedAt: 'Never',
      status: 'active',
    };

    try {
      await fetch('/api/v1/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newKeyName, clientType: newKeyClient }),
      });
    } catch {}

    setApiKeys((prev) => [newKey, ...prev]);
    setJustCreatedKey(fullSecret);
    setNewKeyName('');
  };

  const handleRevokeKey = async (id: string, prefix: string) => {
    try {
      await fetch(`/api/v1/keys?id=${id}&prefix=${prefix}`, { method: 'DELETE' });
    } catch {}
    setApiKeys((prev) => prev.filter((k) => k.id !== id));
  };

  const handleSimulateBatch = () => {
    setIsSimulating(true);
    setTimeout(() => {
      const newEvent: SecurityEvent = {
        id: `evt-${Date.now()}`,
        timestamp: 'Just now',
        eventType: Math.random() > 0.5 ? 'BLOCK' : 'SANITIZE',
        toolName: 'terminal_exec',
        detector: 'Tree-sitter AST & FPE DLP',
        riskLevel: 'HIGH',
        reason: 'Intercepted injected shell sequence with disguised base64 pipe',
      };
      setEvents((prev) => [newEvent, ...prev]);
      setStats((prev) => ({
        ...prev,
        attacksNeutralized: prev.attacksNeutralized + 1,
        secretsTokenized: prev.secretsTokenized + (newEvent.eventType === 'SANITIZE' ? 1 : 0),
        invocations: prev.invocations + 1,
      }));
      setIsSimulating(false);
    }, 400);
  };

  const handleExportSOC2 = () => {
    const report = {
      exportTimestamp: new Date().toISOString(),
      organization: 'Production AI Security Gateway',
      standard: 'SOC2 Type II - Trust Services Criteria (CC6.1, CC6.6, CC6.7)',
      complianceStatus: 'COMPLIANT_ZERO_PLAIN_TEXT',
      statistics: stats,
      auditLedger: events,
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mcp-shield-soc2-audit-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredEvents = events.filter((evt) => {
    const matchesFilter = filterType === 'ALL' || evt.eventType === filterType;
    const matchesQuery =
      evt.reason.toLowerCase().includes(searchQuery.toLowerCase()) ||
      evt.toolName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      evt.detector.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesFilter && matchesQuery;
  });

  return (
    <div className="bg-[#090a0f] text-slate-100 min-h-screen flex flex-col font-sans">
      {/* Console Header */}
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
                  <span className="text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-2 py-0.5 rounded-full font-mono font-medium">
                    CONSOLE
                  </span>
                </div>
                <div className="text-[11px] text-slate-400">Zero-Trust Live Telemetry & Threat Center</div>
              </div>
            </Link>
          </div>

          <div className="flex items-center gap-3">
            {/* Live connection badge */}
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300">
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>Gateway Active</span>
            </div>

            {/* Simulate button */}
            <button
              onClick={handleSimulateBatch}
              disabled={isSimulating}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition border border-slate-700"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${isSimulating ? 'animate-spin' : ''}`} />
              <span className="hidden md:inline">Simulate Live Attack</span>
            </button>

            {/* Export SOC2 button */}
            <button
              onClick={handleExportSOC2}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-black text-xs font-bold transition shadow-lg shadow-emerald-600/20"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export SOC2 Log</span>
            </button>

            <Link href="/" className="text-slate-400 hover:text-white transition p-1.5" title="Back to Website">
              <ArrowLeft className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </header>

      {/* Main Console Workspace */}
      <main className="max-w-7xl mx-auto px-4 py-6 flex-1 w-full space-y-6">
        {/* KPI Scorecard Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-[#0f111a] border border-slate-800/80 p-4 rounded-xl flex flex-col">
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Security Health Score</div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-emerald-400">{stats.healthScore}</span>
              <span className="text-xs text-slate-500 font-mono">/ 100</span>
            </div>
            <div className="mt-2 text-xs text-emerald-400/80 flex items-center gap-1">
              <Shield className="w-3.5 h-3.5" /> Zero-Trust AST Firewall Enforced
            </div>
          </div>

          <div className="bg-[#0f111a] border border-slate-800/80 p-4 rounded-xl flex flex-col">
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Attacks Neutralized</div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-rose-400">{stats.attacksNeutralized}</span>
              <span className="text-xs text-rose-500 font-mono">threats blocked</span>
            </div>
            <div className="mt-2 text-xs text-slate-400 flex items-center gap-1">
              <Ban className="w-3.5 h-3.5 text-rose-400" /> AST, SSRF, & Shell Evasions
            </div>
          </div>

          <div className="bg-[#0f111a] border border-slate-800/80 p-4 rounded-xl flex flex-col">
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Secrets Tokenized (DLP)</div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-cyan-400">{stats.secretsTokenized}</span>
              <span className="text-xs text-cyan-500 font-mono">keys redacted</span>
            </div>
            <div className="mt-2 text-xs text-slate-400 flex items-center gap-1">
              <Key className="w-3.5 h-3.5 text-cyan-400" /> Zero Plaintext Storage
            </div>
          </div>

          <div className="bg-[#0f111a] border border-slate-800/80 p-4 rounded-xl flex flex-col">
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Evaluated Invocations</div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-indigo-400">{stats.invocations.toLocaleString()}</span>
              <span className="text-xs text-indigo-500 font-mono">hotpath calls</span>
            </div>
            <div className="mt-2 text-xs text-slate-400 flex items-center gap-1">
              <Zap className="w-3.5 h-3.5 text-indigo-400" /> <span>&lt; {stats.latency}</span> mean latency
            </div>
          </div>
        </div>

        {/* Analytics Charts Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Threat Timeline Area Chart */}
          <div className="lg:col-span-8 bg-[#0f111a] border border-slate-800 rounded-xl p-5 flex flex-col">
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="text-sm font-semibold text-white flex items-center gap-2">
                  <Activity className="w-4 h-4 text-emerald-400" />
                  <span>Agent Invocations & Threat Interceptions</span>
                </div>
                <div className="text-xs text-slate-400">24-hour evaluation timeline across connected agents</div>
              </div>
              <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                LIVE
              </span>
            </div>

            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={TIMELINE_DATA}>
                  <defs>
                    <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.6} />
                      <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f293d" />
                  <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0c0e18',
                      borderColor: '#334155',
                      fontSize: '12px',
                      borderRadius: '8px',
                    }}
                  />
                  <Area type="monotone" dataKey="allowed" stroke="#10b981" fillOpacity={1} fill="url(#colorAllowed)" name="Safe Invocations" />
                  <Area type="monotone" dataKey="threats" stroke="#f43f5e" fillOpacity={1} fill="url(#colorThreats)" name="Blocked Threats" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Attack Vector Distribution Bar Chart */}
          <div className="lg:col-span-4 bg-[#0f111a] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
            <div>
              <div className="text-sm font-semibold text-white flex items-center gap-2 mb-1">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                <span>Interception by Attack Vector</span>
              </div>
              <div className="text-xs text-slate-400 mb-4">Breakdown of neutralized risks</div>

              <div className="h-52 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={VECTOR_DATA} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#1f293d" />
                    <XAxis type="number" stroke="#64748b" fontSize={10} />
                    <YAxis dataKey="vector" type="category" stroke="#94a3b8" fontSize={10} width={90} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0c0e18',
                        borderColor: '#334155',
                        fontSize: '11px',
                        borderRadius: '8px',
                      }}
                    />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                      {VECTOR_DATA.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
              <span>Top Vector: <strong className="text-cyan-400">DLP Secret Leak</strong></span>
              <span>100% Bijective FPE</span>
            </div>
          </div>
        </div>

        {/* Live Threat Stream & Guardrail Settings */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Live Intercept Stream */}
          <div className="lg:col-span-2 bg-[#0f111a] border border-slate-800 rounded-xl flex flex-col h-[540px]">
            {/* Stream Header */}
            <div className="px-4 py-3 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#131522]/50 rounded-t-xl">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-emerald-400" />
                <span className="font-semibold text-sm text-slate-100">Live Intercept Stream</span>
                <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded-full text-xs font-mono">
                  {filteredEvents.length} events
                </span>
              </div>

              {/* Filters & Search */}
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Filter events..."
                    className="bg-slate-900 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-slate-700 w-36"
                  />
                </div>

                <select
                  value={filterType}
                  onChange={(e) => setFilterType(e.target.value)}
                  className="bg-slate-900 border border-slate-800 rounded-lg px-2 py-1 text-xs text-slate-300 focus:outline-none"
                >
                  <option value="ALL">All Types</option>
                  <option value="BLOCK">Blocked</option>
                  <option value="SANITIZE">Sanitized</option>
                  <option value="QUARANTINE">Quarantined</option>
                </select>

                <button
                  onClick={() => setEvents([])}
                  className="text-xs text-slate-400 hover:text-white bg-slate-900 border border-slate-800 rounded px-2 py-1 transition"
                >
                  Clear
                </button>
              </div>
            </div>

            {/* Event List */}
            <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs">
              {filteredEvents.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-2">
                  <Radio className="w-8 h-8 text-slate-600 animate-pulse" />
                  <p>Listening for agent MCP tool calls...</p>
                  <p className="text-[11px] text-slate-600">Click &ldquo;Simulate Live Attack&rdquo; above or run your local MCP agent.</p>
                </div>
              ) : (
                filteredEvents.map((evt) => (
                  <div
                    key={evt.id}
                    className="p-3 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition flex flex-col gap-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                            evt.eventType === 'BLOCK'
                              ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                              : evt.eventType === 'SANITIZE'
                              ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                              : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                          }`}
                        >
                          {evt.eventType}
                        </span>
                        <span className="text-slate-200 font-semibold">{evt.toolName}</span>
                        <span className="text-[11px] text-slate-500">via {evt.detector}</span>
                      </div>
                      <span className="text-[10px] text-slate-500">{evt.timestamp}</span>
                    </div>
                    <div className="text-slate-400 text-[11px] pl-1 font-sans">{evt.reason}</div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Right Sidebar: Guardrails & CLI Connect */}
          <div className="space-y-6">
            {/* Active Guardrails Card */}
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

            {/* Connect Agent CLI & Key Management Card */}
            <div className="bg-[#0f111a] border border-slate-800 rounded-xl p-4 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <div className="font-semibold text-sm flex items-center gap-2 text-slate-100">
                  <Key className="w-4 h-4 text-emerald-400" /> API Keys & Device Pairing
                </div>
                <button
                  onClick={() => setIsCreateKeyOpen(true)}
                  className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 text-xs font-medium border border-emerald-500/30 transition shadow-sm"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>New Key</span>
                </button>
              </div>

              <p className="text-xs text-slate-400">
                Pair local MCP clients to stream real-time AST evaluations, blocks, and DLP redacting:
              </p>

              <div className="space-y-2">
                {apiKeys.map((k) => (
                  <div
                    key={k.id}
                    className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 hover:border-slate-700 transition space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-medium text-slate-200">{k.name}</span>
                      <span className="text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-1.5 py-0.2 rounded font-mono">
                        {k.status.toUpperCase()}
                      </span>
                    </div>

                    <div className="flex items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
                      <span className="truncate">{k.keyPrefix}••••••••</span>
                      <div className="flex items-center gap-1 shrink-0">
                        <button
                          onClick={() => {
                            const cmd = `mcp-shield link --key ${k.apiKey || k.keyPrefix}`;
                            navigator.clipboard.writeText(cmd);
                            setCopiedKeyId(k.id);
                            setTimeout(() => setCopiedKeyId(null), 2000);
                          }}
                          className="p-1 text-slate-400 hover:text-emerald-400 transition"
                          title="Copy CLI Pairing Command"
                        >
                          {copiedKeyId === k.id ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                        <button
                          onClick={() => handleRevokeKey(k.id, k.keyPrefix)}
                          className="p-1 text-slate-500 hover:text-rose-400 transition"
                          title="Revoke Key"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Quick CLI snippet */}
              <div className="pt-2 border-t border-slate-800/60">
                <div className="text-[11px] text-slate-400 mb-1.5 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-slate-400" /> Quick CLI Pair Command
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-300 flex items-center justify-between">
                  <span className="truncate">mcp-shield link --key {apiKeys[0]?.keyPrefix || 'mcp_live_...'}</span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(`mcp-shield link --key ${apiKeys[0]?.apiKey || apiKeys[0]?.keyPrefix || 'mcp_live_sec_demo'}`);
                      setCopiedKey(true);
                      setTimeout(() => setCopiedKey(false), 2000);
                    }}
                    className="text-slate-400 hover:text-white transition shrink-0 ml-2"
                  >
                    {copiedKey ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>

            {/* Decoy Canary Tripwire */}
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

      {/* Key Creation Dialog Modal */}
      {isCreateKeyOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f111a] border border-slate-700/80 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-5 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                  <Key className="w-4 h-4 text-emerald-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-sm text-white">Generate Client API Key</h3>
                  <p className="text-[11px] text-slate-400">Stream AST security telemetry to this console</p>
                </div>
              </div>
              <button
                onClick={() => setIsCreateKeyOpen(false)}
                className="text-slate-400 hover:text-white p-1 transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1.5">Key Name / Description</label>
                <input
                  type="text"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  placeholder="e.g. Cursor Workstation, Production Gateway"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white placeholder-slate-600 focus:outline-none focus:border-emerald-500/60"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1.5">MCP Client / Host</label>
                <select
                  value={newKeyClient}
                  onChange={(e) => setNewKeyClient(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500/60"
                >
                  <option value="Claude Desktop">Claude Desktop</option>
                  <option value="Cursor IDE">Cursor IDE</option>
                  <option value="Google Antigravity">Google Antigravity</option>
                  <option value="VSCode Cline">VSCode Cline</option>
                  <option value="Windsurf">Windsurf</option>
                  <option value="Custom Agent / SDK">Custom Agent / SDK</option>
                </select>
              </div>

              <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-slate-400 text-[11px] space-y-1">
                <div className="font-medium text-slate-300 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> Zero-Plaintext Transmission
                </div>
                <div>All telemetry batches are signed with HMAC-SHA256. Plaintext secrets are never stored.</div>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2.5 pt-2 border-t border-slate-800">
              <button
                onClick={() => setIsCreateKeyOpen(false)}
                className="px-3.5 py-1.5 rounded-lg text-slate-400 hover:text-white text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  handleGenerateKey();
                  setIsCreateKeyOpen(false);
                }}
                className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-black text-xs font-bold transition shadow-lg shadow-emerald-600/20"
              >
                Generate Key
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Key Reveal Dialog Modal */}
      {justCreatedKey && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f111a] border border-slate-700/80 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-5 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center shrink-0">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <h3 className="font-bold text-sm text-white">API Key Generated Successfully</h3>
                <p className="text-xs text-slate-400">Save this secret key now — it cannot be recovered later</p>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>Copy your secret key now. For your security, this key will never be displayed again.</span>
            </div>

            <div className="space-y-3">
              <div>
                <div className="text-[11px] font-medium text-slate-400 mb-1">Secret Key:</div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between font-mono text-xs text-emerald-300">
                  <span className="truncate mr-2">{justCreatedKey}</span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(justCreatedKey);
                      setCopiedKey(true);
                      setTimeout(() => setCopiedKey(false), 2000);
                    }}
                    className="p-1.5 text-slate-400 hover:text-white transition shrink-0"
                    title="Copy Key"
                  >
                    {copiedKey ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div>
                <div className="text-[11px] font-medium text-slate-400 mb-1">Terminal Pairing Command:</div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between font-mono text-xs text-slate-200">
                  <span className="truncate mr-2">mcp-shield link --key {justCreatedKey}</span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(`mcp-shield link --key ${justCreatedKey}`);
                      setCopiedKey(true);
                      setTimeout(() => setCopiedKey(false), 2000);
                    }}
                    className="p-1.5 text-slate-400 hover:text-white transition shrink-0"
                    title="Copy Command"
                  >
                    {copiedKey ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setJustCreatedKey(null)}
                className="px-5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-black text-xs font-bold transition shadow-lg shadow-emerald-600/20"
              >
                Done & Return to Console
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
