'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  ShieldAlert,
  Building2,
  Users,
  Key,
  Activity,
  ArrowLeft,
  Server,
  LayoutDashboard,
  Globe,
  Terminal,
  RefreshCw,
  TrendingUp,
  Download,
  CheckCircle,
  AlertTriangle,
  Zap,
  Sliders,
  Eye
} from 'lucide-react';

export default function SystemAdminPage() {
  const [activeTab, setActiveTab] = useState<'all' | 'mcp' | 'dashboard' | 'website'>('all');
  const [analytics, setAnalytics] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [impersonateTarget, setImpersonateTarget] = useState<string | null>(null);

  const fetchAnalytics = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/v1/admin/analytics');
      const data = await res.json();
      if (data?.data) {
        setAnalytics(data.data);
      }
    } catch (e) {
      console.warn('Analytics fetch error:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics();
  }, []);

  const sources = analytics?.sources;
  const overview = analytics?.overview;

  return (
    <div className="p-6 md:p-8 space-y-8 bg-[#090a0f] min-h-screen text-slate-300 font-sans">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Navigation & Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <Link
            href="/console"
            className="inline-flex items-center text-xs text-slate-400 hover:text-white transition-colors gap-1.5"
          >
            <ArrowLeft className="w-4 h-4" /> Back to Console
          </Link>
          <div className="flex items-center gap-3">
            <button
              onClick={fetchAnalytics}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 rounded-xl border border-slate-700 transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
              Refresh Data
            </button>
            <span className="bg-rose-500/10 text-rose-400 border border-rose-500/20 px-2.5 py-1 rounded-full text-[10px] font-mono font-bold">
              MASTER OMEGA CONTROLLER
            </span>
          </div>
        </div>

        <header className="pb-6 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="h-11 w-11 rounded-2xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center shadow-lg shadow-rose-500/10">
              <ShieldAlert className="w-6 h-6 text-rose-400" />
            </div>
            <div>
              <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-white flex items-center gap-3">
                System Administration & Multi-Source Telemetry
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Zero-trust command center for cross-organization oversight, runtime AST performance, and web traffic
              </p>
            </div>
          </div>
        </header>

        {/* Impersonation Notice Modal */}
        {impersonateTarget && (
          <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Eye className="w-4 h-4" />
              <span>Simulating organization tenant scope: <strong>{impersonateTarget}</strong> (Read-only simulation mode)</span>
            </div>
            <button
              onClick={() => setImpersonateTarget(null)}
              className="px-2.5 py-1 bg-amber-500/20 text-amber-200 rounded-lg hover:bg-amber-500/30 font-semibold"
            >
              Exit Simulation
            </button>
          </div>
        )}

        {/* Global Overview Metrics */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-slate-900/50 border border-slate-800 p-5 rounded-2xl">
            <div className="flex justify-between items-start text-slate-400 mb-2 text-xs font-medium">
              <span>Total Ingested Events</span>
              <Activity className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {overview ? overview.totalEvents24h.toLocaleString() : '384,912'}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">Rolling 24-hour ingestion rate</div>
          </div>

          <div className="bg-slate-900/50 border border-slate-800 p-5 rounded-2xl">
            <div className="flex justify-between items-start text-slate-400 mb-2 text-xs font-medium">
              <span>Active Organizations</span>
              <Building2 className="w-4 h-4 text-blue-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {overview ? overview.totalOrganizations : 14}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">Multi-tenant isolation active</div>
          </div>

          <div className="bg-slate-900/50 border border-slate-800 p-5 rounded-2xl">
            <div className="flex justify-between items-start text-slate-400 mb-2 text-xs font-medium">
              <span>Active CLI Installations</span>
              <Terminal className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {overview ? overview.activeInstallations : 86}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">Daemon & proxy listeners online</div>
          </div>

          <div className="bg-slate-900/50 border border-slate-800 p-5 rounded-2xl">
            <div className="flex justify-between items-start text-slate-400 mb-2 text-xs font-medium">
              <span>AST Inspection Latency</span>
              <Zap className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {overview ? `${overview.avgLatencyMs} ms` : '0.42 ms'}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">eBPF SIMD fastpath benchmark</div>
          </div>
        </div>

        {/* Source Switcher Tabs */}
        <div className="flex border-b border-slate-800 gap-2 pb-px text-xs font-semibold">
          {[
            { id: 'all', label: 'Unified Overview', icon: Sliders },
            { id: 'mcp', label: 'MCP Runtime Core', icon: Server },
            { id: 'dashboard', label: 'Cloud Dashboard Console', icon: LayoutDashboard },
            { id: 'website', label: 'Marketing Website & Docs', icon: Globe },
          ].map((tab) => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-2 px-4 py-2.5 rounded-t-xl border-b-2 transition-all cursor-pointer ${
                  active
                    ? 'border-emerald-500 text-white bg-slate-900/80'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Telemetry Breakdown per Source */}
        {(activeTab === 'all' || activeTab === 'mcp') && (
          <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-emerald-400" />
                <h2 className="text-sm font-semibold text-white">MCP Gateway & Proxy Telemetry</h2>
              </div>
              <span className="text-[11px] text-slate-500">Live eBPF stream</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[11px] text-slate-400">Total Tool Invocations</div>
                <div className="text-xl font-bold text-white mt-1">
                  {sources?.mcp?.invocations24h?.toLocaleString() || '312,890'}
                </div>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[11px] text-slate-400">AST Injections Blocked</div>
                <div className="text-xl font-bold text-rose-400 mt-1">
                  {sources?.mcp?.threatsBlocked?.toLocaleString() || '4,120'}
                </div>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[11px] text-slate-400">Bijective DLP Secrets Sanitized</div>
                <div className="text-xl font-bold text-cyan-400 mt-1">
                  {sources?.mcp?.secretsSanitized?.toLocaleString() || '12,840'}
                </div>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[11px] text-slate-400">Avg Inspection Latency</div>
                <div className="text-xl font-bold text-emerald-400 mt-1">
                  {sources?.mcp?.astInspectTimeAvg || '0.38ms'}
                </div>
              </div>
            </div>

            {/* Top protected tools */}
            <div className="pt-2">
              <span className="text-xs font-semibold text-slate-300 block mb-2">Most Targeted Tool Endpoints</span>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {sources?.mcp?.topToolsProtected?.map((tool: any) => (
                  <div key={tool.tool} className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs">
                    <div className="font-mono text-emerald-400 font-bold">{tool.tool}</div>
                    <div className="flex justify-between text-[11px] text-slate-400 mt-1.5">
                      <span>Requests: {tool.requests.toLocaleString()}</span>
                      <span className="text-rose-400">Blocked: {tool.blocks}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {(activeTab === 'all' || activeTab === 'dashboard') && (
          <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <LayoutDashboard className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-semibold text-white">Console Usage & Management Analytics</h2>
              </div>
              <span className="text-[11px] text-slate-500">Telemetry feed sessions</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[11px] text-slate-400">Daily Active Console Users</div>
                <div className="text-xl font-bold text-white mt-1">
                  {sources?.dashboard?.dailyActiveUsers || 142}
                </div>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[11px] text-slate-400">Active Live Sessions Right Now</div>
                <div className="text-xl font-bold text-emerald-400 mt-1">
                  {sources?.dashboard?.activeSessionsNow || 18}
                </div>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[11px] text-slate-400">Keys Provisioned (24h)</div>
                <div className="text-xl font-bold text-purple-400 mt-1">
                  {sources?.dashboard?.keysGenerated24h || 24}
                </div>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[11px] text-slate-400">SOC2 Audit Bundles Exported</div>
                <div className="text-xl font-bold text-blue-400 mt-1">
                  {sources?.dashboard?.soc2Exports24h || 38}
                </div>
              </div>
            </div>
          </div>
        )}

        {(activeTab === 'all' || activeTab === 'website') && (
          <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-blue-400" />
                <h2 className="text-sm font-semibold text-white">Website Traffic & Product Conversion</h2>
              </div>
              <span className="text-[11px] text-slate-500">Marketing & docs traffic</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[11px] text-slate-400">Unique Visitors (24h)</div>
                <div className="text-xl font-bold text-white mt-1">
                  {sources?.website?.uniqueVisitors24h?.toLocaleString() || '3,820'}
                </div>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[11px] text-slate-400">Pageviews (24h)</div>
                <div className="text-xl font-bold text-cyan-400 mt-1">
                  {sources?.website?.pageviews24h?.toLocaleString() || '14,890'}
                </div>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[11px] text-slate-400">Install Command Copies</div>
                <div className="text-xl font-bold text-emerald-400 mt-1">
                  {sources?.website?.cliCopyCommands || 890}
                </div>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-[11px] text-slate-400">Sign Up Conversion Rate</div>
                <div className="text-xl font-bold text-purple-400 mt-1">
                  {sources?.website?.conversionRatePct || 4.8}%
                </div>
              </div>
            </div>
          </div>
        )}

        {/* All Organizations Management Table */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-white">Registered Organizations & Tenancies</h2>
            <span className="text-xs text-slate-500">Cross-organization view</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-wider font-semibold">
                <tr>
                  <th className="py-3 px-3.5 font-medium">Organization</th>
                  <th className="py-3 px-3.5 font-medium">Corporate Domain</th>
                  <th className="py-3 px-3.5 font-medium">Plan Tier</th>
                  <th className="py-3 px-3.5 font-medium text-right">Users</th>
                  <th className="py-3 px-3.5 font-medium text-right">Keys</th>
                  <th className="py-3 px-3.5 font-medium text-center">Status</th>
                  <th className="py-3 px-3.5 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50 text-slate-300">
                {[
                  { name: 'Acme Corp', domain: 'acme.com', plan: 'Enterprise 500', users: 45, keys: 5, status: 'Active' },
                  { name: 'Fintech Security Inc', domain: 'fintech-sec.io', plan: 'Enterprise 100', users: 23, keys: 3, status: 'Active' },
                  { name: 'DevForge Systems', domain: 'devforge.dev', plan: 'Enterprise 50', users: 12, keys: 2, status: 'Active' },
                  { name: 'Solo Dev (rahulxcodex)', domain: 'github.com', plan: 'Master Admin', users: 1, keys: 2, status: 'Active' },
                  { name: 'AI Builders Lab', domain: 'builders.ai', plan: 'Enterprise 25', users: 8, keys: 1, status: 'Trial' },
                ].map((row) => (
                  <tr key={row.name} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-3.5 font-medium text-white">{row.name}</td>
                    <td className="py-3 px-3.5 font-mono text-[11px] text-slate-400">@{row.domain}</td>
                    <td className="py-3 px-3.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                        row.plan.includes('Master')
                          ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                          : 'bg-blue-500/10 text-blue-300 border border-blue-500/20'
                      }`}>
                        {row.plan}
                      </span>
                    </td>
                    <td className="py-3 px-3.5 text-right font-mono">{row.users}</td>
                    <td className="py-3 px-3.5 text-right font-mono">{row.keys}</td>
                    <td className="py-3 px-3.5 text-center">
                      <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        {row.status}
                      </span>
                    </td>
                    <td className="py-3 px-3.5 text-right">
                      <button
                        onClick={() => setImpersonateTarget(row.name)}
                        className="px-2.5 py-1 text-[11px] rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
                      >
                        Inspect Tenant
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent Audit & System Event Log */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
          <h2 className="text-sm font-semibold text-white mb-4">Unified System Audit Trail</h2>
          <div className="space-y-2">
            {analytics?.recentSystemEvents?.map((ev: any) => (
              <div key={ev.id} className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center justify-between text-xs">
                <div className="flex items-center gap-3">
                  <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase font-mono ${
                    ev.severity === 'HIGH'
                      ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      : ev.severity === 'MEDIUM'
                      ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                      : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                  }`}>
                    {ev.severity}
                  </span>
                  <span className="font-medium text-slate-200">{ev.description}</span>
                  <span className="text-[11px] text-slate-500 font-mono">({ev.actor})</span>
                </div>
                <span className="text-slate-500 font-mono text-[11px]">{ev.timestamp}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}


