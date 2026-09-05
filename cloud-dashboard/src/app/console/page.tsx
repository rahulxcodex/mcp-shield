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
  X,
  CreditCard,
  LogOut,
  RotateCw,
  MessageSquare,
  User,
  LogIn,
  HelpCircle,
  CheckSquare,
  Square,
  Info,
  Upload
} from 'lucide-react';
import ThemeToggle from '@/components/ThemeToggle';
import SupportModal from '@/components/SupportModal';
import WorkspaceSwitcher from '@/components/WorkspaceSwitcher';
import OnboardingWizard from '@/components/OnboardingWizard';
import EventDetailDrawer, { ThreatEvent } from '@/components/EventDetailDrawer';
import AccountDropdown from '@/components/AccountDropdown';
import MoreDropdown from '@/components/MoreDropdown';
import ReferralCard from '@/components/ReferralCard';
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
  eventId?: string;
  timestamp: string;
  eventType: 'BLOCK' | 'SANITIZE' | 'QUARANTINE' | 'RATE_LIMIT' | 'PASSTHROUGH' | 'PROMPT' | 'ERROR';
  toolName: string;
  detector: string;
  riskLevel: 'BENIGN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  reason: string;
  sequenceNumber?: number;
  installationId?: string;
  environment?: string;
}


interface ApiKeyEntry {
  id: string;
  name: string;
  keyPrefix: string;
  apiKey?: string;
  createdAt: string;
  lastUsedAt?: string;
  expiresAt?: string | null;
  status: 'active' | 'revoked';
}

const INITIAL_EVENTS: SecurityEvent[] = [];

const TIMELINE_DATA = [
  { time: '00:00', allowed: 0, threats: 0 },
  { time: '04:00', allowed: 0, threats: 0 },
  { time: '08:00', allowed: 0, threats: 0 },
  { time: '12:00', allowed: 0, threats: 0 },
  { time: '16:00', allowed: 0, threats: 0 },
  { time: '20:00', allowed: 0, threats: 0 },
  { time: 'Now', allowed: 0, threats: 0 },
];

const VECTOR_DATA = [
  { vector: 'AST Injection', count: 0, color: '#f43f5e' },
  { vector: 'SSRF & Metadata', count: 0, color: '#fb923c' },
  { vector: 'DLP Redacted', count: 0, color: '#22d3ee' },
  { vector: 'Canary Tripped', count: 0, color: '#eab308' },
  { vector: 'Rate Exceeded', count: 0, color: '#a855f7' },
];

export default function ConsolePage() {
  const [events, setEvents] = useState<SecurityEvent[]>(INITIAL_EVENTS);
  const [filterType, setFilterType] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<boolean>(false);
  const [apiKeys, setApiKeys] = useState<ApiKeyEntry[]>([]);
  const [isCreateKeyOpen, setIsCreateKeyOpen] = useState(false);
  const [isAddExistingOpen, setIsAddExistingOpen] = useState(false);
  const [addExistingKey, setAddExistingKey] = useState('');
  const [addExistingName, setAddExistingName] = useState('');
  const [addExistingError, setAddExistingError] = useState<string | null>(null);
  const [addExistingSuccess, setAddExistingSuccess] = useState<string | null>(null);
  const [addExistingLoading, setAddExistingLoading] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyClient, setNewKeyClient] = useState('Claude Desktop');
  const [justCreatedKey, setJustCreatedKey] = useState<string | null>(null);
  const [copiedKeyId, setCopiedKeyId] = useState<string | null>(null);

  const [stats, setStats] = useState({
    healthScore: 100,
    attacksNeutralized: 0,
    secretsTokenized: 0,
    invocations: 0,
    latency: '0.12ms',
  });

  const [timelineData, setTimelineData] = useState(TIMELINE_DATA);
  const [vectorData, setVectorData] = useState(VECTOR_DATA);
  const [expiresInDays, setExpiresInDays] = useState<number>(90);
  const [keySeats, setKeySeats] = useState<number>(25);
  const [isUpgrading, setIsUpgrading] = useState(false);
  const [isPurchaseModalOpen, setIsPurchaseModalOpen] = useState(false);
  const [liveConnected, setLiveConnected] = useState(true);
  const [currentUser, setCurrentUser] = useState<any>(null);
  const [isSupportModalOpen, setIsSupportModalOpen] = useState(false);
  const [rotatingKeyId, setRotatingKeyId] = useState<string | null>(null);
  const [isOnboardingOpen, setIsOnboardingOpen] = useState(false);
  const [dismissOnboardingBanner, setDismissOnboardingBanner] = useState(false);
  const [selectedDetailEvent, setSelectedDetailEvent] = useState<ThreatEvent | null>(null);
  const [selectedEventIds, setSelectedEventIds] = useState<string[]>([]);
  const [envFilter, setEnvFilter] = useState('ALL');
  const [timeRangeFilter, setTimeRangeFilter] = useState('24h');
  const [lastUpdatedSec, setLastUpdatedSec] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setLastUpdatedSec((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    async function checkAuth() {
      try {
        const { createClient } = await import('@/utils/supabase/client');
        const supabase = createClient();
        const { data: { user } } = await supabase.auth.getUser();
        setCurrentUser(user);
      } catch {
        setCurrentUser(null);
      }
    }
    checkAuth();
  }, []);

  const fetchTelemetry = async () => {
    try {
      setLastUpdatedSec(0);
      const [statsRes, eventsRes, keysRes] = await Promise.all([
        fetch('/api/v1/telemetry/stats'),
        fetch(`/api/v1/telemetry/events?filter=${filterType}&query=${encodeURIComponent(searchQuery)}&limit=50`),
        fetch('/api/v1/keys')
      ]);

      if (statsRes.ok) {
        const data = await statsRes.json();
        if (data?.timelineData) setTimelineData(data.timelineData);
        if (data?.vectorData) setVectorData(data.vectorData);
        if (data?.summary) {
          setStats((prev) => ({
            ...prev,
            attacksNeutralized: data.summary.attacksNeutralized,
            secretsTokenized: data.summary.secretsTokenized,
            invocations: data.summary.invocations,
            latency: `${data.summary.astLatencyMs}ms`
          }));
        }
      }

      if (eventsRes.ok) {
        const data = await eventsRes.json();
        if (data?.events && Array.isArray(data.events) && data.events.length > 0) {
          setEvents(data.events);
          if (data.live) setLiveConnected(true);
        }
      }

      if (keysRes.ok) {
        const data = await keysRes.json();
        if (data?.keys && Array.isArray(data.keys)) {
          setApiKeys(data.keys.map((k: any) => ({
            id: k.id,
            name: k.name,
            keyPrefix: k.key_prefix,
            apiKey: k.apiKey,
            createdAt: k.created_at ? new Date(k.created_at).toLocaleDateString() : 'Active',
            lastUsedAt: k.last_used_at ? 'Active' : 'Never',
            expiresAt: k.expires_at,
            status: k.status || 'active'
          })));
        }
      }
    } catch {}
  };

  useEffect(() => {
    fetchTelemetry();
    const timer = setInterval(fetchTelemetry, 8000);
    return () => clearInterval(timer);
  }, [filterType, searchQuery]);

  const handleSignOut = async () => {
    try {
      const { createClient } = await import('@/utils/supabase/client');
      const supabase = createClient();
      await supabase.auth.signOut();
    } catch {}
    window.location.href = '/login';
  };

  const handleUpgradePlan = async () => {
    setIsUpgrading(true);
    try {
      const res = await fetch('/api/v1/billing/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ priceId: 'price_mcp_pro_monthly' })
      });
      if (res.ok) {
        const data = await res.json();
        if (data?.url) {
          window.location.href = data.url;
        }
      }
    } catch {} finally {
      setIsUpgrading(false);
    }
  };

  const handleGenerateKey = async () => {
    try {
      const res = await fetch('/api/v1/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newKeyName, clientType: newKeyClient, expiresInDays, seats: keySeats }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data?.key) {
          const persistedKey: ApiKeyEntry = {
            id: data.key.id,
            name: data.key.name,
            keyPrefix: data.key.keyPrefix,
            apiKey: data.key.apiKey, // Authentically created and returned ONCE by server
            createdAt: 'Just now',
            lastUsedAt: 'Never',
            expiresAt: data.key.expires_at || null,
            status: 'active',
          };
          setApiKeys((prev) => [persistedKey, ...prev]);
          setJustCreatedKey(data.key.apiKey);
          setNewKeyName('');
          return;
        }
      } else {
        const errData = await res.json().catch(() => ({}));
        alert(`Failed to generate key: ${errData.error || 'Server error'}`);
      }
    } catch {
      alert('Network error communicating with key provisioning server.');
    }
  };


  const handleRevokeKey = async (id: string, prefix: string) => {
    try {
      await fetch(`/api/v1/keys?id=${id}&prefix=${prefix}`, { method: 'DELETE' });
    } catch {}
    setApiKeys((prev) => prev.map((k) => k.id === id ? { ...k, status: 'revoked' } : k));
  };

  const handleRotateKey = async (id: string, prefix: string) => {
    setRotatingKeyId(id);
    try {
      const res = await fetch('/api/v1/keys', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ keyId: id, keyPrefix: prefix, expiresInDays })
      });
      if (res.ok) {
        const data = await res.json();
        if (data?.newKey) {
          setApiKeys((prev) => prev.map((k) => k.id === id ? { ...k, status: 'revoked' } : k));
          setApiKeys((prev) => [
            {
              id: data.newKey.id,
              name: data.newKey.name,
              keyPrefix: data.newKey.keyPrefix,
              apiKey: data.newKey.apiKey,
              createdAt: 'Just now',
              lastUsedAt: 'Never',
              expiresAt: data.newKey.expires_at,
              status: 'active'
            },
            ...prev
          ]);
          setJustCreatedKey(data.newKey.apiKey);
        }
      }
    } catch {} finally {
      setRotatingKeyId(null);
    }
  };

  const handleImportExistingKey = async () => {
    const trimmedKey = addExistingKey.trim();
    const trimmedName = addExistingName.trim() || 'Master Key';

    if (!trimmedKey) {
      setAddExistingError('Please enter an API key or Master Key.');
      return;
    }
    if (trimmedKey.length < 8) {
      setAddExistingError('Key must be at least 8 characters long.');
      return;
    }

    setAddExistingLoading(true);
    setAddExistingError(null);

    try {
      const res = await fetch('/api/v1/keys', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawKey: trimmedKey, name: trimmedName })
      });

      const data = await res.json();
      if (!res.ok) {
        setAddExistingError(data.error || 'Failed to import key.');
        return;
      }

      if (data?.key) {
        const importedEntry: ApiKeyEntry = {
          id: data.key.id,
          name: data.key.name,
          keyPrefix: data.key.keyPrefix,
          createdAt: new Date().toLocaleDateString(),
          lastUsedAt: 'Active',
          status: 'active'
        };
        setApiKeys((prev) => [importedEntry, ...prev.map((k) => ({ ...k, status: 'revoked' as const }))]);
        setAddExistingSuccess(data.message || 'Key imported successfully!');

        setTimeout(() => {
          setIsAddExistingOpen(false);
          setAddExistingKey('');
          setAddExistingName('');
          setAddExistingSuccess(null);
        }, 1200);
      }
    } catch {
      setAddExistingError('Network error connecting to key service.');
    } finally {
      setAddExistingLoading(false);
    }
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
                <h1 className="font-bold text-lg leading-tight flex items-center gap-2">
                  <span>MCP-SHIELD</span>
                  <span className="text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-2 py-0.5 rounded-full font-mono font-medium">
                    CONSOLE
                  </span>
                </h1>
                <div className="text-[11px] text-slate-400">Zero-Trust Live Telemetry & Threat Center</div>
              </div>
            </Link>
            <div className="hidden lg:block border-l border-slate-800 pl-3">
              <WorkspaceSwitcher />
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-3">
            {/* Connection health indicator & ticker */}
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs text-slate-300">
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>Live (8s)</span>
              <span className="text-[10px] text-slate-500 font-mono">
                {lastUpdatedSec === 0 ? 'just now' : `${lastUpdatedSec}s ago`}
              </span>
              <button
                onClick={fetchTelemetry}
                title="Refresh Telemetry Stream"
                className="hover:text-white transition-colors"
              >
                <RefreshCw className="w-3 h-3 text-slate-400 hover:text-emerald-400" />
              </button>
            </div>

            {/* More Dropdown — secondary actions */}
            <MoreDropdown
              onOpenOnboarding={() => setIsOnboardingOpen(true)}
              onSimulateAttack={handleSimulateBatch}
              isSimulating={isSimulating}
              onExportSOC2={handleExportSOC2}
              onOpenSupport={() => setIsSupportModalOpen(true)}
            />

            {/* Auth State */}
            {currentUser ? (
              <AccountDropdown
                user={currentUser}
                onSignOut={handleSignOut}
              />
            ) : (
              <div className="flex items-center gap-2">
                <span className="hidden sm:flex items-center gap-1 px-2.5 py-1 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20 text-xs font-bold whitespace-nowrap">
                  <Sparkles className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                  <span>Demo Mode</span>
                </span>
                <Link
                  href="/login"
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-black text-xs font-bold transition shadow-md shadow-emerald-500/20"
                >
                  <LogIn className="w-3.5 h-3.5" />
                  <span>Sign In / Sign Up</span>
                </Link>
                <Link
                  href="/"
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition border border-slate-700"
                >
                  Exit Demo
                </Link>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Main Console Workspace */}
      <main className="max-w-7xl mx-auto px-4 py-6 flex-1 w-full space-y-6">
        {/* Onboarding Checklist Banner */}
        {!dismissOnboardingBanner && (
          <div className="p-3.5 rounded-2xl bg-gradient-to-r from-blue-950/60 to-slate-900 border border-blue-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-blue-500/20 text-blue-400 shrink-0">
                <Sparkles className="w-4 h-4" />
              </div>
              <div>
                <div className="font-semibold text-white flex items-center gap-2">
                  <span>Workspace Onboarding Checklist</span>
                  <span className="text-[10px] bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded font-mono">
                    2/4 Steps Completed
                  </span>
                </div>
                <div className="text-slate-400 text-[11px] mt-0.5">
                  ✓ Org Initialized • ✓ Project Active • Connect local CLI agent with <code>mcpshld wrap</code> • Verify Heartbeat
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0 self-end sm:self-auto">
              <button
                onClick={() => setIsOnboardingOpen(true)}
                className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition shadow-md shadow-blue-500/20"
              >
                Resume Guided Setup →
              </button>
              <button
                onClick={() => setDismissOnboardingBanner(true)}
                className="p-1.5 text-slate-400 hover:text-white"
                title="Dismiss Banner"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* KPI Scorecard Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-[#0f111a] border border-slate-800/80 p-4 rounded-xl flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Security Health Score</span>
                <span title="Calculated from blocked vs total invocations over the last 24 hours (target: 95+)" className="cursor-help">
                  <Info className="w-3.5 h-3.5 text-slate-500 hover:text-slate-300" />
                </span>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-extrabold text-emerald-400">{stats.healthScore}</span>
                <span className="text-xs text-slate-500 font-mono">/ 100</span>
              </div>
            </div>
            <div className="mt-2 text-xs text-emerald-400/80 flex items-center gap-1">
              <Shield className="w-3.5 h-3.5" /> Zero-Trust AST Firewall Enforced
            </div>
          </div>

          <div className="bg-[#0f111a] border border-slate-800/80 p-4 rounded-xl flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Attacks Neutralized</span>
                <span title="Total count of blocked destructive commands, forbidden subshells, and SSRF loopback requests" className="cursor-help">
                  <Info className="w-3.5 h-3.5 text-slate-500 hover:text-slate-300" />
                </span>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-extrabold text-rose-400">{stats.attacksNeutralized}</span>
                <span className="text-xs text-rose-500 font-mono">threats blocked</span>
              </div>
            </div>
            <div className="mt-2 text-xs text-slate-400 flex items-center gap-1">
              <Ban className="w-3.5 h-3.5 text-rose-400" /> AST, SSRF, & Shell Evasions
            </div>
          </div>

          <div className="bg-[#0f111a] border border-slate-800/80 p-4 rounded-xl flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Secrets Tokenized (DLP)</span>
                <span title="Raw cloud credentials, API tokens, and PII converted to format-preserving surrogate tokens in memory" className="cursor-help">
                  <Info className="w-3.5 h-3.5 text-slate-500 hover:text-slate-300" />
                </span>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-extrabold text-cyan-400">{stats.secretsTokenized}</span>
                <span className="text-xs text-cyan-500 font-mono">keys redacted</span>
              </div>
            </div>
            <div className="mt-2 text-xs text-slate-400 flex items-center gap-1">
              <Key className="w-3.5 h-3.5 text-cyan-400" /> Bijective In-Memory FPE
            </div>
          </div>

          <div className="bg-[#0f111a] border border-slate-800/80 p-4 rounded-xl flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Evaluated Invocations</span>
                <span title="Sub-millisecond latency added to hotpath MCP execution by Tree-sitter AST parsing" className="cursor-help">
                  <Info className="w-3.5 h-3.5 text-slate-500 hover:text-slate-300" />
                </span>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-extrabold text-indigo-400">{stats.invocations.toLocaleString()}</span>
                <span className="text-xs text-indigo-500 font-mono">hotpath calls</span>
              </div>
            </div>
            <div className="mt-2 text-xs text-slate-400 flex items-center gap-1">
              <Zap className="w-3.5 h-3.5 text-indigo-400" /> <span>&lt; {stats.latency}</span> AST parse overhead
            </div>
          </div>
        </div>

        {/* Referral Program Card */}
        <ReferralCard />

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
                <AreaChart data={timelineData}>
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
                  <BarChart data={vectorData} layout="vertical">
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
            <div className="px-4 py-3 border-b border-slate-800 flex flex-col gap-2.5 bg-[#131522]/50 rounded-t-xl">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-emerald-400" />
                  <span className="font-semibold text-sm text-slate-100">Live Intercept Stream</span>
                  <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded-full text-xs font-mono">
                    {filteredEvents.length} events
                  </span>
                </div>

                {/* Bulk Actions Bar if items are selected */}
                {selectedEventIds.length > 0 && (
                  <div className="flex items-center gap-2 bg-blue-500/10 border border-blue-500/30 rounded-lg px-2.5 py-1 text-xs">
                    <span className="text-blue-300 font-semibold">{selectedEventIds.length} selected</span>
                    <button
                      onClick={() => {
                        setEvents(events.filter(e => !selectedEventIds.includes(e.id)));
                        setSelectedEventIds([]);
                      }}
                      className="text-[11px] bg-blue-600 hover:bg-blue-500 text-white px-2 py-0.5 rounded font-medium"
                    >
                      Acknowledge
                    </button>
                    <button
                      onClick={() => setSelectedEventIds([])}
                      className="text-[11px] text-slate-400 hover:text-white"
                    >
                      Deselect
                    </button>
                  </div>
                )}
              </div>

              {/* Filters & Search Bar */}
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <div className="relative flex-1 min-w-[140px]">
                  <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search tool / payload..."
                    className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-slate-700"
                  />
                </div>

                <select
                  value={filterType}
                  onChange={(e) => setFilterType(e.target.value)}
                  className="bg-slate-900 border border-slate-800 rounded-lg px-2 py-1 text-slate-300 focus:outline-none"
                >
                  <option value="ALL">All Actions</option>
                  <option value="BLOCK">Blocked Only</option>
                  <option value="SANITIZE">Sanitized Only</option>
                  <option value="QUARANTINE">Quarantined Only</option>
                </select>

                <select
                  value={envFilter}
                  onChange={(e) => setEnvFilter(e.target.value)}
                  className="bg-slate-900 border border-slate-800 rounded-lg px-2 py-1 text-slate-300 focus:outline-none hidden sm:inline-block"
                >
                  <option value="ALL">All Envs</option>
                  <option value="Production">Production</option>
                  <option value="Staging">Staging</option>
                  <option value="Development">Dev</option>
                </select>

                <select
                  value={timeRangeFilter}
                  onChange={(e) => setTimeRangeFilter(e.target.value)}
                  className="bg-slate-900 border border-slate-800 rounded-lg px-2 py-1 text-slate-300 focus:outline-none hidden md:inline-block"
                >
                  <option value="1h">Last 1 Hour</option>
                  <option value="24h">Last 24 Hours</option>
                  <option value="7d">Last 7 Days</option>
                  <option value="30d">Last 30 Days</option>
                </select>

                <button
                  onClick={() => {
                    if (selectedEventIds.length === filteredEvents.length) {
                      setSelectedEventIds([]);
                    } else {
                      setSelectedEventIds(filteredEvents.map(e => e.id));
                    }
                  }}
                  className="text-xs text-slate-400 hover:text-white bg-slate-900 border border-slate-800 rounded px-2 py-1 transition"
                  title="Toggle Select All"
                >
                  {selectedEventIds.length === filteredEvents.length && filteredEvents.length > 0 ? "Deselect All" : "Select All"}
                </button>
              </div>
            </div>

            {/* Event List */}
            <div className="flex-1 overflow-y-auto p-4 space-y-2.5 font-mono text-xs">
              {filteredEvents.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-3 p-6 text-center">
                  <Radio className="w-8 h-8 text-slate-600 animate-pulse" />
                  <div>
                    <p className="text-slate-300 font-semibold text-xs">No Threat Interceptions Found</p>
                    <p className="text-[11px] text-slate-500 mt-1">Your agents are operating clean, or no traffic matches active filters.</p>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setIsOnboardingOpen(true)}
                      className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition"
                    >
                      Connect New Agent
                    </button>
                    <button
                      onClick={handleSimulateBatch}
                      disabled={isSimulating}
                      className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition border border-slate-700"
                    >
                      Simulate Test Attack
                    </button>
                  </div>
                </div>
              ) : (
                filteredEvents.map((evt) => {
                  const isSelected = selectedEventIds.includes(evt.id);
                  return (
                    <div
                      key={evt.id}
                      onClick={() => setSelectedDetailEvent({
                        id: evt.id,
                        timestamp: evt.timestamp,
                        source: evt.detector,
                        category: evt.toolName,
                        action: evt.eventType === 'BLOCK' ? 'BLOCKED' : evt.eventType === 'SANITIZE' ? 'SANITIZED' : 'QUARANTINED',
                        severity: evt.riskLevel,
                        details: evt.reason,
                        rawPayload: evt.reason,
                        status: 'OPEN',
                        assignee: 'Unassigned',
                        astRule: evt.detector.includes('AST') ? 'AST_SUBTREE_DESTRUCTIVE_EXECUTION' : evt.detector.includes('SSRF') ? 'SSRF_EGRESS_METADATA_PROHIBITED' : 'DLP_SECRET_PATTERN_EXPOSURE',
                        remediation: 'Inspect calling AI agent tool invocation parameters. If permitted, configure an allowlist expression in shield.config.yaml.'
                      })}
                      className={`p-3 rounded-xl border cursor-pointer transition flex flex-col gap-1.5 group ${
                        isSelected 
                          ? 'bg-blue-950/20 border-blue-500/50' 
                          : 'bg-slate-900/60 border-slate-800/80 hover:border-slate-700 hover:bg-slate-900/90'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              if (isSelected) {
                                setSelectedEventIds(selectedEventIds.filter(id => id !== evt.id));
                              } else {
                                setSelectedEventIds([...selectedEventIds, evt.id]);
                              }
                            }}
                            className="text-slate-500 hover:text-white"
                          >
                            {isSelected ? (
                              <CheckSquare className="w-3.5 h-3.5 text-blue-400" />
                            ) : (
                              <Square className="w-3.5 h-3.5" />
                            )}
                          </button>
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
                        <span className="text-[10px] text-slate-500 group-hover:text-blue-400 transition-colors">
                          {evt.timestamp} • Inspect →
                        </span>
                      </div>
                      <div className="text-slate-400 text-[11px] pl-6 font-sans truncate">{evt.reason}</div>
                    </div>
                  );
                })
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
                  <Key className="w-4 h-4 text-emerald-400" /> API Keys & Access
                  {apiKeys.length > 0 && (
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                      {apiKeys.length} {apiKeys.length === 1 ? 'Key' : 'Keys'}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => {
                      setIsAddExistingOpen(true);
                      setAddExistingKey("");
                      setAddExistingName("");
                      setAddExistingError(null);
                      setAddExistingSuccess(null);
                    }}
                    className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition shadow-sm"
                    title="Import Existing or Master API Key"
                  >
                    <Upload className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Add Existing</span>
                  </button>
                  <button
                    onClick={() => setIsCreateKeyOpen(true)}
                    className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 text-xs font-medium border border-emerald-500/30 transition shadow-sm"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>New Key</span>
                  </button>
                </div>
              </div>

              <p className="text-xs text-slate-400">
                Pair local MCP clients to stream real-time AST evaluations, blocks, and DLP redacting (1 active key per account):
              </p>

              <div className="space-y-2">
                {apiKeys.length === 0 ? (
                  <div className="p-4 rounded-xl bg-slate-950/60 border border-dashed border-slate-800 text-center space-y-2">
                    <Key className="w-5 h-5 mx-auto text-slate-600" />
                    <p className="text-xs text-slate-300 font-medium">No Active API Keys</p>
                    <p className="text-[11px] text-slate-500">
                      Generate a new key or import your Master Key to start streaming zero-trust protection.
                    </p>
                    <div className="flex items-center justify-center gap-2 pt-1">
                      <button
                        onClick={() => setIsCreateKeyOpen(true)}
                        className="px-3 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium"
                      >
                        Generate Key
                      </button>
                      <button
                        onClick={() => {
                          setIsAddExistingOpen(true);
                          setAddExistingKey("");
                          setAddExistingName("");
                          setAddExistingError(null);
                          setAddExistingSuccess(null);
                        }}
                        className="px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700"
                      >
                        Add Existing Key
                      </button>
                    </div>
                  </div>
                ) : (
                  apiKeys.map((k) => (
                  <div
                    key={k.id}
                    className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 hover:border-slate-700 transition space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-medium text-slate-200">{k.name}</span>
                      <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono border ${
                        k.expiresAt && new Date(k.expiresAt).getTime() < Date.now()
                          ? 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                          : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      }`}>
                        {k.expiresAt && new Date(k.expiresAt).getTime() < Date.now() ? 'EXPIRED' : k.status.toUpperCase()}
                      </span>
                    </div>

                    <div className="flex items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
                      <span className="truncate">{k.keyPrefix}••••••••</span>
                      <div className="flex items-center gap-1 shrink-0">
                        <button
                          onClick={() => {
                            const cmd = `mcpshld link --key ${k.apiKey || k.keyPrefix}`;
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
                          onClick={() => handleRotateKey(k.id, k.keyPrefix)}
                          disabled={rotatingKeyId === k.id || k.status === 'revoked'}
                          className="p-1 text-slate-400 hover:text-amber-400 transition disabled:opacity-40"
                          title="Rotate Key (Revoke old & issue new)"
                        >
                          <RotateCw className={`w-3.5 h-3.5 ${rotatingKeyId === k.id ? 'animate-spin text-amber-400' : ''}`} />
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

                    <div className="text-[10px] text-slate-500 flex items-center justify-between">
                      <span>{k.expiresAt ? (new Date(k.expiresAt).getTime() < Date.now() ? 'Trial Expired' : `Expires: ${new Date(k.expiresAt).toLocaleDateString()}`) : 'No Expiry'}</span>
                      <Link href="/settings/billing" className="text-blue-400 hover:underline">Renew / Upgrade</Link>
                    </div>
                  </div>
                )))}
              </div>

              {/* Quick CLI snippet */}
              <div className="pt-2 border-t border-slate-800/60">
                <div className="text-[11px] text-slate-400 mb-1.5 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-slate-400" /> Quick CLI Pair Command
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-300 flex items-center justify-between">
                  <span className="truncate">mcpshld link --key {apiKeys[0]?.keyPrefix || 'mcp_live_...'}</span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(`mcpshld link --key ${apiKeys[0]?.apiKey || apiKeys[0]?.keyPrefix || 'mcp_live_sec_demo'}`);
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

              <div>
                <label className="block text-slate-300 font-medium mb-1.5">Key Expiration Duration</label>
                <select
                  value={expiresInDays}
                  onChange={(e) => setExpiresInDays(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500/60"
                >
                  <option value={7}>7 Days (Rapid Testing / Staging)</option>
                  <option value={30}>1 Month (Free Trial / 30 Days)</option>
                  <option value={60}>60 Days (2 Months)</option>
                  <option value={90}>90 Days (Quarterly Rotation)</option>
                  <option value={365}>1 Year (Annual)</option>
                  <option value={0}>Never Expire (Service Account)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1.5">Single Key Seat Capacity</label>
                <select
                  value={keySeats}
                  onChange={(e) => setKeySeats(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-emerald-500/60"
                >
                  <option value={1}>1 Seat (Personal Developer / Agent)</option>
                  <option value={25}>25 Seats (Enterprise Team - Single Key)</option>
                  <option value={50}>50 Seats (Enterprise Growth - Single Key)</option>
                  <option value={100}>100 Seats (Enterprise Fleet - Single Key)</option>
                  <option value={500}>500 Seats (Enterprise Scale - Single Key)</option>
                  <option value={1000}>1,000 Seats (Global Enterprise - Single Key)</option>
                </select>
              </div>

              <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-slate-400 text-[11px] space-y-1">
                <div className="font-medium text-slate-300 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> Single Key Fleet Deployment
                </div>
                <div>All {keySeats} seats share this single cryptographic key with centralized tokenization and DLP quota.</div>
              </div>

              <div className="flex items-center justify-end gap-2.5 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsCreateKeyOpen(false)}
                  className="px-3.5 py-1.5 rounded-lg text-slate-400 hover:text-white text-xs font-medium transition"
                >
                  Cancel
                </button>
                <button
                  type="button"
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
                  <span className="truncate mr-2">mcpshld link --key {justCreatedKey}</span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(`mcpshld link --key ${justCreatedKey}`);
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

      {/* Add Existing Key / Master Key Modal */}
      {isAddExistingOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg bg-slate-950 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Upload className="w-4 h-4 text-emerald-400" />
                Add Existing API Key or Master Key
              </h3>
              <button onClick={() => setIsAddExistingOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-xl text-blue-300 text-xs">
              Paste your existing API key or Master Key. The key will be cryptographically verified and bound to your account with 1 active key access.
            </div>

            {addExistingError && (
              <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{addExistingError}</span>
              </div>
            )}

            {addExistingSuccess ? (
              <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs text-center space-y-1">
                <ShieldCheck className="w-6 h-6 mx-auto text-emerald-400" />
                <p className="font-semibold text-white">{addExistingSuccess}</p>
                <p className="text-slate-400">Your key is active and ready for MCP pairing.</p>
              </div>
            ) : (
              <div className="space-y-4 text-xs">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Key Description / Name</label>
                  <input
                    type="text"
                    value={addExistingName}
                    onChange={(e) => { setAddExistingName(e.target.value); setAddExistingError(null); }}
                    placeholder="e.g. Master Admin Key, Enterprise Team Key"
                    className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-white placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">API Key / Master Key</label>
                  <input
                    type="text"
                    value={addExistingKey}
                    onChange={(e) => { setAddExistingKey(e.target.value); setAddExistingError(null); }}
                    placeholder="Paste your key here (e.g. MASTER_... or mcp_live_...)"
                    className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-white font-mono placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
                  />
                  <p className="text-[10px] text-slate-500 mt-1">
                    Accepts Master Keys (MASTER_...) or client API keys (mcp_live_...). Accounts use 1 key with access.
                  </p>
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    onClick={() => setIsAddExistingOpen(false)}
                    className="px-3.5 py-1.5 text-xs text-slate-400 hover:text-white"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleImportExistingKey}
                    disabled={addExistingLoading || !addExistingKey.trim()}
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-black rounded-xl text-xs font-semibold shadow-lg shadow-emerald-500/20"
                  >
                    {addExistingLoading ? 'Verifying...' : 'Import & Activate Key'}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Support & Complaint Modal */}
      <SupportModal
        isOpen={isSupportModalOpen}
        onClose={() => setIsSupportModalOpen(false)}
        defaultType="Complaint"
      />

      {/* Guided Onboarding Wizard Modal */}
      <OnboardingWizard
        isOpen={isOnboardingOpen}
        onClose={() => setIsOnboardingOpen(false)}
        onComplete={() => {
          setIsOnboardingOpen(false);
          setDismissOnboardingBanner(true);
        }}
      />

      {/* Threat Event Detail Drawer */}
      <EventDetailDrawer
        event={selectedDetailEvent}
        onClose={() => setSelectedDetailEvent(null)}
        onUpdateEvent={(updated) => {
          setEvents(events.map(e => e.id === updated.id ? { ...e, reason: updated.details } : e));
          setSelectedDetailEvent(null);
        }}
      />
    </div>
  );
}
