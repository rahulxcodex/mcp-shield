'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import {
  Shield,
  Key,
  Users,
  Activity,
  Trash2,
  ArrowLeft,
  BarChart3,
  Mail,
  Upload,
  Copy,
  Check,
  Plus,
  Send,
  FileText
} from 'lucide-react';

interface DistributedKey {
  id: string;
  name: string;
  prefix: string;
  maxActivations: number;
  used: number;
  remaining: number;
  status: 'ACTIVE' | 'EXHAUSTED' | 'REVOKED';
}

interface ActivationLog {
  id: string;
  keyUsed: string;
  keyPrefix: string;
  deviceHost: string;
  ipAddress: string;
  activatedAt: string;
}

const INITIAL_KEYS: DistributedKey[] = [
  {
    id: 'key-1',
    name: 'Production Team Key',
    prefix: 'mcp_live_a8f9c2d1',
    maxActivations: 50,
    used: 32,
    remaining: 18,
    status: 'ACTIVE',
  },
  {
    id: 'key-2',
    name: 'Contractor Access Key',
    prefix: 'mcp_live_73b9e4a0',
    maxActivations: 25,
    used: 25,
    remaining: 0,
    status: 'EXHAUSTED',
  },
  {
    id: 'key-3',
    name: 'QA Environment Key',
    prefix: 'mcp_live_d4e5f6a7',
    maxActivations: 25,
    used: 3,
    remaining: 22,
    status: 'ACTIVE',
  },
];

const INITIAL_LOGS: ActivationLog[] = [
  {
    id: 'act-1',
    keyUsed: 'Production Team Key',
    keyPrefix: 'mcp_live_a8f9c2d1',
    deviceHost: 'macbook-pro-m3.corp.internal',
    ipAddress: '192.168.1.104',
    activatedAt: '4 minutes ago',
  },
  {
    id: 'act-2',
    keyUsed: 'QA Environment Key',
    keyPrefix: 'mcp_live_d4e5f6a7',
    deviceHost: 'runner-linux-node-08',
    ipAddress: '10.240.0.32',
    activatedAt: '22 minutes ago',
  },
  {
    id: 'act-3',
    keyUsed: 'Production Team Key',
    keyPrefix: 'mcp_live_a8f9c2d1',
    deviceHost: 'antigravity-dev-vm',
    ipAddress: '35.201.88.19',
    activatedAt: '1 hour ago',
  },
  {
    id: 'act-4',
    keyUsed: 'Production Team Key',
    keyPrefix: 'mcp_live_a8f9c2d1',
    deviceHost: 'thinkpad-x1.remote.work',
    ipAddress: '104.28.192.44',
    activatedAt: '3 hours ago',
  },
  {
    id: 'act-5',
    keyUsed: 'Contractor Access Key',
    keyPrefix: 'mcp_live_73b9e4a0',
    deviceHost: 'cursor-ide-client-win',
    ipAddress: '172.56.21.90',
    activatedAt: 'Yesterday at 18:42',
  },
];

export default function EnterpriseAdminPage() {
  const [keys, setKeys] = useState<DistributedKey[]>(INITIAL_KEYS);
  const [revokedToast, setRevokedToast] = useState<string | null>(null);

  // Team key invitation state
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('Developer');
  const [selectedKeyForInvite, setSelectedKeyForInvite] = useState(INITIAL_KEYS[0]?.id || '');
  const [inviteSuccessMsg, setInviteSuccessMsg] = useState<string | null>(null);
  const [csvContent, setCsvContent] = useState('');
  const [isProcessingCsv, setIsProcessingCsv] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);

  const [invitations, setInvitations] = useState([
    { id: 'inv-1', email: 'sarah.connor@acme-corp.com', role: 'Developer', key: 'Production Team Key', status: 'CLAIMED', sentAt: 'Yesterday' },
    { id: 'inv-2', email: 'alex.chen@acme-corp.com', role: 'Security Engineer', key: 'Production Team Key', status: 'PENDING', sentAt: '3 hours ago' },
    { id: 'inv-3', email: 'dev-team-lead@acme-corp.com', role: 'Admin', key: 'Production Team Key', status: 'CLAIMED', sentAt: '2 days ago' },
  ]);

  const handleSendInvite = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteEmail.trim()) return;

    const targetKey = keys.find(k => k.id === selectedKeyForInvite) || keys[0];
    const newInv = {
      id: `inv-${Date.now()}`,
      email: inviteEmail.trim(),
      role: inviteRole,
      key: targetKey?.name || 'Production Team Key',
      status: 'PENDING',
      sentAt: 'Just now'
    };

    setInvitations([newInv, ...invitations]);
    setInviteSuccessMsg(`Invite link dispatched to ${inviteEmail.trim()}`);
    setInviteEmail('');
    setTimeout(() => setInviteSuccessMsg(null), 4000);
  };

  const handleCsvBulkInvite = () => {
    if (!csvContent.trim()) return;
    setIsProcessingCsv(true);

    const emails = csvContent
      .split(/[\n,;]+/)
      .map(e => e.trim())
      .filter(e => e.includes('@') && e.includes('.'));

    if (emails.length === 0) {
      setInviteSuccessMsg('No valid emails detected in CSV / input.');
      setIsProcessingCsv(false);
      return;
    }

    const targetKey = keys.find(k => k.id === selectedKeyForInvite) || keys[0];
    const newInvs = emails.map((em, idx) => ({
      id: `inv-${Date.now()}-${idx}`,
      email: em,
      role: 'Developer',
      key: targetKey?.name || 'Production Team Key',
      status: 'PENDING',
      sentAt: 'Just now'
    }));

    setInvitations([...newInvs, ...invitations]);
    setInviteSuccessMsg(`Successfully queued mass invitations for ${emails.length} team member(s).`);
    setCsvContent('');
    setIsProcessingCsv(false);
    setTimeout(() => setInviteSuccessMsg(null), 5000);
  };

  const copyJoinLink = () => {
    const link = `${window.location.origin}/login?invite=ent_join_${selectedKeyForInvite}&org=acme`;
    navigator.clipboard.writeText(link);
    setCopiedLink(true);
    setTimeout(() => setCopiedLink(false), 2000);
  };

  const handleRevokeKey = (id: string, name: string) => {
    setKeys((prev) =>
      prev.map((k) =>
        k.id === id ? { ...k, status: 'REVOKED' as const } : k
      )
    );
    setRevokedToast(`Key "${name}" has been revoked.`);
    setTimeout(() => setRevokedToast(null), 4000);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-8 font-sans">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Back link */}
        <div>
          <Link
            href="/console"
            className="inline-flex items-center gap-2 text-xs font-medium text-slate-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Console
          </Link>
        </div>

        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
          <div className="flex items-center gap-3.5">
            <div className="h-11 w-11 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shadow-lg shadow-emerald-500/10">
              <Shield className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-white flex items-center gap-2.5">
                <span>Enterprise Admin Panel</span>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  Enterprise
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Manage keys, activations, and team access
              </p>
            </div>
          </div>
        </div>

        {/* Revoked Toast Notification */}
        {revokedToast && (
          <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center justify-between">
            <span>{revokedToast}</span>
            <button
              onClick={() => setRevokedToast(null)}
              className="text-rose-400 hover:text-rose-200 font-bold ml-4"
            >
              &times;
            </button>
          </div>
        )}

        {/* Stats Row */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {/* Card 1: Total Keys Generated */}
          <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Total Keys Generated</span>
              <div className="h-8 w-8 rounded-xl bg-slate-800 flex items-center justify-center">
                <Key className="w-4 h-4 text-slate-300" />
              </div>
            </div>
            <div className="mt-3">
              <div className="text-2xl font-bold text-white tracking-tight">3</div>
              <p className="text-[11px] text-slate-500 mt-1">Active distributed credential sets</p>
            </div>
          </div>

          {/* Card 2: Total Activations */}
          <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Total Activations</span>
              <div className="h-8 w-8 rounded-xl bg-slate-800 flex items-center justify-center">
                <Activity className="w-4 h-4 text-emerald-400" />
              </div>
            </div>
            <div className="mt-3">
              <div className="flex items-baseline justify-between">
                <div className="text-2xl font-bold text-white tracking-tight">47 / 100</div>
                <span className="text-[11px] text-emerald-400 font-mono">47%</span>
              </div>
              <div className="mt-2 bg-slate-800 rounded-full h-2 overflow-hidden">
                <div
                  className="bg-emerald-500 rounded-full h-2 transition-all duration-500"
                  style={{ width: '47%' }}
                />
              </div>
            </div>
          </div>

          {/* Card 3: Active Team Members */}
          <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Active Team Members</span>
              <div className="h-8 w-8 rounded-xl bg-slate-800 flex items-center justify-center">
                <Users className="w-4 h-4 text-cyan-400" />
              </div>
            </div>
            <div className="mt-3">
              <div className="text-2xl font-bold text-white tracking-tight">12</div>
              <p className="text-[11px] text-slate-500 mt-1">Enterprise seats provisioned</p>
            </div>
          </div>
        </div>

        {/* Distributed Keys Table */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-slate-400" />
              <h2 className="text-sm font-semibold text-white">Distributed Keys</h2>
            </div>
            <span className="text-[11px] text-slate-500">
              {keys.length} enterprise key pool{keys.length === 1 ? '' : 's'}
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-wider font-semibold">
                <tr>
                  <th className="py-3 px-3.5">Key Name</th>
                  <th className="py-3 px-3.5">Prefix</th>
                  <th className="py-3 px-3.5 text-right">Max Activations</th>
                  <th className="py-3 px-3.5 text-right">Used</th>
                  <th className="py-3 px-3.5 text-right">Remaining</th>
                  <th className="py-3 px-3.5 text-center">Status</th>
                  <th className="py-3 px-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {keys.map((k) => {
                  const isRevoked = k.status === 'REVOKED';
                  const isExhausted = k.status === 'EXHAUSTED';

                  return (
                    <tr
                      key={k.id}
                      className="hover:bg-slate-800/40 transition-colors"
                    >
                      <td className="py-3 px-3.5 font-medium text-slate-200">
                        {k.name}
                      </td>
                      <td className="py-3 px-3.5 font-mono text-[11px] text-slate-400">
                        {k.prefix}
                      </td>
                      <td className="py-3 px-3.5 text-right font-mono text-slate-300">
                        {k.maxActivations}
                      </td>
                      <td className="py-3 px-3.5 text-right font-mono text-slate-300">
                        {k.used}
                      </td>
                      <td className="py-3 px-3.5 text-right font-mono text-slate-300">
                        {k.remaining}
                      </td>
                      <td className="py-3 px-3.5 text-center">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold border ${
                            isRevoked
                              ? 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                              : isExhausted
                              ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                              : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                          }`}
                        >
                          {k.status}
                        </span>
                      </td>
                      <td className="py-3 px-3.5 text-right">
                        <button
                          onClick={() => handleRevokeKey(k.id, k.name)}
                          disabled={isRevoked}
                          title={isRevoked ? 'Key is already revoked' : 'Revoke Key'}
                          className={`inline-flex items-center justify-center p-1.5 rounded-lg transition-colors ${
                            isRevoked
                              ? 'text-slate-600 cursor-not-allowed'
                              : 'text-rose-400 hover:text-rose-300 hover:bg-rose-500/10'
                          }`}
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent Activations Log */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-slate-400" />
              <h2 className="text-sm font-semibold text-white">Recent Activations Log</h2>
            </div>
            <span className="text-[11px] text-slate-500">Last 5 activations</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-wider font-semibold">
                <tr>
                  <th className="py-3 px-3.5">Key Used</th>
                  <th className="py-3 px-3.5">Device / Host</th>
                  <th className="py-3 px-3.5 font-mono">IP Address</th>
                  <th className="py-3 px-3.5 text-right">Activated At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {INITIAL_LOGS.map((log) => (
                  <tr
                    key={log.id}
                    className="hover:bg-slate-800/40 transition-colors"
                  >
                    <td className="py-3 px-3.5">
                      <div className="font-medium text-slate-200">{log.keyUsed}</div>
                      <div className="font-mono text-[10px] text-slate-500 mt-0.5">
                        {log.keyPrefix}
                      </div>
                    </td>
                    <td className="py-3 px-3.5 font-mono text-slate-300">
                      {log.deviceHost}
                    </td>
                    <td className="py-3 px-3.5 font-mono text-slate-400">
                      {log.ipAddress}
                    </td>
                    <td className="py-3 px-3.5 text-right text-slate-400">
                      {log.activatedAt}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Team Key Invitation & Mass CSV Distribution */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-5 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <div className="flex items-center gap-2">
                <Mail className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-semibold text-white">Distribute Keys & Invite Team Members</h2>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Invite team members via email or upload a CSV. They receive a secure join link to claim and activate their individual key.
              </p>
            </div>
            <button
              onClick={copyJoinLink}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-medium transition"
            >
              {copiedLink ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedLink ? 'Copied Join Link!' : 'Copy Organization Join Link'}</span>
            </button>
          </div>

          {inviteSuccessMsg && (
            <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs flex items-center justify-between">
              <span>{inviteSuccessMsg}</span>
              <button onClick={() => setInviteSuccessMsg(null)} className="font-bold ml-2">&times;</button>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {/* Single / Direct Email Invite */}
            <form onSubmit={handleSendInvite} className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-3">
              <span className="text-xs font-semibold text-white flex items-center gap-2">
                <Send className="w-3.5 h-3.5 text-emerald-400" />
                Send Individual Invitation
              </span>

              <div>
                <label className="block text-[11px] text-slate-400 mb-1">Team Member Email</label>
                <input
                  type="email"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  placeholder="colleague@acme-corp.com"
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Key Quota Pool</label>
                  <select
                    value={selectedKeyForInvite}
                    onChange={(e) => setSelectedKeyForInvite(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-xl px-2.5 py-2 text-xs text-white focus:outline-none focus:border-emerald-500"
                  >
                    {keys.map((k) => (
                      <option key={k.id} value={k.id}>
                        {k.name} ({k.remaining} left)
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Role Permission</label>
                  <select
                    value={inviteRole}
                    onChange={(e) => setInviteRole(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-xl px-2.5 py-2 text-xs text-white focus:outline-none focus:border-emerald-500"
                  >
                    <option value="Developer">Developer (Standard Key)</option>
                    <option value="Security Engineer">Security Engineer</option>
                    <option value="Admin">Team Admin</option>
                  </select>
                </div>
              </div>

              <button
                type="submit"
                disabled={!inviteEmail.trim()}
                className="w-full py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-black font-bold text-xs rounded-xl transition shadow-lg shadow-emerald-600/20 flex items-center justify-center gap-1.5"
              >
                <Plus className="w-3.5 h-3.5" />
                Dispatch Email Invite
              </button>
            </form>

            {/* Mass CSV Upload & Bulk Invite */}
            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-3">
              <span className="text-xs font-semibold text-white flex items-center gap-2">
                <Upload className="w-3.5 h-3.5 text-cyan-400" />
                Mass Email Invite (CSV / Paste)
              </span>

              <div>
                <label className="block text-[11px] text-slate-400 mb-1">
                  Paste emails or CSV rows (comma or newline separated)
                </label>
                <textarea
                  rows={3}
                  value={csvContent}
                  onChange={(e) => setCsvContent(e.target.value)}
                  placeholder="alice@corp.com, bob@corp.com&#10;carol@corp.com"
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl p-2.5 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex items-center justify-between pt-1">
                <label className="text-[11px] text-slate-400 flex items-center gap-1.5 cursor-pointer hover:text-white">
                  <FileText className="w-3.5 h-3.5 text-slate-500" />
                  <span>Choose CSV file</span>
                  <input
                    type="file"
                    accept=".csv,.txt"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) {
                        const reader = new FileReader();
                        reader.onload = (evt) => setCsvContent(String(evt.target?.result || ''));
                        reader.readAsText(file);
                      }
                    }}
                  />
                </label>

                <button
                  onClick={handleCsvBulkInvite}
                  disabled={!csvContent.trim() || isProcessingCsv}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-black font-bold text-xs rounded-xl transition shadow-lg shadow-cyan-600/20"
                >
                  {isProcessingCsv ? 'Sending...' : 'Process Mass Invites'}
                </button>
              </div>
            </div>
          </div>

          {/* Invitation Ledger */}
          <div className="pt-2">
            <span className="text-xs font-semibold text-slate-300 block mb-2">Active Team Key Invitations</span>
            <div className="overflow-x-auto border border-slate-800 rounded-xl">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 text-[10px] uppercase font-semibold">
                  <tr>
                    <th className="py-2.5 px-3">Invitee</th>
                    <th className="py-2.5 px-3">Assigned Role</th>
                    <th className="py-2.5 px-3">Key Pool</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3 text-right">Dispatched</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {invitations.map((inv) => (
                    <tr key={inv.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-2.5 px-3 font-mono text-slate-200">{inv.email}</td>
                      <td className="py-2.5 px-3">{inv.role}</td>
                      <td className="py-2.5 px-3 text-slate-400">{inv.key}</td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase ${
                          inv.status === 'CLAIMED'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                        }`}>
                          {inv.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right text-slate-500 text-[11px]">{inv.sentAt}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
