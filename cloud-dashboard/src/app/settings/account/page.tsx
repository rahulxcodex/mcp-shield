"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import {
  User,
  Shield,
  Key,
  Lock,
  CheckCircle2,
  AlertCircle,
  Activity,
  Sparkles,
  ChevronRight
} from "lucide-react";
import GithubIcon from "@/components/GithubIcon";
import { createClient } from "@/utils/supabase/client";

export default function AccountSettingsPage() {
  const [user, setUser] = useState<any>(null);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passMsg, setPassMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [updatingPass, setUpdatingPass] = useState(false);
  const [keysCount, setKeysCount] = useState<number>(1);

  useEffect(() => {
    async function loadUser() {
      try {
        const supabase = createClient();
        const { data: { user: currentUser } } = await supabase.auth.getUser();
        setUser(currentUser);

        // Fetch user's keys count
        const res = await fetch('/api/v1/keys');
        const data = await res.json();
        if (data?.keys) {
          setKeysCount(data.keys.length);
        }
      } catch (err) {
        console.warn('User load error:', err);
      }
    }
    loadUser();
  }, []);

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword.length < 6) {
      setPassMsg({ type: 'error', text: 'Password must be at least 6 characters long.' });
      return;
    }
    if (newPassword !== confirmPassword) {
      setPassMsg({ type: 'error', text: 'Passwords do not match.' });
      return;
    }

    try {
      setUpdatingPass(true);
      setPassMsg(null);
      const supabase = createClient();
      const { error } = await supabase.auth.updateUser({ password: newPassword });
      if (error) throw error;
      setPassMsg({ type: 'success', text: 'Password updated successfully!' });
      setNewPassword("");
      setConfirmPassword("");
    } catch (err: any) {
      setPassMsg({ type: 'error', text: err.message || 'Failed to update password.' });
    } finally {
      setUpdatingPass(false);
    }
  };

  const email = user?.email || 'rahulsahygupta24@gmail.com';
  const metadata = user?.user_metadata || {};
  const githubUser = metadata.user_name || 'rahulxcodex';
  const fullName = metadata.full_name || 'Rahul Gupta';
  const accountType = metadata.account_type || (email.includes('rahulsahygupta24') ? 'Master Admin' : 'Enterprise User');
  const isMaster = metadata.is_master || email.includes('rahulsahygupta24') || githubUser === 'rahulxcodex';

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white mb-1 flex items-center gap-2">
          <User className="w-6 h-6 text-emerald-400" />
          Individual Account
        </h1>
        <p className="text-xs text-slate-400">
          Manage your personal profile, authentication credentials, active tier quota, and security bindings.
        </p>
      </div>

      {/* Profile Overview Card */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800/80">
          <div className="flex items-center gap-4">
            <div className="h-14 w-14 rounded-2xl bg-gradient-to-tr from-emerald-500 to-cyan-500 flex items-center justify-center text-black font-extrabold text-xl shadow-lg shadow-emerald-500/20">
              {fullName ? fullName[0]?.toUpperCase() : email[0]?.toUpperCase()}
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h2 className="text-base font-bold text-white">{fullName}</h2>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold ${
                  isMaster
                    ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                    : accountType.toLowerCase().includes('enterprise')
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                }`}>
                  {isMaster ? 'Master Administrator' : accountType}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">{email}</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Link
              href="/settings/general"
              className="px-3.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 transition"
            >
              Manage Keys
            </Link>
            {isMaster && (
              <Link
                href="/console/system-admin"
                className="px-3.5 py-1.5 rounded-xl bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-xs font-semibold text-rose-300 transition"
              >
                System Admin
              </Link>
            )}
          </div>
        </div>

        {/* Identity & Linked Accounts */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">
          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-2">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
              Connected GitHub
            </span>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <GithubIcon className="w-4 h-4 text-slate-300" />
                <span className="text-xs font-mono text-white">@{githubUser}</span>
              </div>
              <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-medium">
                Verified OAuth
              </span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-2">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
              Active Security Plan
            </span>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <Shield className="w-4 h-4 text-emerald-400" />
                <span className="text-xs font-semibold text-white">
                  {isMaster ? 'Unlimited Master Access' : 'Enterprise Multi-Seat'}
                </span>
              </div>
              <Link
                href="/settings/billing"
                className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 font-medium"
              >
                View Quota <ChevronRight className="w-3 h-3" />
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* Individual Usage & Quota Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>Linked API Keys</span>
            <Key className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white">{keysCount}</div>
          <p className="text-[11px] text-slate-500 mt-1">Bound to your individual identity</p>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>Threats Filtered (24h)</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-white">1,429</div>
          <p className="text-[11px] text-slate-500 mt-1">Zero malicious payloads leaked</p>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>AST Latency Fastpath</span>
            <Sparkles className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-white">0.38 ms</div>
          <p className="text-[11px] text-slate-500 mt-1">SIMD eBPF pre-filter active</p>
        </div>
      </div>

      {/* Password Management */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2.5 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white">Change Account Password</h2>
            <p className="text-xs text-slate-400">Update your primary console authentication secret.</p>
          </div>
        </div>

        {passMsg && (
          <div className={`p-3 rounded-xl mb-4 text-xs flex items-center gap-2 ${
            passMsg.type === 'success'
              ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border border-rose-500/30 text-rose-300'
          }`}>
            {passMsg.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
            ) : (
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            )}
            <span>{passMsg.text}</span>
          </div>
        )}

        <form onSubmit={handlePasswordChange} className="space-y-4 max-w-md">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="••••••••"
              required
              minLength={6}
              className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Confirm New Password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="••••••••"
              required
              minLength={6}
              className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <button
            type="submit"
            disabled={updatingPass}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-black font-bold text-xs rounded-xl transition shadow-lg shadow-emerald-600/20"
          >
            {updatingPass ? 'Updating...' : 'Update Password'}
          </button>
        </form>
      </div>
    </div>
  );
}
