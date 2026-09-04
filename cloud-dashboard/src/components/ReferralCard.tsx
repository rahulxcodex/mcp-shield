'use client';

import React, { useState, useEffect } from 'react';
import { Gift, Copy, Check, Users, Sparkles, AlertCircle } from 'lucide-react';

export default function ReferralCard() {
  const [referralData, setReferralData] = useState<{
    referralCode: string;
    referralUrl: string;
    totalReferred: number;
    freeMonthsGranted: number;
  } | null>(null);

  const [copied, setCopied] = useState(false);
  const [redeemInput, setRedeemInput] = useState('');
  const [redeemLoading, setRedeemLoading] = useState(false);
  const [redeemStatus, setRedeemStatus] = useState<{ success?: string; error?: string } | null>(null);

  useEffect(() => {
    async function loadReferral() {
      try {
        const res = await fetch('/api/v1/referrals');
        if (res.ok) {
          const data = await res.json();
          setReferralData(data);
        }
      } catch {}
    }
    loadReferral();
  }, []);

  const handleCopy = () => {
    if (!referralData?.referralUrl) return;
    navigator.clipboard.writeText(referralData.referralUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleRedeem = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!redeemInput.trim()) return;
    setRedeemLoading(true);
    setRedeemStatus(null);
    try {
      const res = await fetch('/api/v1/referrals', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ referralCode: redeemInput.trim() })
      });
      const data = await res.json();
      if (res.ok) {
        setRedeemStatus({ success: data.message || '1 Month Free Access Activated!' });
        setRedeemInput('');
      } else {
        setRedeemStatus({ error: data.error || 'Failed to redeem referral code.' });
      }
    } catch {
      setRedeemStatus({ error: 'Network error connecting to referral service.' });
    } finally {
      setRedeemLoading(false);
    }
  };

  return (
    <div className="bg-gradient-to-br from-indigo-950/40 via-slate-900/60 to-slate-950/80 border border-indigo-500/20 rounded-2xl p-5 relative overflow-hidden">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1.5 max-w-xl">
          <div className="flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
              <Gift className="w-4 h-4" />
            </span>
            <span className="text-xs font-semibold text-indigo-400 uppercase tracking-wider">Referral Program</span>
            <span className="px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-[10px] font-medium text-emerald-400 flex items-center gap-1">
              <Sparkles className="w-3 h-3" /> 1 Month Free Access
            </span>
          </div>
          <h3 className="text-sm font-semibold text-white">Refer Friends & Colleagues</h3>
          <p className="text-xs text-slate-400">
            Share your personal referral link. Anyone who signs up using your link receives{' '}
            <strong className="text-slate-200">1 Month of Free MCP Access</strong> with 1 dedicated key and zero-trust AST protection.
          </p>
        </div>

        {referralData && (
          <div className="flex items-center gap-3 self-start md:self-auto bg-slate-900/80 border border-slate-800 rounded-xl p-2.5 px-4 text-center">
            <div>
              <div className="text-lg font-bold text-white">{referralData.totalReferred}</div>
              <div className="text-[10px] text-slate-500 uppercase tracking-wider">Referred</div>
            </div>
            <div className="h-7 w-px bg-slate-800" />
            <div>
              <div className="text-lg font-bold text-emerald-400">{referralData.freeMonthsGranted}</div>
              <div className="text-[10px] text-slate-500 uppercase tracking-wider">Months Free</div>
            </div>
          </div>
        )}
      </div>

      <div className="mt-4 pt-4 border-t border-slate-800/80 grid grid-cols-1 md:grid-cols-2 gap-3 items-center">
        <div className="flex items-center gap-2">
          <div className="flex-1 bg-slate-950/80 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-slate-300 truncate">
            {referralData?.referralUrl || 'Loading referral link...'}
          </div>
          <button
            type="button"
            onClick={handleCopy}
            disabled={!referralData?.referralUrl}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-medium shadow-sm transition"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-300" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied!' : 'Copy Link'}</span>
          </button>
        </div>

        <form onSubmit={handleRedeem} className="flex items-center gap-2">
          <input
            type="text"
            value={redeemInput}
            onChange={(e) => setRedeemInput(e.target.value)}
            placeholder="Have a referral code? e.g. SHIELD-ABC123"
            className="flex-1 bg-slate-950/80 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-indigo-500 uppercase font-mono"
          />
          <button
            type="submit"
            disabled={redeemLoading || !redeemInput.trim()}
            className="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-xs font-medium border border-slate-700 transition shrink-0"
          >
            {redeemLoading ? 'Redeeming...' : 'Apply Code'}
          </button>
        </form>
      </div>

      {redeemStatus?.success && (
        <div className="mt-3 p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
          <Check className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{redeemStatus.success}</span>
        </div>
      )}

      {redeemStatus?.error && (
        <div className="mt-3 p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{redeemStatus.error}</span>
        </div>
      )}
    </div>
  );
}
