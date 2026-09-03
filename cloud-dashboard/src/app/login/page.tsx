'use client';

import React, { useState, Suspense } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { ShieldCheck, ArrowLeft, Mail, Sparkles, AlertCircle, CheckCircle2 } from 'lucide-react';
import GithubIcon from '@/components/GithubIcon';
import { createClient } from '@/utils/supabase/client';

const CONSUMER_EMAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.co.in',
  'hotmail.com', 'outlook.com', 'live.com', 'msn.com', 'icloud.com', 'me.com',
  'aol.com', 'proton.me', 'protonmail.com', 'zoho.com', 'mail.com', 'gmx.com',
  'yandex.com', 'fastmail.com', 'tutanota.com'
]);

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const nextPath = searchParams.get('next') || '/console';
  const initialMode = searchParams.get('mode') === 'signup' ? 'signup' : 'signin';

  const [viewMode, setViewMode] = useState<'signin' | 'signup'>(initialMode);
  const [authMode, setAuthMode] = useState<'enterprise' | 'developer'>('enterprise');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [companyName, setCompanyName] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [magicLinkSent, setMagicLinkSent] = useState(false);
  const [signupSuccess, setSignupSuccess] = useState(false);

  const getEmailDomain = (val: string): string | null => {
    const parts = val.trim().split('@');
    return parts.length === 2 && parts[1].includes('.') ? parts[1].toLowerCase() : null;
  };

  const domain = getEmailDomain(email);
  const isConsumerDomain = domain ? CONSUMER_EMAIL_DOMAINS.has(domain) : false;

  const handleGithubLogin = async () => {
    try {
      setLoading(true);
      setErrorMsg(null);
      const supabase = createClient();
      await supabase.auth.signInWithOAuth({
        provider: 'github',
        options: {
          redirectTo: `${window.location.origin}/auth/callback?next=${encodeURIComponent(nextPath)}`,
        },
      });
    } catch (err: any) {
      setErrorMsg(err.message || 'GitHub sign-in error');
      setLoading(false);
    }
  };

  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;

    if (authMode === 'enterprise') {
      if (!domain) {
        setErrorMsg('Please enter a complete corporate email address (e.g. name@company.com)');
        return;
      }
      if (isConsumerDomain) {
        setErrorMsg(`Enterprise ${viewMode === 'signup' ? 'registration' : 'login'} is strictly reserved for corporate @domain emails. Free email providers (@${domain}) are not permitted.`);
        return;
      }
    }

    try {
      setLoading(true);
      setErrorMsg(null);
      const supabase = createClient();

      if (viewMode === 'signup') {
        if (!password || password.length < 6) {
          setErrorMsg('Password must be at least 6 characters long.');
          setLoading(false);
          return;
        }

        const { error } = await supabase.auth.signUp({
          email,
          password,
          options: {
            data: {
              company: companyName || domain || 'Self',
              account_type: authMode
            },
            emailRedirectTo: `${window.location.origin}/auth/callback?next=${encodeURIComponent(nextPath)}`,
          }
        });

        if (error) throw error;
        setSignupSuccess(true);
      } else {
        // Sign In
        if (password) {
          const { error } = await supabase.auth.signInWithPassword({
            email,
            password,
          });
          if (error) throw error;
          router.push(nextPath);
        } else {
          const { error } = await supabase.auth.signInWithOtp({
            email,
            options: {
              emailRedirectTo: `${window.location.origin}/auth/callback?next=${encodeURIComponent(nextPath)}`,
            },
          });
          if (error) throw error;
          setMagicLinkSent(true);
        }
      }
    } catch (err: any) {
      setErrorMsg(err.message || (viewMode === 'signup' ? 'Sign up failed' : 'Authentication failed'));
    } finally {
      setLoading(false);
    }
  };

  const handleDemoAccess = () => {
    router.push('/console?demo=true');
  };

  return (
    <div className="bg-[#0f111a] border border-slate-800 rounded-2xl p-8 max-w-md w-full shadow-2xl space-y-5">
      {/* Brand Icon */}
      <div className="flex flex-col items-center text-center space-y-2">
        <div className="h-12 w-12 rounded-xl bg-gradient-to-tr from-emerald-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-emerald-500/20">
          <ShieldCheck className="w-7 h-7 text-black stroke-[2.5]" />
        </div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">
          {viewMode === 'signup' ? 'Create Your Account' : 'Sign in to MCP-Shield'}
        </h1>
        <p className="text-slate-400 text-xs">
          {viewMode === 'signup'
            ? 'Set up zero-trust security for your MCP servers and AI agents'
            : 'Access real-time telemetry, AST firewall filters, and cryptographic keys'}
        </p>
      </div>

      {/* Mode Switcher: Sign In vs Sign Up */}
      <div className="grid grid-cols-2 p-1 bg-slate-950 border border-slate-800 rounded-xl text-xs font-bold">
        <button
          type="button"
          onClick={() => { setViewMode('signin'); setErrorMsg(null); setSignupSuccess(false); setMagicLinkSent(false); }}
          className={`py-1.5 rounded-lg transition text-center cursor-pointer ${
            viewMode === 'signin' ? 'bg-slate-800 text-white shadow' : 'text-slate-400 hover:text-white'
          }`}
        >
          Sign In
        </button>
        <button
          type="button"
          onClick={() => { setViewMode('signup'); setErrorMsg(null); setSignupSuccess(false); setMagicLinkSent(false); }}
          className={`py-1.5 rounded-lg transition text-center cursor-pointer ${
            viewMode === 'signup' ? 'bg-emerald-500 text-black shadow shadow-emerald-500/20' : 'text-slate-400 hover:text-white'
          }`}
        >
          Sign Up (New Account)
        </button>
      </div>

      {/* Auth Mode Tabs: Enterprise vs Developer */}
      <div className="grid grid-cols-2 gap-1.5 p-1 bg-slate-900/90 border border-slate-800 rounded-xl">
        <button
          type="button"
          onClick={() => { setAuthMode('enterprise'); setErrorMsg(null); }}
          className={`py-2 px-3 rounded-lg text-xs font-bold transition flex items-center justify-center gap-1.5 cursor-pointer ${
            authMode === 'enterprise'
              ? 'bg-emerald-500 text-black shadow-md shadow-emerald-500/20'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Enterprise (@domain)</span>
        </button>
        <button
          type="button"
          onClick={() => { setAuthMode('developer'); setErrorMsg(null); }}
          className={`py-2 px-3 rounded-lg text-xs font-bold transition flex items-center justify-center gap-1.5 cursor-pointer ${
            authMode === 'developer'
              ? 'bg-slate-800 text-white shadow-md'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <GithubIcon className="w-3.5 h-3.5" />
          <span>Developer</span>
        </button>
      </div>

      {errorMsg && (
        <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {signupSuccess ? (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs text-center space-y-2">
          <CheckCircle2 className="w-6 h-6 mx-auto text-emerald-400" />
          <p className="font-semibold text-white">Account Created Successfully!</p>
          <p className="text-slate-400 text-[11px]">
            Please check your email (<strong className="text-white">{email}</strong>) for verification link to activate your access.
          </p>
          <button
            onClick={() => { setViewMode('signin'); setSignupSuccess(false); }}
            className="mt-2 text-xs text-emerald-400 hover:underline font-semibold"
          >
            Proceed to Sign In &rarr;
          </button>
        </div>
      ) : magicLinkSent ? (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs text-center space-y-2">
          <p className="font-semibold">Check your inbox!</p>
          <p className="text-slate-400 text-[11px]">
            We sent a secure sign-in link to <strong className="text-white">{email}</strong>.
          </p>
        </div>
      ) : (
        <>
          {authMode === 'enterprise' ? (
            /* Enterprise Form (@domain only) */
            <form onSubmit={handleAuthSubmit} className="space-y-3.5">
              <div>
                <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                  Corporate Work Email <span className="text-emerald-400">(@domain required)</span>
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => { setEmail(e.target.value); setErrorMsg(null); }}
                  placeholder="name@company.com"
                  required
                  className={`w-full bg-slate-900 border rounded-xl px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none transition ${
                    isConsumerDomain
                      ? 'border-rose-500 focus:border-rose-500'
                      : domain && !isConsumerDomain
                      ? 'border-emerald-500/80 focus:border-emerald-500'
                      : 'border-slate-800 focus:border-emerald-500'
                  }`}
                />
                {domain && !isConsumerDomain && (
                  <p className="text-[11px] text-emerald-400 mt-1 flex items-center gap-1 font-medium">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Recognized Corporate Domain: <strong>@{domain}</strong></span>
                  </p>
                )}
                {isConsumerDomain && (
                  <p className="text-[11px] text-rose-400 mt-1 flex items-center gap-1">
                    <AlertCircle className="w-3.5 h-3.5" />
                    <span>Free provider @{domain} is blocked. Use your corporate company domain.</span>
                  </p>
                )}
              </div>

              {viewMode === 'signup' && (
                <div>
                  <label className="block text-[11px] font-semibold text-slate-300 mb-1">Company / Organization Name</label>
                  <input
                    type="text"
                    value={companyName}
                    onChange={(e) => setCompanyName(e.target.value)}
                    placeholder="Acme Corp"
                    className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 transition"
                  />
                </div>
              )}

              <div>
                <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                  {viewMode === 'signup' ? 'Set Password (min. 6 characters)' : 'SSO Password (or leave empty for Magic Link)'}
                </label>
                <input
                  type="password"
                  value={password}
                  required={viewMode === 'signup'}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 transition"
                />
              </div>

              <button
                type="submit"
                disabled={loading || isConsumerDomain}
                className="w-full py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 text-black font-extrabold text-xs transition shadow-lg shadow-emerald-500/20 disabled:opacity-50 cursor-pointer"
              >
                {loading
                  ? 'Processing...'
                  : viewMode === 'signup'
                  ? 'Create Enterprise Account'
                  : password
                  ? 'Sign In with SSO'
                  : 'Send Enterprise Magic Link'}
              </button>
            </form>
          ) : (
            /* Developer Mode Form */
            <div className="space-y-3.5">
              <button
                onClick={handleGithubLogin}
                disabled={loading}
                className="w-full flex items-center justify-center gap-3 bg-slate-100 hover:bg-white text-slate-900 font-semibold py-2.5 rounded-xl text-xs transition shadow-lg disabled:opacity-50 cursor-pointer"
              >
                <GithubIcon className="w-4 h-4" />
                <span>{viewMode === 'signup' ? 'Sign Up with GitHub' : 'Continue with GitHub'}</span>
              </button>

              <div className="relative flex py-1 items-center">
                <div className="flex-grow border-t border-slate-800"></div>
                <span className="flex-shrink mx-4 text-[11px] text-slate-500 uppercase tracking-wider font-mono">
                  or email and password
                </span>
                <div className="flex-grow border-t border-slate-800"></div>
              </div>

              <form onSubmit={handleAuthSubmit} className="space-y-3">
                <div>
                  <label className="block text-[11px] font-medium text-slate-400 mb-1">Developer Email</label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="developer@example.com"
                    required
                    className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 transition"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-medium text-slate-400 mb-1">
                    {viewMode === 'signup' ? 'Password (min. 6 characters)' : 'Password (leave blank for magic link)'}
                  </label>
                  <input
                    type="password"
                    value={password}
                    required={viewMode === 'signup'}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 transition"
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-white font-semibold text-xs transition border border-slate-700 disabled:opacity-50 cursor-pointer"
                >
                  {loading
                    ? 'Processing...'
                    : viewMode === 'signup'
                    ? 'Create Developer Account'
                    : password
                    ? 'Sign In'
                    : 'Send Magic Link'}
                </button>
              </form>
            </div>
          )}
        </>
      )}

      {/* Switch mode links */}
      <div className="text-center text-xs text-slate-400">
        {viewMode === 'signin' ? (
          <p>
            Don't have an account?{' '}
            <button
              onClick={() => { setViewMode('signup'); setErrorMsg(null); }}
              className="text-emerald-400 hover:underline font-semibold cursor-pointer"
            >
              Sign up now
            </button>
          </p>
        ) : (
          <p>
            Already have an account?{' '}
            <button
              onClick={() => { setViewMode('signin'); setErrorMsg(null); }}
              className="text-emerald-400 hover:underline font-semibold cursor-pointer"
            >
              Sign in
            </button>
          </p>
        )}
      </div>

      {/* Demo Mode Button */}
      <div className="pt-2 border-t border-slate-800">
        <button
          onClick={handleDemoAccess}
          className="w-full py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 hover:border-emerald-500/40 text-slate-300 hover:text-white font-medium text-xs transition flex items-center justify-center gap-2 cursor-pointer"
        >
          <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
          <span>Instant Demo Mode (No Login Required)</span>
        </button>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-[#090a0f] text-slate-100 px-4 py-8 relative">
      <Link
        href="/"
        className="absolute top-6 left-6 text-xs text-slate-400 hover:text-white flex items-center gap-1.5 transition"
      >
        <ArrowLeft className="w-4 h-4" />
        <span>Back to Home</span>
      </Link>

      <Suspense fallback={<div className="text-xs text-slate-500 font-mono">Loading authentication...</div>}>
        <LoginForm />
      </Suspense>
    </div>
  );
}
