'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { Cookie, Shield, X } from 'lucide-react';

export type CookieConsentChoice = 'all' | 'essential' | null;

export const COOKIE_CONSENT_KEY = 'mcp_shield_cookie_consent';

export function getCookieConsent(): CookieConsentChoice {
  if (typeof window === 'undefined') return null;
  try {
    const val = localStorage.getItem(COOKIE_CONSENT_KEY);
    return val === 'all' || val === 'essential' ? val : null;
  } catch {
    return null;
  }
}

export default function CookieConsent() {
  const [consent, setConsent] = useState<CookieConsentChoice>('all'); // default to non-rendering state until mounted
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const stored = getCookieConsent();
    if (!stored) {
      setIsVisible(true);
    }
  }, []);

  const saveChoice = (choice: 'all' | 'essential') => {
    try {
      localStorage.setItem(COOKIE_CONSENT_KEY, choice);
      window.dispatchEvent(
        new CustomEvent('mcp_shield_consent_changed', { detail: { choice } })
      );
    } catch {
      // ignore local storage restrictions
    }
    setConsent(choice);
    setIsVisible(false);
  };

  if (!isVisible) return null;

  return (
    <aside
      aria-label="Cookie and telemetry preferences"
      role="dialog"
      aria-modal="false"
      className="fixed bottom-4 right-4 left-4 sm:left-auto sm:max-w-md z-50 bg-[#0d0f17]/95 backdrop-blur-md border border-slate-800 rounded-2xl p-5 shadow-2xl text-xs text-slate-300 animate-in fade-in slide-in-from-bottom-4 duration-300"
    >
      <div className="flex items-start gap-3">
        <div className="h-9 w-9 rounded-xl bg-emerald-500/15 text-emerald-400 flex items-center justify-center shrink-0">
          <Cookie className="w-5 h-5" />
        </div>
        <div className="flex-1 space-y-1.5">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold text-white text-sm flex items-center gap-1.5">
              <span>Privacy &amp; Cookie Preferences</span>
            </h2>
            <button
              onClick={() => saveChoice('essential')}
              aria-label="Close and reject non-essential cookies"
              className="text-slate-400 hover:text-white transition p-1"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <p className="text-slate-400 text-[11px] leading-relaxed">
            MCP Shield uses zero-payload telemetry and essential cookies to secure your sessions. We never track raw prompts or sensitive execution arguments. Read our{' '}
            <Link href="/privacy" className="text-emerald-400 hover:underline">
              Privacy Policy
            </Link>.
          </p>
        </div>
      </div>

      <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-end gap-2.5">
        <button
          type="button"
          onClick={() => saveChoice('essential')}
          className="px-3.5 py-1.5 rounded-xl border border-slate-700 hover:border-slate-600 text-slate-300 hover:text-white font-medium text-xs transition cursor-pointer"
        >
          Reject Non-Essential
        </button>
        <button
          type="button"
          onClick={() => saveChoice('all')}
          className="px-4 py-1.5 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs transition shadow-sm cursor-pointer"
        >
          Accept All
        </button>
      </div>
    </aside>
  );
}
