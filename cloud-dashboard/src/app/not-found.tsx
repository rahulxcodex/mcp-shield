import React from 'react';
import Link from 'next/link';
import { ShieldAlert, Home, Terminal, BookOpen, ArrowLeft } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-[#090a0f] text-slate-100 px-6 py-12">
      <div className="max-w-md w-full text-center space-y-6">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 mx-auto">
          <ShieldAlert className="w-8 h-8" />
        </div>

        <div className="space-y-2">
          <div className="inline-block px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-[11px] font-mono text-emerald-400">
            ERROR 404: RESOURCE_NOT_FOUND
          </div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight">
            Page Not Found
          </h1>
          <p className="text-sm text-slate-400 leading-relaxed">
            The security boundary could not locate the requested route or resource. It may have been moved, decommissioned, or never existed.
          </p>
        </div>

        <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-3">
          <Link
            href="/"
            className="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs transition flex items-center justify-center gap-2 shadow-sm"
          >
            <Home className="w-4 h-4" />
            <span>Return to Home</span>
          </Link>
          <Link
            href="/console"
            className="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-200 font-medium text-xs transition flex items-center justify-center gap-2"
          >
            <Terminal className="w-4 h-4 text-emerald-400" />
            <span>Launch Console</span>
          </Link>
          <Link
            href="/guide"
            className="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-200 font-medium text-xs transition flex items-center justify-center gap-2"
          >
            <BookOpen className="w-4 h-4 text-slate-400" />
            <span>Guide</span>
          </Link>
        </div>

        <div className="border-t border-slate-800/80 pt-6 text-xs text-slate-500">
          Need technical assistance? Submit a ticket via{' '}
          <Link href="/privacy" className="text-emerald-400 hover:underline">
            Support &amp; Privacy
          </Link>.
        </div>
      </div>
    </div>
  );
}
