'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { ShieldCheck, Terminal, Menu, X, ArrowUpRight } from 'lucide-react';

export default function LandingNavbar() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 border-b border-slate-800/80 bg-[#090a0f]/85 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand */}
        <Link href="/" className="flex items-center gap-3 group">
          <div className="h-9 w-9 rounded-xl bg-gradient-to-tr from-emerald-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-emerald-500/20 group-hover:scale-105 transition">
            <ShieldCheck className="w-5 h-5 text-black stroke-[2.5]" />
          </div>
          <div>
            <div className="font-bold text-lg leading-tight flex items-center gap-2 text-white">
              <span>MCP-SHIELD</span>
              <span className="text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded-full font-mono font-semibold tracking-wider">
                v2.4 LTS
              </span>
            </div>
            <div className="text-[11px] text-slate-400 hidden sm:block">Model Context Protocol Security</div>
          </div>
        </Link>

        {/* Desktop Navigation */}
        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-300">
          <a href="#features" className="hover:text-emerald-400 transition">Features</a>
          <a href="#architecture" className="hover:text-emerald-400 transition">Architecture</a>
          <a href="#simulator" className="hover:text-emerald-400 transition flex items-center gap-1">
            <span>Playground</span>
            <span className="text-[9px] bg-indigo-500/20 text-indigo-300 px-1.5 py-0.2 rounded border border-indigo-500/30">INTERACTIVE</span>
          </a>
          <a href="#install" className="hover:text-emerald-400 transition">Installation</a>
          <a href="#benchmarks" className="hover:text-emerald-400 transition">Benchmarks</a>
          <a href="#faq" className="hover:text-emerald-400 transition">FAQ</a>
        </nav>

        {/* Action CTAs */}
        <div className="hidden sm:flex items-center gap-3">
          <a
            href="https://github.com/rahulxcodex/mcp-shield"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-semibold text-slate-300 hover:text-white hover:border-slate-700 transition"
          >
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
            </svg>
            <span>GitHub</span>
          </a>

          <Link
            href="/console"
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 text-black font-semibold text-xs shadow-lg shadow-emerald-500/20 hover:opacity-95 transition"
          >
            <span>Launch Console</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {/* Mobile menu toggle */}
        <div className="md:hidden flex items-center gap-2">
          <Link
            href="/console"
            className="px-2.5 py-1 rounded-lg bg-emerald-500 text-black text-xs font-bold"
          >
            Console
          </Link>
          <button
            onClick={() => setMobileOpen(!mobileOpen)}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white"
            aria-label="Toggle Navigation Menu"
          >
            {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Mobile dropdown */}
      {mobileOpen && (
        <div className="md:hidden border-b border-slate-800 bg-[#0c0e17] px-4 py-4 space-y-3 text-sm">
          <a
            href="#features"
            onClick={() => setMobileOpen(false)}
            className="block py-1 text-slate-300 hover:text-emerald-400"
          >
            Features
          </a>
          <a
            href="#architecture"
            onClick={() => setMobileOpen(false)}
            className="block py-1 text-slate-300 hover:text-emerald-400"
          >
            Architecture
          </a>
          <a
            href="#simulator"
            onClick={() => setMobileOpen(false)}
            className="block py-1 text-slate-300 hover:text-emerald-400"
          >
            Interactive Playground
          </a>
          <a
            href="#install"
            onClick={() => setMobileOpen(false)}
            className="block py-1 text-slate-300 hover:text-emerald-400"
          >
            Installation Guides
          </a>
          <a
            href="#benchmarks"
            onClick={() => setMobileOpen(false)}
            className="block py-1 text-slate-300 hover:text-emerald-400"
          >
            Benchmarks
          </a>
          <a
            href="#faq"
            onClick={() => setMobileOpen(false)}
            className="block py-1 text-slate-300 hover:text-emerald-400"
          >
            FAQ
          </a>
          <div className="pt-2 border-t border-slate-800 flex gap-3">
            <Link
              href="/console"
              onClick={() => setMobileOpen(false)}
              className="flex-1 text-center py-2 rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 text-black font-semibold text-xs"
            >
              Launch Console
            </Link>
            <a
              href="https://github.com/rahulxcodex/mcp-shield"
              target="_blank"
              rel="noreferrer"
              className="flex items-center justify-center px-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-white"
            >
              GitHub
            </a>
          </div>
        </div>
      )}
    </header>
  );
}
