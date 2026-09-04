'use client';

import React, { useState, useRef, useEffect } from 'react';
import Link from 'next/link';
import { 
  ShieldCheck, 
  Menu, 
  X, 
  ArrowUpRight, 
  ChevronDown, 
  BookOpen, 
  Terminal, 
  BarChart3, 
  HelpCircle, 
  MessageSquare 
} from 'lucide-react';
import ThemeToggle from '@/components/ThemeToggle';
import SupportModal from '@/components/SupportModal';

export default function LandingNavbar() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [supportOpen, setSupportOpen] = useState(false);
  const [resourcesOpen, setResourcesOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setResourcesOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <header className="sticky top-0 z-50 border-b border-slate-800/80 bg-[#090a0f]/85 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        {/* Brand */}
        <Link href="/" className="flex items-center gap-3 group shrink-0">
          <div className="h-9 w-9 rounded-xl bg-gradient-to-tr from-emerald-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-emerald-500/20 group-hover:scale-105 transition shrink-0">
            <ShieldCheck className="w-5 h-5 text-black stroke-[2.5]" />
          </div>
          <div className="shrink-0">
            <div className="font-bold text-base sm:text-lg leading-tight flex items-center gap-2 text-white whitespace-nowrap">
              <span>MCP-SHIELD</span>
              <span className="text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded-full font-mono font-semibold tracking-wider whitespace-nowrap inline-flex items-center">
                v2.4 LTS
              </span>
            </div>
            <div className="text-[11px] text-slate-400 hidden sm:block whitespace-nowrap">Model Context Protocol Security</div>
          </div>
        </Link>

        {/* Desktop Navigation */}
        <nav className="hidden md:flex items-center gap-1.5 lg:gap-3 text-xs lg:text-sm font-medium text-slate-300 whitespace-nowrap">
          <a 
            href="#features" 
            className="px-3 py-1.5 rounded-lg hover:text-white hover:bg-slate-800/50 transition"
          >
            Features
          </a>
          <a 
            href="#architecture" 
            className="px-3 py-1.5 rounded-lg hover:text-white hover:bg-slate-800/50 transition"
          >
            Architecture
          </a>
          <a 
            href="#simulator" 
            className="px-3 py-1.5 rounded-lg hover:text-white hover:bg-slate-800/50 transition flex items-center gap-1.5"
          >
            <span>Playground</span>
            <span className="text-[9px] bg-indigo-500/20 text-indigo-300 px-1.5 py-0.5 rounded-full border border-indigo-500/30 font-semibold tracking-wider">
              INTERACTIVE
            </span>
          </a>

          {/* Resources & Docs Dropdown */}
          <div className="relative" ref={dropdownRef}>
            <button
              onClick={() => setResourcesOpen(!resourcesOpen)}
              className={`flex items-center gap-1 px-3 py-1.5 rounded-lg transition ${
                resourcesOpen 
                  ? 'text-white bg-slate-800/80' 
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/50'
              }`}
              aria-expanded={resourcesOpen}
            >
              <span>Resources</span>
              <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-200 ${resourcesOpen ? 'rotate-180 text-emerald-400' : 'text-slate-400'}`} />
            </button>

            {resourcesOpen && (
              <div className="absolute left-0 mt-2 w-72 rounded-xl bg-[#0e111a]/95 border border-slate-800 shadow-2xl backdrop-blur-xl p-2.5 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
                <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 px-2.5 py-1 font-semibold">
                  Documentation & Verification
                </div>

                <Link
                  href="/guide"
                  onClick={() => setResourcesOpen(false)}
                  className="flex items-start gap-2.5 p-2 rounded-lg hover:bg-slate-800/70 transition group"
                >
                  <div className="p-1.5 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 group-hover:bg-emerald-500/20 transition mt-0.5">
                    <BookOpen className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-slate-200 group-hover:text-emerald-300 transition flex items-center gap-1.5">
                      User Guide
                      <span className="text-[9px] bg-emerald-500/10 text-emerald-400 px-1 py-0.2 rounded font-mono font-normal">v2.4</span>
                    </div>
                    <div className="text-[11px] text-slate-400 leading-snug">Comprehensive manual & security specifications</div>
                  </div>
                </Link>

                <a
                  href="#install"
                  onClick={() => setResourcesOpen(false)}
                  className="flex items-start gap-2.5 p-2 rounded-lg hover:bg-slate-800/70 transition group"
                >
                  <div className="p-1.5 rounded-md bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 group-hover:bg-cyan-500/20 transition mt-0.5">
                    <Terminal className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition">Installation</div>
                    <div className="text-[11px] text-slate-400 leading-snug">Quickstart CLI, Docker & agent setup</div>
                  </div>
                </a>

                <a
                  href="#benchmarks"
                  onClick={() => setResourcesOpen(false)}
                  className="flex items-start gap-2.5 p-2 rounded-lg hover:bg-slate-800/70 transition group"
                >
                  <div className="p-1.5 rounded-md bg-purple-500/10 text-purple-400 border border-purple-500/20 group-hover:bg-purple-500/20 transition mt-0.5">
                    <BarChart3 className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-slate-200 group-hover:text-purple-300 transition">Benchmarks</div>
                    <div className="text-[11px] text-slate-400 leading-snug">P50/P99 latency & mutation test suite</div>
                  </div>
                </a>

                <a
                  href="#faq"
                  onClick={() => setResourcesOpen(false)}
                  className="flex items-start gap-2.5 p-2 rounded-lg hover:bg-slate-800/70 transition group"
                >
                  <div className="p-1.5 rounded-md bg-amber-500/10 text-amber-400 border border-amber-500/20 group-hover:bg-amber-500/20 transition mt-0.5">
                    <HelpCircle className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-slate-200 group-hover:text-amber-300 transition">FAQ</div>
                    <div className="text-[11px] text-slate-400 leading-snug">Zero-trust architecture & threat model FAQs</div>
                  </div>
                </a>

                <div className="my-1.5 border-t border-slate-800/80" />

                <button
                  onClick={() => {
                    setResourcesOpen(false);
                    setSupportOpen(true);
                  }}
                  className="w-full flex items-start gap-2.5 p-2 rounded-lg hover:bg-slate-800/70 transition group text-left cursor-pointer"
                >
                  <div className="p-1.5 rounded-md bg-rose-500/10 text-rose-400 border border-rose-500/20 group-hover:bg-rose-500/20 transition mt-0.5">
                    <MessageSquare className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-slate-200 group-hover:text-rose-300 transition">Complaints & Support</div>
                    <div className="text-[11px] text-slate-400 leading-snug">Direct priority resolution & dispute desk</div>
                  </div>
                </button>
              </div>
            )}
          </div>
        </nav>

        {/* Action CTAs */}
        <div className="hidden md:flex items-center gap-2 lg:gap-3 shrink-0">
          <a
            href="https://github.com/rahulxcodex/mcp-shield"
            target="_blank"
            rel="noreferrer"
            aria-label="GitHub Repository"
            title="GitHub Repository"
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white hover:border-slate-700 transition shrink-0"
          >
            <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
            </svg>
          </a>

          <ThemeToggle />

          <Link
            href="/login"
            className="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-800/50 transition shrink-0"
          >
            Sign In
          </Link>

          <Link
            href="/console"
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 text-black font-semibold text-xs shadow-lg shadow-emerald-500/20 hover:opacity-95 transition shrink-0 whitespace-nowrap"
          >
            <span>Launch Console</span>
            <ArrowUpRight className="w-3.5 h-3.5 shrink-0" />
          </Link>
        </div>

        {/* Mobile menu toggle */}
        <div className="md:hidden flex items-center gap-2">
          <ThemeToggle />
          <Link
            href="/console"
            className="px-2.5 py-1 rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 text-black text-xs font-bold shrink-0"
          >
            Console
          </Link>
          <button
            onClick={() => setMobileOpen(!mobileOpen)}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white shrink-0"
            aria-label="Toggle Navigation Menu"
          >
            {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Mobile dropdown */}
      {mobileOpen && (
        <div className="md:hidden border-b border-slate-800 bg-[#0c0e17] px-4 py-4 space-y-3 text-sm">
          <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold px-1">Navigation</div>
          <div className="grid grid-cols-2 gap-2">
            <a
              href="#features"
              onClick={() => setMobileOpen(false)}
              className="p-2 rounded-lg bg-slate-900/50 border border-slate-800 text-slate-300 hover:text-emerald-400 text-xs font-medium"
            >
              Features
            </a>
            <a
              href="#architecture"
              onClick={() => setMobileOpen(false)}
              className="p-2 rounded-lg bg-slate-900/50 border border-slate-800 text-slate-300 hover:text-emerald-400 text-xs font-medium"
            >
              Architecture
            </a>
            <a
              href="#simulator"
              onClick={() => setMobileOpen(false)}
              className="p-2 rounded-lg bg-slate-900/50 border border-slate-800 text-slate-300 hover:text-emerald-400 text-xs font-medium col-span-2 flex items-center justify-between"
            >
              <span>Interactive Playground</span>
              <span className="text-[9px] bg-indigo-500/20 text-indigo-300 px-1.5 py-0.5 rounded border border-indigo-500/30">INTERACTIVE</span>
            </a>
          </div>

          <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold px-1 pt-2">Resources</div>
          <div className="space-y-1">
            <Link
              href="/guide"
              onClick={() => setMobileOpen(false)}
              className="flex items-center gap-2 py-1.5 px-2 rounded-lg text-emerald-400 font-medium hover:bg-slate-900/50"
            >
              <BookOpen className="w-4 h-4 shrink-0" />
              <span>User Guide (Complete Manual)</span>
            </Link>
            <a
              href="#install"
              onClick={() => setMobileOpen(false)}
              className="flex items-center gap-2 py-1.5 px-2 rounded-lg text-slate-300 hover:text-emerald-400 hover:bg-slate-900/50"
            >
              <Terminal className="w-4 h-4 shrink-0 text-cyan-400" />
              <span>Installation Guides</span>
            </a>
            <a
              href="#benchmarks"
              onClick={() => setMobileOpen(false)}
              className="flex items-center gap-2 py-1.5 px-2 rounded-lg text-slate-300 hover:text-emerald-400 hover:bg-slate-900/50"
            >
              <BarChart3 className="w-4 h-4 shrink-0 text-purple-400" />
              <span>Benchmarks & Metrics</span>
            </a>
            <a
              href="#faq"
              onClick={() => setMobileOpen(false)}
              className="flex items-center gap-2 py-1.5 px-2 rounded-lg text-slate-300 hover:text-emerald-400 hover:bg-slate-900/50"
            >
              <HelpCircle className="w-4 h-4 shrink-0 text-amber-400" />
              <span>FAQ</span>
            </a>
            <button
              onClick={() => { setMobileOpen(false); setSupportOpen(true); }}
              className="w-full text-left flex items-center gap-2 py-1.5 px-2 rounded-lg text-rose-400 hover:bg-slate-900/50 font-medium cursor-pointer"
            >
              <MessageSquare className="w-4 h-4 shrink-0" />
              <span>Complaints & Support</span>
            </button>
          </div>

          <div className="pt-2 border-t border-slate-800 flex gap-2">
            <Link
              href="/login"
              onClick={() => setMobileOpen(false)}
              className="flex-1 text-center py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-semibold text-xs hover:border-slate-700"
            >
              Sign In
            </Link>
            <Link
              href="/console"
              onClick={() => setMobileOpen(false)}
              className="flex-1 text-center py-2 rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 text-black font-bold text-xs"
            >
              Launch Console
            </Link>
          </div>
        </div>
      )}

      {/* Support & Complaint Modal */}
      <SupportModal
        isOpen={supportOpen}
        onClose={() => setSupportOpen(false)}
        defaultType="Complaint"
      />
    </header>
  );
}
