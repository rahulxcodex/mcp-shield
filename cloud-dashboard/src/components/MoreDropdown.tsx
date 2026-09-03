'use client';

import React, { useState, useRef, useEffect } from 'react';
import Link from 'next/link';
import {
  ChevronDown,
  Sparkles,
  RefreshCw,
  Download,
  CreditCard,
  MessageSquare,
  Sun,
} from 'lucide-react';
import ThemeToggle from '@/components/ThemeToggle';

interface MoreDropdownProps {
  onOpenOnboarding: () => void;
  onSimulateAttack: () => void;
  isSimulating: boolean;
  onExportSOC2: () => void;
  onOpenSupport: () => void;
}

export default function MoreDropdown({
  onOpenOnboarding,
  onSimulateAttack,
  isSimulating,
  onExportSOC2,
  onOpenSupport,
}: MoreDropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition border border-slate-700 cursor-pointer"
        aria-expanded={isOpen}
        aria-haspopup="true"
      >
        <span>More</span>
        <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div className="absolute right-0 top-full mt-2 w-56 bg-[#0d0e15] border border-slate-800 rounded-xl shadow-2xl z-50 py-1.5">
          {/* 1. Onboarding Setup */}
          <button
            type="button"
            onClick={() => {
              setIsOpen(false);
              onOpenOnboarding();
            }}
            className="flex items-center gap-2.5 px-3.5 py-2 text-xs text-slate-300 hover:bg-slate-800/60 hover:text-white transition cursor-pointer w-full text-left"
          >
            <Sparkles className="w-4 h-4 text-blue-400 shrink-0" />
            <span>Onboarding Setup</span>
          </button>

          {/* 2. Simulate Live Attack */}
          <button
            type="button"
            onClick={() => {
              if (!isSimulating) {
                onSimulateAttack();
                setIsOpen(false);
              }
            }}
            disabled={isSimulating}
            className={`flex items-center gap-2.5 px-3.5 py-2 text-xs text-slate-300 hover:bg-slate-800/60 hover:text-white transition cursor-pointer w-full text-left ${
              isSimulating ? 'opacity-50 cursor-not-allowed' : ''
            }`}
          >
            <RefreshCw className={`w-4 h-4 text-cyan-400 shrink-0 ${isSimulating ? 'animate-spin' : ''}`} />
            <span>Simulate Live Attack</span>
          </button>

          {/* 3. Divider */}
          <div className="border-t border-slate-800 my-1.5 mx-3" />

          {/* 4. Export SOC2 Log */}
          <button
            type="button"
            onClick={() => {
              setIsOpen(false);
              onExportSOC2();
            }}
            className="flex items-center gap-2.5 px-3.5 py-2 text-xs text-slate-300 hover:bg-slate-800/60 hover:text-white transition cursor-pointer w-full text-left"
          >
            <Download className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>Export SOC2 Log</span>
          </button>

          {/* 5. Plans & Quota */}
          <Link
            href="/settings/billing"
            onClick={() => setIsOpen(false)}
            className="flex items-center gap-2.5 px-3.5 py-2 text-xs text-slate-300 hover:bg-slate-800/60 hover:text-white transition cursor-pointer w-full text-left"
          >
            <CreditCard className="w-4 h-4 text-blue-400 shrink-0" />
            <span>Plans & Quota</span>
          </Link>

          {/* 6. Divider */}
          <div className="border-t border-slate-800 my-1.5 mx-3" />

          {/* 7. Feedback & Support */}
          <button
            type="button"
            onClick={() => {
              setIsOpen(false);
              onOpenSupport();
            }}
            className="flex items-center gap-2.5 px-3.5 py-2 text-xs text-slate-300 hover:bg-slate-800/60 hover:text-white transition cursor-pointer w-full text-left"
          >
            <MessageSquare className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>Feedback & Support</span>
          </button>

          {/* 8. Theme Toggle row */}
          <div className="flex items-center justify-between px-3.5 py-2 text-xs text-slate-300">
            <div className="flex items-center gap-2.5">
              <Sun className="w-4 h-4 text-amber-400 shrink-0" />
              <span>Theme</span>
            </div>
            <ThemeToggle />
          </div>
        </div>
      )}
    </div>
  );
}
