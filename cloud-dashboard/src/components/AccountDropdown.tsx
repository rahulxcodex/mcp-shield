'use client';

import { useState, useRef, useEffect } from 'react';
import Link from 'next/link';
import { User, Settings, Shield, LogOut, ChevronDown } from 'lucide-react';
import Github from './GithubIcon';

export interface AccountDropdownProps {
  user: {
    email: string;
    app_metadata?: {
      role?: string;
      plan?: string;
      [key: string]: any;
    };
    user_metadata?: {
      avatar_url?: string;
      full_name?: string;
      user_name?: string;
      company?: string;
      account_type?: string;
      is_master?: boolean;
      [key: string]: any;
    };
  } | null;
  onSignOut: () => void;
}

export default function AccountDropdown({ user, onSignOut }: AccountDropdownProps) {
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

  if (!user) return null;

  const email = user.email || '';
  const metadata = user.user_metadata || {};
  const fullName = metadata.full_name;
  const username = metadata.user_name;
  const avatarUrl = metadata.avatar_url;
  const accountTypeRaw = metadata.account_type || '';

  const displayName = fullName || email;
  const initials = fullName
    ? fullName
        .split(' ')
        .map((part) => part[0])
        .filter(Boolean)
        .slice(0, 2)
        .join('')
        .toUpperCase()
    : email[0]?.toUpperCase() || 'U';

  const isMasterAdmin =
    email.toLowerCase() === 'rahulsahygupta24@gmail.com' ||
    user.app_metadata?.role === 'master_admin';
  const isEnterprise = accountTypeRaw.toLowerCase().includes('enterprise') || isMasterAdmin;

  let badgeText = 'Developer';
  if (isMasterAdmin) {
    badgeText = 'Master Admin';
  } else if (isEnterprise) {
    badgeText = 'Enterprise';
  } else if (accountTypeRaw) {
    badgeText = accountTypeRaw;
  }

  return (
    <div className="relative inline-block" ref={dropdownRef}>
      {/* Circular Avatar Trigger Button */}
      <button
        type="button"
        onClick={() => setIsOpen((prev) => !prev)}
        className="flex items-center gap-1.5 p-0.5 rounded-full hover:bg-slate-800/60 transition focus:outline-none focus:ring-1 focus:ring-emerald-500/50"
        aria-expanded={isOpen}
        aria-haspopup="true"
        title={displayName}
      >
        {avatarUrl ? (
          <img
            src={avatarUrl}
            alt={displayName}
            className="h-8 w-8 rounded-full object-cover border border-slate-700"
          />
        ) : (
          <div className="h-8 w-8 rounded-full bg-gradient-to-tr from-emerald-500 to-cyan-500 flex items-center justify-center text-black font-bold text-xs shrink-0 shadow-sm">
            {initials}
          </div>
        )}
        <ChevronDown
          className={`w-3.5 h-3.5 text-slate-400 transition-transform duration-200 ${
            isOpen ? 'rotate-180 text-emerald-400' : ''
          }`}
        />
      </button>

      {/* Dropdown Panel */}
      {isOpen && (
        <div className="absolute right-0 top-full mt-2 w-72 z-50 bg-[#0d0e15] border border-slate-800 rounded-xl shadow-2xl p-2 text-xs text-slate-300 animate-in fade-in zoom-in-95 duration-100">
          {/* 1. Profile Section */}
          <div className="p-2 pb-2.5">
            <div className="flex items-center gap-3">
              {avatarUrl ? (
                <img
                  src={avatarUrl}
                  alt={displayName}
                  className="h-9 w-9 rounded-full object-cover border border-slate-700 shrink-0"
                />
              ) : (
                <div className="h-9 w-9 rounded-full bg-gradient-to-tr from-emerald-500 to-cyan-500 flex items-center justify-center text-black font-bold text-xs shrink-0">
                  {initials}
                </div>
              )}
              <div className="min-w-0 flex-1">
                <div className="font-semibold text-white truncate text-xs" title={displayName}>
                  {displayName}
                </div>
                <div className="mt-1">
                  <span className="inline-block bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded-full text-[10px] font-mono">
                    {badgeText}
                  </span>
                </div>
              </div>
            </div>

            {/* 2. Connected GitHub */}
            {username && (
              <div className="mt-2.5 flex items-center gap-2 px-2 py-1 rounded-md bg-slate-900/70 border border-slate-800/80 text-[11px] text-slate-300">
                <Github className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                <span className="text-slate-400">GitHub:</span>
                <span className="font-mono text-slate-200 truncate">@{username}</span>
              </div>
            )}

            {/* 3. Email */}
            <div className="mt-1.5 flex items-center gap-2 px-1 text-[11px] text-slate-400">
              <User className="w-3.5 h-3.5 text-slate-500 shrink-0" />
              <span className="truncate">{email}</span>
            </div>
          </div>

          {/* 4. Divider */}
          <div className="my-1 border-t border-slate-800" />

          {/* 5. Links Section */}
          <div className="py-0.5 space-y-0.5">
            <Link
              href="/settings/account"
              onClick={() => setIsOpen(false)}
              className="flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-slate-300 hover:bg-slate-800/60 hover:text-white transition"
            >
              <Settings className="w-4 h-4 text-slate-400" />
              <span>Account Settings</span>
            </Link>

            {isEnterprise && (
              <Link
                href="/console/admin"
                onClick={() => setIsOpen(false)}
                className="flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-slate-300 hover:bg-slate-800/60 hover:text-white transition"
              >
                <Shield className="w-4 h-4 text-emerald-400" />
                <span>Admin Panel</span>
              </Link>
            )}

            {isMasterAdmin && (
              <Link
                href="/console/system-admin"
                onClick={() => setIsOpen(false)}
                className="flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-slate-300 hover:bg-slate-800/60 hover:text-white transition"
              >
                <Shield className="w-4 h-4 text-cyan-400" />
                <span>System Admin</span>
              </Link>
            )}
          </div>

          {/* 6. Divider */}
          <div className="my-1 border-t border-slate-800" />

          {/* 7. Sign Out Button */}
          <div className="pt-0.5">
            <button
              type="button"
              onClick={() => {
                setIsOpen(false);
                onSignOut();
              }}
              className="w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-rose-400 hover:bg-rose-500/10 transition font-medium text-left"
            >
              <LogOut className="w-4 h-4 text-rose-400" />
              <span>Sign Out</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
