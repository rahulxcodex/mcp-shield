"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { 
  Settings, 
  CreditCard, 
  Users, 
  Shield, 
  History, 
  Webhook, 
  ChevronRight, 
  LayoutDashboard,
  Building2,
  User
} from "lucide-react";
import WorkspaceSwitcher from "@/components/WorkspaceSwitcher";

export default function SettingsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();

  const navItems = [
    { href: "/settings/account", label: "My Account", icon: User },
    { href: "/settings/general", label: "General & Keys", icon: Settings },
    { href: "/settings/security", label: "Security, MFA & SSO", icon: Shield },
    { href: "/settings/team", label: "Team & Permissions", icon: Users },
    { href: "/settings/billing", label: "Billing & Plans", icon: CreditCard },
    { href: "/settings/integrations", label: "Integrations & Alerts", icon: Webhook },
    { href: "/settings/audit", label: "Audit Logs", icon: History },
  ];

  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-50">
      {/* Top Breadcrumb & Switcher Header */}
      <header className="h-14 border-b border-slate-800 bg-slate-900/50 backdrop-blur-md px-6 flex items-center justify-between">
        <div className="flex items-center gap-3 text-xs">
          <Link 
            href="/console" 
            className="flex items-center gap-1.5 text-slate-400 hover:text-white transition-colors"
          >
            <LayoutDashboard className="w-3.5 h-3.5" />
            <span>Console</span>
          </Link>
          <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
          <span className="text-slate-300 font-medium">Organization Settings</span>
        </div>

        <div className="flex items-center gap-4">
          <WorkspaceSwitcher />
          <Link
            href="/console"
            className="px-3 py-1 rounded-lg bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 border border-blue-500/20 text-xs font-medium transition-colors"
          >
            ← Back to Telemetry Feed
          </Link>
        </div>
      </header>

      <div className="flex flex-1">
        {/* Settings Sidebar */}
        <aside className="w-64 border-r border-slate-800 bg-slate-900/30 p-6 flex flex-col justify-between">
          <div>
            <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-4 px-3">
              Workspace Configuration
            </div>
            <nav className="space-y-1.5">
              {navItems.map((item) => {
                const Icon = item.icon;
                const isActive = pathname === item.href;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs font-medium transition-all ${
                      isActive
                        ? "bg-blue-600 text-white shadow-lg shadow-blue-500/20"
                        : "text-slate-400 hover:text-white hover:bg-slate-800/60"
                    }`}
                  >
                    <Icon className={`w-4 h-4 ${isActive ? "text-white" : "text-slate-400"}`} />
                    <span>{item.label}</span>
                  </Link>
                );
              })}
            </nav>
          </div>

          <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl text-[11px] text-slate-400">
            <div className="font-medium text-slate-200 mb-1 flex items-center gap-1.5">
              <Building2 className="w-3.5 h-3.5 text-blue-400" />
              Tenant Isolation Active
            </div>
            RLS policies and cryptographic keys strictly isolate your team's telemetry stream.
          </div>
        </aside>

        {/* Main Content Area */}
        <main className="flex-1 p-8 max-w-5xl">
          {children}
        </main>
      </div>
    </div>
  );
}
