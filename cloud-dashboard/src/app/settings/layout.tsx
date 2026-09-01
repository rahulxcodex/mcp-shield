import Link from 'next/link';
import { Settings, CreditCard, Users } from 'lucide-react';

export default function SettingsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-50">
      {/* Sidebar */}
      <aside className="w-64 border-r border-slate-800 bg-slate-900 p-6">
        <h2 className="text-xl font-semibold mb-6 flex items-center gap-2">
          <Settings className="h-5 w-5" />
          Settings
        </h2>
        <nav className="space-y-2">
          <Link
            href="/settings/general"
            className="flex items-center gap-2 px-3 py-2 rounded-md hover:bg-slate-800 text-slate-300 hover:text-white transition-colors"
          >
            <Settings className="h-4 w-4" />
            General
          </Link>
          <Link
            href="/settings/billing"
            className="flex items-center gap-2 px-3 py-2 rounded-md hover:bg-slate-800 text-slate-300 hover:text-white transition-colors"
          >
            <CreditCard className="h-4 w-4" />
            Billing
          </Link>
          <Link
            href="/settings/team"
            className="flex items-center gap-2 px-3 py-2 rounded-md hover:bg-slate-800 text-slate-300 hover:text-white transition-colors"
          >
            <Users className="h-4 w-4" />
            Team
          </Link>
        </nav>
      </aside>

      {/* Main Content */}
      <main className="flex-1 p-8">
        {children}
      </main>
    </div>
  );
}
