"use client";

import { useState } from "react";
import { History, Shield, Download, Filter, User, Calendar, CheckCircle2 } from "lucide-react";

interface AuditEntry {
  id: string;
  action: string;
  actor: string;
  role: string;
  target: string;
  timestamp: string;
  ip: string;
  status: "SUCCESS" | "DENIED";
}

export default function AuditLogsPage() {
  const [logs] = useState<AuditEntry[]>([
    {
      id: "aud-01",
      action: "API_KEY_CREATED",
      actor: "rahul@mcp-shield.dev",
      role: "Owner",
      target: "mcp_live_a8f9c2d1 (Staging Agent)",
      timestamp: "2026-09-03 21:14:02 UTC",
      ip: "103.42.112.98",
      status: "SUCCESS"
    },
    {
      id: "aud-02",
      action: "ROLE_ELEVATION",
      actor: "rahul@mcp-shield.dev",
      role: "Owner",
      target: "dev@acme.com promoted to Admin",
      timestamp: "2026-09-03 19:30:15 UTC",
      ip: "103.42.112.98",
      status: "SUCCESS"
    },
    {
      id: "aud-03",
      action: "BILLING_TIER_CHANGED",
      actor: "rahul@mcp-shield.dev",
      role: "Owner",
      target: "Enterprise Multi-Seat Fleet Activated (25 Seats)",
      timestamp: "2026-09-03 16:45:00 UTC",
      ip: "103.42.112.98",
      status: "SUCCESS"
    },
    {
      id: "aud-04",
      action: "CROSS_TENANT_READ_ATTEMPT",
      actor: "unknown_client_token",
      role: "External",
      target: "Tenant project lookup blocked by RLS policy",
      timestamp: "2026-09-03 14:12:44 UTC",
      ip: "198.51.100.24",
      status: "DENIED"
    },
    {
      id: "aud-05",
      action: "KEY_ROTATION",
      actor: "rahul@mcp-shield.dev",
      role: "Owner",
      target: "mcp_live_e3108bf6 revoked and reissued",
      timestamp: "2026-09-03 11:02:18 UTC",
      ip: "103.42.112.98",
      status: "SUCCESS"
    }
  ]);

  const [downloaded, setDownloaded] = useState(false);

  const handleExportCsv = () => {
    const csvContent = "data:text/csv;charset=utf-8," + 
      "ID,Action,Actor,Role,Target,Timestamp,IP,Status\n" + 
      logs.map(l => `${l.id},${l.action},${l.actor},${l.role},"${l.target}",${l.timestamp},${l.ip},${l.status}`).join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `mcp_shield_audit_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setDownloaded(true);
    setTimeout(() => setDownloaded(false), 3000);
  };

  return (
    <div className="max-w-5xl space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1.5 flex items-center gap-2">
            <History className="w-6 h-6 text-blue-400" />
            Privileged Organization Audit Logs
          </h1>
          <p className="text-xs text-slate-400">
            Immutable, cryptographically chained audit events tracking key creation, membership updates, and policy shifts.
          </p>
        </div>
        <button
          onClick={handleExportCsv}
          className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-semibold text-slate-200 transition-colors"
        >
          {downloaded ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Download className="w-4 h-4" />}
          <span>{downloaded ? "CSV Exported" : "Export Audit CSV"}</span>
        </button>
      </div>

      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-wider font-semibold">
              <tr>
                <th className="p-3.5">Timestamp (UTC)</th>
                <th className="p-3.5">Action</th>
                <th className="p-3.5">Actor</th>
                <th className="p-3.5">Target / Detail</th>
                <th className="p-3.5">IP Address</th>
                <th className="p-3.5">Verdict</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {logs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="p-3.5 font-mono text-[11px] text-slate-400 whitespace-nowrap">{log.timestamp}</td>
                  <td className="p-3.5 font-mono font-medium text-slate-200 whitespace-nowrap">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-[10px] border border-slate-700">
                      {log.action}
                    </span>
                  </td>
                  <td className="p-3.5 whitespace-nowrap">
                    <div className="font-medium text-slate-200">{log.actor}</div>
                    <div className="text-[10px] text-slate-500">{log.role}</div>
                  </td>
                  <td className="p-3.5 max-w-xs truncate">{log.target}</td>
                  <td className="p-3.5 font-mono text-slate-400">{log.ip}</td>
                  <td className="p-3.5 whitespace-nowrap">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                      log.status === "SUCCESS"
                        ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                        : "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                    }`}>
                      {log.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
