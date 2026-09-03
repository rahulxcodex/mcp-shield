"use client";

import { useState, useEffect } from "react";
import { Building2, ChevronDown, Check, Plus, ShieldCheck } from "lucide-react";

interface Workspace {
  id: string;
  name: string;
  plan: "free" | "pro" | "enterprise";
  role: "owner" | "admin" | "member";
}

export default function WorkspaceSwitcher() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([
    { id: "ws-default", name: "Primary Engineering Org", plan: "enterprise", role: "owner" },
    { id: "ws-staging", name: "Security Staging Cluster", plan: "pro", role: "admin" }
  ]);
  const [activeWorkspace, setActiveWorkspace] = useState<Workspace>(workspaces[0]);
  const [isOpen, setIsOpen] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [newOrgName, setNewOrgName] = useState("");

  useEffect(() => {
    async function loadWorkspaces() {
      try {
        const res = await fetch("/api/v1/organizations");
        if (res.ok) {
          const orgs = await res.json();
          if (Array.isArray(orgs) && orgs.length > 0) {
            const mapped: Workspace[] = orgs.map((o: any) => ({
              id: o.id,
              name: o.name || "Default Workspace",
              plan: o.plan || "free",
              role: o.role || "owner"
            }));
            setWorkspaces(mapped);
            setActiveWorkspace(mapped[0]);
          }
        }
      } catch {
        // Fallback to local default workspace
      }
    }
    loadWorkspaces();
  }, []);

  const handleCreateOrg = () => {
    if (!newOrgName.trim()) return;
    const newWs: Workspace = {
      id: "ws-" + Date.now(),
      name: newOrgName.trim(),
      plan: "free",
      role: "owner"
    };
    setWorkspaces([...workspaces, newWs]);
    setActiveWorkspace(newWs);
    setNewOrgName("");
    setIsCreating(false);
    setIsOpen(false);
  };

  return (
    <div className="relative inline-block text-left">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-800 text-slate-200 text-xs transition-colors"
      >
        <Building2 className="w-3.5 h-3.5 text-blue-400" />
        <span className="font-medium max-w-[140px] truncate">{activeWorkspace.name}</span>
        <span className={`px-1.5 py-0.2 text-[9px] rounded uppercase font-semibold tracking-wider ${
          activeWorkspace.plan === "enterprise"
            ? "bg-purple-500/20 text-purple-300 border border-purple-500/30"
            : activeWorkspace.plan === "pro"
            ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
            : "bg-slate-800 text-slate-400 border border-slate-700"
        }`}>
          {activeWorkspace.plan}
        </span>
        <ChevronDown className="w-3 h-3 text-slate-400" />
      </button>

      {isOpen && (
        <div className="absolute left-0 mt-2 w-72 rounded-xl bg-slate-950 border border-slate-800 shadow-2xl z-50 p-2">
          <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider px-2 py-1">
            Workspaces & Organizations
          </div>
          <div className="space-y-1 max-h-48 overflow-y-auto">
            {workspaces.map((ws) => (
              <button
                key={ws.id}
                onClick={() => {
                  setActiveWorkspace(ws);
                  setIsOpen(false);
                }}
                className="w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-left hover:bg-slate-900 transition-colors group"
              >
                <div className="flex items-center gap-2 truncate">
                  <ShieldCheck className="w-3.5 h-3.5 text-slate-400 group-hover:text-blue-400" />
                  <div className="truncate">
                    <div className="text-xs text-slate-200 font-medium truncate">{ws.name}</div>
                    <div className="text-[10px] text-slate-500 capitalize">{ws.role} • {ws.plan} plan</div>
                  </div>
                </div>
                {activeWorkspace.id === ws.id && (
                  <Check className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                )}
              </button>
            ))}
          </div>

          <div className="border-t border-slate-800/80 mt-2 pt-2">
            {!isCreating ? (
              <button
                onClick={() => setIsCreating(true)}
                className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-xs text-blue-400 hover:bg-blue-500/10 transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                Create Organization
              </button>
            ) : (
              <div className="p-1 space-y-2">
                <input
                  type="text"
                  placeholder="New Org Name..."
                  value={newOrgName}
                  onChange={(e) => setNewOrgName(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
                  autoFocus
                />
                <div className="flex gap-1 justify-end">
                  <button
                    onClick={() => setIsCreating(false)}
                    className="px-2 py-0.5 text-[11px] text-slate-400 hover:text-white"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleCreateOrg}
                    className="px-2.5 py-0.5 text-[11px] bg-blue-600 hover:bg-blue-500 text-white rounded font-medium"
                  >
                    Create
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
