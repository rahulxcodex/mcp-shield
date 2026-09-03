"use client";

import { useState } from "react";
import { 
  X, 
  ShieldAlert, 
  Terminal, 
  Cpu, 
  Clock, 
  FileCode2, 
  CheckCircle, 
  AlertTriangle, 
  UserCheck, 
  Send,
  PlusCircle,
  Copy,
  Check
} from "lucide-react";

export interface ThreatEvent {
  id: string;
  timestamp: string;
  source: string;
  category: string;
  action: "BLOCKED" | "SANITIZED" | "ALLOWED" | "QUARANTINED" | "RATE_LIMITED";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "BENIGN";

  details: string;
  rawPayload?: string;
  status?: "OPEN" | "IN_REVIEW" | "RESOLVED";
  assignee?: string;
  analystNotes?: string[];
  astRule?: string;
  remediation?: string;
}

interface EventDetailDrawerProps {
  event: ThreatEvent | null;
  onClose: () => void;
  onUpdateEvent?: (updated: ThreatEvent) => void;
}

export default function EventDetailDrawer({ event, onClose, onUpdateEvent }: EventDetailDrawerProps) {
  const [currentStatus, setCurrentStatus] = useState<"OPEN" | "IN_REVIEW" | "RESOLVED">(
    event?.status || "OPEN"
  );
  const [assignee, setAssignee] = useState<string>(event?.assignee || "Unassigned");
  const [notes, setNotes] = useState<string[]>(event?.analystNotes || [
    "Threat detected during tool dispatch AST tree traversal.",
    "Blocked by Zero-Trust Command Invariant Engine."
  ]);
  const [newNote, setNewNote] = useState("");
  const [copiedPayload, setCopiedPayload] = useState(false);
  const [allowlistSaved, setAllowlistSaved] = useState(false);

  if (!event) return null;

  const handleAddNote = () => {
    if (!newNote.trim()) return;
    const updatedNotes = [...notes, `[${new Date().toLocaleTimeString()}] ${newNote.trim()}`];
    setNotes(updatedNotes);
    setNewNote("");
    if (onUpdateEvent) {
      onUpdateEvent({ ...event, analystNotes: updatedNotes, status: currentStatus, assignee });
    }
  };

  const handleStatusChange = (status: "OPEN" | "IN_REVIEW" | "RESOLVED") => {
    setCurrentStatus(status);
    if (onUpdateEvent) {
      onUpdateEvent({ ...event, status, assignee, analystNotes: notes });
    }
  };

  const handleCreateAllowlist = () => {
    setAllowlistSaved(true);
    setTimeout(() => setAllowlistSaved(false), 3000);
  };

  const handleCopyPayload = () => {
    navigator.clipboard.writeText(event.rawPayload || event.details);
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-xl bg-slate-950 border-l border-slate-800 shadow-2xl flex flex-col animate-in slide-in-from-right duration-300">
      {/* Drawer Header */}
      <div className="p-5 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-xl border ${
            event.action === "BLOCKED" 
              ? "bg-rose-500/10 border-rose-500/30 text-rose-400" 
              : event.action === "SANITIZED"
              ? "bg-amber-500/10 border-amber-500/30 text-amber-400"
              : "bg-blue-500/10 border-blue-500/30 text-blue-400"
          }`}>
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-white">Event #{event.id.slice(0, 8)}</h3>
              <span className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase tracking-wider ${
                event.action === "BLOCKED"
                  ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                  : event.action === "SANITIZED"
                  ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                  : "bg-blue-500/20 text-blue-300 border border-blue-500/30"
              }`}>
                {event.action}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">Source: {event.source} • Severity: {event.severity}</p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Drawer Body */}
      <div className="flex-1 overflow-y-auto p-5 space-y-6">
        {/* Incident Management Status Bar */}
        <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl grid grid-cols-2 gap-3 text-xs">
          <div>
            <label className="block text-[10px] uppercase font-semibold text-slate-400 mb-1">
              Incident Status
            </label>
            <select
              value={currentStatus}
              onChange={(e) => handleStatusChange(e.target.value as any)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-blue-500 text-xs"
            >
              <option value="OPEN">🚨 Open (Needs Review)</option>
              <option value="IN_REVIEW">🔍 In Review</option>
              <option value="RESOLVED">✅ Resolved / False Positive</option>
            </select>
          </div>

          <div>
            <label className="block text-[10px] uppercase font-semibold text-slate-400 mb-1">
              Security Analyst
            </label>
            <select
              value={assignee}
              onChange={(e) => setAssignee(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-blue-500 text-xs"
            >
              <option value="Unassigned">Unassigned</option>
              <option value="SecOps Lead">SecOps Lead (You)</option>
              <option value="Tier-2 SOC">Tier-2 SOC Team</option>
            </select>
          </div>
        </div>

        {/* Why was this blocked? */}
        <div className="space-y-2">
          <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
            <Cpu className="w-4 h-4 text-blue-400" />
            Why was this intercepted?
          </h4>
          <div className="p-3.5 rounded-xl border border-rose-500/20 bg-rose-500/5 text-xs text-rose-200 leading-relaxed">
            <span className="font-semibold text-rose-300 block mb-1">
              Rule Violation: {event.astRule || "AST_SUBTREE_DESTRUCTIVE_EXECUTION"}
            </span>
            {event.details}
          </div>
        </div>

        {/* Payload / Command Inspector */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <Terminal className="w-4 h-4 text-emerald-400" />
              Raw Intercepted Payload
            </h4>
            <button
              onClick={handleCopyPayload}
              className="text-[11px] text-slate-400 hover:text-white flex items-center gap-1"
            >
              {copiedPayload ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedPayload ? "Copied" : "Copy"}</span>
            </button>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 font-mono text-xs text-slate-300 overflow-x-auto">
            <code>{event.rawPayload || event.details}</code>
          </div>
        </div>

        {/* Remediation Guidance */}
        <div className="space-y-2">
          <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
            <FileCode2 className="w-4 h-4 text-amber-400" />
            Remediation & Action Guidance
          </h4>
          <div className="p-3.5 bg-slate-900/50 border border-slate-800 rounded-xl text-xs text-slate-300 space-y-2">
            <p>
              {event.remediation || 
                "1. If this invocation was intentional, add an explicit tool parameter allowlist pattern in shield.config.yaml."}
            </p>
            <p className="text-slate-400 text-[11px]">
              2. Instruct your AI agent to avoid subshell chaining, backticks, or direct filesystem root modifications.
            </p>
            
            <div className="pt-2 border-t border-slate-800">
              <button
                onClick={handleCreateAllowlist}
                disabled={allowlistSaved}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/30 text-blue-300 text-xs font-medium transition-colors"
              >
                <PlusCircle className="w-3.5 h-3.5" />
                <span>{allowlistSaved ? "Allowlist Exception Drafted" : "Create Allowlist Exception"}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Investigation Timeline & Analyst Notes */}
        <div className="space-y-2">
          <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
            <Clock className="w-4 h-4 text-indigo-400" />
            Analyst Notes & Audit Trail
          </h4>
          <div className="space-y-2">
            {notes.map((note, idx) => (
              <div key={idx} className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80 text-xs text-slate-300">
                {note}
              </div>
            ))}
          </div>

          <div className="flex gap-2 pt-1">
            <input
              type="text"
              placeholder="Add investigator note..."
              value={newNote}
              onChange={(e) => setNewNote(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleAddNote()}
              className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
            <button
              onClick={handleAddNote}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-medium flex items-center gap-1"
            >
              <Send className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
