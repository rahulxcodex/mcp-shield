"use client";

import { useState, useEffect } from "react";
import { 
  Key, 
  Copy, 
  Check, 
  Terminal, 
  RotateCw, 
  Trash2, 
  AlertTriangle, 
  ShieldCheck, 
  Calendar, 
  Plus, 
  Clock, 
  ShieldAlert,
  X
} from "lucide-react";

interface KeyItem {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  last_used?: string;
  last_ip?: string;
  project: string;
  env: string;
  status: "ACTIVE" | "ROTATED" | "REVOKED";
  expires_in_days: number;
}

export default function GeneralSettingsPage() {
  const [keys, setKeys] = useState<KeyItem[]>([
    {
      id: "key-1",
      name: "Production Claude Gateway",
      prefix: "mcp_live_a8f9c2d1",
      created_at: "2026-09-01",
      last_used: "12 seconds ago",
      last_ip: "103.42.112.98",
      project: "Prod Gateway",
      env: "Production",
      status: "ACTIVE",
      expires_in_days: 90
    },
    {
      id: "key-2",
      name: "Staging Antigravity Agent",
      prefix: "mcp_live_73b9e4a0",
      created_at: "2026-08-20",
      last_used: "2 hours ago",
      last_ip: "142.250.190.46",
      project: "Staging Cluster",
      env: "Staging",
      status: "ACTIVE",
      expires_in_days: 30
    }
  ]);

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyEnv, setNewKeyEnv] = useState("Production");
  const [newKeyExpiry, setNewKeyExpiry] = useState("90");
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [rotatedMessage, setRotatedMessage] = useState<string | null>(null);

  const handleCreateKey = () => {
    if (!newKeyName.trim()) return;
    const randomHex = Array.from({ length: 8 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
    const fullSecret = `mcp_live_${randomHex}${Array.from({ length: 24 }, () => Math.floor(Math.random() * 16).toString(16)).join("")}`;
    
    const newKey: KeyItem = {
      id: "key-" + Date.now(),
      name: newKeyName.trim(),
      prefix: `mcp_live_${randomHex}`,
      created_at: new Date().toISOString().split("T")[0],
      last_used: "Never",
      last_ip: "N/A",
      project: "Default Project",
      env: newKeyEnv,
      status: "ACTIVE",
      expires_in_days: parseInt(newKeyExpiry, 10)
    };

    setKeys([newKey, ...keys]);
    setCreatedSecret(fullSecret);
  };

  const handleRotateKey = (id: string) => {
    setKeys(keys.map(k => {
      if (k.id === id) {
        const randomHex = Array.from({ length: 8 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
        return {
          ...k,
          prefix: `mcp_live_${randomHex}`,
          last_used: "Never",
          status: "ACTIVE"
        };
      }
      return k;
    }));
    setRotatedMessage(`Key rotated successfully. Old secret is immediately invalidated.`);
    setTimeout(() => setRotatedMessage(null), 3500);
  };

  const handleRevokeKey = (id: string) => {
    setKeys(keys.map(k => k.id === id ? { ...k, status: "REVOKED" } : k));
  };

  const handleDeleteKey = (id: string) => {
    setKeys(keys.filter(k => k.id !== id));
  };

  return (
    <div className="max-w-5xl space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1 flex items-center gap-2">
            <Key className="w-6 h-6 text-blue-400" />
            API Keys & CLI Credentials
          </h1>
          <p className="text-xs text-slate-400">
            Cryptographically hashed HMAC credentials for linking local CLI proxies, IDE extensions, and cloud gateways.
          </p>
        </div>

        <button
          onClick={() => {
            setShowCreateModal(true);
            setCreatedSecret(null);
            setNewKeyName("");
          }}
          className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-lg shadow-blue-500/20 transition-all"
        >
          <Plus className="w-4 h-4" />
          Create New API Key
        </button>
      </div>

      {rotatedMessage && (
        <div className="p-3.5 rounded-xl bg-blue-500/10 border border-blue-500/30 text-blue-300 text-xs flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-blue-400" />
          <span>{rotatedMessage}</span>
        </div>
      )}

      {/* Keys Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-wider font-semibold">
              <tr>
                <th className="p-3.5">Key Name & Prefix</th>
                <th className="p-3.5">Environment</th>
                <th className="p-3.5">Created</th>
                <th className="p-3.5">Last Used & IP</th>
                <th className="p-3.5">Expiry</th>
                <th className="p-3.5">Status</th>
                <th className="p-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {keys.map((k) => (
                <tr key={k.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="p-3.5">
                    <div className="font-semibold text-slate-200">{k.name}</div>
                    <div className="font-mono text-[11px] text-emerald-400 mt-0.5">{k.prefix}...</div>
                  </td>
                  <td className="p-3.5">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                      k.env === "Production" ? "bg-purple-500/20 text-purple-300 border border-purple-500/30" : "bg-slate-800 text-slate-300"
                    }`}>
                      {k.env}
                    </span>
                  </td>
                  <td className="p-3.5 text-slate-400">{k.created_at}</td>
                  <td className="p-3.5">
                    <div className="text-slate-200">{k.last_used}</div>
                    <div className="text-[10px] font-mono text-slate-500">{k.last_ip}</div>
                  </td>
                  <td className="p-3.5 text-slate-400">{k.expires_in_days} days</td>
                  <td className="p-3.5">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      k.status === "ACTIVE" 
                        ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30" 
                        : "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                    }`}>
                      {k.status}
                    </span>
                  </td>
                  <td className="p-3.5 text-right">
                    <div className="flex items-center justify-end gap-1">
                      {k.status === "ACTIVE" && (
                        <button
                          onClick={() => handleRotateKey(k.id)}
                          title="Rotate Key"
                          className="p-1.5 text-slate-400 hover:text-blue-400 hover:bg-blue-500/10 rounded-lg transition-colors"
                        >
                          <RotateCw className="w-3.5 h-3.5" />
                        </button>
                      )}
                      {k.status === "ACTIVE" && (
                        <button
                          onClick={() => handleRevokeKey(k.id)}
                          title="Revoke Key"
                          className="p-1.5 text-slate-400 hover:text-amber-400 hover:bg-amber-500/10 rounded-lg transition-colors"
                        >
                          <AlertTriangle className="w-3.5 h-3.5" />
                        </button>
                      )}
                      <button
                        onClick={() => handleDeleteKey(k.id)}
                        title="Delete Key"
                        className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Compromise Warning & Security Invariant */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-2xl flex items-start gap-3 text-xs text-slate-400">
        <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <div className="text-slate-200 font-semibold mb-1">Zero-Plaintext Key Storage Guarantee</div>
          Raw API key secrets are never stored in the database. Only standard SHA-256 hashes are retained.
          If an API key is suspected of being exposed or committed to public version control, rotate or revoke it immediately.
        </div>
      </div>

      {/* Create Key Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg bg-slate-950 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Key className="w-4 h-4 text-blue-400" />
                Generate Client Telemetry Key
              </h3>
              <button onClick={() => setShowCreateModal(false)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            {!createdSecret ? (
              <div className="space-y-4 text-xs">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Key Description / Client Name</label>
                  <input
                    type="text"
                    value={newKeyName}
                    onChange={(e) => setNewKeyName(e.target.value)}
                    placeholder="e.g. CI/CD Pipeline Gateway, Cursor Extension"
                    className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-300 font-medium mb-1">Environment</label>
                    <select
                      value={newKeyEnv}
                      onChange={(e) => setNewKeyEnv(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                    >
                      <option value="Production">Production</option>
                      <option value="Staging">Staging</option>
                      <option value="Development">Development</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-slate-300 font-medium mb-1">Expiry Period</label>
                    <select
                      value={newKeyExpiry}
                      onChange={(e) => setNewKeyExpiry(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                    >
                      <option value="30">30 Days</option>
                      <option value="90">90 Days</option>
                      <option value="365">365 Days</option>
                      <option value="0">Never (Enterprise only)</option>
                    </select>
                  </div>
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    onClick={() => setShowCreateModal(false)}
                    className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleCreateKey}
                    disabled={!newKeyName.trim()}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-xl text-xs font-semibold shadow-lg shadow-blue-500/20"
                  >
                    Generate Secret
                  </button>
                </div>
              </div>
            ) : (
              <div className="space-y-4 text-xs">
                <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-300">
                  <span className="font-semibold block mb-1">Copy Your Secret Now (Reveal Once)</span>
                  This is the only time this secret will be shown. It cannot be recovered once this modal is closed.
                </div>

                <div className="p-3 bg-slate-900 border border-slate-700 rounded-xl flex items-center justify-between font-mono text-emerald-400">
                  <span className="truncate">{createdSecret}</span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(createdSecret);
                      setCopiedKey(true);
                      setTimeout(() => setCopiedKey(false), 2000);
                    }}
                    className="flex items-center gap-1 text-slate-400 hover:text-white ml-2 shrink-0"
                  >
                    {copiedKey ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    <span>{copiedKey ? "Copied" : "Copy"}</span>
                  </button>
                </div>

                <div className="flex justify-end pt-2">
                  <button
                    onClick={() => setShowCreateModal(false)}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-xs font-semibold"
                  >
                    Done
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
