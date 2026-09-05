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
  X,
  Upload
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
  const [showAddKeyModal, setShowAddKeyModal] = useState(false);
  const [addKeyValue, setAddKeyValue] = useState("");
  const [addKeyName, setAddKeyName] = useState("");
  const [addKeyError, setAddKeyError] = useState<string | null>(null);
  const [addKeySuccess, setAddKeySuccess] = useState(false);


  useEffect(() => {
    fetch('/api/v1/keys')
      .then((res) => res.json())
      .then((data) => {
        if (data?.keys && Array.isArray(data.keys) && data.keys.length > 0) {
          const mapped: KeyItem[] = data.keys.map((k: any) => ({
            id: k.id,
            name: k.name,
            prefix: k.key_prefix,
            created_at: k.created_at ? k.created_at.split('T')[0] : 'Today',
            last_used: k.last_used_at ? 'Active' : 'Never',
            last_ip: 'N/A',
            project: 'Production Project',
            env: 'Production',
            status: k.status === 'revoked' ? 'REVOKED' : 'ACTIVE',
            expires_in_days: 90
          }));
          setKeys(mapped);
        }
      })
      .catch(() => {});
  }, []);

  const handleCreateKey = async () => {
    if (!newKeyName.trim()) return;
    try {
      const res = await fetch('/api/v1/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newKeyName.trim(),
          clientType: newKeyEnv,
          expiresInDays: parseInt(newKeyExpiry, 10),
          seats: 1
        })
      });

      if (res.ok) {
        const data = await res.json();
        if (data?.key) {
          const created: KeyItem = {
            id: data.key.id,
            name: data.key.name,
            prefix: data.key.keyPrefix,
            created_at: new Date().toISOString().split('T')[0],
            last_used: 'Never',
            last_ip: 'N/A',
            project: 'Production Project',
            env: newKeyEnv,
            status: 'ACTIVE',
            expires_in_days: parseInt(newKeyExpiry, 10)
          };
          setKeys([created, ...keys]);
          setCreatedSecret(data.key.apiKey);
          return;
        }
      }
      const err = await res.json().catch(() => ({}));
      alert(`Key generation failed: ${err.error || 'Server error'}`);
    } catch {
      alert('Network error connecting to key service.');
    }
  };

  const handleRotateKey = async (id: string) => {
    try {
      const target = keys.find(k => k.id === id);
      const res = await fetch('/api/v1/keys', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ keyId: id, keyPrefix: target?.prefix, expiresInDays: 90 })
      });

      if (res.ok) {
        const data = await res.json();
        if (data?.newKey) {
          setKeys(keys.map(k => {
            if (k.id === id) {
              return {
                ...k,
                id: data.newKey.id,
                prefix: data.newKey.keyPrefix,
                last_used: 'Never',
                status: 'ACTIVE'
              };
            }
            return k;
          }));
          setCreatedSecret(data.newKey.apiKey);
          setShowCreateModal(true);
          setRotatedMessage(`Key rotated successfully. New secret displayed below.`);
          setTimeout(() => setRotatedMessage(null), 4000);
          return;
        }
      }
    } catch {}
    alert('Key rotation request failed.');
  };

  const handleRevokeKey = async (id: string) => {
    try {
      const target = keys.find(k => k.id === id);
      await fetch(`/api/v1/keys?id=${id}&prefix=${target?.prefix || ''}`, {
        method: 'DELETE'
      });
      setKeys(keys.map(k => k.id === id ? { ...k, status: "REVOKED" } : k));
    } catch {
      setKeys(keys.map(k => k.id === id ? { ...k, status: "REVOKED" } : k));
    }
  };

  const handleDeleteKey = async (id: string) => {
    await handleRevokeKey(id);
    setKeys(keys.filter(k => k.id !== id));
  };

  const handleAddExistingKey = async () => {
    const trimmedKey = addKeyValue.trim();
    const trimmedName = addKeyName.trim();

    if (!trimmedKey) {
      setAddKeyError("Please paste the API key.");
      return;
    }
    if (!trimmedName) {
      setAddKeyError("Please provide a name for this key.");
      return;
    }

    if (trimmedKey.length < 8) {
      setAddKeyError("Key must be at least 8 characters long.");
      return;
    }

    try {
      setAddKeyError(null);
      const res = await fetch('/api/v1/keys', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawKey: trimmedKey, name: trimmedName })
      });

      if (res.ok) {
        const data = await res.json();
        if (data?.key) {
          const imported: KeyItem = {
            id: data.key.id,
            name: data.key.name,
            prefix: data.key.keyPrefix,
            created_at: new Date().toISOString().split('T')[0],
            last_used: 'Never',
            last_ip: 'N/A',
            project: 'Imported',
            env: 'Production',
            status: 'ACTIVE',
            expires_in_days: 0
          };
          setKeys([imported, ...keys]);
          setAddKeySuccess(true);
          setTimeout(() => {
            setShowAddKeyModal(false);
            setAddKeyValue("");
            setAddKeyName("");
            setAddKeySuccess(false);
          }, 1500);
          return;
        }
      }
      const err = await res.json().catch(() => ({}));
      setAddKeyError(err.error || 'Failed to import key.');
    } catch {
      setAddKeyError('Network error connecting to key service.');
    }
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

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              setShowAddKeyModal(true);
              setAddKeyValue("");
              setAddKeyName("");
              setAddKeyError(null);
              setAddKeySuccess(false);
            }}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-all"
          >
            <Upload className="w-4 h-4" />
            Add Existing Key
          </button>
          <button
            onClick={() => {
              setShowCreateModal(true);
              setCreatedSecret(null);
              setNewKeyName("");
            }}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-lg shadow-blue-500/20 transition-all"
          >
            <Plus className="w-4 h-4" />
            Generate New Key
          </button>
        </div>
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

      {/* Add Existing Key Modal */}
      {showAddKeyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg bg-slate-950 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Upload className="w-4 h-4 text-emerald-400" />
                Add Existing API Key
              </h3>
              <button onClick={() => setShowAddKeyModal(false)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-xl text-blue-300 text-xs">
              Paste a key you received from your enterprise admin or another source. The key will be validated and its hash stored securely.
            </div>

            {addKeyError && (
              <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{addKeyError}</span>
              </div>
            )}

            {addKeySuccess ? (
              <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs text-center space-y-1">
                <ShieldCheck className="w-6 h-6 mx-auto text-emerald-400" />
                <p className="font-semibold text-white">Key Added Successfully!</p>
                <p className="text-slate-400">The key has been validated and securely stored.</p>
              </div>
            ) : (
              <div className="space-y-4 text-xs">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Key Name / Description</label>
                  <input
                    type="text"
                    value={addKeyName}
                    onChange={(e) => { setAddKeyName(e.target.value); setAddKeyError(null); }}
                    placeholder="e.g. Enterprise Team Key, Master Admin Key"
                    className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-white placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">API Key</label>
                  <input
                    type="text"
                    value={addKeyValue}
                    onChange={(e) => { setAddKeyValue(e.target.value); setAddKeyError(null); }}
                    placeholder="Paste your API key or license key"
                    className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-white font-mono placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
                  />
                  <p className="text-[10px] text-slate-500 mt-1">
                    Accepts any key format: enterprise distributed keys, master keys, or third-party keys.
                  </p>
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    onClick={() => setShowAddKeyModal(false)}
                    className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleAddExistingKey}
                    disabled={!addKeyValue.trim() || !addKeyName.trim()}
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-black rounded-xl text-xs font-semibold shadow-lg shadow-emerald-500/20"
                  >
                    Import Key
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
