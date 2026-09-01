'use client';

import { useState, useEffect } from 'react';
import { Key, Copy, Check, Terminal } from 'lucide-react';

export default function GeneralSettingsPage() {
  const [orgId, setOrgId] = useState<string | null>(null);
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    async function loadOrg() {
      const orgRes = await fetch('/api/v1/organizations');
      const orgs = await orgRes.json();
      if (orgs.length > 0) {
        setOrgId(orgs[0].id);
      }
    }
    loadOrg();
  }, []);

  const generateKey = async () => {
    if (!orgId) {
      setError('No organization found. Please try again.');
      return;
    }
    
    setIsGenerating(true);
    setError('');
    try {
      const res = await fetch('/api/v1/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ organization_id: orgId })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to generate key');
      setApiKey(data.apiKey);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsGenerating(false);
    }
  };

  const copyToClipboard = () => {
    if (apiKey) {
      navigator.clipboard.writeText(apiKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="max-w-4xl">
      <h1 className="text-3xl font-bold mb-2 text-white">General Settings</h1>
      <p className="text-slate-400 mb-8">Manage your workspace API keys and configuration.</p>

      <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 mb-8">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Key className="h-5 w-5 text-slate-400" />
          API Keys (For CLI Agent)
        </h2>
        <p className="text-slate-400 text-sm mb-6">
          Generate a secret API key to pair your local <code>mcp-shield</code> CLI with this cloud dashboard.
        </p>

        {!apiKey ? (
          <button
            onClick={generateKey}
            disabled={isGenerating || !orgId}
            className="bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white font-medium py-2 px-4 rounded-md transition-colors"
          >
            {isGenerating ? 'Generating...' : 'Generate New API Key'}
          </button>
        ) : (
          <div className="space-y-4">
            <div className="p-4 bg-slate-950 border border-emerald-500/30 rounded-lg">
              <p className="text-xs text-emerald-400 font-bold uppercase mb-2">Your Secret Key (Copy it now, it won't be shown again)</p>
              <div className="flex items-center justify-between bg-slate-900 p-3 rounded border border-slate-800">
                <code className="text-emerald-300 font-mono text-sm">{apiKey}</code>
                <button onClick={copyToClipboard} className="text-slate-400 hover:text-white transition">
                  {copied ? <Check className="h-5 w-5 text-emerald-500" /> : <Copy className="h-5 w-5" />}
                </button>
              </div>
            </div>

            <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-800">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-2">
                <Terminal className="h-4 w-4" /> Next Steps:
              </h3>
              <p className="text-sm text-slate-400 font-mono bg-slate-950 p-2 rounded">
                npx mcp-shield link --key {apiKey}
              </p>
            </div>
          </div>
        )}
        {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
      </div>
    </div>
  );
}
