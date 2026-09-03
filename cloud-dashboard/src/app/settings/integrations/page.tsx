"use client";

import { useState } from "react";
import { Webhook, MessageSquare, Bell, Radio, Check, Save } from "lucide-react";

export default function IntegrationsSettingsPage() {
  const [webhookUrl, setWebhookUrl] = useState("https://hooks.slack.com/services/T00/B00/XXXXXX");
  const [slackAlerts, setSlackAlerts] = useState(true);
  const [teamsAlerts, setTeamsAlerts] = useState(false);
  const [emailAlerts, setEmailAlerts] = useState(true);
  const [pagerdutyKey, setPagerdutyKey] = useState("");
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white mb-1.5 flex items-center gap-2">
          <Webhook className="w-6 h-6 text-blue-400" />
          Alert Integrations & Webhooks
        </h1>
        <p className="text-xs text-slate-400">
          Stream high-severity threat intercepts and zero-day containment alerts to Slack, Microsoft Teams, SIEM, or PagerDuty.
        </p>
      </div>

      {/* Outbound Webhook */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-4">
        <h2 className="text-sm font-semibold text-white flex items-center gap-2">
          <Radio className="w-4 h-4 text-blue-400" />
          Outbound Threat Webhook (JSON-RPC / SIEM)
        </h2>
        <p className="text-xs text-slate-400">
          Every blocked subshell or intercepted data exfiltration fires an HMAC-signed POST request with the AST violation payload.
        </p>
        <input
          type="url"
          value={webhookUrl}
          onChange={(e) => setWebhookUrl(e.target.value)}
          placeholder="https://siem.corp.internal/api/v1/mcp-alerts"
          className="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-2 text-xs text-white placeholder:text-slate-500 font-mono focus:outline-none focus:border-blue-500"
        />
      </div>

      {/* Alert Destinations */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-4">
        <h2 className="text-sm font-semibold text-white flex items-center gap-2">
          <Bell className="w-4 h-4 text-emerald-400" />
          Incident Notification Channels
        </h2>

        <div className="space-y-3">
          <label className="flex items-center justify-between p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 cursor-pointer">
            <div className="flex items-center gap-3">
              <MessageSquare className="w-4 h-4 text-emerald-400" />
              <div>
                <div className="text-xs font-medium text-slate-200">Slack Instant Threat Alerts</div>
                <div className="text-[11px] text-slate-400">Notify #security-incidents when CRITICAL AST exploits are blocked.</div>
              </div>
            </div>
            <input
              type="checkbox"
              checked={slackAlerts}
              onChange={(e) => setSlackAlerts(e.target.checked)}
              className="w-4 h-4 rounded border-slate-700 text-blue-600 focus:ring-0"
            />
          </label>

          <label className="flex items-center justify-between p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 cursor-pointer">
            <div className="flex items-center gap-3">
              <MessageSquare className="w-4 h-4 text-blue-400" />
              <div>
                <div className="text-xs font-medium text-slate-200">Microsoft Teams Channel Alerts</div>
                <div className="text-[11px] text-slate-400">Dispatch adaptive threat cards into corporate Teams security channels.</div>
              </div>
            </div>
            <input
              type="checkbox"
              checked={teamsAlerts}
              onChange={(e) => setTeamsAlerts(e.target.checked)}
              className="w-4 h-4 rounded border-slate-700 text-blue-600 focus:ring-0"
            />
          </label>

          <label className="flex items-center justify-between p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 cursor-pointer">
            <div className="flex items-center gap-3">
              <Bell className="w-4 h-4 text-purple-400" />
              <div>
                <div className="text-xs font-medium text-slate-200">Executive Security Email Digest</div>
                <div className="text-[11px] text-slate-400">Daily rollups of tokenized secrets and blocked zero-day command attempts.</div>
              </div>
            </div>
            <input
              type="checkbox"
              checked={emailAlerts}
              onChange={(e) => setEmailAlerts(e.target.checked)}
              className="w-4 h-4 rounded border-slate-700 text-blue-600 focus:ring-0"
            />
          </label>
        </div>
      </div>

      {/* PagerDuty */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-3">
        <h2 className="text-sm font-semibold text-white">PagerDuty On-Call Integration</h2>
        <p className="text-xs text-slate-400">
          Trigger PagerDuty on-call security engineer pages for uncontained container escapes or mass honeypot tripwire triggers.
        </p>
        <input
          type="password"
          value={pagerdutyKey}
          onChange={(e) => setPagerdutyKey(e.target.value)}
          placeholder="PagerDuty Integration Routing Key..."
          className="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-2 text-xs text-white placeholder:text-slate-500 font-mono focus:outline-none focus:border-blue-500"
        />
      </div>

      <div className="flex justify-end pt-2">
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-lg shadow-blue-500/20 transition-all"
        >
          {saved ? <Check className="w-4 h-4 text-emerald-300" /> : <Save className="w-4 h-4" />}
          <span>{saved ? "Settings Saved" : "Save Integrations"}</span>
        </button>
      </div>
    </div>
  );
}
