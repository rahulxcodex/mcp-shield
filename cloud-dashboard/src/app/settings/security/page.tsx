"use client";

import { useState } from "react";
import { 
  ShieldCheck, 
  Smartphone, 
  Laptop, 
  Globe, 
  Key, 
  Check, 
  Lock, 
  AlertCircle,
  QrCode,
  Building,
  Trash2
} from "lucide-react";

interface DeviceSession {
  id: string;
  device: string;
  browser: string;
  ip: string;
  location: string;
  lastActive: string;
  isCurrent: boolean;
}

export default function SecuritySettingsPage() {
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [showMfaModal, setShowMfaModal] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const [ssoDomain, setSsoDomain] = useState("enterprise.acme-corp.com");
  const [ssoProvider, setSsoProvider] = useState("okta");
  const [ssoConfigured, setSsoConfigured] = useState(false);
  const [sessions, setSessions] = useState<DeviceSession[]>([
    {
      id: "sess-1",
      device: "Windows 11 Workstation",
      browser: "Chrome 134.0",
      ip: "103.42.112.98",
      location: "Bengaluru, India",
      lastActive: "Active Now",
      isCurrent: true
    },
    {
      id: "sess-2",
      device: "MacBook Pro (M3 Max)",
      browser: "Safari 18.2",
      ip: "142.250.190.46",
      location: "San Jose, CA, United States",
      lastActive: "2 hours ago",
      isCurrent: false
    }
  ]);
  const [ipAllowlist, setIpAllowlist] = useState("103.42.112.0/24\n142.250.0.0/16");
  const [ipSaved, setIpSaved] = useState(false);

  const handleRevokeSession = (id: string) => {
    setSessions(sessions.filter((s) => s.id !== id));
  };

  const handleVerifyMfa = () => {
    if (mfaCode.length === 6) {
      setMfaEnabled(true);
      setShowMfaModal(false);
      setMfaCode("");
    }
  };

  return (
    <div className="max-w-4xl space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white mb-1.5 flex items-center gap-2">
          <ShieldCheck className="w-6 h-6 text-blue-400" />
          Security, Authentication & Sessions
        </h1>
        <p className="text-xs text-slate-400">
          Manage multi-factor authentication, enterprise SAML/OIDC SSO, session policies, and corporate device boundaries.
        </p>
      </div>

      {/* Multi-Factor Authentication */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <Smartphone className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white">Multi-Factor Authentication (2FA)</h2>
              <p className="text-xs text-slate-400">Secure sign-in with Google Authenticator, 1Password, or YubiKey TOTP.</p>
            </div>
          </div>
          <button
            onClick={() => {
              if (mfaEnabled) {
                setMfaEnabled(false);
              } else {
                setShowMfaModal(true);
              }
            }}
            className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold transition-all ${
              mfaEnabled
                ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                : "bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-500/20"
            }`}
          >
            {mfaEnabled ? "Enabled (Click to Disable)" : "Enable 2FA"}
          </button>
        </div>

        {showMfaModal && (
          <div className="p-4 bg-slate-950 border border-slate-700 rounded-xl space-y-3 mt-4 animate-in fade-in">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
              <QrCode className="w-4 h-4 text-blue-400" />
              Scan QR code in Authenticator app
            </div>
            <div className="p-3 bg-slate-900 rounded-lg text-center font-mono text-xs text-slate-300 border border-slate-800">
              SECRET KEY: JBSWY3DPEHPK3PXP
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                maxLength={6}
                placeholder="6-digit code..."
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ""))}
                className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500 font-mono tracking-widest text-center"
              />
              <button
                onClick={handleVerifyMfa}
                disabled={mfaCode.length !== 6}
                className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold"
              >
                Verify & Activate
              </button>
              <button
                onClick={() => setShowMfaModal(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Enterprise SAML / OIDC Single Sign-On */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
              <Building className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white">Enterprise SSO (SAML 2.0 & OIDC)</h2>
              <p className="text-xs text-slate-400">Delegate authentication to your corporate Identity Provider (IdP).</p>
            </div>
          </div>
          <span className={`px-2.5 py-1 text-[10px] rounded-md font-semibold uppercase tracking-wider ${
            ssoConfigured
              ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
              : "bg-slate-800 text-slate-400 border border-slate-700"
          }`}>
            {ssoConfigured ? "SSO Active" : "Unconfigured"}
          </span>
        </div>

        <div className="grid grid-cols-2 gap-4 text-xs">
          <div>
            <label className="block text-[11px] font-medium text-slate-300 uppercase tracking-wider mb-1">
              Identity Provider (IdP)
            </label>
            <select
              value={ssoProvider}
              onChange={(e) => setSsoProvider(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="okta">Okta Enterprise SSO (SAML 2.0)</option>
              <option value="azure">Microsoft Azure Entra ID</option>
              <option value="google">Google Workspace (Cloud Identity)</option>
              <option value="ping">PingIdentity / PingFederate</option>
            </select>
          </div>

          <div>
            <label className="block text-[11px] font-medium text-slate-300 uppercase tracking-wider mb-1">
              Verified Corporate Domain
            </label>
            <input
              type="text"
              value={ssoDomain}
              onChange={(e) => setSsoDomain(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>

        <div className="mt-4 pt-4 border-t border-slate-800/80 flex items-center justify-between">
          <span className="text-[11px] text-slate-500">
            ACS URL: <code className="text-slate-400">https://mcpshield.dev/api/v1/auth/saml/callback</code>
          </span>
          <button
            onClick={() => setSsoConfigured(true)}
            className="px-4 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold shadow-lg shadow-purple-500/20"
          >
            {ssoConfigured ? "Update IdP Metadata" : "Configure IdP Connection"}
          </button>
        </div>
      </div>

      {/* Active Device & Session Management */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
        <h2 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
          <Laptop className="w-4 h-4 text-blue-400" />
          Active Sessions & Authorized Devices
        </h2>
        <p className="text-xs text-slate-400 mb-4">
          Review and revoke active JWT access tokens and devices currently authorized to access this organization.
        </p>

        <div className="space-y-3">
          {sessions.map((sess) => (
            <div
              key={sess.id}
              className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center justify-between text-xs"
            >
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">
                  <Laptop className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2 font-medium text-slate-200">
                    <span>{sess.device}</span>
                    {sess.isCurrent && (
                      <span className="px-1.5 py-0.2 bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded text-[9px] font-semibold uppercase">
                        Current Session
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-0.5">
                    {sess.browser} • IP: {sess.ip} • {sess.location} • Last active: {sess.lastActive}
                  </div>
                </div>
              </div>

              {!sess.isCurrent && (
                <button
                  onClick={() => handleRevokeSession(sess.id)}
                  className="flex items-center gap-1 px-2.5 py-1 text-xs text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  Revoke
                </button>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* IP Allowlisting */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
        <h2 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
          <Globe className="w-4 h-4 text-blue-400" />
          IP & CIDR Allowlisting
        </h2>
        <p className="text-xs text-slate-400 mb-3">
          Restrict organization console access and CLI telemetry ingestion to corporate VPN CIDR blocks.
        </p>
        <textarea
          rows={3}
          value={ipAllowlist}
          onChange={(e) => setIpAllowlist(e.target.value)}
          className="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 font-mono text-xs text-slate-200 focus:outline-none focus:border-blue-500"
          placeholder="One CIDR block per line (e.g. 192.168.1.0/24)..."
        />
        <div className="mt-3 flex justify-end">
          <button
            onClick={() => {
              setIpSaved(true);
              setTimeout(() => setIpSaved(false), 2000);
            }}
            className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold"
          >
            {ipSaved ? "Allowlist Enforced ✓" : "Save IP Restrictions"}
          </button>
        </div>
      </div>
    </div>
  );
}
