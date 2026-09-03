import Link from "next/link";
import { ShieldCheck, FileCheck, Lock, Globe, Server, Download, CheckCircle2, AlertCircle } from "lucide-react";
import LandingNavbar from "@/components/LandingNavbar";

export const metadata = {
  title: "Compliance & Trust Center | MCP Shield",
  description: "Enterprise security architecture, SOC 2 audit-evidence reporting, cryptographic zero-knowledge payload handling, and data residency specifications."
};

export default function CompliancePage() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-50">
      <LandingNavbar />

      <main className="max-w-5xl mx-auto px-6 py-16 space-y-12">
        {/* Header */}
        <div className="space-y-4 text-center max-w-2xl mx-auto">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold">
            <ShieldCheck className="w-4 h-4" />
            Security & Trust Center
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            Security Architecture & Compliance Evidence
          </h1>
          <p className="text-sm text-slate-400 leading-relaxed">
            MCP Shield provides cryptographic audit controls, tamper-evident logging, and in-memory AST containment to accelerate your enterprise compliance.
          </p>
        </div>

        {/* Clear Trust Disclaimer Alert */}
        <div className="p-4 rounded-2xl bg-blue-500/10 border border-blue-500/20 text-xs text-blue-200 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
          <div className="leading-relaxed">
            <strong className="text-white block mb-0.5">SOC 2 Audit-Evidence Notice</strong>
            MCP Shield provides cryptographically verifiable audit trails and zero-trust technical safeguards (CC6.1, CC6.6, CC6.8, CC7.2). Utilizing MCP Shield supports your organization's SOC 2 readiness but does not automatically certify your organization without your independent third-party auditor review.
          </div>
        </div>

        {/* Core Guarantees Grid */}
        <div className="grid md:grid-cols-2 gap-6">
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 w-fit">
              <Lock className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-white">Zero Customer Payload Storage</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Tree-sitter AST analysis and shell command inspection execute entirely in ephemeral memory on your proxy instance. Raw tool inputs and prompt parameters are never persisted to cloud storage.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="p-2.5 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400 w-fit">
              <FileCheck className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-white">Tamper-Evident SHA-256 Hash Chaining</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Every intercepted threat event is hashed and chained into a cryptographically continuous audit ledger. Any retroactive tampering invalidates the verification signature.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400 w-fit">
              <Globe className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-white">Data Residency & Region Pinning</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Enterprise fleets can pin metadata, license verification, and telemetry ingestion to specific geographical jurisdictions (US-East, EU-Frankfurt, and APAC-Tokyo).
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400 w-fit">
              <Server className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-white">Operational Service Level Agreement</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              MCP Shield operates with an operational target of 99.9% uptime for cloud telemetry endpoints. Mission-critical on-premises and air-gapped clusters operate 100% autonomously without cloud dependency.
            </p>
          </div>
        </div>

        {/* Cryptographic Specifications */}
        <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6 space-y-4">
          <h2 className="text-base font-semibold text-white">Cryptographic Implementation Standards</h2>
          <div className="grid sm:grid-cols-3 gap-4 text-xs">
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
              <div className="text-slate-400 mb-1">In-Transit Encryption</div>
              <div className="font-mono text-slate-200 font-semibold">TLS 1.3 / mTLS</div>
            </div>
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
              <div className="text-slate-400 mb-1">Telemetry Signatures</div>
              <div className="font-mono text-slate-200 font-semibold">HMAC-SHA256</div>
            </div>
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
              <div className="text-slate-400 mb-1">License Key Cryptography</div>
              <div className="font-mono text-slate-200 font-semibold">Ed25519 Asymmetric</div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
