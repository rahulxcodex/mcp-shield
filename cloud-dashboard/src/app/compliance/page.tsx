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

        {/* Compliance Control Support Matrix */}
        <div className="space-y-4">
          <div className="space-y-1">
            <h2 className="text-xl font-bold text-white">Technical Compliance Control Support Matrix</h2>
            <p className="text-xs text-slate-400">
              Detailed mapping of MCP Shield technical safeguards to regulatory and industry compliance frameworks.
            </p>
          </div>

          <div className="border border-slate-800 rounded-2xl overflow-hidden bg-slate-900/60">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase text-[10px] font-semibold tracking-wider">
                  <tr>
                    <th className="p-3.5">Framework</th>
                    <th className="p-3.5">Control ID</th>
                    <th className="p-3.5">Standard Requirement</th>
                    <th className="p-3.5">MCP Shield Technical Implementation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  <tr className="hover:bg-slate-800/30">
                    <td className="p-3.5 font-semibold text-white whitespace-nowrap">SOC 2 Type II</td>
                    <td className="p-3.5 font-mono text-blue-400 whitespace-nowrap">CC6.1</td>
                    <td className="p-3.5">Logical Access & Authorization Controls</td>
                    <td className="p-3.5 text-[11px] text-slate-300">Granular per-tool capability tokens, Ed25519 asymmetric signature verification, role-based authorization scopes, and automatic session isolation.</td>
                  </tr>
                  <tr className="hover:bg-slate-800/30">
                    <td className="p-3.5 font-semibold text-white whitespace-nowrap">SOC 2 Type II</td>
                    <td className="p-3.5 font-mono text-blue-400 whitespace-nowrap">CC6.6</td>
                    <td className="p-3.5">Boundary Protection & External Interfacing</td>
                    <td className="p-3.5 text-[11px] text-slate-300">Authoritative outbound SSRF filtering, socket DNS pinning, 5-hop redirect containment, RFC 1918 / 169.254.169.254 egress denial, and Tree-sitter AST shell firewall.</td>
                  </tr>
                  <tr className="hover:bg-slate-800/30">
                    <td className="p-3.5 font-semibold text-white whitespace-nowrap">SOC 2 Type II</td>
                    <td className="p-3.5 font-mono text-blue-400 whitespace-nowrap">CC6.7</td>
                    <td className="p-3.5">Data Transmission & Token Redaction</td>
                    <td className="p-3.5 text-[11px] text-slate-300">Enforced TLS 1.3 in-transit encryption with HSTS; local format-preserving encryption (FPE) bijective tokenization of secrets and PII before egress.</td>
                  </tr>
                  <tr className="hover:bg-slate-800/30">
                    <td className="p-3.5 font-semibold text-white whitespace-nowrap">SOC 2 Type II</td>
                    <td className="p-3.5 font-mono text-blue-400 whitespace-nowrap">CC6.8 / CC7.2</td>
                    <td className="p-3.5">Threat Detection & Anomaly Prevention</td>
                    <td className="p-3.5 text-[11px] text-slate-300">Real-time AST destructive command detection, multi-stage toxic flow tracking, sliding-window rate & token budget tripwires with fail-closed denial.</td>
                  </tr>
                  <tr className="hover:bg-slate-800/30">
                    <td className="p-3.5 font-semibold text-white whitespace-nowrap">HIPAA Security</td>
                    <td className="p-3.5 font-mono text-emerald-400 whitespace-nowrap">§ 164.312(b)</td>
                    <td className="p-3.5">Audit Controls & Non-Repudiation</td>
                    <td className="p-3.5 text-[11px] text-slate-300">Tamper-evident HMAC-SHA256 Merkle chain audit logging; mathematically verifiable non-repudiation of all agent-executed operations with zero-PII storage.</td>
                  </tr>
                  <tr className="hover:bg-slate-800/30">
                    <td className="p-3.5 font-semibold text-white whitespace-nowrap">ISO 27001:2022</td>
                    <td className="p-3.5 font-mono text-purple-400 whitespace-nowrap">A.8.20 / A.8.24</td>
                    <td className="p-3.5">Network Security & Use of Cryptography</td>
                    <td className="p-3.5 text-[11px] text-slate-300">Strict local socket routing, timing-safe cryptographic comparisons (`crypto.timingSafeEqual`), and hardware-accelerated AES-256 at rest.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Auditor Evidence Export */}
        <section className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Download className="w-4 h-4 text-blue-400" />
            Auditor Evidence Package & Verification Artifacts
          </h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            MCP Shield equips your compliance and security engineering teams with turnkey export tools to provide continuous audit evidence directly to external auditors (AICPA, ISO registrars, HIPAA compliance officers):
          </p>
          <div className="grid sm:grid-cols-2 gap-4 pt-1">
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <span className="font-semibold text-white text-xs block">CLI Merkle Ledger Export</span>
              <p className="text-[11px] text-slate-400">
                Export and cryptographically verify local audit logs without cloud connectivity:
              </p>
              <pre className="p-2.5 bg-slate-900 rounded-lg font-mono text-[10px] text-emerald-400 overflow-x-auto">
                npx mcpshld audit export --format=json --verify
              </pre>
            </div>
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <span className="font-semibold text-white text-xs block">Automated Security Verification</span>
              <p className="text-[11px] text-slate-400">
                Run the 26-point automated security audit harness directly in your CI/CD pipeline:
              </p>
              <pre className="p-2.5 bg-slate-900 rounded-lg font-mono text-[10px] text-blue-400 overflow-x-auto">
                npx tsx scripts/verify-external-audit.ts
              </pre>
            </div>
          </div>
        </section>

      </main>
    </div>
  );
}
