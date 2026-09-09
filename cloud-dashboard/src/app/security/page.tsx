import LandingNavbar from "@/components/LandingNavbar";
import { ShieldAlert, Terminal, Lock, Bug, Mail, Clock, CheckCircle2, AlertTriangle, Key, ShieldCheck, FileCheck2 } from "lucide-react";
import Link from "next/link";

export const metadata = {
  title: "Security Disclosure & Architecture | MCP Shield",
  description: "Vulnerability disclosure policy, response SLAs, Safe Harbor commitment, and cryptographic specifications for MCP Shield."
};

export default function SecurityPage() {
  const slas = [
    { severity: "Critical", response: "< 24 hours", fix: "< 7 business days", desc: "Remote code execution, egress sandbox escapes, auth bypasses" },
    { severity: "High", response: "< 48 hours", fix: "< 14 business days", desc: "SSRF filter escapes, credential disclosure, policy bypasses" },
    { severity: "Medium", response: "< 72 hours", fix: "< 30 business days", desc: "Rate-limiting issues, non-sensitive information leakage" },
    { severity: "Low", response: "< 5 business days", fix: "Next scheduled release", desc: "Hardening opportunities, minor edge cases" }
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50">
      <LandingNavbar />
      <main className="max-w-4xl mx-auto px-6 py-16 space-y-10 text-xs leading-relaxed text-slate-300">
        
        {/* Header */}
        <div className="space-y-3">
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs font-semibold">
            <ShieldAlert className="w-3.5 h-3.5" />
            Vulnerability Disclosure & Defense Architecture
          </div>
          <h1 className="text-3xl font-bold text-white">Security at MCP Shield</h1>
          <p className="text-slate-400 max-w-2xl">
            We treat security as our core invariant. Learn about our coordinated vulnerability disclosure program, response SLAs, Safe Harbor legal protections, and defense-in-depth architecture.
          </p>
        </div>

        {/* Vulnerability Reporting & SLAs */}
        <section className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Bug className="w-4 h-4 text-rose-400" />
            Coordinated Vulnerability Disclosure & SLAs
          </h2>
          <p>
            If you discover a security vulnerability in the <code>mcpshld</code> package, the core runtime proxy, or our cloud platform, please disclose it to us responsibly. We adhere to strict triage and response SLAs:
          </p>

          <div className="grid sm:grid-cols-2 gap-3 pt-1">
            <div className="p-3.5 bg-slate-950 rounded-xl font-mono border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-2">
                <Mail className="w-4 h-4 text-rose-400" />
                Security Triage Email:
              </span>
              <a href="mailto:security@mcp-shield.dev" className="text-emerald-400 hover:underline">
                security@mcp-shield.dev
              </a>
            </div>
            <div className="p-3.5 bg-slate-950 rounded-xl font-mono border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-2">
                <FileCheck2 className="w-4 h-4 text-blue-400" />
                RFC 9116 Metadata:
              </span>
              <Link href="/.well-known/security.txt" className="text-blue-400 hover:underline">
                /.well-known/security.txt
              </Link>
            </div>
          </div>

          <div className="border border-slate-800 rounded-xl overflow-hidden mt-4">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase text-[10px] font-semibold tracking-wider">
                <tr>
                  <th className="p-3">Severity</th>
                  <th className="p-3">Triage SLA</th>
                  <th className="p-3">Remediation SLA</th>
                  <th className="p-3">Example Scope</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {slas.map((s, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/30">
                    <td className="p-3 font-semibold text-white">{s.severity}</td>
                    <td className="p-3 font-mono text-emerald-400">{s.response}</td>
                    <td className="p-3 font-mono text-blue-400">{s.fix}</td>
                    <td className="p-3 text-slate-400 text-[11px]">{s.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p className="text-slate-400 text-[11px]">
            Please do not open public GitHub issues for security vulnerabilities until a patched advisory and CVE have been issued.
          </p>
        </section>

        {/* Safe Harbor */}
        <section className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            Security Research Safe Harbor
          </h2>
          <p>
            We consider security research conducted in good faith under this policy to be authorized and protected. When conducting research within the scope defined below:
          </p>
          <ul className="list-disc pl-5 space-y-1.5 text-slate-300">
            <li>We will <strong>not</strong> initiate legal action against you under the Computer Fraud and Abuse Act (CFAA), DMCA § 1201, or equivalent state or international laws.</li>
            <li>We will <strong>not</strong> pursue claims for breach of terms of service related to your good-faith testing activities.</li>
            <li>We will collaborate with you in attributing discovery credit via our security advisories and Hall of Fame.</li>
            <li>If a third party initiates legal action against you while operating under this policy, we will affirm that your research was authorized.</li>
          </ul>
        </section>

        {/* Program Scope */}
        <section className="space-y-4">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Terminal className="w-4 h-4 text-amber-400" />
            Research Scope
          </h2>
          <div className="grid md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 space-y-2">
              <span className="font-semibold text-emerald-400 text-xs uppercase tracking-wider block">
                In-Scope Targets
              </span>
              <ul className="list-disc pl-4 space-y-1 text-[11px] text-slate-300">
                <li><code>mcpshld</code> CLI & Core Engine (`src/` runtime proxy)</li>
                <li>Egress proxy SSRF containment & DNS pinning logic</li>
                <li>Tree-sitter AST shell firewall & token sanitization</li>
                <li>Cloud Dashboard web APIs (`cloud-dashboard/src/app/api`)</li>
                <li>Cryptographic HMAC audit ledger verification</li>
              </ul>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 space-y-2">
              <span className="font-semibold text-rose-400 text-xs uppercase tracking-wider block">
                Out-of-Scope Targets
              </span>
              <ul className="list-disc pl-4 space-y-1 text-[11px] text-slate-300">
                <li>Upstream LLM provider APIs (OpenAI, Anthropic, Google)</li>
                <li>Denial-of-service (DoS/DDoS) against shared infrastructure</li>
                <li>Automated aggressive volumetric scanning without rate limits</li>
                <li>Social engineering, phishing, or physical attacks against personnel</li>
              </ul>
            </div>
          </div>
        </section>

        {/* Key Security Invariants */}
        <section className="space-y-4">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Lock className="w-4 h-4 text-blue-400" />
            Defense-in-Depth Architectural Invariants
          </h2>
          <div className="grid sm:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 space-y-1.5">
              <strong className="text-white block">Zero-Plaintext Storage</strong>
              <p className="text-[11px] text-slate-400">
                API keys and tokens are hashed with SHA-256 before database persistence. Raw tool parameters and prompt strings execute strictly in local memory and are never persisted to cloud storage.
              </p>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 space-y-1.5">
              <strong className="text-white block">Egress SSRF & DNS Pinning</strong>
              <p className="text-[11px] text-slate-400">
                The egress proxy pins resolved socket IPs to prevent DNS rebinding, enforces 5-hop recursive redirect containment, and strictly blocks RFC 1918, link-local, and cloud metadata (169.254.169.254).
              </p>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 space-y-1.5">
              <strong className="text-white block">Fail-Closed Boundary</strong>
              <p className="text-[11px] text-slate-400">
                Any unparseable AST structure, socket failure, session discrepancy, or rate budget overrun triggers immediate fail-closed denial with standardized JSON-RPC error codes.
              </p>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 space-y-1.5">
              <strong className="text-white block">Tamper-Evident Merkle Ledger</strong>
              <p className="text-[11px] text-slate-400">
                Every policy violation and threat event is chained using HMAC-SHA256 hashes into a cryptographic audit ledger, guaranteeing mathematical non-repudiation of past audit logs.
              </p>
            </div>
          </div>
        </section>

        {/* PGP Encryption */}
        <section className="p-5 rounded-2xl bg-slate-900/40 border border-slate-800 space-y-2">
          <h2 className="text-xs font-semibold text-white flex items-center gap-2">
            <Key className="w-3.5 h-3.5 text-amber-400" />
            PGP Encryption Fingerprint
          </h2>
          <p className="text-[11px] text-slate-400">
            For confidential disclosures containing sensitive proof-of-concept exploits, please encrypt your communication using our PGP key:
          </p>
          <pre className="p-3 bg-slate-950 rounded-xl font-mono text-[11px] text-emerald-400 border border-slate-800 overflow-x-auto">
            Fingerprint: 4A9F 81BC E290 6FD1 7E34 90AA 28E4 B39C D840 91A2
          </pre>
        </section>

      </main>
    </div>
  );
}
