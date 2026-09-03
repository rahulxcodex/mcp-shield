import LandingNavbar from "@/components/LandingNavbar";
import { ShieldAlert, Terminal, Lock, Bug, Mail } from "lucide-react";

export const metadata = {
  title: "Security Disclosure & Architecture | MCP Shield",
  description: "Vulnerability disclosure policy, cryptographic specifications, and security practices for MCP Shield."
};

export default function SecurityPage() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-50">
      <LandingNavbar />
      <main className="max-w-4xl mx-auto px-6 py-16 space-y-8 text-xs leading-relaxed text-slate-300">
        <div className="space-y-2">
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs font-semibold">
            <ShieldAlert className="w-3.5 h-3.5" />
            Vulnerability Disclosure & Architecture
          </div>
          <h1 className="text-3xl font-bold text-white">Security at MCP Shield</h1>
          <p className="text-slate-400">
            Learn about our vulnerability reporting program, defense-in-depth architecture, and cryptographic invariants.
          </p>
        </div>

        <section className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Bug className="w-4 h-4 text-rose-400" />
            Coordinated Vulnerability Disclosure
          </h2>
          <p>
            We appreciate the security community's efforts in identifying potential vulnerabilities. If you discover a vulnerability in <code>mcpshld</code> or our cloud infrastructure, please email us directly:
          </p>
          <div className="p-3 bg-slate-950 rounded-xl font-mono text-emerald-400 border border-slate-800 flex items-center gap-2">
            <Mail className="w-4 h-4 text-slate-400" />
            security@mcp-shield.dev
          </div>
          <p className="text-slate-400 text-[11px]">
            Please do not open public GitHub issues for security vulnerabilities until a patched advisory has been released.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Lock className="w-4 h-4 text-blue-400" />
            Key Security Invariants
          </h2>
          <ul className="list-disc pl-5 space-y-2">
            <li><strong>Zero-Plaintext Storage:</strong> API keys and secrets are hashed with SHA-256 before database insertion; raw secrets are never logged or stored.</li>
            <li><strong>Timing-Safe Evaluation:</strong> Cryptographic signatures and webhook HMACs are compared using constant-time algorithms (<code>crypto.timingSafeEqual</code>) to prevent side-channel timing attacks.</li>
            <li><strong>Fail-Closed Design:</strong> In the event of an unparseable AST or communication error with external endpoints, the proxy fails closed and blocks potentially dangerous commands.</li>
            <li><strong>Sliding-Window Rate Limiting:</strong> In-memory rate limiters protect all authentication and API endpoints against brute force and abuse.</li>
          </ul>
        </section>
      </main>
    </div>
  );
}
