import LandingNavbar from "@/components/LandingNavbar";
import { ShieldCheck, Database, EyeOff, Lock, Trash2, Globe2, FileText } from "lucide-react";
import Link from "next/link";

export const metadata = {
  title: "Privacy Policy | MCP Shield",
  description: "MCP Shield Privacy Policy detailing zero-payload telemetry, metadata schema, RLS data isolation, and GDPR/CCPA rights."
};

export default function PrivacyPage() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-50">
      <LandingNavbar />
      <main className="max-w-4xl mx-auto px-6 py-16 space-y-10 text-xs leading-relaxed text-slate-300">
        
        {/* Header */}
        <div className="space-y-3">
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-semibold">
            <ShieldCheck className="w-3.5 h-3.5" />
            Data Protection & Privacy Architecture
          </div>
          <h1 className="text-3xl font-bold text-white">Privacy Policy</h1>
          <p className="text-slate-400">
            Effective Date: September 2026 • Last Reviewed: September 2026
          </p>
        </div>

        {/* 1. Zero-Payload Guarantee */}
        <section className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <EyeOff className="w-4 h-4 text-emerald-400" />
            1. Zero-Customer-Payload Architecture
          </h2>
          <p>
            MCP Shield is engineered from the ground up around the invariant of <strong>Zero-Customer-Payload Transmission</strong>. When running the <code>mcpshld</code> proxy locally or within your internal private subnets:
          </p>
          <ul className="list-disc pl-5 space-y-1.5 text-slate-300">
            <li><strong>No Raw Prompts:</strong> Raw prompt texts, system instructions, and agent reasoning chains are processed strictly in local memory and are never transmitted to MCP Shield servers.</li>
            <li><strong>No Source Code or File Ingestion:</strong> Files inspected by MCP tools remain strictly within your local process sandbox. Neither AST parse trees nor source contents leave your environment.</li>
            <li><strong>Local DLP Tokenization:</strong> Sensitive tokens (API keys, credit card numbers, PII) detected by our format-preserving encryption (FPE) engine are redacted or replaced locally before reaching MCP servers.</li>
          </ul>
        </section>

        {/* 2. Metadata Schema */}
        <section className="space-y-4">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Database className="w-4 h-4 text-blue-400" />
            2. Telemetry Metadata Schema
          </h2>
          <p>
            If you connect your proxy to the MCP Shield Cloud Management Console, only non-reversible execution metadata is collected:
          </p>
          <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 font-mono text-[11px] text-slate-300 space-y-2">
            <div className="text-emerald-400 font-semibold">// Structure of Cloud Telemetry Event Payload:</div>
            <pre className="text-slate-400 overflow-x-auto">{`{
  "event_id": "evt_9f81bc28-e4b3-490a-a28e-4b39cd84091a",
  "org_id": "org_744fb1fb-de02-47c1-8b85-7ce3d6506838",
  "timestamp": "2026-09-09T16:30:00Z",
  "tool_name": "execute_command",           // Sanitized tool identifier
  "policy_action": "BLOCK",                  // ALLOW | BLOCK | AUDIT
  "rule_code": "AST_DESTRUCTIVE_EXECUTION",  // Specific threat identifier
  "pipeline_latency_ms": 0.19,               // Engine overhead metric
  "client_version": "mcpshld@1.0.25",        // Engine version string
  "merkle_leaf_hmac": "e3b0c44298fc1c149af..." // SHA-256 integrity hash
}`}</pre>
          </div>
        </section>

        {/* 3. Storage Security & Multi-Tenant Isolation */}
        <section className="space-y-4">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Lock className="w-4 h-4 text-purple-400" />
            3. Multi-Tenant Isolation & Storage Security
          </h2>
          <p>
            All cloud metadata is stored in enterprise-grade PostgreSQL managed via Supabase:
          </p>
          <div className="grid sm:grid-cols-3 gap-3">
            <div className="p-3.5 rounded-xl bg-slate-900/40 border border-slate-800 space-y-1">
              <strong className="text-white block">PostgreSQL RLS</strong>
              <p className="text-[11px] text-slate-400">
                Every table enforces strict Row-Level Security policies; records are isolated strictly by organization UUID at the database engine level.
              </p>
            </div>
            <div className="p-3.5 rounded-xl bg-slate-900/40 border border-slate-800 space-y-1">
              <strong className="text-white block">AES-256 at Rest</strong>
              <p className="text-[11px] text-slate-400">
                All persistent volumes and database storage engines are encrypted using hardware-backed AES-256 encryption.
              </p>
            </div>
            <div className="p-3.5 rounded-xl bg-slate-900/40 border border-slate-800 space-y-1">
              <strong className="text-white block">TLS 1.3 in Transit</strong>
              <p className="text-[11px] text-slate-400">
                All HTTP, WebSocket, and gRPC endpoints enforce modern TLS 1.3 ciphers with HSTS preloaded.
              </p>
            </div>
          </div>
        </section>

        {/* 4. Data Retention & Deletion Lifecycle */}
        <section className="space-y-4">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Trash2 className="w-4 h-4 text-amber-400" />
            4. Data Retention & Hard-Deletion Lifecycle
          </h2>
          <div className="space-y-2 text-slate-300">
            <p>
              Telemetry logs and threat audit records adhere to strict time-to-live (TTL) lifecycles:
            </p>
            <ul className="list-disc pl-5 space-y-1 text-slate-400">
              <li><strong>Pro Plans:</strong> Rolling 30-day retention. Expired metadata is pruned daily via automated database cron jobs.</li>
              <li><strong>Enterprise Plans:</strong> Configurable retention between 30 and 365 days, with optional cold-storage export to customer S3/GCS buckets.</li>
              <li><strong>Hard Deletion (GDPR Article 17):</strong> Organization owners may trigger a full hard deletion via the admin console or by contacting <code>privacy@mcp-shield.dev</code>. Executing hard deletion invokes immediate cascading removal across all production tables, with automated disaster-recovery backup purges completing within 14 days.</li>
            </ul>
          </div>
        </section>

        {/* 5. GDPR, CCPA & Subprocessors */}
        <section className="space-y-3">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Globe2 className="w-4 h-4 text-blue-400" />
            5. Global Privacy Rights & Subprocessors
          </h2>
          <p>
            We comply fully with the General Data Protection Regulation (GDPR) and California Consumer Privacy Act (CCPA):
          </p>
          <ul className="list-disc pl-5 space-y-1 text-slate-400">
            <li><strong>No Sale of Data:</strong> We never sell, rent, or monetize personal data or telemetry metadata.</li>
            <li><strong>Data Processing Agreement (DPA):</strong> Standard Contractual Clauses (SCCs) and our enterprise DPA are available upon request for enterprise customers.</li>
            <li><strong>Subprocessor Directory:</strong> Review our verified third-party infrastructure providers on our <Link href="/subprocessors" className="text-blue-400 underline hover:text-blue-300">Authorized Subprocessors directory</Link>.</li>
          </ul>
        </section>

      </main>
    </div>
  );
}
