import LandingNavbar from "@/components/LandingNavbar";

export const metadata = {
  title: "Privacy Policy | MCP Shield",
  description: "MCP Shield Privacy Policy detailing zero-payload telemetry, data minimization, and GDPR/CCPA rights."
};

export default function PrivacyPage() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-50">
      <LandingNavbar />
      <main className="max-w-4xl mx-auto px-6 py-16 space-y-8 text-xs leading-relaxed text-slate-300">
        <h1 className="text-3xl font-bold text-white mb-2">Privacy Policy</h1>
        <p className="text-slate-400">Effective Date: September 2026</p>

        <section className="space-y-3">
          <h2 className="text-base font-semibold text-white">1. Data Minimization & Zero-Payload Architecture</h2>
          <p>
            MCP Shield is engineered under the principle of Zero-Trust and extreme data minimization. The MCP Shield CLI and proxy execute all AST parsing, DLP tokenization, and command tree inspections strictly within local memory. Under no circumstances are raw LLM prompts, agent reasoning traces, or sensitive customer payloads transferred to or stored on our servers.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-base font-semibold text-white">2. Information We Collect</h2>
          <p>When you utilize the MCP Shield cloud telemetry dashboard, we collect:</p>
          <ul className="list-disc pl-5 space-y-1">
            <li><strong>Account Data:</strong> Corporate email address, authentication credentials, and organizational role.</li>
            <li><strong>Telemetry Metadata:</strong> Cryptographic HMAC signatures, sanitized tool call names, rule violation IDs (e.g. <code>AST_SUBTREE_DESTRUCTIVE_EXECUTION</code>), execution timestamps, and client versions.</li>
            <li><strong>Billing Details:</strong> Payment transaction IDs and subscription tier status processed securely via Stripe or Razorpay. We do not store credit card numbers.</li>
          </ul>
        </section>

        <section className="space-y-3">
          <h2 className="text-base font-semibold text-white">3. Data Retention & Deletion</h2>
          <p>
            Standard telemetry metadata is retained for 30 days on Pro plans and up to 365 days on Enterprise plans. You may request immediate deletion of all organization records and telemetry by contacting security@mcp-shield.dev.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-base font-semibold text-white">4. GDPR & CCPA Compliance</h2>
          <p>
            We respect user rights regarding data access, rectification, and erasure under GDPR (EU) and CCPA (California). Data residency controls allow Enterprise customers to restrict all processing to EU or US regions.
          </p>
        </section>
      </main>
    </div>
  );
}
