import LandingNavbar from "@/components/LandingNavbar";

export const metadata = {
  title: "Terms of Service | MCP Shield",
  description: "Terms and conditions governing the use of MCP Shield open-source CLI, proxy gateway, and cloud enterprise dashboard."
};

export default function TermsPage() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-50">
      <LandingNavbar />
      <main className="max-w-4xl mx-auto px-6 py-16 space-y-8 text-xs leading-relaxed text-slate-300">
        <h1 className="text-3xl font-bold text-white mb-2">Terms of Service</h1>
        <p className="text-slate-400">Last Updated: September 2026</p>

        <section className="space-y-3">
          <h2 className="text-base font-semibold text-white">1. Agreement to Terms</h2>
          <p>
            By deploying the MCP Shield open-source package (<code>mcpshld</code>) or subscribing to the MCP Shield Cloud Console, you agree to comply with and be bound by these Terms of Service.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-base font-semibold text-white">2. Open-Source vs Commercial Licensing</h2>
          <p>
            The core AST parser, DLP sanitizer, and local proxy gateway are open-source software under the MIT License. Enterprise multi-seat centralized telemetry, SAML SSO, and fleet key distribution require an active commercial subscription or signed enterprise agreement.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-base font-semibold text-white">3. Operational SLA & Availability</h2>
          <p>
            Cloud services are provided with a target operational availability of 99.9%. Dedicated 99.99% availability SLAs, custom incident escalation paths, and financial remedies require a customized Enterprise Agreement.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-base font-semibold text-white">4. Acceptable Use & Security</h2>
          <p>
            You agree not to use MCP Shield to reverse engineer or bypass third-party authorization systems or conduct unauthorized penetration attacks against targets without written consent.
          </p>
        </section>
      </main>
    </div>
  );
}
