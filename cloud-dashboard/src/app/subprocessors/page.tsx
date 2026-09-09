import LandingNavbar from "@/components/LandingNavbar";
import { Server, Database, CreditCard, ShieldCheck, Mail, Bell } from "lucide-react";
import Link from "next/link";

export const metadata = {
  title: "Authorized Subprocessors | MCP Shield",
  description: "Official directory of third-party infrastructure and service providers utilized by MCP Shield."
};

export default function SubprocessorsPage() {
  const subprocessors = [
    {
      name: "Vercel Inc.",
      purpose: "Edge CDN hosting, serverless compute, and TLS termination",
      dataProcessed: "Dashboard web assets, edge API ingress, IP routing metadata",
      location: "United States (Global Anycast Edge)",
      securityCertification: "SOC 2 Type II, ISO 27001",
      dpa: "Executed"
    },
    {
      name: "Supabase, Inc.",
      purpose: "PostgreSQL multi-tenant database & authentication engine",
      dataProcessed: "User accounts, SHA-256 hashed API keys, Merkle audit metadata",
      location: "AWS us-east-1 (N. Virginia), AWS eu-central-1 (Frankfurt option)",
      securityCertification: "SOC 2 Type II, ISO 27001, HIPAA Compliant",
      dpa: "Executed"
    },
    {
      name: "Stripe, Inc.",
      purpose: "Payment processing and subscription billing (Global USD)",
      dataProcessed: "Billing contact details, payment transaction IDs, subscription tier",
      location: "United States",
      securityCertification: "PCI-DSS Level 1 Service Provider",
      dpa: "Executed"
    },
    {
      name: "Razorpay Software Private Limited",
      purpose: "Payment gateway and INR subscription billing (India)",
      dataProcessed: "Customer tax ID (GSTIN), business name, INR transaction IDs",
      location: "India",
      securityCertification: "PCI-DSS Level 1, ISO 27001",
      dpa: "Executed"
    },
    {
      name: "Resend, Inc.",
      purpose: "Transactional email delivery (security alerts & auth magic links)",
      dataProcessed: "Recipient business email, alert notification timestamps",
      location: "United States",
      securityCertification: "SOC 2 Type II",
      dpa: "Executed"
    }
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50">
      <LandingNavbar />
      <main className="max-w-5xl mx-auto px-6 py-16 space-y-10 text-xs text-slate-300">
        
        {/* Header */}
        <div className="space-y-3">
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold">
            <ShieldCheck className="w-3.5 h-3.5" />
            Infrastructure Transparency
          </div>
          <h1 className="text-3xl font-bold text-white">Authorized Third-Party Subprocessors</h1>
          <p className="text-slate-400 max-w-2xl leading-relaxed">
            To deliver our enterprise cloud dashboard and telemetry aggregation services, MCP Shield engages carefully vetted third-party service providers ("Subprocessors"). Each subprocessor undergoes rigorous security auditing and must execute a Data Processing Agreement with Standard Contractual Clauses.
          </p>
        </div>

        {/* Subprocessor Directory Table */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase text-[10px] font-semibold tracking-wider">
                <tr>
                  <th className="p-4">Subprocessor</th>
                  <th className="p-4">Purpose & Data Processed</th>
                  <th className="p-4">Hosting Jurisdiction</th>
                  <th className="p-4">Security Certifications</th>
                  <th className="p-4">DPA Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {subprocessors.map((sub, i) => (
                  <tr key={i} className="hover:bg-slate-800/30">
                    <td className="p-4 font-semibold text-white whitespace-nowrap">{sub.name}</td>
                    <td className="p-4 space-y-1">
                      <div className="text-slate-200">{sub.purpose}</div>
                      <div className="text-[11px] text-slate-400">Data: {sub.dataProcessed}</div>
                    </td>
                    <td className="p-4 text-slate-400 text-[11px] whitespace-nowrap">{sub.location}</td>
                    <td className="p-4 font-mono text-[11px] text-blue-400 whitespace-nowrap">{sub.securityCertification}</td>
                    <td className="p-4 font-mono text-[11px] text-emerald-400 whitespace-nowrap">{sub.dpa}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Subprocessor Notification Policy */}
        <section className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 space-y-3">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Bell className="w-4 h-4 text-amber-400" />
            Subprocessor Notification & Objection Policy
          </h2>
          <p className="text-slate-400 leading-relaxed">
            MCP Shield provides enterprise customers with at least <strong>30 days advance written notice</strong> prior to onboarding any new third-party subprocessor with access to telemetry metadata. Customers may object to the appointment of a new subprocessor on reasonable data protection grounds by contacting <a href="mailto:dpa@mcp-shield.dev" className="text-blue-400 underline">dpa@mcp-shield.dev</a> within the 30-day notice window.
          </p>
        </section>

      </main>
    </div>
  );
}
