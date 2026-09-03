import LandingNavbar from "@/components/LandingNavbar";
import { Server, Database, CreditCard } from "lucide-react";

export const metadata = {
  title: "Authorized Subprocessors | MCP Shield",
  description: "Official directory of third-party infrastructure and service providers utilized by MCP Shield."
};

export default function SubprocessorsPage() {
  const subprocessors = [
    {
      name: "Vercel Inc.",
      purpose: "Edge hosting, serverless compute, and static asset delivery",
      location: "United States (Global Edge)",
      securityCertification: "SOC 2 Type II, ISO 27001"
    },
    {
      name: "Supabase, Inc.",
      purpose: "PostgreSQL multi-tenant database & authentication engine",
      location: "United States (AWS us-east-1)",
      securityCertification: "SOC 2 Type II, HIPAA Compliant"
    },
    {
      name: "Stripe, Inc.",
      purpose: "Payment processing and subscription billing (Global USD)",
      location: "United States",
      securityCertification: "PCI-DSS Level 1 Service Provider"
    },
    {
      name: "Razorpay Software Private Limited",
      purpose: "Payment gateway and INR subscription billing (India)",
      location: "India",
      securityCertification: "PCI-DSS Level 1, ISO 27001"
    }
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50">
      <LandingNavbar />
      <main className="max-w-4xl mx-auto px-6 py-16 space-y-8 text-xs text-slate-300">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Authorized Third-Party Subprocessors</h1>
          <p className="text-slate-400">
            MCP Shield engages third-party entities to assist in providing our enterprise cloud platform.
          </p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase text-[10px] font-semibold tracking-wider">
              <tr>
                <th className="p-4">Subprocessor</th>
                <th className="p-4">Processing Activity</th>
                <th className="p-4">Jurisdiction</th>
                <th className="p-4">Certifications</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {subprocessors.map((sub, i) => (
                <tr key={i} className="hover:bg-slate-800/30">
                  <td className="p-4 font-semibold text-white">{sub.name}</td>
                  <td className="p-4 text-slate-300">{sub.purpose}</td>
                  <td className="p-4 text-slate-400">{sub.location}</td>
                  <td className="p-4 font-mono text-[11px] text-blue-400">{sub.securityCertification}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}
