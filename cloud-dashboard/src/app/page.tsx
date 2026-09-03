import React from 'react';
import Link from 'next/link';
import LandingNavbar from '@/components/LandingNavbar';
import AttackSimulator from '@/components/AttackSimulator';
import InstallationTabs from '@/components/InstallationTabs';
import SecurityMatrix from '@/components/SecurityMatrix';
import { ShieldCheck, Terminal, Lock, Zap, Cpu, EyeOff, Activity, Radio, Flame, CheckCircle2, ArrowRight, FileText, Key, Network, HelpCircle } from 'lucide-react';
import GithubIcon from '@/components/GithubIcon';

export default function HomePage() {
  return (
    <div className="min-h-screen flex flex-col bg-[#090a0f] text-slate-100 font-sans">
      <LandingNavbar />

      <main className="flex-1">
        {/* HERO SECTION */}
        <section className="relative pt-20 pb-24 overflow-hidden border-b border-slate-800/80">
          {/* Subtle geometric grid background */}
          <div className="absolute inset-0 bg-[linear-gradient(to_right,#1f293d15_1px,transparent_1px),linear-gradient(to_bottom,#1f293d15_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none" />
          
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
            <div className="text-center max-w-4xl mx-auto space-y-6">
              {/* Release announcement badge */}
              <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-slate-900/90 border border-slate-700 text-xs text-slate-300 shadow-xl hover:border-emerald-500/50 transition">
                <span className="flex h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
                <span className="font-semibold text-emerald-400">MCP Shield 2.4 Released</span>
                <span className="text-slate-500">|</span>
                <span>Zero-Trust Model Context Protocol Firewall</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
              </div>

              {/* Main Headline */}
              <h1 className="text-4xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight text-white leading-[1.1]">
                Zero-Trust Security Gateway for{' '}
                <span className="bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 via-cyan-400 to-indigo-400">
                  Model Context Protocol
                </span>{' '}
                & AI Agents
              </h1>

              {/* Subtitle */}
              <p className="text-base sm:text-xl text-slate-400 max-w-3xl mx-auto leading-relaxed">
                Protect autonomous agents in Claude Desktop, Cursor, and custom frameworks from prompt injection,
                AST shell command escalation, cloud metadata SSRF, and credential exfiltration in <strong className="text-emerald-400 font-semibold">&lt; 0.2ms</strong>.
              </p>

              {/* CTAs */}
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4">
                <Link
                  href="/console"
                  className="w-full sm:w-auto px-6 py-3.5 rounded-xl bg-gradient-to-r from-emerald-500 via-teal-500 to-cyan-500 text-black font-bold text-sm shadow-xl shadow-emerald-500/20 hover:scale-[1.02] transition flex items-center justify-center gap-2"
                >
                  <Activity className="w-4 h-4" />
                  <span>Launch Live Security Console</span>
                </Link>

                <a
                  href="#simulator"
                  className="w-full sm:w-auto px-6 py-3.5 rounded-xl bg-slate-900 border border-slate-700 hover:border-slate-500 text-white font-semibold text-sm transition flex items-center justify-center gap-2"
                >
                  <Cpu className="w-4 h-4 text-cyan-400" />
                  <span>Explore Attack Simulator</span>
                </a>

                <a
                  href="https://github.com/rahulxcodex/mcp-shield"
                  target="_blank"
                  rel="noreferrer"
                  className="w-full sm:w-auto px-5 py-3.5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white font-medium text-sm transition flex items-center justify-center gap-2"
                >
                  <GithubIcon className="w-4 h-4" />
                  <span>Star on GitHub</span>
                </a>
              </div>

              {/* Trust Indicators */}
              <div className="pt-10 grid grid-cols-2 sm:grid-cols-4 gap-4 text-center max-w-3xl mx-auto">
                <div className="p-3 rounded-xl bg-slate-900/50 border border-slate-800/80">
                  <div className="text-xl sm:text-2xl font-black text-emerald-400 font-mono">&lt; 0.2ms</div>
                  <div className="text-xs text-slate-400 mt-0.5">Mean Latency</div>
                </div>
                <div className="p-3 rounded-xl bg-slate-900/50 border border-slate-800/80">
                  <div className="text-xl sm:text-2xl font-black text-cyan-400 font-mono">Tree-sitter</div>
                  <div className="text-xs text-slate-400 mt-0.5">AST Multi-Shell</div>
                </div>
                <div className="p-3 rounded-xl bg-slate-900/50 border border-slate-800/80">
                  <div className="text-xl sm:text-2xl font-black text-indigo-400 font-mono">FPE Bijective</div>
                  <div className="text-xs text-slate-400 mt-0.5">DLP Tokenizer</div>
                </div>
                <div className="p-3 rounded-xl bg-slate-900/50 border border-slate-800/80">
                  <div className="text-xl sm:text-2xl font-black text-amber-400 font-mono">SOC2 Ready</div>
                  <div className="text-xs text-slate-400 mt-0.5">WORM Audit Logs</div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* INTERACTIVE ATTACK SIMULATOR */}
        <AttackSimulator />

        {/* ARCHITECTURE SECTION */}
        <section id="architecture" className="py-20 bg-[#0c0e18] border-b border-slate-800/80 relative">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center max-w-3xl mx-auto mb-16">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono font-medium mb-4">
                <Network className="w-3.5 h-3.5" />
                <span>IN-LINE INVOCATION INTERCEPTION</span>
              </div>
              <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
                How MCP Shield Secures Agent Tool Invocations
              </h2>
              <p className="mt-4 text-base text-slate-400">
                MCP Shield functions as a bidirectional cryptographic reverse proxy placed seamlessly between the AI Agent runtime
                and upstream Model Context Protocol servers.
              </p>
            </div>

            {/* Architecture Visual Diagram */}
            <div className="p-6 sm:p-8 rounded-2xl bg-[#08090e] border border-slate-800 shadow-2xl space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 relative items-center">
                {/* Step 1: AI Client */}
                <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 text-center space-y-2">
                  <div className="w-10 h-10 mx-auto rounded-lg bg-indigo-500/20 text-indigo-400 flex items-center justify-center font-bold">
                    1
                  </div>
                  <div className="font-bold text-slate-200">AI Agent Runtime</div>
                  <div className="text-xs text-slate-400">Claude Desktop, Cursor, Antigravity, CrewAI, AutoGen</div>
                  <div className="text-[11px] font-mono text-indigo-400 bg-indigo-500/10 py-1 rounded border border-indigo-500/20">
                    JSON-RPC stdio / SSE
                  </div>
                </div>

                {/* Step 2: MCP Shield Gateway */}
                <div className="p-6 rounded-xl bg-emerald-950/20 border-2 border-emerald-500/50 text-center space-y-3 shadow-xl shadow-emerald-500/10">
                  <div className="w-10 h-10 mx-auto rounded-lg bg-emerald-500 text-black flex items-center justify-center font-bold">
                    <ShieldCheck className="w-6 h-6 stroke-[2.5]" />
                  </div>
                  <div className="font-bold text-emerald-300 text-base">MCP Shield Zero-Trust Proxy</div>
                  <ul className="text-xs text-slate-300 space-y-1.5 text-left list-disc list-inside">
                    <li>Tree-sitter AST Syntax Parser</li>
                    <li>Bijective FPE DLP Engine</li>
                    <li>SSRF & 169.254.169.254 Guard</li>
                    <li>Canary Honeytoken Tripwires</li>
                  </ul>
                  <div className="text-[11px] font-mono text-emerald-400 font-bold">
                    Overhead &lt; 0.2ms
                  </div>
                </div>

                {/* Step 3: MCP Servers */}
                <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 text-center space-y-2">
                  <div className="w-10 h-10 mx-auto rounded-lg bg-cyan-500/20 text-cyan-400 flex items-center justify-center font-bold">
                    3
                  </div>
                  <div className="font-bold text-slate-200">Protected MCP Tools</div>
                  <div className="text-xs text-slate-400">Filesystem, Shell Exec, PostgreSQL, GitHub, AWS, Puppeteer</div>
                  <div className="text-[11px] font-mono text-cyan-400 bg-cyan-500/10 py-1 rounded border border-cyan-500/20">
                    Guarded Execution
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* CORE FEATURES GRID */}
        <section id="features" className="py-20 bg-[#090a0f] border-b border-slate-800/80">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center max-w-3xl mx-auto mb-16">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-mono font-medium mb-4">
                <Lock className="w-3.5 h-3.5" />
                <span>UNCOMPROMISING AGENT DEFENSE</span>
              </div>
              <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
                Enterprise Capabilities Built for AI Safety
              </h2>
              <p className="mt-4 text-base text-slate-400">
                Engineered from the ground up to solve vulnerabilities unique to autonomous agents and LLM tool calling.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {/* Card 1 */}
              <div className="p-6 rounded-2xl bg-[#0c0e18] border border-slate-800 hover:border-emerald-500/40 transition group">
                <div className="p-3 rounded-xl bg-emerald-500/10 text-emerald-400 w-fit mb-4 group-hover:scale-110 transition">
                  <Terminal className="w-6 h-6" />
                </div>
                <h3 className="text-lg font-bold text-white mb-2">AST Command Parser</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Deep grammar validation with Tree-sitter for Bash, Zsh, PowerShell, and Python. Detects subshell escapes,
                  base64 obfuscation, and rm -rf root deletes that evade regex.
                </p>
              </div>

              {/* Card 2 */}
              <div className="p-6 rounded-2xl bg-[#0c0e18] border border-slate-800 hover:border-cyan-500/40 transition group">
                <div className="p-3 rounded-xl bg-cyan-500/10 text-cyan-400 w-fit mb-4 group-hover:scale-110 transition">
                  <EyeOff className="w-6 h-6" />
                </div>
                <h3 className="text-lg font-bold text-white mb-2">Bijective FPE DLP</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Format-Preserving Encryption tokenizes AWS keys, private tokens, and credentials into safe surrogates
                  before entering context, and detokenizes them only upon downstream return.
                </p>
              </div>

              {/* Card 3 */}
              <div className="p-6 rounded-2xl bg-[#0c0e18] border border-slate-800 hover:border-indigo-500/40 transition group">
                <div className="p-3 rounded-xl bg-indigo-500/10 text-indigo-400 w-fit mb-4 group-hover:scale-110 transition">
                  <Network className="w-6 h-6" />
                </div>
                <h3 className="text-lg font-bold text-white mb-2">SSRF & Cloud Metadata Guard</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Prevents agents from curling 169.254.169.254 (AWS IMDS), Google Metadata, or internal RFC 1918 networks,
                  protecting internal microservices from prompt redirection.
                </p>
              </div>

              {/* Card 4 */}
              <div className="p-6 rounded-2xl bg-[#0c0e18] border border-slate-800 hover:border-amber-500/40 transition group">
                <div className="p-3 rounded-xl bg-amber-500/10 text-amber-400 w-fit mb-4 group-hover:scale-110 transition">
                  <Flame className="w-6 h-6" />
                </div>
                <h3 className="text-lg font-bold text-white mb-2">Decoy Canary Honeytokens</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Injects synthetic decoy credentials into the agent LLM context. Any attempt by a jailbroken prompt to
                  read or transmit the token triggers instant session lockdown.
                </p>
              </div>

              {/* Card 5 */}
              <div className="p-6 rounded-2xl bg-[#0c0e18] border border-slate-800 hover:border-emerald-500/40 transition group">
                <div className="p-3 rounded-xl bg-emerald-500/10 text-emerald-400 w-fit mb-4 group-hover:scale-110 transition">
                  <Zap className="w-6 h-6" />
                </div>
                <h3 className="text-lg font-bold text-white mb-2">SIMD eBPF Fastpath</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Compiled hotpath rules execute in sub-millisecond time. Enjoy enterprise-grade security without adding
                  human-noticeable latency to conversational agent workflows.
                </p>
              </div>

              {/* Card 6 */}
              <div className="p-6 rounded-2xl bg-[#0c0e18] border border-slate-800 hover:border-cyan-500/40 transition group">
                <div className="p-3 rounded-xl bg-cyan-500/10 text-cyan-400 w-fit mb-4 group-hover:scale-110 transition">
                  <FileText className="w-6 h-6" />
                </div>
                <h3 className="text-lg font-bold text-white mb-2">Cryptographic WORM Audit</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Every tool call, policy evaluation, and blocked attempt is hashed with HMAC-SHA256 into a tamper-proof
                  audit ledger, ready for SOC2, HIPAA, and ISO 27001 AI governance.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* INSTALLATION TABS */}
        <InstallationTabs />

        {/* SECURITY COMPARISON MATRIX */}
        <SecurityMatrix />

        {/* FREQUENTLY ASKED QUESTIONS */}
        <section id="faq" className="py-20 bg-[#0c0e18] border-b border-slate-800/80">
          <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center mb-12">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-slate-800 border border-slate-700 text-slate-300 text-xs font-mono font-medium mb-3">
                <HelpCircle className="w-3.5 h-3.5" />
                <span>FREQUENTLY ASKED QUESTIONS</span>
              </div>
              <h2 className="text-3xl font-extrabold text-white">Frequently Asked Questions</h2>
            </div>

            <div className="space-y-4">
              <div className="p-5 rounded-xl bg-[#08090e] border border-slate-800">
                <h3 className="font-bold text-sm text-slate-200 mb-2">How does MCP Shield integrate with my existing setup?</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  MCP Shield acts as a transparent command wrapper. In your Claude Desktop config (or Cursor mcp.json), you simply prepend
                  <code className="text-emerald-400 font-mono"> npx @rahulxcodex/mcp-shield proxy -- </code> before your existing server command.
                  No code modifications to the MCP server or agent are required.
                </p>
              </div>

              <div className="p-5 rounded-xl bg-[#08090e] border border-slate-800">
                <h3 className="font-bold text-sm text-slate-200 mb-2">Is MCP Shield open-source and free to use?</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Yes, MCP Shield core is 100% open-source under the Apache-2.0 / MIT license. The cloud dashboard and console can be self-hosted
                  for free on GitHub, Vercel, and Supabase.
                </p>
              </div>

              <div className="p-5 rounded-xl bg-[#08090e] border border-slate-800">
                <h3 className="font-bold text-sm text-slate-200 mb-2">Does MCP Shield send my private code or tool data to third parties?</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Never. MCP Shield runs entirely locally on your workstation by default. If you configure telemetry, only anonymized security event metadata
                  (detector name, risk level, rule id) is transmitted using your private HMAC key.
                </p>
              </div>

              <div className="p-5 rounded-xl bg-[#08090e] border border-slate-800">
                <h3 className="font-bold text-sm text-slate-200 mb-2">Can MCP Shield protect against SSRF to cloud metadata?</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Yes. MCP Shield inspects all URL parameters and network fetch calls, denying requests to 169.254.169.254, 127.0.0.1, RFC 1918 private subnets,
                  and performing DNS rebinding verification.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* CTA BANNER */}
        <section className="py-20 bg-gradient-to-b from-[#0c0e18] to-[#090a0f]">
          <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 text-center space-y-6">
            <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
              Ready to Lock Down Your AI Agents?
            </h2>
            <p className="text-slate-400 text-sm sm:text-base max-w-2xl mx-auto">
              Deploy MCP Shield in less than 60 seconds and gain instant real-time visibility and AST security over all tool calls.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4">
              <Link
                href="/console"
                className="w-full sm:w-auto px-8 py-4 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 text-black font-bold text-sm shadow-xl shadow-emerald-500/25 hover:opacity-95 transition flex items-center justify-center gap-2"
              >
                <span>Launch Security Console</span>
                <ArrowRight className="w-4 h-4" />
              </Link>
              <a
                href="https://github.com/rahulxcodex/mcp-shield"
                target="_blank"
                rel="noreferrer"
                className="w-full sm:w-auto px-8 py-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 text-white font-semibold text-sm transition flex items-center justify-center gap-2"
              >
                <GithubIcon className="w-4 h-4" />
                <span>Explore Codebase</span>
              </a>
            </div>
          </div>
        </section>
      </main>

      {/* FOOTER */}
      <footer className="border-t border-slate-800/80 bg-[#08090e] py-12 text-xs text-slate-400">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-3">
            <div className="h-7 w-7 rounded-lg bg-emerald-500/20 text-emerald-400 flex items-center justify-center">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <div>
              <span className="font-bold text-slate-200">MCP-SHIELD</span>
              <span className="text-slate-500 ml-2">Zero-Trust Model Context Protocol Gateway</span>
            </div>
          </div>

          <div className="flex items-center gap-6">
            <a href="#features" className="hover:text-white transition">Features</a>
            <a href="#simulator" className="hover:text-white transition">Simulator</a>
            <a href="#install" className="hover:text-white transition">Installation</a>
            <Link href="/console" className="hover:text-white transition text-emerald-400">Console</Link>
            <a href="https://github.com/rahulxcodex/mcp-shield" target="_blank" rel="noreferrer" className="hover:text-white transition">
              GitHub
            </a>
          </div>

          <div className="text-slate-500">
            Open Source under Apache-2.0 & MIT.
          </div>
        </div>
      </footer>
    </div>
  );
}

