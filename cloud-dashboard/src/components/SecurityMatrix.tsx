'use client';

import React from 'react';
import { Check, X, Shield, Zap } from 'lucide-react';

interface Row {
  feature: string;
  description: string;
  mcpShield: boolean | string;
  rawMcp: boolean | string;
  regexWaf: boolean | string;
}

const COMPARISONS: Row[] = [
  {
    feature: 'AST-Level Command Inspection',
    description: 'Parses Bash, PowerShell, and Python into syntax trees to catch obfuscated injection.',
    mcpShield: true,
    rawMcp: false,
    regexWaf: false,
  },
  {
    feature: 'Bijective FPE DLP Tokenization',
    description: 'Masks secrets bidirectionally with format-preserving surrogate tokens so LLMs never see plaintext.',
    mcpShield: true,
    rawMcp: false,
    regexWaf: 'Redaction only (Lossy)',
  },
  {
    feature: 'Cloud Metadata & SSRF Interception',
    description: 'Blocks AWS IMDS (169.254.169.254), GCP/Azure metadata, and private RFC 1918 subnets.',
    mcpShield: true,
    rawMcp: false,
    regexWaf: 'Partial',
  },
  {
    feature: 'Sub-Millisecond Mean Overhead',
    description: 'Hot-path latency impact on agent tool evaluation.',
    mcpShield: '< 0.2 ms (SIMD)',
    rawMcp: '0 ms (No defense)',
    regexWaf: '> 15 ms',
  },
  {
    feature: 'Decoy Honey-Token Tripwires',
    description: 'Injects synthetic canary credentials into agent context to detect prompt jailbreaks instantly.',
    mcpShield: true,
    rawMcp: false,
    regexWaf: false,
  },
  {
    feature: 'Cryptographic WORM Audit Trails',
    description: 'HMAC-signed tamper-evident ledger for SOC2, HIPAA, and ISO 27001 AI compliance.',
    mcpShield: true,
    rawMcp: false,
    regexWaf: 'Basic text logs',
  },
  {
    feature: 'Zero External Cloud Dependency',
    description: 'Can run 100% air-gapped on-premise without telemetry leaving local machine.',
    mcpShield: true,
    rawMcp: true,
    regexWaf: false,
  },
];

export default function SecurityMatrix() {
  return (
    <section id="benchmarks" className="py-20 bg-[#090a0f] border-b border-slate-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-12">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-mono font-medium mb-4">
            <Shield className="w-3.5 h-3.5" />
            <span>ENTERPRISE DEFENSE MATRIX</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            Why Conventional Firewalls Fail for AI Agents
          </h2>
          <p className="mt-4 text-base text-slate-400">
            AI agents dynamically generate arbitrary syntax, polymorphic shell scripts, and multi-step tool calls.
            Traditional regex filters miss 87% of AST evasions. See how MCP Shield delivers complete zero-trust coverage.
          </p>
        </div>

        {/* Matrix Table */}
        <div className="overflow-x-auto rounded-2xl border border-slate-800 bg-[#0c0e18] shadow-2xl">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-[#0f111e]">
                <th className="py-4 px-6 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Security Capability
                </th>
                <th className="py-4 px-6 text-xs font-semibold text-emerald-400 uppercase tracking-wider bg-emerald-950/20 border-x border-emerald-500/20">
                  <div className="flex items-center gap-1.5">
                    <span>MCP Shield (Proxy)</span>
                    <span className="text-[10px] bg-emerald-500 text-black font-bold px-1.5 py-0.2 rounded">RECOMMENDED</span>
                  </div>
                </th>
                <th className="py-4 px-6 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Raw MCP Servers
                </th>
                <th className="py-4 px-6 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Generic Web WAF
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {COMPARISONS.map((row, idx) => (
                <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                  <td className="py-4 px-6">
                    <div className="font-semibold text-slate-200">{row.feature}</div>
                    <div className="text-[11px] text-slate-400 mt-0.5">{row.description}</div>
                  </td>
                  <td className="py-4 px-6 bg-emerald-950/10 border-x border-emerald-500/20 text-emerald-300 font-medium">
                    {typeof row.mcpShield === 'boolean' ? (
                      <span className="flex items-center gap-1.5 font-bold text-emerald-400">
                        <Check className="w-4 h-4 text-emerald-400" /> Yes
                      </span>
                    ) : (
                      <span className="font-semibold">{row.mcpShield}</span>
                    )}
                  </td>
                  <td className="py-4 px-6 text-slate-400">
                    {typeof row.rawMcp === 'boolean' ? (
                      row.rawMcp ? (
                        <Check className="w-4 h-4 text-slate-300" />
                      ) : (
                        <X className="w-4 h-4 text-rose-500/70" />
                      )
                    ) : (
                      <span>{row.rawMcp}</span>
                    )}
                  </td>
                  <td className="py-4 px-6 text-slate-400">
                    {typeof row.regexWaf === 'boolean' ? (
                      row.regexWaf ? (
                        <Check className="w-4 h-4 text-slate-300" />
                      ) : (
                        <X className="w-4 h-4 text-rose-500/70" />
                      )
                    ) : (
                      <span>{row.regexWaf}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
