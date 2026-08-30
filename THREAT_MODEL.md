# Threat Model

## Overview
MCP-Shield is an early-stage tool designed to mitigate risks associated with autonomous AI agents running in local development environments. It is **not** a silver bullet and is not currently designed to withstand highly sophisticated, targeted adversarial attacks. 

Security tools live or die on being trustworthy under adversarial pressure. This document transparently outlines what MCP-Shield can currently do, and what its known limitations are.

## In Scope
- **Accidental Destructive Commands**: Preventing the LLM from accidentally deleting critical files (e.g., basic `rm -rf /` checks).
- **Runaway Loops**: Stopping agents that get stuck in repetitive tool-calling loops, burning API tokens.
- **Basic Exfiltration**: Redacting obvious credentials (e.g., standard API key formats, high-entropy strings) from outbound prompts.
- **File System Guardrails**: Staging file modifications for human review via Copy-on-Write (COW).

## Out of Scope (Known Limitations)
- **Advanced Shell Evasion**: Adversaries or highly capable models might bypass the AST filter using encoding tricks, `$IFS` substitution, or alias abuse. True isolation requires virtualization or containerization. The AST filter is a defense-in-depth measure, not an impenetrable sandbox.
- **Complex Data Exfiltration**: Malicious agents could exfiltrate data using covert channels (e.g., timing attacks, DNS rebinding, steganography) that bypass the basic regex/entropy DLP engine.
- **Host Compromise**: If the host environment is already compromised, MCP-Shield cannot protect the user.

## Defense-in-Depth Milestones & Active Hardening

To ensure complete transparency and continuous hardening, we have implemented the following core initiatives:

1. **Adversarial Fuzzing**: Continuous automated fuzzing engine ([`tests/fuzz/ast-fuzzer.test.ts`](tests/fuzz/ast-fuzzer.test.ts) & `npm run fuzz`) generating thousands of shell evasion mutations across quote obfuscation, wrapper chaining (`sudo`, `env`, `nice`, `timeout`), path traversals, redirections (`<<<`), and destructive tools.
2. **Transparent Performance Benchmarking**: Documented, reproducible hot-path latency numbers published in [BENCHMARKS.md](BENCHMARKS.md) (< 0.2 ms p50 overhead per tool call, > 6,700 ops/sec AST throughput).
3. **Community Red-Team Validation**: Formal red-team challenge program and test harness ([REDTEAM.md](REDTEAM.md) & [`tests/redteam/bypasses.test.ts`](tests/redteam/bypasses.test.ts)) to track, reproduce, and mitigate novel bypasses.

