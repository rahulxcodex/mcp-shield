# MCP-Shield 🛡️ — Enterprise & Public Launch Kit (GTM Playbook)

This Launch Kit provides ready-to-publish assets, social copy, Product Hunt materials, Show HN submissions, and press release templates for the **MCP-Shield Enterprise Launch**.

---

## 🚀 1. Product Hunt Launch Package

### Listing Metadata
* **Product Name:** MCP-Shield 🛡️
* **Tagline:** The Zero-Trust Firewall for Autonomous AI Agents & MCP
* **Category:** Developer Tools, Artificial Intelligence, Security, Open Source
* **Target Launch Date:** Phase 1 Launch Week (Tuesday 12:01 AM PT)

### Maker First Comment
```markdown
Hey Product Hunt! 👋 I'm super excited to share **MCP-Shield** with you all today.

If you’ve used autonomous coding assistants like Claude Desktop, Cursor, Windsurf, or Cline, you know how magical it feels when an agent writes code and runs tests on your machine.

...Until an agent encounters an untrusted file with an indirect prompt injection that tells it:
`sudo env nice -n 19 rm -rf /` or attempts to exfiltrate your `.env` AWS keys to a webhook.

Watching an autonomous agent almost wipe a root directory was my wake-up call. We shouldn’t have to choose between AI agent velocity and host machine security.

**That’s why we built MCP-Shield:**
🛡️ **AST Shell Firewall:** Uses native Tree-Sitter C grammars (Bash, PowerShell, CMD) to unwrap execution layers (`sudo`, `env`, `nice`) and block destructive commands before they touch your OS.
🔑 **Zero-Latency DLP Sanitizer:** Automatically scans and reversibly masks AWS/OpenAI/GitHub keys with synthetic tokens in under 150µs.
👻 **Dual-Mode (Shadow vs. Enforce):** Run in Shadow Mode for 48 hours to discover what your agents are trying to execute, then switch to Active Fail-Closed Enforcement.
⚡ **1-Command Setup:** Run `npx mcp-shield protect` and it automatically configures Claude Desktop, Cursor, and Cline.

It’s completely open source (MIT), adds <150µs latency (no slow LLM-as-a-judge!), and requires zero configuration to get started.

Try it out and let us know what you think! 🛡️
```

### Key Product Hunt FAQs
**Q: Why not just use Docker or sandboxes?**  
*A: Sandboxing is great for virtualization, but developers want agents to edit local files, run local compilers, and interact with existing tools without 30-second container spin-up overhead. MCP-Shield provides real-time, deterministic wire protection directly inside your native workflow.*

**Q: Does MCP-Shield use an LLM to evaluate commands?**  
*A: No! LLM-as-a-judge is slow (800ms–2s), expensive, and susceptible to prompt injection itself. MCP-Shield uses native Tree-Sitter AST parsers running in C/Node at sub-millisecond speeds (<150µs) with deterministic policy enforcement.*

---

## ⚡ 2. Show HN: Submission Copy

### Title
`Show HN: MCP-Shield – Zero-Trust AST shell firewall and DLP for AI agents`

### Body Text
```markdown
Hi HN,

Autonomous AI agents (Cursor, Claude Desktop, Windsurf, Cline) are executing shell commands and accessing filesystems on behalf of developers every day.

The problem: Current MCP clients grant LLMs raw shell execution privileges. A prompt injection hidden in a third-party pull request, issue body, or web scrape can instruct the agent to run obfuscated shell deletions (`rm -rf /`, delayed expansion, nested wrappers) or exfiltrate environment secrets.

Naive regex fails because shell syntax is notoriously complex (`$IFS`, quotes, subshell pipelines, alias expansion). LLM-as-a-judge is too slow (800ms+) and can itself be jailbroken.

We built **MCP-Shield** (https://github.com/rahulxcodex/mcp-shield), a lightweight stdio proxy that sits between your AI client and downstream MCP servers:

1. **Multi-Engine AST Parser:** Uses Tree-Sitter to parse full shell ASTs across POSIX Bash, PowerShell, and cmd.exe. It unwraps execution chains (`sudo -> env -> nice -> rm`) and catches destructive primitives regardless of obfuscation.
2. **Reversible DLP Tokenizer:** High-entropy single-pass scanner that tokenizes cloud credentials (AWS, GCP, OpenAI, Anthropic, SSH keys) with ephemeral tokens before they enter LLM context, restoring them only for trusted endpoints.
3. **Sub-Millisecond Performance:** Benchmarked at <150µs overhead per call. Developers experience zero noticeable lag.
4. **Shadow / Discovery Mode:** POC mode that logs potential attacks and policy breaches without terminating commands, giving security teams an audit trail of agent activity.

Get started in 1 command:
$ npx mcp-shield protect

GitHub: https://github.com/rahulxcodex/mcp-shield
Architecture & Benchmarks: https://github.com/rahulxcodex/mcp-shield/blob/main/SECURITY_ARCHITECTURE.md

Would love to hear your thoughts, feedback, and edge-case attacks!
```

---

## 🐦 3. Social Media Launch Threads (Twitter / X & LinkedIn)

### Tweet 1 (Hook)
```text
Autonomous AI agents are awesome. Until an indirect prompt injection tells Claude Desktop to execute `sudo env nice rm -rf /` or leak your $AWS_SECRET_ACCESS_KEY.

Today we're launching MCP-Shield 🛡️: The Zero-Trust Security Gateway & AST Firewall for AI Agents and MCP.

🧵👇
```

### Tweet 2 (The Problem & AST Solution)
```text
Why not regex? Regex fails on basic shell tricks: $IFS, nested quotes, subshell pipes, and alias expansion.
Why not LLM-as-a-judge? Too slow (1.5s latency) and vulnerable to jailbreaks.

MCP-Shield uses native Tree-Sitter AST parsing in <150µs with deterministic policy enforcement.
```

### Tweet 3 (1-Command Install & Call to Action)
```text
Protect Claude Desktop, Cursor, Windsurf, and Cline in 1 command:

$ npx mcp-shield protect

⚡ Sub-millisecond latency
🔑 Bidirectional DLP secret masking
👻 Shadow / Discovery audit mode

⭐ Star on GitHub: https://github.com/rahulxcodex/mcp-shield
🚀 Upvote on Product Hunt!
```

---

## 📰 4. Enterprise Press Release Template

**FOR IMMEDIATE RELEASE**

### MCP-Shield Launches Enterprise Zero-Trust Security Gateway to Secure Autonomous AI Agents and MCP Workflows

*Deterministic AST shell firewall and real-time DLP secret sanitization protect enterprise infrastructure against prompt injection, destructive commands, and credential exfiltration.*

**SAN FRANCISCO, CA** — Today marks the launch of **MCP-Shield**, an enterprise-grade security gateway designed to secure autonomous AI coding agents and the Model Context Protocol (MCP) ecosystem. 

As enterprises rapidly adopt autonomous AI tools like Cursor, Claude Desktop, and bespoke AI agents, security leaders face a growing dilemma: autonomous agents need terminal and filesystem access to be productive, but unconstrained access exposes organizations to catastrophic infrastructure wipes and credential theft via indirect prompt injection.

MCP-Shield solves this challenge by operating as a transparent, high-performance proxy directly on the JSON-RPC communication layer. Key enterprise capabilities include:
- **Deterministic Multi-Engine AST Shell Firewall:** Blocks malicious shell commands across POSIX, PowerShell, and cmd.exe in under 150 microseconds without relying on brittle regex or slow LLM judges.
- **Reversible DLP Credential Masking:** Eliminates API key leaks by tokenizing cloud credentials before they reach model context.
- **Dual-Mode Deployment (Shadow & Enforce):** Allows security teams to evaluate organizational AI risk in passive discovery mode before enabling active fail-closed enforcement.
- **Enterprise Compliance Readiness:** Designed to satisfy SOC 2 Type II, ISO 27001, PCI-DSS, and HIPAA access and transmission security controls.

"Enterprise developers should not have to sacrifice security for AI velocity," said the MCP-Shield team. "MCP-Shield delivers the rigorous security controls CISOs require while maintaining the sub-millisecond responsiveness developers demand."

To learn more about MCP-Shield or begin an enterprise evaluation, visit [https://github.com/rahulxcodex/mcp-shield](https://github.com/rahulxcodex/mcp-shield) or contact enterprise@mcp-shield.dev.
