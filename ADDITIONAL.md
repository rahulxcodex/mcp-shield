# Additional Security & Architecture Resources 📖

This document curates foundational specifications, threat frameworks, security standards, and research papers relevant to the Model Context Protocol (MCP) and AI agent execution security.

---

## 🌐 Official Specifications & Standards

- **[Model Context Protocol (MCP) Specification](https://modelcontextprotocol.io/)**  
  The open protocol standard created by Anthropic for connecting LLM clients to external tools, resources, and prompt templates.
- **[JSON-RPC 2.0 Specification](https://www.jsonrpc.org/specification)**  
  The underlying transport-agnostic remote procedure call protocol used across MCP stdio and SSE connections.
- **[Tree-Sitter Parser Ecosystem](https://tree-sitter.github.io/tree-sitter/)**  
  Incremental parser generator tool used by MCP-Shield (`tree-sitter-bash`) to generate concrete syntax trees for AST-level shell command inspection.

---

## 🛡️ AI Security & Threat Modeling Frameworks

- **[OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)**  
  Standardized taxonomy of the most critical vulnerabilities in LLM applications, including Prompt Injection (LLM01), Insecure Output Handling (LLM02), Training Data Poisoning (LLM03), Model Denial of Service (LLM04), Sensitive Information Disclosure (LLM06), and Excessive Agency (LLM08).
- **[MITRE ATLAS™ (Adversarial Threat Landscape for Artificial-Intelligence Systems)](https://atlas.mitre.org/)**  
  Globally accessible knowledge base of adversary tactics, techniques, and real-world case studies against artificial intelligence systems.
- **[NIST AI Risk Management Framework (AI RMF 1.0)](https://www.nist.gov/itl/ai-risk-management-framework)**  
  Guidance from the National Institute of Standards and Technology for managing risks in the design, development, deployment, and evaluation of AI products.
- **[Cloud Security Alliance (CSA) AI Safety Guidelines](https://cloudsecurityalliance.org/research/working-groups/ai-safety)**  
  Best practices for securing enterprise generative AI workflows, agentic tool access, and multi-tenant AI systems.

---

## 🔒 Cryptography & Audit Trail Standards

- **[RFC 6962 - Certificate Transparency (Append-Only Hash Chains)](https://datatracker.ietf.org/doc/html/rfc6962)**  
  The mathematical principles behind tamper-evident hash chaining utilized in MCP-Shield's `SessionLogger` and `ReplayCommand`.
- **[FIPS 180-4 - Secure Hash Standard (SHA-256 / HMAC-SHA-256)](https://csrc.nist.gov/publications/detail/fips/180-4/final)**  
  Cryptographic hashing standards ensuring collision resistance in audit record verification.

---

## 📚 Academic & Industry Research

1. **Prompt Injection & Indirect Prompt Injection**
   - *Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection* (Greshake et al., 2023)
   - *Evaluating the Robustness of LLM Guardrails against Adaptive Attacks* (Zou et al., 2023)
2. **Autonomous Agent Sandboxing & Privilege Separation**
   - *Security Considerations for Autonomous Tool-Using LLM Agents* (Schönherr et al., 2024)
   - *Least Privilege in Agentic Systems: Preventing Tool Capability Escalation* (DeepMind Safety Research)
3. **AST-Based Command Security vs Regex Evasion**
   - *Understanding and Bypassing Regex-Based Command Filters in Modern Shell Interpreters* (USENIX Security)
   - *Grammar-Guided Sanitization for Structured Input Interception* (ACM CCS)

---

## 🛠️ Developer Ecosystem & Client Integrations

- **[Claude Desktop](https://claude.ai/download)** - Anthropic's desktop client supporting native MCP server configuration.
- **[Cursor IDE](https://www.cursor.com/)** - AI-native code editor with integrated MCP tool support.
- **[Windsurf (Codeium)](https://codeium.com/windsurf)** - Agentic IDE featuring native MCP integration.
- **[Cline (VS Code Extension)](https://github.com/cline/cline)** - Autonomous coding agent extension for Visual Studio Code.
- **[Zed Editor](https://zed.dev/)** - High-performance code editor with native MCP client support.

---

## 🤝 Community & Support

- **Issue Tracker**: [GitHub Issues](https://github.com/rahulxcodex/mcp-shield/issues)
- **Discussions**: [GitHub Discussions](https://github.com/rahulxcodex/mcp-shield/discussions)
- **Security Disclosures**: [SECURITY.md](SECURITY.md)
