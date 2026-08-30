# MCP-Shield Security Architecture

MCP-Shield operates on a Zero-Trust Architecture designed specifically for Model Context Protocol (MCP) agents and AI-driven workflows. It sits between an LLM agent client and downstream MCP servers, intercepting all JSON-RPC traffic.

## Architectural Tenets

1. **Deny by Default / Allowlist First**: Tools, paths, environment variables, and egress domains are blocked unless explicitly authorized.
2. **Capability-Based Authorization**: Rather than relying purely on regex patterns over command strings, tools are mapped to core capabilities (`filesystemRead`, `shellExecution`, `networkAccess`).
3. **Execution Isolation Boundaries**: Any capability flagged as `arbitrary-code-execution` (e.g. bash, node, python) automatically transitions the session into a containerized sandbox with restricted privileges.
4. **Fail-Closed Design**: Any failure in the security evaluation pipeline (parser crash, schema validation failure, timeout) results in an immediate `BLOCK` or `QUARANTINE`.

## Component Overview

- **PolicyEngine**: The central decision authority. It evaluates aggregated evidence against configured policies using a strict priority ladder (`QUARANTINE > BLOCK > PROMPT > SANDBOX > ALLOW`).
- **ASTAnalyzer**: Parses shell commands into a structural Abstract Syntax Tree to defeat syntactic evasion (obfuscation, chaining, alias wrapping).
- **ContainerSandbox**: Spawns downstream MCP servers in ephemeral, unprivileged Docker containers with `network=none`, `read-only root`, and dropped capabilities.
- **COWFileSystem**: Uses a Copy-On-Write overlay to stage potentially dangerous file modifications for human operator approval before atomic commitment.
- **SecretVault**: Encrypts and redacts high-entropy secrets and API keys dynamically, replacing them with bijective session-scoped tokens.
