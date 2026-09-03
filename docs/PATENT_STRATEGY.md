# MCP-Shield — Strategic Patent & Intellectual Property Filing Blueprint

## 1. Executive Summary & Patent Opportunity

MCP-Shield occupies a novel technological intersection: **Autonomous AI Agent Execution Boundaries & Format-Preserving Cryptographic Secret Isolation within Streaming RPC Protocols**. 

Standard DLP systems inspect static data at rest or transit. Standard API gateways inspect HTTP requests. **MCP-Shield is the first system to enforce dynamic, bidirectional AST synthesis, format-preserving encryption (FPE) token substitution, subshell secret restoration, and post-execution output resanitization inside streaming JSON-RPC / Model Context Protocol flows.**

---

## 2. Core Patent Candidate 1 (Primary Utility Patent)

### Title
**Method, System, and Computer-Readable Medium for Bijective Safe Secret Restoration and Deterministic AST Execution Guardrails in Model Context Protocol and Autonomous Agent Runtimes**

### Field of the Invention
Artificial Intelligence Security, Autonomous Agent Runtimes, JSON-RPC Protocol Firewalls, Format-Preserving Encryption (FPE), and Ephemeral Process Sandbox Isolation.

### Background & Deficiency in Prior Art
- **Prior Art A (Standard LLM Guardrails - NeMo, Llama Guard)**: Operate on natural language text prompts before model inference. Incapable of intercepting tool-call invocation streams, parsing multi-language shell syntax ASTs, or handling stateful protocol transitions.
- **Prior Art B (Standard Secret Scanners - GitGuardian, Trufflehog)**: Static regex scanners that alert on credentials. They cannot bijectively tokenize secrets for agent reasoning and safely rehydrate them only inside an ephemeral execution sandbox.
- **Prior Art C (Traditional API Gateways - Kong, Envoy)**: HTTP/gRPC load balancers and rate limiters lacking semantic understanding of autonomous agent reflection loops, JSON-RPC tool declarations, or parameter-level command injections.

### Independent Claim 1 (Method Claim)
> A computer-implemented method for securing autonomous agent tool execution across a bidirectional model context protocol (MCP) channel, comprising:
> 1. **Intercepting**, via an inline bidirectional protocol proxy, a structured JSON-RPC tool invocation message dispatched from an artificial intelligence agent destined for an execution server;
> 2. **Parsing** execution arguments of said tool invocation message into an abstract syntax tree (AST) representation prior to operating system shell dispatch;
> 3. **Detecting** one or more high-entropy cryptographic credentials within said tool invocation message;
> 4. **Bijectively replacing** each detected cryptographic credential with a format-preserving encrypted canary token using a deterministic cryptographic key, wherein the structural syntax and delimiters of the original credential are preserved;
> 5. **Dispatching** the synthesized tool execution payload containing said canary token to an isolated subshell execution boundary;
> 6. **Restoring**, exclusively within said isolated subshell execution boundary immediately prior to system call execution, the cleartext cryptographic credential corresponding to said canary token; and
> 7. **Sanitizing** standard output and standard error emitted from said subshell execution by replacing any re-emitted cleartext credentials with corresponding canary tokens before transmitting the tool response message back to the artificial intelligence agent.

### Dependent Claims (2–10)
- **Claim 2 (Non-linear Risk Scoring)**: Computing a composite non-linear risk score combining AST entropy, unverified network egress vectors, and executable binary drift against a signed provenance registry.
- **Claim 3 (Fail-Closed Protocol State Machine)**: Enforcing a formal finite state machine wherein unauthorized JSON-RPC methods received prior to completion of an authenticated handshake trigger immediate fail-closed frame destruction.
- **Claim 4 (Stateful N-Gram Anomaly Sequencing)**: Tracking a rolling temporal sequence of agent tool calls and blocking execution upon matching hazardous sequences comprising credential read followed by external network transmission.
- **Claim 5 (Format-Preserving Delimiter Preservation)**: Preserving checksum validity (e.g. Luhn algorithm) and provider-specific secret prefix structures within generated canary tokens.

---

## 3. Secondary Patent Candidate 2 (Defensive Continuation)

### Title
**System and Method for Decentralized Multi-Factor Cryptographic Provenance and Runtime Drift Attestation in Model Context Protocol Server Registries**

### Focus
- Cryptographic hashing of tool schemas, binary executables, and dependencies.
- Runtime drift detection alerting when an MCP server's live behavior or schema diverges from its signed registry manifest.

---

## 4. Actionable Step-by-Step Patent Roadmap

```text
┌─────────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────────┐
│  Phase 1: Immediate     │     │  Phase 2: 12-Month      │     │  Phase 3: National &    │
│  US Provisional Patent  │ ──> │  PCT International App  │ ──> │  Global Grant Phase     │
│  (Est. 3k - 5k USD)     │     │  (Preserves 150+ mkts)  │     │  (US, EU, JP, IN)       │
└─────────────────────────┘     └─────────────────────────┘     └─────────────────────────┘
```

1. **Step 1: File US Provisional Patent Application immediately**
   - **Cost**: Approximately 3,000 to 5,000 USD via registered patent attorney (or USPTO micro-entity self-filing for ~150 USD).
   - **Benefit**: Secures a formal priority date worldwide without publishing the specification for 12 months. Establishes "Patent Pending" status.
2. **Step 2: Maintain Trade Secret Protection on Scoring Weights**
   - **Do NOT patent the exact weight constants** (e.g., `AST_COMPLEXITY_EXPONENT = 1.35`, specific anomaly weights). 
   - Keep proprietary weights and reasoning trees strictly in the private enterprise repository (`mcp-shield-enterprise-intel`) exposed via `/api/v1/intel/scoring`. Patents require public disclosure; trade secrets protect algorithms indefinitely as long as kept confidential.
3. **Step 3: Convert to Non-Provisional + PCT within 12 Months**
   - File PCT (Patent Cooperation Treaty) to lock in priority across 157 member countries.

---

## 5. Summary Table: Patent vs Trade Secret Partition

| Asset | Protection Strategy | Location | Rationale |
|---|---|---|---|
| Bijective Secret Restoration & Subshell Isolation | Utility Patent | Open Source + Specification | Architecture visible in client; needs patent exclusivity. |
| AST Protocol Boundary & Framing | Utility Patent | Open Source CLI | Protects protocol enforcement against reverse-engineering. |
| Non-Linear Composite Risk Formula & Weights | Trade Secret | Private Repo (`/api/v1/intel/scoring`) | Disclosing formula allows competitors to bypass detection thresholds. |
| Zero-Day Attack Reasoning Chains | Trade Secret | Private Repo (`/api/v1/intel/corpus`) | Proprietary attack intelligence dataset gives perpetual competitive moat. |
| Registry Reputation & Publisher Trust Graph | Trade Secret | Enterprise Cloud Backend | Hard to reproduce dataset; continuous enterprise flywheel. |
