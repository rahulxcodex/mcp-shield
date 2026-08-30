# MCP-Shield Control Matrix

This matrix maps MCP-Shield's internal security controls to common threat frameworks (OWASP Top 10 for LLM Applications and MITRE ATT&CK).

| Control Feature | Threat Mitigated | Framework Mapping | Status |
| :--- | :--- | :--- | :--- |
| **AST Shell Parsing** | OS Command Injection via LLM Prompts | OWASP LLM02: Insecure Output Handling <br> MITRE T1059: Command and Scripting Interpreter | ✅ Enforced |
| **Container Sandbox** | Host privilege escalation & persistence | MITRE T1611: Escape to Host | ✅ Enforced |
| **Egress Exfiltration Firewall** | Unauthorized data exfiltration | OWASP LLM06: Sensitive Information Disclosure <br> MITRE T1048: Exfiltration Over Alternative Protocol | ✅ Enforced |
| **Copy-On-Write (COW) Staging** | Arbitrary File Write / System Destruction | MITRE T1485: Data Destruction | ✅ Enforced |
| **Secret Tokenization (DLP)** | API Key and Credential Leakage | OWASP LLM06: Sensitive Information Disclosure <br> MITRE T1552: Unsecured Credentials | ✅ Enforced |
| **Rate Limiter** | Runaway LLM Loops / DoS | OWASP LLM04: Model Denial of Service | ✅ Enforced |
| **Environment Variable Allowlisting**| Env Injection / Secret Leaks via Child Process | MITRE T1552.004: Environment Variables | ✅ Enforced |
| **Schema Pinning** | Malicious dynamic tool capabilities | MITRE T1565: Data Manipulation | ✅ Enforced |
