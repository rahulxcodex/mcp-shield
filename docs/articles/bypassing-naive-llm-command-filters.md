# Bypassing Naive LLM Command Filters (And How We Engineered MCP-Shield to Stop Them) 🛡️

*A Red-Team Case Study on Model Context Protocol (MCP) Security*

As autonomous AI agents (Claude Desktop, Cursor, Windsurf, Cline) transition from simple text generators to active execution environments, they become susceptible to **indirect prompt injection**.

When an agent reads untrusted data — whether from a scraped web page, a retrieved GitHub issue, or an error traceback — an adversary can embed hidden instructions directing the agent to execute malicious shell commands.

In response, many agent platforms install basic input filters. In this article, we examine the most common naive filter implementations, demonstrate how red-team evasion techniques bypass them, and detail how **MCP-Shield** mitigates each class of attack.

---

## 1. Case Study 1: The Substring / Regex Filter

### The Defense
```python
# Naive Python tool guard
BLOCKED_PATTERNS = ["rm -rf", "sudo", "mkfs", "dd"]
def execute_command(cmd: str):
    for pattern in BLOCKED_PATTERNS:
        if pattern in cmd:
            raise SecurityError(f"Blocked dangerous pattern: {pattern}")
    subprocess.run(cmd, shell=True)
```

### The Evasion
1. **Parameter Expansion**: `${CMD:-rm} -rf /` or `$IFS` splitting: `rm$IFS-rf$IFS/`
2. **Path Quoting**: `'/b'in'/'rm -rf /` or `"r""m" -rf /`
3. **Hex/Base64 Obfuscation**: `$(printf '\x72\x6d') -rf /`
4. **Invocation Wrapping**: `env nice -n 19 timeout 10 rm -rf /` (avoids `sudo`)

### How MCP-Shield Mitigates It
MCP-Shield uses `tree-sitter-bash` to walk syntax tree nodes directly. Before evaluating nodes:
- De-obfuscates `$IFS` whitespace replacements.
- Strips quote literals from identifier tokens.
- Recursively unwraps execution utility wrappers (`sudo`, `env`, `nice`, `timeout`, `stdbuf`, `pkexec`).
- Blocks dynamic subshell evaluations `$()` and process substitutions `<()`.

---

## 2. Case Study 2: Naive POSIX Argument Parsers & Substring Matching

### The Defense
Developers often try to inspect arguments after splitting on spaces:
```javascript
const tokens = command.split(' ');
if (tokens[0] === 'rm' && tokens.some(t => t.includes('r'))) {
    block();
}
```

### The Vulnerability & False-Positive Traps
1. **False Positive Collision**: A benign build cleanup command `rm -exclude=cache ./dist` is blocked because `-exclude=cache` contains the letter `'r'`.
2. **Evasion via Combined Flags**: Flags like `-rf` vs `-r -f` vs `--recursive --force` vs `-rvf` are not parsed consistently.
3. **The `--` End-of-Options Boundary**:
   ```bash
   rm -- -r /
   ```
   In POSIX standard, `-r` after `--` is a literal filename, NOT an option flag. Naive parsers misclassify it.

### How MCP-Shield Mitigates It
MCP-Shield implements POSIX-compliant argument parsing in `ASTAnalyzer.parseCommandFlagsAndOperands()`:
- Splits short flags character-by-character (`-rf` -> `r`, `f`).
- Distinguishes option keys from values (`-exclude=dir` yields flag `exclude`, never substring `'r'`).
- Strictly enforces `--` operand delimiters.
- Distinguishes Windows switches (`/s`, `/q`) from Unix root paths (`/src`).

---

## 3. Case Study 3: The Pipeline & Subshell Escape

### The Defense
Some gateways only inspect the first command in a pipeline, assuming subsequent pipe stages are harmless utilities like `grep` or `head`.

```bash
# Gateway inspects "cat app.log" -> Marks as SAFE!
cat app.log | (python3 -c "import os; os.system('id')")
cat list.txt | xargs sh
```

### The Evasion
The first stage `cat` is benign. However, downstream pipe targets execute arbitrary interpreters (`sh`, `bash`, `python3`) or compound subshells `( ... )`.

### How MCP-Shield Mitigates It
MCP-Shield traverses all pipeline nodes from stage $1$ to $N$:
1. Every pipe target must be strictly allowlisted (`SAFE_PIPE_TARGETS` = `grep`, `awk`, `sed`, `sort`, `uniq`, `head`, `tail`, `wc`, `tr`, `jq`).
2. Compound subshells `| ( ... )` and block groups `| { ... }` in pipeline positions are rejected fail-closed.
3. `xargs` invocations are recursively unwrapped and validated against safe targets.

---

## 4. Case Study 4: Cloud Metadata SSRF & Exfiltration

### The Defense
Blocking domain strings like `evil.com` or `localhost`.

### The Evasion
1. **Cloud Instance Metadata Service (IMDSv1)**: `http://169.254.169.254/latest/meta-data/` to dump AWS IAM temporary role credentials.
2. **Alternative IP Encodings**: `http://0x7f000001/` or `http://2130706433/` (decimal representations of `127.0.0.1`).
3. **DNS Rebinding**: Attacker domain resolves to `evil.com` initially, then TTL=0 resolves to `169.254.169.254` on subsequent requests.

### How MCP-Shield Mitigates It
In `PolicyEngine.checkEgress()`:
- Enforces strict link-local (`169.254.0.0/16`) and RFC 1918 private network blocking (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- Blocks IPv4-mapped IPv6 and localhost loopbacks.
- Performs IP pinning to neutralize DNS rebinding attacks.

---

## 5. Summary Table: Naive Filters vs MCP-Shield

| Attack Vector | Naive Regex / Substring Filter | MCP-Shield Gateway |
| :--- | :--- | :--- |
| **$IFS Parameter Splitting** | ❌ Bypassed | ✅ Normalized & Blocked |
| **Quoted Command Concatenation** | ❌ Bypassed | ✅ Unrolled & Blocked |
| **Stacked Wrappers (`sudo env nice`)** | ❌ Bypassed | ✅ Recursively Unwrapped |
| **Combined Short Flags (`-rf`)** | ⚠️ High False Positives | ✅ POSIX Flag Disambiguation |
| **Pipeline Subshell Escapes** | ❌ Bypassed | ✅ Strict Pipe Allowlists |
| **Cloud Metadata SSRF (`169.254...`)** | ❌ Bypassed | ✅ Active IP Pinning & Egress Shield |
| **Performance Overhead** | Variable / ReDoS Risks | ⚡ ~150 µs Zero-Allocation Hot-Path |

---

## 🚀 Experience Zero-Trust Agent Security

Protect your Claude Desktop, Cursor, and Windsurf environments with one command:

```bash
npx mcp-shield protect
```

Read our open-source codebase and submit bypass challenges:  
👉 [https://github.com/rahulxcodex/mcp-shield](https://github.com/rahulxcodex/mcp-shield)
