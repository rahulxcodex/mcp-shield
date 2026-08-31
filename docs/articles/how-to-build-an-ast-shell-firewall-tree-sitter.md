# How I Built an AST Shell Firewall for Bash with Tree-Sitter 🌲

*By Rahul (@rahulxcodex) — Creator of MCP-Shield*

When building developer tools that allow autonomous AI agents (like Claude Desktop, Cursor, or Cline) to execute shell commands via the Model Context Protocol (MCP), the most common security impulse is to write a regex filter:

```typescript
// The naive approach: regex blocklist
const DANGEROUS = [/rm\s+-rf/, /mkfs/, /dd\s+if=/];
function isSafe(cmd: string) {
  return !DANGEROUS.some(r => r.test(cmd));
}
```

Within 10 minutes of adversarial testing, this approach completely collapses.

In this article, I’ll explain why regular expressions are fundamentally the wrong abstraction for shell security, and walk through how we engineered a sub-millisecond **AST Shell Firewall** using native `tree-sitter-bash` C bindings.

---

## 1. Why Regex Fails on Shell Grammar

Bash is not a regular language; it is a context-sensitive command execution language with complex quoting, expansions, and nesting rules. 

Here are five ways a prompt-injected LLM or malicious payload bypasses regex blocklists while achieving the exact same destructive payload:

### 1. Shell Variable & Delimiter Substitution
```bash
# Regex looking for "rm -rf" fails:
rm$IFS-rf$IFS/
${CMD:-rm} -rf /
```
`$IFS` (Internal Field Separator) is replaced by bash with a space at runtime.

### 2. Quoting & Backslash Obfuscation
```bash
\r\m -rf /
"r"'m' -rf /
```
Bash concatenates adjacent quoted string tokens into the single command primitive `rm`.

### 3. Stacked Execution Wrappers
```bash
sudo env nohup nice -n 19 timeout 30s rm -rf /
```
A regex looking for `rm` at the start of a command string misses the underlying primitive buried beneath multiple wrapper utilities.

### 4. Subshell & Compound Piping
```bash
cat app.log | (python3 -c "import os; os.system('id')")
cat list.txt | xargs sh
```

### 5. Short-Flag Collisions vs Benign Options
If you try to broaden your regex to check for the letter `'r'` in dashed flags, benign commands break:
```bash
# Legitimate command falsely blocked by naive substring matching:
rm -exclude=cache ./dist
```
POSIX combined short flags (`-rf`) must be decomposed into individual switches (`-r`, `-f`), while long options (`--exclude`, `--format`) and operands following `--` must be parsed distinctly.

---

## 2. Parsing Bash with Tree-Sitter

To solve this deterministically, we need an **Abstract Syntax Tree (AST)**.

Tree-Sitter is an incremental parsing system that generates concrete syntax trees from language grammars. Using `tree-sitter-bash`, a command like `sudo env nice rm -rf /` is parsed into a structured AST:

```
command [0, 0] - [0, 29]
  name: command_name [0, 0] - [0, 4]
    word: "sudo"
  argument: word: "env"
  argument: word: "nice"
  argument: word: "rm"
  argument: word: "-rf"
  argument: word: "/"
```

### Initializing Tree-Sitter in TypeScript
```typescript
import Parser from 'tree-sitter';
// @ts-ignore
import Bash from 'tree-sitter-bash';

export class ASTAnalyzer {
  private parser: Parser;

  constructor() {
    this.parser = new Parser();
    this.parser.setLanguage(Bash);
  }
}
```

---

## 3. Unwrapping the Command Wrapper Chain

When an agent executes `sudo nice env rm -rf /`, the root command node in the AST has `sudo` as its command name. We must iteratively unwrap wrapper binaries to find the underlying executable primitive.

We define known execution wrappers and their option signatures:

```typescript
const EXEC_WRAPPERS: Record<string, { skipFlags: boolean; takesArg: string[] }> = {
  'sudo': { skipFlags: true, takesArg: ['-u', '-g', '-p', '-C'] },
  'env': { skipFlags: true, takesArg: ['-u', '-S'] },
  'nice': { skipFlags: true, takesArg: ['-n'] },
  'nohup': { skipFlags: false, takesArg: [] },
  'timeout': { skipFlags: true, takesArg: ['-s', '-k'] },
  'stdbuf': { skipFlags: true, takesArg: ['-i', '-o', '-e'] },
  'pkexec': { skipFlags: true, takesArg: ['--user'] }
};
```

Our unwrapper recursively steps through tokens, skipping wrapper flags and option values, until it uncovers the true primitive:

```typescript
private unwrapCommandTokens(tokens: string[]): { primitive: string; args: string[] } {
  let idx = 0;
  while (idx < tokens.length) {
    const rawToken = tokens[idx];
    const normalized = this.normalizeToken(rawToken);

    if (EXEC_WRAPPERS[normalized]) {
      const config = EXEC_WRAPPERS[normalized];
      idx++;
      while (idx < tokens.length) {
        const arg = tokens[idx];
        if (config.takesArg.includes(arg)) {
          idx += 2; // Skip flag and its argument value
        } else if (arg.startsWith('-')) {
          idx++;
        } else if (normalized === 'env' && arg.includes('=')) {
          idx++; // Skip env var assignments (e.g., VAR=val)
        } else {
          break;
        }
      }
    } else {
      break;
    }
  }

  return {
    primitive: idx < tokens.length ? this.normalizeToken(tokens[idx]) : '',
    args: tokens.slice(idx + 1)
  };
}
```

---

## 4. POSIX Short-Flag Disambiguation

Once the primitive (e.g., `rm`) is identified, we must parse its arguments.

POSIX allows short flags to be combined: `-rf` is equivalent to `-r -f` or `-fr`. Furthermore, any argument following `--` is strictly a file operand, never a flag.

```typescript
public parseCommandFlagsAndOperands(args: string[]): { flags: Set<string>; operands: string[] } {
  const flags = new Set<string>();
  const operands: string[] = [];
  let parseFlags = true;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    // End-of-options delimiter
    if (parseFlags && arg === '--') {
      parseFlags = false;
      continue;
    }

    if (parseFlags && arg.startsWith('-')) {
      if (arg.startsWith('--')) {
        // Long option: --recursive
        const optionName = arg.slice(2).split('=')[0];
        flags.add(optionName.toLowerCase());
      } else {
        // Short option or combined short flags: -rf -> 'r', 'f'
        const optionBody = arg.slice(1).split('=')[0];
        for (const char of optionBody) {
          flags.add(char);
        }
      }
    } else {
      operands.push(arg);
    }
  }

  return { flags, operands };
}
```

Now, checking for recursive deletions is precise:
```typescript
const isRecursive = flags.has('r') || flags.has('R') || flags.has('recursive');
const isForce = flags.has('f') || flags.has('force');

if (isRecursive && operands.some(p => this.isDangerousPath(p))) {
  return { isSafe: false, reason: 'Recursive deletion of root/system path' };
}
```

---

## 5. Pipeline Validation & Subshell Defenses

In bash pipelines (`cmd1 | cmd2 | cmd3`), each stage must be inspected. Attackers often try to pipe output into arbitrary interpreters or subshells:

```bash
cat app.log | (python3 -c "import os; os.system('id')")
```

When walking pipeline nodes in Tree-Sitter:
1. Every pipeline target must match an explicit allowlist (`SAFE_PIPE_TARGETS` like `grep`, `awk`, `sed`, `sort`, `uniq`, `head`, `tail`, `wc`, `tr`, `jq`).
2. Compound statements, subshells `( ... )`, command blocks `{ ... }`, and while-loops as pipe targets are immediately rejected.

---

## 6. Performance & Conclusion

Because Tree-Sitter uses optimized native C grammars and we pre-allocate parser state, AST parsing runs in **< 130 microseconds** per command (> 7,500 ops/sec).

By moving from heuristic regex checks to deterministic AST grammar inspection, MCP-Shield provides an uncompromising security boundary without adding perceivable latency to AI agent interactions.

Explore the complete implementation on GitHub:  
👉 [https://github.com/rahulxcodex/mcp-shield](https://github.com/rahulxcodex/mcp-shield)
