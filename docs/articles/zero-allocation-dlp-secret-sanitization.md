# Pre-Allocated Buffer High-Entropy DLP: Sanitizing Secrets on the Hot Path in < 150µs 🔑

*By Rahul (@rahulxcodex) — Creator of MCP-Shield*

When autonomous AI agents interact with development environments, they constantly read and write text: terminal output, stack traces, `.env` files, database dumps, and API responses.

A major risk in the Model Context Protocol (MCP) ecosystem is **secret leakage**. If an agent reads an environment file containing an `AWS_SECRET_ACCESS_KEY` or `OPENAI_API_KEY`, that credential is sent upstream in prompt context to third-party LLM providers, cached in provider logs, or potentially exfiltrated via prompt injection.

To solve this, we built a **Lossless Reversible Data Loss Prevention (DLP) Sanitizer** into **MCP-Shield**.

In this post, we explain how we achieved **sub-150 microsecond latency** while eliminating per-calculation TypedArray allocations and maintaining high-throughput Shannon entropy scanning.

---

## 1. The Core Architecture: Reversible Tokenization

Unlike standard DLP tools that permanently redact secrets with `[REDACTED]`, an AI coding assistant needs to pass tokenized placeholders between tools without breaking data flow.

```
Agent Request (Contains Real API Key)
       │
       ▼
┌──────────────────────────────────────┐
│ MCP-Shield Sanitizer                 │
│ 1. Scan payload with Compound Regex  │
│ 2. Calculate Shannon Entropy         │
│ 3. Store in AES-256-GCM Vault        │
│ 4. Replace with session-scoped token │
└──────────────────┬───────────────────┘
                   │
                   ▼
Downstream MCP Server receives: `[[SHIELD_SECRET_3f9b2c1a-...]]`
                   │
                   ▼
Downstream Tool Response contains: `[[SHIELD_SECRET_3f9b2c1a-...]]`
                   │
                   ▼
┌──────────────────────────────────────┐
│ MCP-Shield Restorer                  │
│ 1. Lookup token in Vault             │
│ 2. Losslessly restore original key   │
└──────────────────┬───────────────────┘
                   │
                   ▼
Agent Context receives sanitized results
```

---

## 2. Compound Pattern Matching in a Single Pass

Running 15 separate regular expressions sequentially across every incoming JSON-RPC frame causes severe CPU overhead and regex backtracking.

MCP-Shield compiles all known cloud credential formats into a single **Compound Regular Expression**:

```typescript
const COMPOUND_REGEX = /((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})|(sk-ant-api03-[a-zA-Z0-9\-_]{20,})|(sk-(?:proj-)?[a-zA-Z0-9]{20,})|(xox[baprs]-[a-zA-Z0-9]{10,})|(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{82})|(AIza[0-9A-Za-z\-_]{35})|(sk_(?:live|test)_[0-9a-zA-Z]{24,})|(hf_[a-zA-Z0-9]{34,})|(glpat-[0-9a-zA-Z\-_]{20,})|(ey[A-Za-z0-9\-_=]{10,}\.ey[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,})|(-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----)|\b([a-zA-Z0-9+\/_\-]{40,}={0,2})\b/g;
```

When a match occurs in the callback:
- If it matched capture groups 1–11 (AWS, Anthropic, OpenAI, Slack, GitHub, Google, Stripe, HuggingFace, GitLab, JWT, SSH), it is immediately tokenized.
- If it matched group 12 (generic 40+ character string), it falls through to **Shannon Entropy Analysis**.

---

## 3. Eliminating Allocations in Shannon Entropy Calculations

The Shannon entropy $H(X)$ of a string is given by:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

A naive implementation allocates a new frequency map or `new Uint32Array(256)` on every string evaluation:

```typescript
// BAD: Allocates memory on the hot path for every token
function calculateEntropyBad(str: string): number {
  const frequencies = new Uint32Array(256); // ❌ Garbage collection churn!
  // ...
}
```

In a stream processing thousands of lines of logs per second, this triggers continuous V8 garbage collection cycles, degrading proxy throughput.

### The Pre-Allocated Hot-Path Buffer Solution
In MCP-Shield, we pre-allocate an instance buffer `this.charFrequencies = new Uint32Array(256)` once when the sanitizer initializes:

```typescript
export class SecretSanitizer {
  // Pre-allocated frequency buffer to eliminate heap allocations on entropy frequency counts
  private charFrequencies = new Uint32Array(256);

  private calculateEntropy(str: string): number {
    const len = str.length;
    if (len === 0) return 0;

    // Reset buffer in-place without reallocating
    this.charFrequencies.fill(0);

    for (let i = 0; i < len; i++) {
      const code = str.charCodeAt(i);
      if (code < 256) {
        this.charFrequencies[code]++;
      }
    }

    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      const count = this.charFrequencies[i];
      if (count > 0) {
        const p = count / len;
        entropy -= p * Math.log2(p);
      }
    }

    return entropy;
  }
}
```

---

## 4. Empirical Baseline Benchmarks

> **⚠️ Disclosure**: Tested against our curated baseline corpus of 1,780 lines of simulated multi-language code, configs, and logs (`benchmarks/secret-detection.bench.ts`). This verifies deterministic rule coverage against known formats and high-entropy noise fixtures; independent external evaluation against held-out public datasets is ongoing.

| Category | Lines | Real Secrets | True Positives | False Positives | False Negatives | Precision (Baseline) | Recall (Baseline) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Source Code (TypeScript)** | 420 | 60 | 60 | 0 | 0 | 100.0% | 100.0% |
| **Source Code (Python)** | 340 | 40 | 40 | 0 | 0 | 100.0% | 100.0% |
| **Infrastructure (YAML/JSON)** | 280 | 60 | 60 | 0 | 0 | 100.0% | 100.0% |
| **CI/CD & Server Logs** | 140 | 40 | 40 | 0 | 0 | 100.0% | 100.0% |
| **Certificates & Keys** | 120 | 20 | 20 | 0 | 0 | 100.0% | 100.0% |
| **Build Log Noise Dump** | 260 | 80 | 80 | 0 | 0 | 100.0% | 100.0% |
| **Benign Code Control** | 220 | 0 | 0 | 0 | 0 | 100.0% | 100.0% |

### Performance Metrics
- **DLP Scanning Throughput**: `> 215,000 lines/second`
- **1 KB Payload Overhead**: `17.5 µs`
- **14 KB Payload Overhead**: `3.5 ms`
- **Proxy Hot-Path Total**: `~ 157 µs` median latency

---

## 5. Lossless Bijective Roundtrip Guarantee

We verified that `restore(sanitize(payload)) === payload` holds true across arbitrarily nested JSON payloads using property-based fuzz testing via `fast-check`.

```typescript
it('should losslessly round-trip complex JSON structures containing multiple secrets', () => {
  fc.assert(
    fc.property(jsonPayloadArbitrary, (data) => {
      const originalJson = JSON.stringify(data);
      const sanitized = sanitizer.sanitize(originalJson);
      const restored = sanitizer.restore(sanitized);

      expect(restored).toBe(originalJson);
    })
  );
});
```

---

## 🚀 Get Started with MCP-Shield

Add DLP secret sanitization to your local MCP agents today:

```bash
npx mcp-shield protect
```

Full benchmark methodology and source code:  
👉 [https://github.com/rahulxcodex/mcp-shield](https://github.com/rahulxcodex/mcp-shield)
