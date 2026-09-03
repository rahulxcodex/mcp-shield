---
name: mcp-shield-architecture
description: Complete architectural context, trade secret boundaries, cryptographic licensing workflows, and deployment topology for the 3 MCP-Shield repositories. Use in new chats to instantly load full context.
---

# MCP-Shield 3-Repository System Architecture & Context Guide

This skill provides full contextual grounding across the 3 repositories comprising the MCP-Shield ecosystem. Use this skill whenever working on MCP-Shield features, security auditing, deployments, or trade secret boundaries.

## 1. Repository Ecosystem Topology

```
+-----------------------------------------------------------------------------------+
| 1. mcp-shield (Public Open Source / npm: mcpshld / MIT)                          |
|    - Local Zero-Trust Gateway & AST Firewall (CLI: mcp-shield, mcpshld)           |
|    - Bijective Format-Preserving Encryption DLP Sanitizer                         |
|    - Multi-Tenant Memory-Safe State Machine & Stream Framing                      |
|    - Open Security Benchmark Suite (42 suites / 693 tests)                        |
|    - Cloud Telemetry Emitter & Next.js Console (Deployed on Vercel)              |
+-----------------------------------------+-----------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        | HTTP RPC (x-api-key)                                              | Ed25519 Public Verification
        v                                                                   v
+---------------------------------------------------+   +---------------------------------------------------+
| 2. mcp-shield-enterprise-intel (Private / Render) |   | 3. mcp-shield-licensing (Private / Vercel API)    |
|    - TRADE SECRET BOUNDARY                        |   |    - Ed25519 Military-Grade Private Signing Key   |
|    - Non-linear multi-factor Risk Scoring Engine  |   |    - Anti-Sybil GitHub Account Age Validation     |
|    - Proprietary AST Complexity Exponents         |   |    - Stripe Billing & Webhook Synchronization     |
|    - Egress Severity Multipliers & Drift Penalty  |   |    - Supabase Organization & Tenant State         |
|    - Live URL: mcp-shield-enterprise-intel.onrender|   |    - Live URL: mcp-shield-licensing.vercel.app     |
+---------------------------------------------------+   +---------------------------------------------------+
```

---

## 2. Trade Secret Isolation Matrix

| Component | Repository | Visibility | Storage Location | Protection Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **Non-Linear Risk Scoring** | `mcp-shield-enterprise-intel` | **Private** | `src/intel/risk-engine.ts` | Isolated behind Render HTTPS microservice (`x-api-key: mcpshld_live_*`). Constants (`AST_COMPLEXITY_EXPONENT = 1.35`, `EGRESS_SEVERITY_MULTIPLIER = 2.45`, `DRIFT_BASE_PENALTY = 35.0`) never appear in public client code. |
| **License Private Key** | `mcp-shield-licensing` | **Private** | Vercel KMS / `LICENSE_PRIVATE_KEY` | Ed25519 signing key strictly stored in Vercel environment variables. Public client only contains `MCowBQYDK2VwAyEA...` public key for verification. |
| **Master Key Verification** | `mcp-shield` | **Public** | `src/security/license-manager.ts` | One-way cryptographic SHA-256 hash comparison. Plaintext bypass keys are forbidden in client code. |
| **Stripe / Supabase Admin** | `mcp-shield-licensing` | **Private** | `src/app/api/v1/billing/*` | Webhook secrets and Service Role keys restricted to private server routes. |

---

## 3. Cryptographic License Verification Workflow

```
[User signs up on Licensing Portal]
         |
         v
[Next.js API: /api/license]
   1. Validates GitHub OAuth token with GitHub API (Account age > 1 year anti-sybil)
   2. Generates payload: { githubId, issuedAt, expiresAt, isTrial, tier }
   3. Signs payload using Ed25519 Private Key (LICENSE_PRIVATE_KEY)
   4. Returns license: base64(payload).base64(signature)
         |
         v
[Client runs: mcp-shield license <key>]
   1. Reads public key: MCowBQYDK2VwAyEA70w3xsSl9Dm+tkcGIEXZLHlJaRqWPHJp+IprYiPLjNA=
   2. Verifies cryptographic signature with crypto.verify()
   3. Checks timestamp expiration
   4. Installs key to ~/.mcp-shield/license.key
```

---

## 4. Key Environment Variables Map

### `mcp-shield` (Client / Gateway)
- `MCP_SHIELD_PUBLIC_KEY`: Optional Ed25519 public key override.
- `MCP_SHIELD_API_KEY`: API key for remote enterprise scoring (`mcpshld_live_*`).
- `ENTERPRISE_INTEL_ENDPOINT`: Default `https://mcp-shield-enterprise-intel.onrender.com`.
- `MCP_SHIELD_MASTER_KEY_HASH`: SHA-256 hash for emergency bypass.

### `mcp-shield-enterprise-intel` (Render Web Service)
- `PORT`: Default `10000` (Render default).
- `NODE_ENV`: `production`.

### `mcp-shield-licensing` (Vercel API)
- `LICENSE_PRIVATE_KEY`: Ed25519 PEM private key for signing licenses.
- `NEXT_PUBLIC_SUPABASE_URL`: Supabase project URL.
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`: Client Supabase anon key.
- `SUPABASE_SERVICE_ROLE_KEY`: Admin key for webhooks & license provisioning.
- `STRIPE_SECRET_KEY`: Stripe API secret key.
- `STRIPE_WEBHOOK_SECRET`: Stripe webhook verification secret.

---

## 5. Standard Deployment & Release Protocol

1. **Test Suite**: Always run `npm test` in `mcp-shield` (must pass 42/42 suites, 693+ tests).
2. **Build**: Run `npm run build` (`tsc -p tsconfig.build.json`).
3. **NPM Publish**: Bump semver in `package.json`, run `npm publish --access public`.
4. **Git Push**: Push `main` branch to all 3 repositories on GitHub.
5. **Vercel**: Automatic CD builds triggered on commit to `rahulxcodex/mcp-shield` and `rahulxcodex/mcp-shield-licensing`.
6. **Render**: Automatic CD deploys `rahulxcodex/mcp-shield-enterprise-intel` via webhook.
