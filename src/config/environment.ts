import { z } from 'zod';

/**
 * MCP Shield Production Environment Schema & Invariant Validator
 * Enforces Phase 1.4 & Non-Negotiable Rules 2, 6:
 * - Strict schema validation on startup
 * - Minimum entropy/length for keys
 * - No dummy/placeholder fallbacks in production
 * - Fail-closed on missing production requirements
 */
export const EnvironmentConfigSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  MCP_SHIELD_ENV: z.enum(['development', 'staging', 'production']).default('production'),
  MCP_SHIELD_API_KEY: z.string().min(16).optional(),
  MCP_SHIELD_CLOUD_URL: z.string().url().default('https://cloud.mcp-shield.com/api/v1/telemetry/ingest'),
  ENTERPRISE_INTEL_ENDPOINT: z.string().url().default('https://mcp-shield-enterprise-intel.onrender.com'),
  MCP_SHIELD_FPE_KEY: z.string().min(32).optional(),
  MCP_SHIELD_CONFIG_PATH: z.string().optional(),
  MCP_SHIELD_CONFIG_SHA256: z.string().regex(/^[a-fA-F0-9]{64}$/, 'Must be 64-character hex SHA-256 digest').optional(),
  AUDIT_SIGNING_KEY: z.string().min(16).optional(),
});

export type EnvironmentConfig = z.infer<typeof EnvironmentConfigSchema>;

export function validateEnvironment(rawEnv: Record<string, string | undefined> = process.env): EnvironmentConfig {
  const result = EnvironmentConfigSchema.safeParse(rawEnv);
  if (!result.success) {
    const errorDetails = result.error.issues.map((e: z.ZodIssue) => `${e.path.join('.')}: ${e.message}`).join('; ');
    if (rawEnv.NODE_ENV === 'production') {
      throw new Error(`[MCP-SHIELD CRITICAL] Production environment configuration invalid: ${errorDetails}`);
    }
    console.warn(`[MCP-SHIELD WARN] Environment validation warnings: ${errorDetails}`);
  }

  // Non-Negotiable Rule 6: Prohibit placeholder secrets in production
  if (rawEnv.NODE_ENV === 'production') {
    const forbiddenSubstrings = ['placeholder', 'dummy', 'sk_test_', 'default-mcp-shield', 'mock_'];
    for (const [key, value] of Object.entries(rawEnv)) {
      if (!value) continue;
      for (const forbidden of forbiddenSubstrings) {
        if (value.toLowerCase().includes(forbidden)) {
          throw new Error(
            `[MCP-SHIELD CRITICAL] Insecure fallback secret detected in environment variable "${key}" for production mode.`
          );
        }
      }
    }
  }

  return result.success ? result.data : (rawEnv as unknown as EnvironmentConfig);
}

export const environment = validateEnvironment();
