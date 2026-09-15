import * as crypto from 'crypto';

export interface ToolDefinition {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface PinnedSchemaRecord {
  toolName: string;
  definitionDigest: string;
  signature: string; // Ed25519 signature hex
  pinnedAt: number;
}

/**
 * Cryptographic Schema Pinning Engine
 * Enforces immutable Ed25519 digests over { name, description, inputSchema } on every tool call,
 * preventing post-initialization schema poisoning and description-injection bypasses.
 */
export class CryptographicSchemaPinner {
  private readonly pinnedSchemas: Map<string, PinnedSchemaRecord> = new Map();
  private readonly signingKey: crypto.KeyObject;
  public readonly publicKey: crypto.KeyObject;

  constructor(keyPair?: { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject }) {
    if (keyPair) {
      this.signingKey = keyPair.privateKey;
      this.publicKey = keyPair.publicKey;
    } else {
      const generated = crypto.generateKeyPairSync('ed25519');
      this.signingKey = generated.privateKey;
      this.publicKey = generated.publicKey;
    }
  }

  /**
   * Deterministic canonical serialization of tool definition
   */
  public static computeDigest(tool: ToolDefinition): string {
    const canonical = JSON.stringify({
      description: tool.description || '',
      inputSchema: tool.inputSchema || {},
      name: tool.name
    });

    return crypto.createHash('sha3-256').update(canonical).digest('hex');
  }

  /**
   * Pins a tool definition at registration time with an Ed25519 cryptographic signature
   */
  public pinTool(tool: ToolDefinition): PinnedSchemaRecord {
    const digest = CryptographicSchemaPinner.computeDigest(tool);
    const msg = Buffer.from(`SCHEMA_PIN:${tool.name}:${digest}`, 'utf8');
    const signature = crypto.sign(null, msg, this.signingKey).toString('hex');

    const record: PinnedSchemaRecord = {
      toolName: tool.name,
      definitionDigest: digest,
      signature,
      pinnedAt: Date.now()
    };

    this.pinnedSchemas.set(tool.name, record);
    return record;
  }

  /**
   * Verifies that incoming tool invocation matches the pinned immutable cryptographic digest
   */
  public verifyToolInvocation(tool: ToolDefinition): { valid: boolean; reason?: string } {
    const pinned = this.pinnedSchemas.get(tool.name);
    if (!pinned) {
      return {
        valid: false,
        reason: `Tool '${tool.name}' is unpinned. Dynamic unverified tools are blocked.`
      };
    }

    const currentDigest = CryptographicSchemaPinner.computeDigest(tool);
    if (currentDigest !== pinned.definitionDigest) {
      return {
        valid: false,
        reason: `SCHEMA PINNING VIOLATION: Tool '${tool.name}' definition was mutated post-initialization`
      };
    }

    // Verify Ed25519 attestation
    try {
      const msg = Buffer.from(`SCHEMA_PIN:${tool.name}:${pinned.definitionDigest}`, 'utf8');
      const sig = Buffer.from(pinned.signature, 'hex');
      const isValid = crypto.verify(null, msg, this.publicKey, sig);
      if (!isValid) {
        return {
          valid: false,
          reason: `SCHEMA PINNING VIOLATION: Invalid Ed25519 schema signature for '${tool.name}'`
        };
      }
    } catch (err: any) {
      return {
        valid: false,
        reason: `Cryptographic schema signature verification failed: ${err.message}`
      };
    }

    return { valid: true };
  }

  public getPinnedCount(): number {
    return this.pinnedSchemas.size;
  }
}
