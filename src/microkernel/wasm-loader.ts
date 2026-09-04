import * as crypto from 'crypto';
import { SecurityEvidence } from '../security/evidence';

export interface PluginManifest {
  pluginName: string;
  version: string;
  publisherId: string;
  sha256Digest: string;
  signature: string;
  maxMemoryPages?: number;
  timeoutMs?: number;
}

export interface LoadedPlugin {
  manifest: PluginManifest;
  instance: WebAssembly.Instance;
  memory: WebAssembly.Memory;
  loadedAt: number;
}

export class WasmMicrokernel {
  private plugins = new Map<string, LoadedPlugin>();
  private trustedPublishers = new Set<string>(['mcp-shield-verified', 'official-antigravity']);
  private publisherKeys = new Map<string, string>();

  constructor(options?: { trustedPublishers?: string[]; publisherKeys?: Record<string, string> }) {
    if (options?.trustedPublishers) {
      options.trustedPublishers.forEach(pub => this.trustedPublishers.add(pub));
    }
    if (options?.publisherKeys) {
      Object.entries(options.publisherKeys).forEach(([pub, key]) => this.publisherKeys.set(pub, key));
    }
  }

  public registerTrustedPublisher(publisherId: string, secretKey: string): void {
    this.trustedPublishers.add(publisherId);
    this.publisherKeys.set(publisherId, secretKey);
  }

  /**
   * Cryptographically verifies and loads a sandboxed WebAssembly security plugin.
   * Fail closed for invalid signatures, unknown publisher, unexpected digest, or resource abuse.
   */
  public async loadPlugin(manifest: PluginManifest, wasmBuffer: Buffer): Promise<void> {
    // 1. Publisher allowlist verification
    if (!this.trustedPublishers.has(manifest.publisherId)) {
      throw new Error("FAIL_CLOSED: Plugin publisher '" + manifest.publisherId + "' is not in the trusted allowlist.");
    }

    // 2. Binary digest verification
    const computedDigest = crypto.createHash('sha256').update(wasmBuffer).digest('hex');
    const digestMatch = crypto.timingSafeEqual(
      Buffer.from(computedDigest, 'hex'),
      Buffer.from(manifest.sha256Digest, 'hex')
    );
    if (!digestMatch) {
      throw new Error("FAIL_CLOSED: Plugin '" + manifest.pluginName + "' SHA-256 digest mismatch.");
    }

    // 3. Cryptographic signature verification
    const secretKey = this.publisherKeys.get(manifest.publisherId);
    if (!secretKey) {
      throw new Error("FAIL_CLOSED: Missing verification key for publisher '" + manifest.publisherId + "'.");
    }

    const payloadToSign = manifest.publisherId + ':' + manifest.pluginName + ':' + manifest.sha256Digest + ':' + manifest.version;
    const expectedSig = crypto.createHmac('sha256', secretKey).update(payloadToSign).digest('hex');
    const sigMatch = manifest.signature.length === expectedSig.length && crypto.timingSafeEqual(
      Buffer.from(manifest.signature, 'utf8'),
      Buffer.from(expectedSig, 'utf8')
    );

    if (!sigMatch) {
      throw new Error("FAIL_CLOSED: Cryptographic signature verification failed for plugin '" + manifest.pluginName + "'.");
    }

    // 4. Memory bounds sandbox configuration (max pages, e.g. 16 pages = 1 MB)
    const maxPages = manifest.maxMemoryPages || 16;
    const memory = new WebAssembly.Memory({ initial: 1, maximum: maxPages });

    const wasmModule = await WebAssembly.compile(new Uint8Array(wasmBuffer));
    const instance = await WebAssembly.instantiate(wasmModule, {
      env: {
        memory,
        abort: () => {
          throw new Error('FAIL_CLOSED: Wasm execution aborted due to fault');
        }
      }
    });

    this.plugins.set(manifest.pluginName, {
      manifest,
      instance,
      memory,
      loadedAt: Date.now()
    });
  }

  /**
   * Execute an isolated analyzer. Fail-closed: missing export throws error instead of returning true.
   */
  public analyze(pluginName: string, payload: string): boolean {
    const plugin = this.plugins.get(pluginName);
    if (!plugin) {
      throw new Error("FAIL_CLOSED: Plugin '" + pluginName + "' is not loaded.");
    }

    const analyzeFn = plugin.instance.exports.analyzePayload as Function;
    if (typeof analyzeFn !== 'function') {
      // FAIL CLOSED: Never fallback to return true
      throw new Error("FAIL_CLOSED: Plugin '" + pluginName + "' does not export 'analyzePayload' function.");
    }

    try {
      const result = analyzeFn(0, payload.length);
      return result === 1;
    } catch (err: any) {
      throw new Error("FAIL_CLOSED: Plugin execution failed: " + err.message);
    }
  }

  public getPluginDetails(pluginName: string): LoadedPlugin | undefined {
    return this.plugins.get(pluginName);
  }
}
