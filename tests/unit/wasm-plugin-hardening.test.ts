import * as crypto from 'crypto';
import { WasmMicrokernel, PluginManifest } from '../../src/microkernel/wasm-loader';

describe('Hardened WasmMicrokernel (Roadmap Section 8)', () => {
  // Minimal valid WebAssembly binary module: (module)
  const emptyWasmBytes = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  const emptyDigest = crypto.createHash('sha256').update(emptyWasmBytes).digest('hex');
  const secretKey = 'test-signing-key-123';

  const computeSig = (pub: string, name: string, digest: string, ver: string) => {
    return crypto.createHmac('sha256', secretKey).update(pub + ':' + name + ':' + digest + ':' + ver).digest('hex');
  };

  it('rejects plugins from unknown publishers (Fail-Closed)', async () => {
    const microkernel = new WasmMicrokernel();
    const manifest: PluginManifest = {
      pluginName: 'rogue-plugin',
      version: '1.0.0',
      publisherId: 'untrusted-entity',
      sha256Digest: emptyDigest,
      signature: 'dummy-sig'
    };

    await expect(microkernel.loadPlugin(manifest, emptyWasmBytes)).rejects.toThrow(
      /is not in the trusted allowlist/
    );
  });

  it('rejects plugins when SHA-256 digest mismatches', async () => {
    const microkernel = new WasmMicrokernel({
      trustedPublishers: ['mcp-shield-verified'],
      publisherKeys: { 'mcp-shield-verified': secretKey }
    });

    const manifest: PluginManifest = {
      pluginName: 'corrupted-plugin',
      version: '1.0.0',
      publisherId: 'mcp-shield-verified',
      sha256Digest: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      signature: computeSig('mcp-shield-verified', 'corrupted-plugin', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '1.0.0')
    };

    await expect(microkernel.loadPlugin(manifest, emptyWasmBytes)).rejects.toThrow(
      /SHA-256 digest mismatch/
    );
  });

  it('rejects plugins with forged/invalid signature', async () => {
    const microkernel = new WasmMicrokernel({
      trustedPublishers: ['mcp-shield-verified'],
      publisherKeys: { 'mcp-shield-verified': secretKey }
    });

    const manifest: PluginManifest = {
      pluginName: 'forged-plugin',
      version: '1.0.0',
      publisherId: 'mcp-shield-verified',
      sha256Digest: emptyDigest,
      signature: 'bad-signature-that-does-things-not-match-hmac-digest-32bytes-valid'
    };

    await expect(microkernel.loadPlugin(manifest, emptyWasmBytes)).rejects.toThrow(
      /Cryptographic signature verification failed/
    );
  });

  it('fails closed when plugin does not export analyzePayload (never silently returns true)', async () => {
    const microkernel = new WasmMicrokernel({
      trustedPublishers: ['mcp-shield-verified'],
      publisherKeys: { 'mcp-shield-verified': secretKey }
    });

    const manifest: PluginManifest = {
      pluginName: 'empty-plugin',
      version: '1.0.0',
      publisherId: 'mcp-shield-verified',
      sha256Digest: emptyDigest,
      signature: computeSig('mcp-shield-verified', 'empty-plugin', emptyDigest, '1.0.0')
    };

    await microkernel.loadPlugin(manifest, emptyWasmBytes);
    expect(() => microkernel.analyze('empty-plugin', 'test-payload')).toThrow(
      /does not export 'analyzePayload' function/
    );
  });
});
