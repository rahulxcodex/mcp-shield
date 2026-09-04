import { AuthoritativeEgressEngine } from '../../src/security/egress/egress-engine';

describe('AuthoritativeEgressEngine (Roadmap Section 5.4)', () => {
  it('allows benign public URLs and pins the resolved IP', async () => {
    const engine = new AuthoritativeEgressEngine({
      dnsResolver: async () => ['93.184.216.34']
    });

    const decision = await engine.evaluateDestination('https://example.com/api/v1/data');
    expect(decision.allowed).toBe(true);
    expect(decision.destinationClass).toBe('PUBLIC');
    expect(decision.pinnedIp).toBe('93.184.216.34');
    expect(decision.rebindingDetected).toBe(false);
  });

  it('unconditionally blocks cloud instance metadata IP addresses', async () => {
    const engine = new AuthoritativeEgressEngine();
    const decision = await engine.evaluateDestination('http://169.254.169.254/latest/meta-data/');
    expect(decision.allowed).toBe(false);
    expect(decision.destinationClass).toBe('CLOUD_METADATA');
    expect(decision.reason).toContain('Cloud Metadata IP');
  });

  it('unconditionally blocks cloud metadata hostnames', async () => {
    const engine = new AuthoritativeEgressEngine();
    const decision = await engine.evaluateDestination('http://metadata.google.internal/computeMetadata/v1/');
    expect(decision.allowed).toBe(false);
    expect(decision.destinationClass).toBe('CLOUD_METADATA');
  });

  it('detects DNS rebinding attacks returning public and internal addresses', async () => {
    const engine = new AuthoritativeEgressEngine({
      dnsResolver: async () => ['93.184.216.34', '192.168.1.50']
    });

    const decision = await engine.evaluateDestination('https://attacker-rebinding.com/steal');
    expect(decision.allowed).toBe(false);
    expect(decision.rebindingDetected).toBe(true);
    expect(decision.reason).toContain('DNS Rebinding attack detected');
  });

  it('blocks redirect chains that pivot from public to internal networks', async () => {
    const engine = new AuthoritativeEgressEngine({
      dnsResolver: async (host) => {
        if (host === 'pub.com') return ['93.184.216.34'];
        if (host === 'int.internal') return ['10.0.0.5'];
        return ['1.1.1.1'];
      }
    });

    const chain = ['https://pub.com/redirect', 'https://int.internal/admin'];
    const decision = await engine.validateRedirectChain(chain);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain('Redirect hop 2 denied');
  });

  it('blocks loopback IP in default policy', async () => {
    const engine = new AuthoritativeEgressEngine();
    const decision = await engine.evaluateDestination('http://127.0.0.1:8080/debug');
    expect(decision.allowed).toBe(false);
    expect(decision.destinationClass).toBe('LOOPBACK');
  });
});
