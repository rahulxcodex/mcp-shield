import { IpClassifier, EgressSecurityConfig } from '../../src/security/ip-utils';

describe('IpClassifier & CIDR Parser', () => {
  const defaultEgressConfig: EgressSecurityConfig = {
    enabled: true,
    allowPrivateNetworks: false,
    blockLoopback: true,
    blockLinkLocal: true,
    blockMetadataEndpoints: true,
    blockedDomains: ['*.ngrok.io', '*.evil.com']
  };

  describe('IPv4 Classification & Normalization', () => {
    it('accurately classifies loopback IPv4 addresses (127.0.0.0/8)', () => {
      const ips = ['127.0.0.1', '127.0.0.254', '127.100.200.1', 'localhost', 'service.localhost'];
      for (const ip of ips) {
        const cls = IpClassifier.classify(ip);
        expect(cls.isLoopback).toBe(true);
        const check = IpClassifier.checkEgressViolation(ip, defaultEgressConfig);
        expect(check.isBlocked).toBe(true);
      }
    });

    it('accurately classifies link-local IPv4 addresses (169.254.0.0/16)', () => {
      const ips = ['169.254.1.1', '169.254.100.200', '169.254.0.1'];
      for (const ip of ips) {
        const cls = IpClassifier.classify(ip);
        expect(cls.isLinkLocal).toBe(true);
        const check = IpClassifier.checkEgressViolation(ip, defaultEgressConfig);
        expect(check.isBlocked).toBe(true);
      }
    });

    it('accurately classifies cloud metadata endpoints (169.254.169.254, metadata.google.internal)', () => {
      const endpoints = ['169.254.169.254', 'metadata.google.internal', 'instance-data'];
      for (const ep of endpoints) {
        const cls = IpClassifier.classify(ep);
        expect(cls.isMetadata).toBe(true);
        const check = IpClassifier.checkEgressViolation(ep, defaultEgressConfig);
        expect(check.isBlocked).toBe(true);
      }
    });

    it('accurately classifies RFC 1918 private IPv4 networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)', () => {
      const privateIps = [
        '10.0.0.1', '10.255.255.254',
        '172.16.0.1', '172.31.255.254',
        '192.168.0.1', '192.168.1.254',
        '100.64.0.1', '100.127.255.254' // CGNAT
      ];
      for (const ip of privateIps) {
        const cls = IpClassifier.classify(ip);
        expect(cls.isPrivate).toBe(true);
        const check = IpClassifier.checkEgressViolation(ip, defaultEgressConfig);
        expect(check.isBlocked).toBe(true);
      }
    });

    it('allows legitimate public IPv4 destinations', () => {
      const publicIps = ['8.8.8.8', '1.1.1.1', '140.82.121.3', 'api.github.com'];
      for (const ip of publicIps) {
        const check = IpClassifier.checkEgressViolation(ip, defaultEgressConfig);
        expect(check.isBlocked).toBe(false);
      }
    });
  });

  describe('IPv6 Classification & IPv4-Mapped IPv6 Normalization', () => {
    it('accurately classifies IPv6 loopback (::1, [::1])', () => {
      const loopbacks = ['::1', '[::1]', '0:0:0:0:0:0:0:1'];
      for (const ip of loopbacks) {
        const cls = IpClassifier.classify(ip);
        expect(cls.isLoopback).toBe(true);
        const check = IpClassifier.checkEgressViolation(ip, defaultEgressConfig);
        expect(check.isBlocked).toBe(true);
      }
    });

    it('accurately normalizes and blocks IPv4-mapped IPv6 loopback (::ffff:127.0.0.1)', () => {
      const mapped = ['::ffff:127.0.0.1', '::ffff:7f00:1', '0:0:0:0:0:ffff:127.0.0.1'];
      for (const ip of mapped) {
        const normalized = IpClassifier.normalizeIp(ip);
        expect(normalized.isIpv4Mapped).toBe(true);
        expect(normalized.underlyingIpv4).toBe('127.0.0.1');
        const check = IpClassifier.checkEgressViolation(ip, defaultEgressConfig);
        expect(check.isBlocked).toBe(true);
      }
    });

    it('accurately normalizes and blocks IPv4-mapped IPv6 cloud metadata (::ffff:169.254.169.254)', () => {
      const mapped = ['::ffff:169.254.169.254', '0:0:0:0:0:ffff:169.254.169.254'];
      for (const ip of mapped) {
        const normalized = IpClassifier.normalizeIp(ip);
        expect(normalized.isIpv4Mapped).toBe(true);
        const check = IpClassifier.checkEgressViolation(ip, defaultEgressConfig);
        expect(check.isBlocked).toBe(true);
      }
    });

    it('accurately normalizes and blocks IPv4-mapped IPv6 private networks (::ffff:10.0.0.1, ::ffff:192.168.1.1)', () => {
      const mapped = ['::ffff:10.0.0.1', '::ffff:192.168.1.1'];
      for (const ip of mapped) {
        const check = IpClassifier.checkEgressViolation(ip, defaultEgressConfig);
        expect(check.isBlocked).toBe(true);
      }
    });

    it('accurately classifies IPv6 Link-Local (fe80::/10) and ULA (fc00::/7)', () => {
      const ipv6List = ['fe80::1', 'fe80::dead:beef', 'fc00::1', 'fd00::1234'];
      for (const ip of ipv6List) {
        const check = IpClassifier.checkEgressViolation(ip, defaultEgressConfig);
        expect(check.isBlocked).toBe(true);
      }
    });
  });

  describe('Domain Wildcards & Egress Blocklists', () => {
    it('blocks blacklisted domain wildcards (*.evil.com, *.ngrok.io)', () => {
      const blockedHosts = ['sub.evil.com', 'evil.com', 'tunnel.ngrok.io', 'test.ngrok.io'];
      for (const host of blockedHosts) {
        const check = IpClassifier.checkEgressViolation(host, defaultEgressConfig);
        expect(check.isBlocked).toBe(true);
      }
    });

    it('supports allow-only mode (allowMode: deny) strictly', () => {
      const allowOnlyConfig: EgressSecurityConfig = {
        enabled: true,
        allowMode: 'deny',
        allowedDomains: ['*.anthropic.com', 'api.openai.com']
      };

      expect(IpClassifier.checkEgressViolation('api.anthropic.com', allowOnlyConfig).isBlocked).toBe(false);
      expect(IpClassifier.checkEgressViolation('api.openai.com', allowOnlyConfig).isBlocked).toBe(false);
      expect(IpClassifier.checkEgressViolation('google.com', allowOnlyConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('attacker.com', allowOnlyConfig).isBlocked).toBe(true);
    });
  });
});
