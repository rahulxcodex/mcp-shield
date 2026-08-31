import { IpClassifier, EgressSecurityConfig, parseIpv4ToBigInt, parseIpv6ToBigInt } from '../../src/security/ip-utils';
import { parseConnectAuthority, NetworkEgressProxy } from '../../src/security/network-proxy';
import { PolicyEngine } from '../../src/security/policy-engine';

describe('SSRF & Canonical IP/CIDR Egress Regression Corpus', () => {
  const defaultConfig: EgressSecurityConfig = {
    enabled: true,
    allowMode: 'allow',
    blockedDomains: ['*.evil.com', '*.ngrok.io'],
    allowPrivateNetworks: false,
    blockLoopback: true,
    blockLinkLocal: true,
    blockMetadataEndpoints: true
  };

  describe('IPv4 Alternate Encodings & Egress Protection', () => {
    test('blocks standard dotted decimal loopback (127.0.0.1, 127.127.127.127)', () => {
      expect(IpClassifier.checkEgressViolation('127.0.0.1', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('127.127.127.127', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('127.0.0.2', defaultConfig).isBlocked).toBe(true);
    });

    test('blocks octal IPv4 loopback (0177.0.0.1, 0177.0000.0000.0001)', () => {
      expect(parseIpv4ToBigInt('0177.0.0.1')).toBe(2130706433n);
      expect(IpClassifier.checkEgressViolation('0177.0.0.1', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('0177.0000.0000.0001', defaultConfig).isBlocked).toBe(true);
    });

    test('blocks hexadecimal IPv4 loopback (0x7f.0.0.1, 0x7f000001, 0x7f.0x0.0x0.0x1)', () => {
      expect(parseIpv4ToBigInt('0x7f.0.0.1')).toBe(2130706433n);
      expect(parseIpv4ToBigInt('0x7f000001')).toBe(2130706433n);
      expect(IpClassifier.checkEgressViolation('0x7f.0.0.1', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('0x7f000001', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('0x7f.0x0.0x0.0x1', defaultConfig).isBlocked).toBe(true);
    });

    test('blocks decimal 32-bit integer IPv4 loopback (2130706433)', () => {
      expect(parseIpv4ToBigInt('2130706433')).toBe(2130706433n);
      expect(IpClassifier.checkEgressViolation('2130706433', defaultConfig).isBlocked).toBe(true);
    });

    test('blocks cloud metadata endpoints (169.254.169.254, 0xa9fea9fe, metadata.google.internal)', () => {
      expect(IpClassifier.checkEgressViolation('169.254.169.254', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('0xa9.0xfe.0xa9.0xfe', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('metadata.google.internal', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('instance-data', defaultConfig).isBlocked).toBe(true);
    });

    test('blocks RFC 1918 private IPv4 networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)', () => {
      expect(IpClassifier.checkEgressViolation('10.0.0.1', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('10.255.255.254', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('172.16.0.1', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('172.31.255.254', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('192.168.1.1', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('192.168.100.50', defaultConfig).isBlocked).toBe(true);
    });

    test('blocks Carrier-Grade NAT RFC 6598 (100.64.0.0/10)', () => {
      expect(IpClassifier.checkEgressViolation('100.64.0.1', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('100.127.255.254', defaultConfig).isBlocked).toBe(true);
    });

    test('allows legitimate public IPv4 destinations', () => {
      expect(IpClassifier.checkEgressViolation('8.8.8.8', defaultConfig).isBlocked).toBe(false);
      expect(IpClassifier.checkEgressViolation('1.1.1.1', defaultConfig).isBlocked).toBe(false);
      expect(IpClassifier.checkEgressViolation('93.184.216.34', defaultConfig).isBlocked).toBe(false);
    });
  });

  describe('IPv6 & IPv4-Mapped IPv6 Normalization', () => {
    test('blocks IPv6 loopback (::1, [::1], 0:0:0:0:0:0:0:1)', () => {
      expect(IpClassifier.checkEgressViolation('::1', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('[::1]', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('0:0:0:0:0:0:0:1', defaultConfig).isBlocked).toBe(true);
    });

    test('blocks IPv4-mapped IPv6 loopback (::ffff:127.0.0.1, ::ffff:7f00:1)', () => {
      expect(IpClassifier.checkEgressViolation('::ffff:127.0.0.1', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('::ffff:7f00:1', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('0:0:0:0:0:ffff:127.0.0.1', defaultConfig).isBlocked).toBe(true);
    });

    test('blocks IPv4-mapped IPv6 metadata (::ffff:169.254.169.254)', () => {
      expect(IpClassifier.checkEgressViolation('::ffff:169.254.169.254', defaultConfig).isBlocked).toBe(true);
    });

    test('blocks IPv4-mapped IPv6 private networks (::ffff:10.0.0.1, ::ffff:192.168.1.1)', () => {
      expect(IpClassifier.checkEgressViolation('::ffff:10.0.0.1', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('::ffff:192.168.1.1', defaultConfig).isBlocked).toBe(true);
    });

    test('blocks IPv6 Link-Local (fe80::/10) and ULA private (fc00::/7)', () => {
      expect(IpClassifier.checkEgressViolation('fe80::1', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('fe80::dead:beef', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('fc00::1', defaultConfig).isBlocked).toBe(true);
      expect(IpClassifier.checkEgressViolation('fd12:3456:789a::1', defaultConfig).isBlocked).toBe(true);
    });

    test('blocks AWS IPv6 metadata (fd00:ec2::254)', () => {
      expect(IpClassifier.checkEgressViolation('fd00:ec2::254', defaultConfig).isBlocked).toBe(true);
    });
  });

  describe('HTTP CONNECT Authority Parser', () => {
    test('parses IPv6 literal with port [::1]:8080', () => {
      const parsed = parseConnectAuthority('[::1]:8080');
      expect(parsed).toEqual({ host: '::1', port: 8080 });
    });

    test('parses IPv6 literal without port [fe80::1] (default port 443)', () => {
      const parsed = parseConnectAuthority('[fe80::1]');
      expect(parsed).toEqual({ host: 'fe80::1', port: 443 });
    });

    test('parses hostname with port api.github.com:443', () => {
      const parsed = parseConnectAuthority('api.github.com:443');
      expect(parsed).toEqual({ host: 'api.github.com', port: 443 });
    });

    test('parses IPv4 with port 93.184.216.34:80', () => {
      const parsed = parseConnectAuthority('93.184.216.34:80');
      expect(parsed).toEqual({ host: '93.184.216.34', port: 80 });
    });

    test('rejects malformed authority with unclosed brackets [::1:8080', () => {
      expect(parseConnectAuthority('[::1:8080')).toBeNull();
    });

    test('rejects malformed authority with invalid port api.github.com:99999', () => {
      expect(parseConnectAuthority('api.github.com:99999')).toBeNull();
    });

    test('rejects unbracketed multi-colon IPv6 literal ::1:8080', () => {
      expect(parseConnectAuthority('::1:8080')).toBeNull();
    });
  });
});
