import * as net from 'net';

export interface IpClassification {
  normalizedIp: string;
  version: 'ipv4' | 'ipv6' | 'hostname';
  isIpv4Mapped: boolean;
  isLoopback: boolean;
  isLinkLocal: boolean;
  isMetadata: boolean;
  isPrivate: boolean;
  isCarrierGradeNat: boolean;
  isUnspecifiedOrBroadcast: boolean;
}

export interface EgressSecurityConfig {
  enabled: boolean;
  allowMode?: 'allow' | 'deny';
  allowedDomains?: string[];
  blockedDomains?: string[];
  allowPrivateNetworks?: boolean;
  blockLoopback?: boolean;
  blockLinkLocal?: boolean;
  blockMetadataEndpoints?: boolean;
}

interface CidrRange {
  name: string;
  start: bigint;
  end: bigint;
  version: 4 | 6;
}

/**
 * Parses any standard or alternate IPv4 representation (dotted decimal, octal, hex, or 32-bit integer)
 * into a canonical BigInt number.
 */
export function parseIpv4ToBigInt(ipStr: string): bigint | null {
  const clean = ipStr.trim().toLowerCase();

  // 1. Single 32-bit integer or hex number e.g. 2130706433 or 0x7f000001
  if (/^0x[0-9a-f]+$/i.test(clean)) {
    try {
      const val = BigInt(clean);
      if (val >= 0n && val <= 0xffffffffn) return val;
    } catch {
      return null;
    }
  }

  if (/^\d+$/.test(clean) && !clean.includes('.')) {
    try {
      const val = BigInt(clean);
      if (val >= 0n && val <= 0xffffffffn) return val;
    } catch {
      return null;
    }
  }

  // 2. Dotted notation (can have 1 to 4 parts with mixed decimal, octal, or hex)
  const parts = clean.split('.');
  if (parts.length < 1 || parts.length > 4) return null;

  const partValues: bigint[] = [];
  for (const part of parts) {
    if (!part) return null;
    let val: bigint;
    if (part.startsWith('0x') || part.startsWith('0X')) {
      if (!/^0x[0-9a-f]+$/i.test(part)) return null;
      val = BigInt(part);
    } else if (part.startsWith('0') && part.length > 1) {
      // Octal notation
      if (!/^[0-7]+$/.test(part)) return null;
      val = BigInt(parseInt(part, 8));
    } else {
      if (!/^\d+$/.test(part)) return null;
      val = BigInt(part);
    }
    partValues.push(val);
  }

  // Combine according to standard inet_aton semantics:
  // 4 parts: a.b.c.d -> each <= 255
  // 3 parts: a.b.c -> a,b <= 255, c <= 65535
  // 2 parts: a.b -> a <= 255, b <= 16777215
  // 1 part: a -> a <= 4294967295
  let num = 0n;
  if (partValues.length === 4) {
    if (partValues.some(p => p > 255n || p < 0n)) return null;
    num = (partValues[0] << 24n) | (partValues[1] << 16n) | (partValues[2] << 8n) | partValues[3];
  } else if (partValues.length === 3) {
    if (partValues[0] > 255n || partValues[1] > 255n || partValues[2] > 65535n) return null;
    num = (partValues[0] << 24n) | (partValues[1] << 16n) | partValues[2];
  } else if (partValues.length === 2) {
    if (partValues[0] > 255n || partValues[1] > 16777215n) return null;
    num = (partValues[0] << 24n) | partValues[1];
  } else if (partValues.length === 1) {
    if (partValues[0] > 4294967295n || partValues[0] < 0n) return null;
    num = partValues[0];
  }

  return (num >= 0n && num <= 0xffffffffn) ? num : null;
}

export function bigIntToIpv4(num: bigint): string {
  const oct1 = Number((num >> 24n) & 0xffn);
  const oct2 = Number((num >> 16n) & 0xffn);
  const oct3 = Number((num >> 8n) & 0xffn);
  const oct4 = Number(num & 0xffn);
  return `${oct1}.${oct2}.${oct3}.${oct4}`;
}

export function parseIpv6ToBigInt(ip: string): bigint | null {
  let fullIp = ip.toLowerCase().trim();

  // Strip brackets
  fullIp = fullIp.replace(/^\[|\]$/g, '');
  
  // Handle IPv4 mapped inside IPv6 (e.g. ::ffff:192.168.1.1 or ::ffff:0x7f000001)
  if (fullIp.includes('.')) {
    const lastColon = fullIp.lastIndexOf(':');
    const v4Part = fullIp.substring(lastColon + 1);
    const v6Prefix = fullIp.substring(0, lastColon);
    const v4Num = parseIpv4ToBigInt(v4Part);
    if (v4Num === null) return null;
    
    const hex1 = ((v4Num >> 16n) & 0xffffn).toString(16);
    const hex2 = (v4Num & 0xffffn).toString(16);
    fullIp = `${v6Prefix}:${hex1}:${hex2}`;
  }

  const parts = fullIp.split('::');
  if (parts.length > 2) return null;
  
  let hextets: string[] = [];
  if (parts.length === 2) {
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts[1] ? parts[1].split(':') : [];
    const missing = 8 - (left.length + right.length);
    if (missing < 0) return null;
    const middle = new Array(missing).fill('0');
    hextets = [...left, ...middle, ...right];
  } else {
    hextets = fullIp.split(':');
  }

  if (hextets.length !== 8) return null;

  let num = 0n;
  for (const h of hextets) {
    if (!/^[0-9a-f]{1,4}$/i.test(h)) return null;
    num = (num << 16n) | BigInt(parseInt(h, 16));
  }
  return num;
}

export function bigIntToIpv6(num: bigint): string {
  const hextets: string[] = [];
  for (let i = 7; i >= 0; i--) {
    const h = Number((num >> BigInt(i * 16)) & 0xffffn);
    hextets.push(h.toString(16));
  }
  return hextets.join(':');
}

function parseCidr(cidr: string): CidrRange | null {
  const [ipStr, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);
  
  const v4Num = parseIpv4ToBigInt(ipStr);
  if (v4Num !== null && !ipStr.includes(':')) {
    if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;
    const mask = prefix === 0 ? 0n : ((1n << 32n) - 1n) ^ ((1n << BigInt(32 - prefix)) - 1n);
    const start = v4Num & mask;
    const end = start | ((1n << BigInt(32 - prefix)) - 1n);
    return { name: cidr, start, end, version: 4 };
  }
  
  const v6Num = parseIpv6ToBigInt(ipStr);
  if (v6Num !== null) {
    if (isNaN(prefix) || prefix < 0 || prefix > 128) return null;
    const mask = prefix === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - prefix)) - 1n);
    const start = v6Num & mask;
    const end = start | ((1n << BigInt(128 - prefix)) - 1n);
    return { name: cidr, start, end, version: 6 };
  }

  return null;
}

// Pre-computed CIDR tables
const IPV4_PRIVATE_RANGES = [
  parseCidr('10.0.0.0/8')!,
  parseCidr('172.16.0.0/12')!,
  parseCidr('192.168.0.0/16')!
];

const IPV4_LOOPBACK_RANGES = [
  parseCidr('127.0.0.0/8')!
];

const IPV4_LINK_LOCAL_RANGES = [
  parseCidr('169.254.0.0/16')!
];

const IPV4_METADATA_RANGES = [
  parseCidr('169.254.169.254/32')!
];

const IPV4_CARRIER_GRADE_NAT = [
  parseCidr('100.64.0.0/10')!
];

const IPV4_UNSPECIFIED_AND_SPECIAL = [
  parseCidr('0.0.0.0/8')!,
  parseCidr('255.255.255.255/32')!,
  parseCidr('224.0.0.0/4')!, // Multicast
  parseCidr('240.0.0.0/4')!  // Reserved
];

const IPV6_LOOPBACK_RANGES = [
  parseCidr('::1/128')!
];

const IPV6_LINK_LOCAL_RANGES = [
  parseCidr('fe80::/10')!
];

const IPV6_PRIVATE_RANGES = [
  parseCidr('fc00::/7')! // Unique Local Addresses (ULA)
];

const IPV6_METADATA_RANGES = [
  parseCidr('fd00:ec2::254/128')! // AWS IPv6 metadata
];

const IPV6_UNSPECIFIED_AND_SPECIAL = [
  parseCidr('::/128')!,
  parseCidr('ff00::/8')! // Multicast
];

function isIpInRanges(num: bigint, ranges: CidrRange[]): boolean {
  for (const r of ranges) {
    if (num >= r.start && num <= r.end) return true;
  }
  return false;
}

export class IpClassifier {
  /**
   * Normalizes an IP string or hostname.
   * Resolves alternate IPv4 encodings (hex/octal/int) and unmaps IPv4-mapped IPv6 addresses.
   */
  public static normalizeIp(rawInput: string): { normalized: string; isIpv4Mapped: boolean; underlyingIpv4?: string } {
    let clean = rawInput.trim().toLowerCase().replace(/^\[|\]$/g, '');

    // Check for IPv4 mapped inside IPv6 e.g. ::ffff:192.168.1.1 or ::ffff:7f00:1 or 0:0:0:0:0:ffff:127.0.0.1
    const ipv4MappedRegex = /^(?:::ffff:|0:0:0:0:0:ffff:)(.+)$/i;
    const mappedMatch = ipv4MappedRegex.exec(clean);
    if (mappedMatch) {
      const rest = mappedMatch[1];
      const v4Num = parseIpv4ToBigInt(rest);
      if (v4Num !== null) {
        const canonical = bigIntToIpv4(v4Num);
        return { normalized: canonical, isIpv4Mapped: true, underlyingIpv4: canonical };
      }
      if (rest.includes(':')) {
        const hexParts = rest.split(':');
        if (hexParts.length === 2 && /^[0-9a-f]{1,4}$/i.test(hexParts[0]) && /^[0-9a-f]{1,4}$/i.test(hexParts[1])) {
          const high = parseInt(hexParts[0], 16);
          const low = parseInt(hexParts[1], 16);
          const oct1 = (high >> 8) & 0xff;
          const oct2 = high & 0xff;
          const oct3 = (low >> 8) & 0xff;
          const oct4 = low & 0xff;
          const canonical = `${oct1}.${oct2}.${oct3}.${oct4}`;
          return { normalized: canonical, isIpv4Mapped: true, underlyingIpv4: canonical };
        }
      }
    }

    // Check if it's an alternate IPv4 representation (e.g. 0177.0.0.1 or 0x7f000001 or 2130706433)
    if (!clean.includes(':')) {
      const v4Num = parseIpv4ToBigInt(clean);
      if (v4Num !== null) {
        const canonical = bigIntToIpv4(v4Num);
        return { normalized: canonical, isIpv4Mapped: false, underlyingIpv4: canonical };
      }
    }

    // Check if it's standard IPv6
    const v6Num = parseIpv6ToBigInt(clean);
    if (v6Num !== null) {
      return { normalized: clean, isIpv4Mapped: false };
    }

    return { normalized: clean, isIpv4Mapped: false };
  }

  /**
   * Evaluates if a given IP or hostname falls into private, loopback, link-local, or cloud metadata ranges.
   */
  public static classify(input: string): IpClassification {
    const { normalized, isIpv4Mapped, underlyingIpv4 } = this.normalizeIp(input);
    const target = underlyingIpv4 || normalized;

    // Check IPv4 (canonicalized)
    const v4Num = parseIpv4ToBigInt(target);
    if (v4Num !== null && !target.includes(':')) {
      const isLoopback = isIpInRanges(v4Num, IPV4_LOOPBACK_RANGES);
      const isLinkLocal = isIpInRanges(v4Num, IPV4_LINK_LOCAL_RANGES);
      const isMetadata = isIpInRanges(v4Num, IPV4_METADATA_RANGES);
      const isPrivate = isIpInRanges(v4Num, IPV4_PRIVATE_RANGES);
      const isCarrierGradeNat = isIpInRanges(v4Num, IPV4_CARRIER_GRADE_NAT);
      const isUnspecifiedOrBroadcast = isIpInRanges(v4Num, IPV4_UNSPECIFIED_AND_SPECIAL);

      return {
        normalizedIp: target,
        version: 'ipv4',
        isIpv4Mapped,
        isLoopback,
        isLinkLocal,
        isMetadata,
        isPrivate: isPrivate || isCarrierGradeNat,
        isCarrierGradeNat,
        isUnspecifiedOrBroadcast
      };
    }

    // Check IPv6
    const v6Num = parseIpv6ToBigInt(target);
    if (v6Num !== null) {
      const isLoopback = isIpInRanges(v6Num, IPV6_LOOPBACK_RANGES);
      const isLinkLocal = isIpInRanges(v6Num, IPV6_LINK_LOCAL_RANGES);
      const isMetadata = isIpInRanges(v6Num, IPV6_METADATA_RANGES);
      const isPrivate = isIpInRanges(v6Num, IPV6_PRIVATE_RANGES);
      const isUnspecifiedOrBroadcast = isIpInRanges(v6Num, IPV6_UNSPECIFIED_AND_SPECIAL);

      return {
        normalizedIp: target,
        version: 'ipv6',
        isIpv4Mapped,
        isLoopback,
        isLinkLocal,
        isMetadata,
        isPrivate,
        isCarrierGradeNat: false,
        isUnspecifiedOrBroadcast
      };
    }

    // Hostname
    const isLocalHostname = target === 'localhost' || target.endsWith('.localhost') || target === 'local' || target.endsWith('.local');
    const isCloudMetadataHost = target === 'metadata.google.internal' || target === 'instance-data';
    
    return {
      normalizedIp: target,
      version: 'hostname',
      isIpv4Mapped: false,
      isLoopback: isLocalHostname,
      isLinkLocal: false,
      isMetadata: isCloudMetadataHost,
      isPrivate: isLocalHostname,
      isCarrierGradeNat: false,
      isUnspecifiedOrBroadcast: false
    };
  }

  /**
   * Matches a hostname against a domain pattern:
   * - 'example.com': Exact apex match only
   * - '*.example.com': Matches apex 'example.com' and all subdomains 'sub.example.com', 'a.b.example.com'
   * - '**.example.com': Multi-level wildcard covering apex and all subdomains
   */
  public static matchesDomainPattern(hostname: string, pattern: string): boolean {
    const host = hostname.toLowerCase().trim();
    const pat = pattern.toLowerCase().trim();

    if (!host || !pat) return false;

    // Multi-level wildcard: **.example.com
    if (pat.startsWith('**.')) {
      const baseDomain = pat.slice(3);
      return host === baseDomain || host.endsWith('.' + baseDomain);
    }

    // Standard wildcard: *.example.com (matches apex and subdomains)
    if (pat.startsWith('*.')) {
      const baseDomain = pat.slice(2);
      return host === baseDomain || host.endsWith('.' + baseDomain);
    }

    // Exact match
    return host === pat;
  }

  /**
   * Checks if a URL protocol scheme is supported by MCP-Shield egress gateway.
   */
  public static checkProtocolViolation(urlStr: string): { isBlocked: boolean; reason?: string } {
    if (!urlStr || !urlStr.includes('://')) return { isBlocked: false };
    try {
      const parsed = new URL(urlStr);
      const protocol = parsed.protocol.toLowerCase();
      const ALLOWED_PROTOCOLS = new Set(['http:', 'https:', 'ws:', 'wss:']);
      if (!ALLOWED_PROTOCOLS.has(protocol)) {
        return {
          isBlocked: true,
          reason: `UNSUPPORTED_EGRESS_PROTOCOL: Protocol "${protocol}" is rejected by egress gateway.`
        };
      }
    } catch {}
    return { isBlocked: false };
  }

  /**
   * Tests if an IP or Hostname violates the given egress policy configuration.
   */
  public static checkEgressViolation(
    ipOrHost: string,
    config: EgressSecurityConfig
  ): { isBlocked: boolean; reason?: string } {
    if (!config.enabled) {
      return { isBlocked: false };
    }

    // Check protocol scheme if full URL is passed
    const protoCheck = this.checkProtocolViolation(ipOrHost);
    if (protoCheck.isBlocked) {
      return protoCheck;
    }

    let target = ipOrHost;
    try {
      if (ipOrHost.includes('://')) {
        target = new URL(ipOrHost).hostname;
      }
    } catch {}

    const classification = this.classify(target);

    // 1. Loopback blocking
    if (config.blockLoopback !== false && classification.isLoopback) {
      return { isBlocked: true, reason: `Loopback destination blocked: ${classification.normalizedIp}` };
    }

    // 2. Link-local blocking
    if (config.blockLinkLocal !== false && classification.isLinkLocal) {
      return { isBlocked: true, reason: `Link-local destination blocked: ${classification.normalizedIp}` };
    }

    // 3. Metadata endpoint blocking (e.g. AWS/GCP/Azure metadata 169.254.169.254)
    if (config.blockMetadataEndpoints !== false && classification.isMetadata) {
      return { isBlocked: true, reason: `Cloud metadata endpoint blocked: ${classification.normalizedIp}` };
    }

    // 4. Private network blocking (RFC 1918, RFC 4193, CGNAT)
    if (config.allowPrivateNetworks === false && classification.isPrivate) {
      return { isBlocked: true, reason: `Private RFC1918/RFC4193 network destination blocked: ${classification.normalizedIp}` };
    }

    // 5. Special / Unspecified / Broadcast
    if (classification.isUnspecifiedOrBroadcast) {
      return { isBlocked: true, reason: `Special/Broadcast destination blocked: ${classification.normalizedIp}` };
    }

    // 6. Domain Allow / Deny Lists
    const hostname = classification.normalizedIp.toLowerCase();
    
    if (config.allowMode === 'deny') {
      let isExplicitlyAllowed = false;
      if (config.allowedDomains && config.allowedDomains.length > 0) {
        isExplicitlyAllowed = config.allowedDomains.some(d => this.matchesDomainPattern(hostname, d));
      }
      if (!isExplicitlyAllowed) {
        return { isBlocked: true, reason: `Domain '${hostname}' is not in allowed domains list.` };
      }
    } else {
      if (config.blockedDomains && config.blockedDomains.length > 0) {
        const isBlocked = config.blockedDomains.some(d => this.matchesDomainPattern(hostname, d));
        if (isBlocked) {
          return { isBlocked: true, reason: `Domain '${hostname}' matches blocked domains list.` };
        }
      }
    }

    return { isBlocked: false };
  }
}

/**
 * Detects special, non-standard, or obfuscated IP representations (octal, hex, dword)
 */
export function isSpecialIpRepresentation(ipStr: string): boolean {
  if (!ipStr) return false;
  const clean = ipStr.trim().toLowerCase();
  if (/^0x[0-9a-f]+/i.test(clean)) return true;
  if (/^0[0-7]{2,}/.test(clean)) return true;
  if (/^\d{8,11}$/.test(clean) && !clean.includes('.')) return true;
  if (clean.includes('.')) {
    const parts = clean.split('.');
    for (const part of parts) {
      if (/^0[0-7]+$/.test(part) && part.length > 1) return true;
      if (/^0x[0-9a-f]+$/i.test(part)) return true;
    }
  }
  return false;
}

export function isPrivateIp(ipStr: string): boolean {
  const c = IpClassifier.classify(ipStr);
  return c.isPrivate;
}

export function normalizeIpAddress(ipStr: string): string {
  return IpClassifier.normalizeIp(ipStr).normalized;
}
