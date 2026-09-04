import * as dns from 'dns';
import * as net from 'net';
import { isPrivateIp, normalizeIpAddress } from '../ip-utils';

export type DestinationClass =
  | 'PUBLIC'
  | 'PRIVATE'
  | 'LOOPBACK'
  | 'LINK_LOCAL'
  | 'CLOUD_METADATA'
  | 'RESERVED'
  | 'BLOCKED_DOMAIN';

export interface EgressDecision {
  allowed: boolean;
  destinationClass: DestinationClass;
  canonicalUrl: string;
  host: string;
  port: number;
  resolvedIps: string[];
  pinnedIp?: string;
  reason?: string;
  rebindingDetected: boolean;
}

export interface EgressPolicyOptions {
  allowMode?: 'allowlist' | 'blocklist' | 'deny';
  allowedDomains?: string[];
  blockedDomains?: string[];
  allowedCidrs?: string[];
  blockedCidrs?: string[];
  allowPrivate?: boolean;
  allowLoopback?: boolean;
  dnsResolver?: (hostname: string) => Promise<string[]>;
}

const CLOUD_METADATA_IPS = new Set([
  '169.254.169.254', // AWS, Azure, GCP, OpenStack
  '169.254.169.253', // AWS DNS / VPC resolver
  'fd00:ec2::254'    // AWS IPv6 metadata
]);

const CLOUD_METADATA_HOSTS = new Set([
  'metadata.google.internal',
  'metadata',
  'instance-data'
]);

export class AuthoritativeEgressEngine {
  private options: EgressPolicyOptions;
  private dnsCache: Map<string, { ips: string[]; timestamp: number }> = new Map();

  constructor(options: EgressPolicyOptions = {}) {
    this.options = {
      allowMode: options.allowMode || 'blocklist',
      allowedDomains: options.allowedDomains || [],
      blockedDomains: options.blockedDomains || [],
      allowedCidrs: options.allowedCidrs || [],
      blockedCidrs: options.blockedCidrs || [],
      allowPrivate: options.allowPrivate ?? false,
      allowLoopback: options.allowLoopback ?? false,
      dnsResolver: options.dnsResolver
    };
  }

  /**
   * Evaluates destination URL with canonicalization, pre-flight DNS resolution,
   * classification, and DNS rebinding protection.
   */
  public async evaluateDestination(rawUrl: string): Promise<EgressDecision> {
    // 1. URL Parse & Normalization
    let parsed: URL;
    try {
      // Normalize NFKC to prevent Unicode homoglyph bypasses
      const normalized = rawUrl.normalize('NFKC').trim();
      parsed = new URL(normalized);
    } catch {
      return {
        allowed: false,
        destinationClass: 'RESERVED',
        canonicalUrl: rawUrl,
        host: '',
        port: 0,
        resolvedIps: [],
        reason: 'Malformed URL: Failed to parse canonical destination',
        rebindingDetected: false
      };
    }

    const host = parsed.hostname.toLowerCase();
    const port = parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === 'https:' ? 443 : 80;

    // 2. Check metadata hostnames directly
    if (CLOUD_METADATA_HOSTS.has(host)) {
      return {
        allowed: false,
        destinationClass: 'CLOUD_METADATA',
        canonicalUrl: parsed.href,
        host,
        port,
        resolvedIps: [],
        reason: 'Egress blocked: Destination attempts access to Cloud Instance Metadata',
        rebindingDetected: false
      };
    }

    // 3. Domain Blocklist / Allowlist
    if (this.options.blockedDomains?.some((d) => host === d || host.endsWith('.' + d))) {
      return {
        allowed: false,
        destinationClass: 'BLOCKED_DOMAIN',
        canonicalUrl: parsed.href,
        host,
        port,
        resolvedIps: [],
        reason: `Egress blocked: Host '${host}' matches blocked domain list`,
        rebindingDetected: false
      };
    }

    // 4. Resolve IPs or inspect raw IP address
    let resolvedIps: string[] = [];
    const isDirectIp = net.isIP(host) !== 0;

    if (isDirectIp) {
      const canonicalIp = normalizeIpAddress(host);
      if (canonicalIp) resolvedIps.push(canonicalIp);
      else resolvedIps.push(host);
    } else {
      try {
        resolvedIps = await this.resolveHostname(host);
      } catch (err: any) {
        return {
          allowed: false,
          destinationClass: 'RESERVED',
          canonicalUrl: parsed.href,
          host,
          port,
          resolvedIps: [],
          reason: `DNS resolution failed for '${host}': ${err.message}`,
          rebindingDetected: false
        };
      }
    }

    if (resolvedIps.length === 0) {
      return {
        allowed: false,
        destinationClass: 'RESERVED',
        canonicalUrl: parsed.href,
        host,
        port,
        resolvedIps: [],
        reason: `Host '${host}' resolved to no reachable addresses`,
        rebindingDetected: false
      };
    }

    // 5. DNS Rebinding Detection: check if resolution contains a mixture of public and private/metadata IPs
    let hasPublic = false;
    let hasRestricted = false;
    const classifications = resolvedIps.map((ip) => ({ ip, destClass: this.classifyIp(ip) }));

    for (const { destClass } of classifications) {
      if (destClass === 'PUBLIC') hasPublic = true;
      else hasRestricted = true;
    }

    if (hasPublic && hasRestricted) {
      return {
        allowed: false,
        destinationClass: 'PRIVATE',
        canonicalUrl: parsed.href,
        host,
        port,
        resolvedIps,
        reason: `DNS Rebinding attack detected: Host '${host}' alternates between public and internal addresses`,
        rebindingDetected: true
      };
    }

    for (const { ip, destClass } of classifications) {
      // Unconditional block on metadata
      if (destClass === 'CLOUD_METADATA') {
        return {
          allowed: false,
          destinationClass: 'CLOUD_METADATA',
          canonicalUrl: parsed.href,
          host,
          port,
          resolvedIps,
          reason: `Egress blocked: Host '${host}' resolves to Cloud Metadata IP ${ip}`,
          rebindingDetected: false
        };
      }

      // Check loopback / private policy
      if (destClass === 'LOOPBACK' && !this.options.allowLoopback) {
        return {
          allowed: false,
          destinationClass: 'LOOPBACK',
          canonicalUrl: parsed.href,
          host,
          port,
          resolvedIps,
          reason: `Egress blocked: Host '${host}' resolves to Loopback address ${ip}`,
          rebindingDetected: false
        };
      }

      if (destClass === 'PRIVATE' && !this.options.allowPrivate) {
        return {
          allowed: false,
          destinationClass: 'PRIVATE',
          canonicalUrl: parsed.href,
          host,
          port,
          resolvedIps,
          reason: `Egress blocked: Host '${host}' resolves to Private network address ${ip}`,
          rebindingDetected: false
        };
      }
    }

    const rebindingDetected = hasPublic && hasRestricted;
    if (rebindingDetected) {
      return {
        allowed: false,
        destinationClass: 'PRIVATE',
        canonicalUrl: parsed.href,
        host,
        port,
        resolvedIps,
        reason: `DNS Rebinding attack detected: Host '${host}' alternates between public and internal addresses`,
        rebindingDetected: true
      };
    }

    // 6. Allowlist verification if enabled
    if (this.options.allowMode === 'allowlist') {
      const matched = this.options.allowedDomains?.some((d) => host === d || host.endsWith('.' + d));
      if (!matched) {
        return {
          allowed: false,
          destinationClass: 'PUBLIC',
          canonicalUrl: parsed.href,
          host,
          port,
          resolvedIps,
          reason: `Egress blocked: Host '${host}' is not on the allowed domain list`,
          rebindingDetected: false
        };
      }
    }

    return {
      allowed: true,
      destinationClass: 'PUBLIC',
      canonicalUrl: parsed.href,
      host,
      port,
      resolvedIps,
      pinnedIp: resolvedIps[0], // Pin to first resolved IP to prevent TOCTOU rebinding during socket connect
      rebindingDetected: false
    };
  }

  /**
   * Validates an HTTP 3xx redirect chain
   */
  public async validateRedirectChain(chain: string[]): Promise<EgressDecision> {
    for (let i = 0; i < chain.length; i++) {
      const stepUrl = chain[i];
      const decision = await this.evaluateDestination(stepUrl);
      if (!decision.allowed) {
        return {
          ...decision,
          reason: `Redirect hop ${i + 1} denied: ${decision.reason}`
        };
      }
    }

    return await this.evaluateDestination(chain[chain.length - 1]);
  }

  public classifyIp(ip: string): DestinationClass {
    const norm = normalizeIpAddress(ip) || ip;

    if (CLOUD_METADATA_IPS.has(norm)) {
      return 'CLOUD_METADATA';
    }

    if (norm === '127.0.0.1' || norm === '::1' || norm.startsWith('127.')) {
      return 'LOOPBACK';
    }

    if (norm.startsWith('169.254.') || norm.startsWith('fe80:')) {
      return 'LINK_LOCAL';
    }

    if (isPrivateIp(norm)) {
      return 'PRIVATE';
    }

    return 'PUBLIC';
  }

  private async resolveHostname(host: string): Promise<string[]> {
    if (this.options.dnsResolver) {
      return await this.options.dnsResolver(host);
    }

    return new Promise((resolve, reject) => {
      dns.resolve(host, (err, addresses) => {
        if (err) {
          // Fallback to lookup for IPv4/IPv6 compatibility
          dns.lookup(host, { all: true }, (lookupErr, lookupAddrs) => {
            if (lookupErr) return reject(lookupErr);
            resolve(lookupAddrs.map((a) => a.address));
          });
          return;
        }
        resolve(addresses);
      });
    });
  }
}
