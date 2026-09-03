import { PolicyEngine } from '../../src/security/policy-engine';
import { ConfigLoader } from '../../src/security/config';

describe('Deep Egress Inspection Suite (Field-Agnostic & Decoded Payloads)', () => {
  let policyEngine: PolicyEngine;

  beforeAll(() => {
    policyEngine = new PolicyEngine(ConfigLoader.getHardenedProfile());
  });

  it('EGRESS-DEEP-01: Detects SSRF in arbitrary nested fields without heuristic field names', () => {
    // Arbitrary unknown custom field name containing metadata IP
    const payload = {
      userCustomData: {
        networkOptions: {
          arbitraryTarget: '169.254.169.254'
        }
      }
    };
    const res = policyEngine.checkEgress(payload);
    expect(res.isBlocked).toBe(true);
  });

  it('EGRESS-DEEP-02: Detects and blocks URL-encoded destinations', () => {
    // http://169.254.169.254 URL-encoded
    const encodedPayload = {
      destination: 'http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data'
    };
    const res = policyEngine.checkEgress(encodedPayload);
    expect(res.isBlocked).toBe(true);
  });

  it('EGRESS-DEEP-03: Detects and blocks Base64-encoded egress targets', () => {
    // "http://169.254.169.254" in base64 is "aHR0cDovLzE2OS4yNTQuMTY5LjI1NA=="
    const b64Payload = {
      blob: 'aHR0cDovLzE2OS4yNTQuMTY5LjI1NA=='
    };
    const res = policyEngine.checkEgress(b64Payload);
    expect(res.isBlocked).toBe(true);
  });

  it('EGRESS-DEEP-04: Blocks loopback and internal targets in array parameters', () => {
    const arrayPayload = {
      destinations: ['https://legitimate.org', '127.0.0.1:8080']
    };
    const res = policyEngine.checkEgress(arrayPayload);
    expect(res.isBlocked).toBe(true);
  });
});
