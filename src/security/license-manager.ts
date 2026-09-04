import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

export class LicenseManager {
  // Ed25519 Public Key hardcoded in the enterprise binary for verification
  private readonly defaultPublicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA70w3xsSl9Dm+tkcGIEXZLHlJaRqWPHJp+IprYiPLjNA=
-----END PUBLIC KEY-----`;

  /**
   * Retrieves the normalized Ed25519 public key, supporting environment override.
   */
  public getPublicKey(): string {
    // Strict server-side trust root selection: NEXT_PUBLIC_* is excluded to prevent client-exposed trust-root tampering
    const envKey = process.env.MCP_SHIELD_PUBLIC_KEY || process.env.LICENSE_PUBLIC_KEY;
    if (envKey) {
      return envKey.replace(/\\n/g, '\n').trim();
    }
    return this.defaultPublicKey;
  }

  /**
   * Verifies the cryptographic authenticity of the MCP Shield product key.
   */
  public verifyLicense(licenseKey: string): boolean {
    try {
      if (licenseKey.startsWith('MASTER_')) {
        return this.verifyMasterKey(licenseKey);
      }

      // License format: base64(payload).base64(signature)
      const [b64Payload, b64Signature] = licenseKey.split('.');
      if (!b64Payload || !b64Signature) return false;

      const payload = Buffer.from(b64Payload, 'base64').toString('utf8');
      const signature = Buffer.from(b64Signature, 'base64');
      
      const isVerified = crypto.verify(
        null,
        Buffer.from(payload),
        this.getPublicKey(),
        signature
      );

      if (!isVerified) {
        throw new Error('License signature verification failed. Counterfeit key detected.');
      }

      const licenseData = JSON.parse(payload);
      
      // Strict validation of payload structure and expiration timestamp
      if (
        !licenseData ||
        typeof licenseData !== 'object' ||
        typeof licenseData.expiresAt !== 'number' ||
        !Number.isFinite(licenseData.expiresAt) ||
        licenseData.expiresAt <= 0
      ) {
        throw new Error('License validation failed: Missing, invalid, or non-finite expiration timestamp.');
      }

      // Check Trial / Expiry
      if (Date.now() > licenseData.expiresAt) {
        throw new Error('Your MCP Shield trial/license has expired. Please purchase a new key.');
      }

      const seats = licenseData.seats || (licenseData.tier === 'enterprise' ? 25 : 1);
      const tierDesc = licenseData.tier || (licenseData.isTrial ? 'Trial' : 'Production');
      console.log(`License Verified: Issued to ${licenseData.githubId || 'Enterprise'} (${tierDesc}, ${seats} Seats)`);
      return true;

    } catch (error: any) {
      console.error('LICENSE ERROR:', error?.message || error);
      if (process.env.NODE_ENV === 'test' || process.env.MCP_SHIELD_NO_EXIT) {
        throw error;
      }
      process.exit(1); // Hard exit if license is invalid
    }
  }

  private verifyMasterKey(key: string): boolean {
    const cleanKey = (key || '').trim();
    if (!cleanKey) return false;

    // Cryptographic emergency verification requires explicit server-side environment configuration.
    // Hardcoded public hashes are strictly forbidden to eliminate binary reverse-engineering bypasses.
    const envMasterHash = process.env.MCP_SHIELD_MASTER_KEY_HASH;
    const envMasterKey = process.env.MCP_SHIELD_MASTER_KEY;

    if (!envMasterHash && !envMasterKey) {
      return false;
    }

    const masterHash = crypto.createHash('sha256').update(cleanKey).digest('hex');

    if (envMasterHash) {
      const bufA = Buffer.from(masterHash, 'utf8');
      const bufB = Buffer.from(envMasterHash.trim(), 'utf8');
      if (bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB)) {
        console.log('✅ Master License Key Accepted via secure server environment.');
        return true;
      }
    }

    if (envMasterKey) {
      const bufA = Buffer.from(cleanKey, 'utf8');
      const bufB = Buffer.from(envMasterKey.trim(), 'utf8');
      if (bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB)) {
        console.log('✅ Master License Key Accepted via secure server environment.');
        return true;
      }
    }

    return false;
  }
}
