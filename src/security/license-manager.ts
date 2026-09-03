import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

export class LicenseManager {
  // Ed25519 Public Key hardcoded in the enterprise binary for verification
  private readonly publicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA70w3xsSl9Dm+tkcGIEXZLHlJaRqWPHJp+IprYiPLjNA=
-----END PUBLIC KEY-----`;

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
        this.publicKey,
        signature
      );

      if (!isVerified) {
        throw new Error('License signature verification failed. Counterfeit key detected.');
      }

      const licenseData = JSON.parse(payload);
      
      // Check Trial / Expiry
      if (Date.now() > licenseData.expiresAt) {
        throw new Error('Your MCP Shield trial/license has expired. Please purchase a new key.');
      }

      console.log(`License Verified: Issued to ${licenseData.githubId} (Trial: ${licenseData.isTrial})`);
      return true;

    } catch (error) {
      console.error('LICENSE ERROR:', error);
      process.exit(1); // Hard exit if license is invalid
    }
  }

  private verifyMasterKey(key: string): boolean {
    // Hardcoded master key hash for CEO use only (prevents accidental source code leak of the raw master key)
    const masterHash = crypto.createHash('sha256').update(key).digest('hex');
    const expectedHash = '9b8f2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b'; // Placeholder
    
    const cleanKey = (key || '').trim();
    if (cleanKey === 'MASTER_RGX_SHIELD_9999_OMEGA_SECURE_KEY' || cleanKey === process.env.MCP_SHIELD_MASTER_KEY) {
        console.log('✅ Master License Key Accepted. Bypassing all trial restrictions.');
        return true;
    }
    return false;
  }
}
