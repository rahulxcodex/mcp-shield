import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export class LicenseManager {
  // Ed25519 Public Key hardcoded in the enterprise binary for verification
  private readonly defaultPublicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA70w3xsSl9Dm+tkcGIEXZLHlJaRqWPHJp+IprYiPLjNA=
-----END PUBLIC KEY-----`;

  /**
   * Generates a stable host machine fingerprint for hardware/environment license binding.
   */
  public static getMachineFingerprint(): string {
    const raw = `${os.platform()}:${os.hostname()}:${os.arch()}:${os.homedir()}`;
    return crypto.createHash('sha256').update(raw).digest('hex');
  }

  /**
   * Retrieves the normalized Ed25519 public key, enforcing vendor trust-root attestation on overrides.
   */
  public getPublicKey(): string {
    // Strict server-side trust root selection: NEXT_PUBLIC_* is excluded to prevent client-exposed trust-root tampering
    const envKey = process.env.MCP_SHIELD_PUBLIC_KEY || process.env.LICENSE_PUBLIC_KEY;
    if (envKey) {
      const normalized = envKey.replace(/\\n/g, '\n').trim();
      if (normalized === this.defaultPublicKey.trim()) {
        return this.defaultPublicKey;
      }
      // Attestation verification: Custom trust root must be cryptographically endorsed by vendor root key
      const attestation = process.env.MCP_SHIELD_TRUST_ATTESTATION || process.env.LICENSE_TRUST_ATTESTATION;
      const allowUnverified = process.env.MCP_SHIELD_ALLOW_UNVERIFIED_ROOT === 'true' || (process.env.NODE_ENV === 'test' && process.env.MCP_SHIELD_STRICT_ATTESTATION !== 'true');
      if (attestation) {
        try {
          const isValid = crypto.verify(
            null,
            Buffer.from(normalized),
            this.defaultPublicKey,
            Buffer.from(attestation, 'base64')
          );
          if (!isValid) {
            throw new Error('Invalid vendor trust attestation for custom public key');
          }
          return normalized;
        } catch (e: any) {
          throw new Error(`Trust-root verification failed: ${e?.message || 'Invalid attestation'}`);
        }
      } else if (allowUnverified) {
        return normalized;
      } else {
        throw new Error('Untrusted root override: Custom MCP_SHIELD_PUBLIC_KEY requires vendor attestation (MCP_SHIELD_TRUST_ATTESTATION) or explicit MCP_SHIELD_ALLOW_UNVERIFIED_ROOT=true.');
      }
    }
    return this.defaultPublicKey;
  }

  private static revokedKeyHashes: Set<string> = new Set<string>();

  public static addRevokedKey(keyOrHash: string): void {
    const clean = (keyOrHash || '').trim();
    if (!clean) return;
    const hash = clean.length === 64 && /^[0-9a-f]+$/i.test(clean)
      ? clean.toLowerCase()
      : crypto.createHash('sha256').update(clean).digest('hex');
    LicenseManager.revokedKeyHashes.add(hash);
  }

  public static isKeyRevoked(keyOrHash: string): boolean {
    const clean = (keyOrHash || '').trim();
    if (!clean) return false;
    const hash = clean.length === 64 && /^[0-9a-f]+$/i.test(clean)
      ? clean.toLowerCase()
      : crypto.createHash('sha256').update(clean).digest('hex');

    if (LicenseManager.revokedKeyHashes.has(hash)) return true;

    const envRevoked = process.env.MCP_SHIELD_REVOKED_KEYS;
    if (envRevoked) {
      const hashes = envRevoked.split(',').map((s) => s.trim().toLowerCase());
      if (hashes.includes(hash)) return true;
    }

    return false;
  }

  /**
   * Verifies the cryptographic authenticity of the MCP Shield product key.
   */
  public verifyLicense(
    licenseKey: string,
    options?: { machineFingerprint?: string; revocationList?: string[]; checkRevocation?: boolean }
  ): boolean {
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

      // Strict Revocation Verification: Check against local CRL and revocation list
      const keyHash = crypto.createHash('sha256').update(licenseKey).digest('hex');
      const isRevoked =
        LicenseManager.isKeyRevoked(keyHash) ||
        Boolean(options?.revocationList && options.revocationList.map((h) => h.toLowerCase()).includes(keyHash));

      if (isRevoked) {
        throw new Error('License revoked: This license key has been revoked or shut off by the vendor.');
      }

      // Strict Trial Machine Binding Verification (SEC-FINDING-001)
      if (licenseData.isTrial && licenseData.machineFingerprint) {
        const expectedFingerprint = options?.machineFingerprint || process.env.MCP_SHIELD_MACHINE_FINGERPRINT || LicenseManager.getMachineFingerprint();
        const bufA = Buffer.from(licenseData.machineFingerprint);
        const bufB = Buffer.from(expectedFingerprint);
        if (bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB)) {
          throw new Error('License binding violation: Trial license is bound to a different machine/environment.');
        }
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
