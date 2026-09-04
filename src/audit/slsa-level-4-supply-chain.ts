import { FeatureStatus, UnsupportedSecurityFeatureError } from '../security/feature-flags';

export const SLSA_L4_STATUS: FeatureStatus = 'UNSUPPORTED';
export const SLSA_L4 = false;

export function verifySlsaLevel4Attestation(): never {
  throw new UnsupportedSecurityFeatureError('SLSA_LEVEL_4', 'SLSA Level 4 continuous build attestation is unsupported.');
}
