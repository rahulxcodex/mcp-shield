import { FeatureStatus, UnsupportedSecurityFeatureError } from './feature-flags';

export const CAC_PIV_STATUS: FeatureStatus = 'UNSUPPORTED';
export const CAC_PIV_MTLS = false;

export function verifyCacPivClientCert(): never {
  throw new UnsupportedSecurityFeatureError('CAC_PIV_MTLS', 'Hardware CAC/PIV client certificate verification is unsupported.');
}
