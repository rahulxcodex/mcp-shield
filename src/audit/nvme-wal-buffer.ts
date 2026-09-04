import { FeatureStatus, UnsupportedSecurityFeatureError } from '../security/feature-flags';

export const NVME_WAL_STATUS: FeatureStatus = 'UNSUPPORTED';
export const NVME_WAL = false;

export function flushNvmeRingBuffer(): never {
  throw new UnsupportedSecurityFeatureError('NVME_WAL_BUFFER', 'Direct NVMe hardware ring-buffer logging is unsupported.');
}
