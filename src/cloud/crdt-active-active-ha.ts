import { FeatureStatus, UnsupportedSecurityFeatureError } from '../security/feature-flags';

export const CRDT_HA_STATUS: FeatureStatus = 'UNSUPPORTED';
export const CRDT_HA = false;

export function synchronizeCrdtState(): never {
  throw new UnsupportedSecurityFeatureError('CRDT_ACTIVE_ACTIVE_HA', 'Multi-region CRDT state synchronization is unsupported.');
}
