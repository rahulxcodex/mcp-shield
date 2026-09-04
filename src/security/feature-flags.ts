export type FeatureStatus = 'SUPPORTED' | 'EXPERIMENTAL' | 'UNSUPPORTED' | 'DISABLED';

export class UnsupportedSecurityFeatureError extends Error {
  constructor(featureName: string, reason?: string) {
    super(
      "UNSUPPORTED_SECURITY_FEATURE: '" + featureName + "' is currently not supported in this runtime environment." +
      (reason ? " (" + reason + ")" : " Contact enterprise support or refer to product security roadmap.")
    );
    this.name = 'UnsupportedSecurityFeatureError';
  }
}

export const SECURITY_FEATURE_REGISTRY: Record<string, { status: FeatureStatus; description: string }> = {
  'CAC_PIV_MTLS': {
    status: 'UNSUPPORTED',
    description: 'Hardware CAC/PIV smartcard mTLS client certificate validation'
  },
  'SLSA_LEVEL_4': {
    status: 'UNSUPPORTED',
    description: 'Automated SLSA Level 4 continuous build provenance attestation'
  },
  'CRDT_ACTIVE_ACTIVE_HA': {
    status: 'UNSUPPORTED',
    description: 'Multi-region CRDT state synchronization for active-active high availability'
  },
  'NVME_WAL_BUFFER': {
    status: 'UNSUPPORTED',
    description: 'Direct NVMe hardware ring-buffer write-ahead log acceleration'
  },
  'WASM_MICROKERNEL_PLUGINS': {
    status: 'SUPPORTED',
    description: 'Cryptographically verified sandboxed WebAssembly execution plugins'
  }
};

export function getFeatureStatus(featureName: string): FeatureStatus {
  return SECURITY_FEATURE_REGISTRY[featureName]?.status || 'UNSUPPORTED';
}

export function assertFeatureSupported(featureName: string): void {
  const feature = SECURITY_FEATURE_REGISTRY[featureName];
  if (!feature || feature.status !== 'SUPPORTED') {
    throw new UnsupportedSecurityFeatureError(featureName, feature?.description);
  }
}
