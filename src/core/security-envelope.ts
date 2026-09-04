import { SecurityEvidence } from '../security/evidence';
import { canonicalizeJson } from '../security/canonical-json';

export interface MessageMetadata {
  messageId?: string | number | null;
  method?: string;
  timestamp: number;
  transport: 'stdio' | 'websocket' | 'sse' | 'memory';
  sessionId?: string;
  origin?: string;
  contentLength?: number;
}

export interface SecurityEnvelope<T = any> {
  readonly message: T;
  readonly rawBuffer?: Buffer;
  readonly canonical?: Uint8Array;
  readonly metadata: MessageMetadata;
  readonly evidence: SecurityEvidence[];
}

export class SecurityEnvelopeFactory {
  /**
   * Constructs an immutable SecurityEnvelope, parsing and canonicalizing exactly once
   */
  public static fromBuffer<T = any>(
    buffer: Buffer,
    metadataOverrides?: Partial<MessageMetadata>
  ): SecurityEnvelope<T> {
    const rawString = buffer.toString('utf8');
    const message = JSON.parse(rawString);

    const metadata: MessageMetadata = {
      messageId: message.id ?? null,
      method: message.method,
      timestamp: Date.now(),
      transport: 'stdio',
      contentLength: buffer.length,
      ...metadataOverrides
    };

    // Deterministic canonical digest/bytes
    const canonicalString = canonicalizeJson(message);
    const canonical = Buffer.from(canonicalString, 'utf8');

    return {
      message: Object.freeze(message),
      rawBuffer: buffer,
      canonical,
      metadata: Object.freeze(metadata),
      evidence: []
    };
  }

  /**
   * Constructs an envelope from an already parsed structured object
   */
  public static fromObject<T = any>(
    obj: T,
    metadataOverrides?: Partial<MessageMetadata>
  ): SecurityEnvelope<T> {
    const metadata: MessageMetadata = {
      messageId: (obj as any)?.id ?? null,
      method: (obj as any)?.method,
      timestamp: Date.now(),
      transport: 'memory',
      ...metadataOverrides
    };

    return {
      message: Object.isFrozen(obj) ? obj : Object.freeze({ ...obj }),
      metadata: Object.freeze(metadata),
      evidence: []
    };
  }
}
