import * as crypto from 'crypto';

export interface AuditEvent {
  timestamp: string;
  actor: string;
  action: string;
  payloadHash: string;
  previousHash: string;
  signature: string;
}

export class AuditComplianceLedger {
  private ledger: AuditEvent[] = [];
  private lastHash: string = crypto.createHash('sha256').update('GENESIS').digest('hex');
  private privateKey: string; // In production this would be an HSM/KMS reference

  constructor() {
    this.privateKey = 'mock-audit-private-key'; 
  }

  /**
   * Logs an event to the immutable, cryptographically signed ledger
   */
  public logEvent(actor: string, action: string, rawPayload: string): AuditEvent {
    const payloadHash = crypto.createHash('sha256').update(rawPayload).digest('hex');
    const timestamp = new Date().toISOString();
    
    // Create Merkle-tree style chaining
    const eventString = `${timestamp}:${actor}:${action}:${payloadHash}:${this.lastHash}`;
    const signature = crypto.createHmac('sha256', this.privateKey).update(eventString).digest('hex');
    
    const event: AuditEvent = {
      timestamp,
      actor,
      action,
      payloadHash,
      previousHash: this.lastHash,
      signature
    };
    
    this.ledger.push(event);
    this.lastHash = signature; // Chain the hash
    
    return event;
  }
  
  public getLedger(): AuditEvent[] {
    return [...this.ledger];
  }
}
