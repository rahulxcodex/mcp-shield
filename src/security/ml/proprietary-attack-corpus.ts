/**
 * MCP Shield - Proprietary Attack Corpus Store
 * Step 3 Roadmap - Section 7 & Milestone D
 *
 * Implements structured, privacy-preserving incident record storage for confirmed security events,
 * human feedback labels, and regression replay suites.
 */

import { SecurityEvidence } from '../evidence';
import { hashCanonicalJson } from '../canonical-json';

export type IncidentOutcome = 'BLOCKED' | 'QUARANTINED' | 'FALSE_POSITIVE' | 'BYPASS_DETECTED' | 'CONFIRMED_EXPLOIT';

export interface ConfirmedSecurityEvent {
  id: string;
  timestamp: number;
  serverIdentity: string;
  publisher?: string;
  toolName: string;
  toolSchemaHash: string;
  capabilities: string[];
  requestSummary: {
    byteSize: number;
    entropy: number;
    extractedCommandFingerprint?: string;
    destinationClass?: 'internal' | 'cloud_metadata' | 'external_internet' | 'loopback';
  };
  sequenceContext: string[]; // recent tool history
  detectorOutputs: Array<{ detectorId: string; category: string; severity: number }>;
  finalDecision: 'BLOCK' | 'ALLOW' | 'PROMPT' | 'SANDBOX';
  humanFeedback?: {
    reviewedBy: string;
    isActualAttack: boolean;
    notes?: string;
  };
  incidentOutcome: IncidentOutcome;
}

export class ProprietaryAttackCorpusStore {
  private events = new Map<string, ConfirmedSecurityEvent>();

  /**
   * Records a confirmed or flagged security event
   */
  public recordEvent(event: Omit<ConfirmedSecurityEvent, 'id' | 'timestamp'>): ConfirmedSecurityEvent {
    const timestamp = Date.now();
    const id = `SEC-EVT-${hashCanonicalJson({ ...event, timestamp }).slice(0, 16)}`;
    const fullEvent: ConfirmedSecurityEvent = {
      ...event,
      id,
      timestamp
    };
    this.events.set(id, fullEvent);
    return fullEvent;
  }

  public getEvent(id: string): ConfirmedSecurityEvent | undefined {
    return this.events.get(id);
  }

  public getAllEvents(): ConfirmedSecurityEvent[] {
    return Array.from(this.events.values());
  }

  /**
   * Annotates an event with human reviewer feedback
   */
  public annotateFeedback(eventId: string, feedback: { reviewedBy: string; isActualAttack: boolean; notes?: string }): boolean {
    const event = this.events.get(eventId);
    if (!event) return false;
    event.humanFeedback = feedback;
    if (!feedback.isActualAttack) {
      event.incidentOutcome = 'FALSE_POSITIVE';
    } else if (event.incidentOutcome === 'BLOCKED') {
      event.incidentOutcome = 'CONFIRMED_EXPLOIT';
    }
    return true;
  }

  /**
   * Retrieves high-confidence confirmed attack samples for hard-negative mining and regression testing
   */
  public getConfirmedAttacks(): ConfirmedSecurityEvent[] {
    return Array.from(this.events.values()).filter(e =>
      e.incidentOutcome === 'CONFIRMED_EXPLOIT' ||
      (e.humanFeedback?.isActualAttack === true) ||
      (e.detectorOutputs.some(d => d.severity >= 0.95) && e.incidentOutcome !== 'FALSE_POSITIVE')
    );
  }

  /**
   * Retrieves false-positive samples to refine detector thresholds
   */
  public getFalsePositives(): ConfirmedSecurityEvent[] {
    return Array.from(this.events.values()).filter(e =>
      e.incidentOutcome === 'FALSE_POSITIVE' || e.humanFeedback?.isActualAttack === false
    );
  }

  public size(): number {
    return this.events.size;
  }
}
