import { FeatureStatus, getFeatureStatus } from '../../security/feature-flags';
import { SecurityPipeline } from '../pipeline/security-pipeline';

export interface SessionStore {
  get(sessionId: string): any;
  set(sessionId: string, session: any): void;
  delete(sessionId: string): boolean;
  clear(): void;
  count(): number;
}

export class InMemorySessionStore implements SessionStore {
  private sessions = new Map<string, any>();

  public get(sessionId: string): any {
    return this.sessions.get(sessionId);
  }

  public set(sessionId: string, session: any): void {
    this.sessions.set(sessionId, session);
  }

  public delete(sessionId: string): boolean {
    return this.sessions.delete(sessionId);
  }

  public clear(): void {
    this.sessions.clear();
  }

  public count(): number {
    return this.sessions.size;
  }
}

export interface BehaviorStore {
  recordInvocation(toolName: string, features: Record<string, any>): void;
  getHistory(toolName: string): any[];
  clear(): void;
}

export class InMemoryBehaviorStore implements BehaviorStore {
  private history = new Map<string, any[]>();
  private readonly maxPerTool: number;

  constructor(maxPerTool = 100) {
    this.maxPerTool = maxPerTool;
  }

  public recordInvocation(toolName: string, features: Record<string, any>): void {
    const list = this.history.get(toolName) || [];
    list.push({ timestamp: Date.now(), ...features });
    if (list.length > this.maxPerTool) {
      list.shift();
    }
    this.history.set(toolName, list);
  }

  public getHistory(toolName: string): any[] {
    return this.history.get(toolName) || [];
  }

  public clear(): void {
    this.history.clear();
  }
}

export interface ReputationStore {
  getReputation(entityId: string): number;
  updateReputation(entityId: string, delta: number): void;
  clear(): void;
}

export class InMemoryReputationStore implements ReputationStore {
  private scores = new Map<string, number>();

  public getReputation(entityId: string): number {
    return this.scores.get(entityId) ?? 1.0; // Default clean baseline
  }

  public updateReputation(entityId: string, delta: number): void {
    const current = this.getReputation(entityId);
    const updated = Math.max(0.0, Math.min(1.0, current + delta));
    this.scores.set(entityId, updated);
  }

  public clear(): void {
    this.scores.clear();
  }
}

export interface ThreatCorpusStore {
  hasPattern(pattern: string): boolean;
  addPattern(pattern: string): void;
  clear(): void;
}

export class InMemoryThreatCorpusStore implements ThreatCorpusStore {
  private patterns = new Set<string>();

  public hasPattern(pattern: string): boolean {
    return this.patterns.has(pattern);
  }

  public addPattern(pattern: string): void {
    this.patterns.add(pattern);
  }

  public clear(): void {
    this.patterns.clear();
  }
}

export interface FeatureStore {
  isFeatureEnabled(featureId: string): boolean;
  getStatus(featureId: string): FeatureStatus;
}

export class DefaultFeatureStore implements FeatureStore {
  public isFeatureEnabled(featureId: string): boolean {
    return getFeatureStatus(featureId) === 'SUPPORTED';
  }

  public getStatus(featureId: string): FeatureStatus {
    return getFeatureStatus(featureId);
  }
}

export class SecurityRuntime {
  public readonly sessionStore: SessionStore;
  public readonly behaviorStore: BehaviorStore;
  public readonly reputationStore: ReputationStore;
  public readonly threatStore: ThreatCorpusStore;
  public readonly featureStore: FeatureStore;

  constructor(options?: {
    sessionStore?: SessionStore;
    behaviorStore?: BehaviorStore;
    reputationStore?: ReputationStore;
    threatStore?: ThreatCorpusStore;
    featureStore?: FeatureStore;
  }) {
    this.sessionStore = options?.sessionStore || new InMemorySessionStore();
    this.behaviorStore = options?.behaviorStore || new InMemoryBehaviorStore();
    this.reputationStore = options?.reputationStore || new InMemoryReputationStore();
    this.threatStore = options?.threatStore || new InMemoryThreatCorpusStore();
    this.featureStore = options?.featureStore || new DefaultFeatureStore();
  }

  public createPipeline(): SecurityPipeline {
    return new SecurityPipeline();
  }

  public reset(): void {
    this.sessionStore.clear();
    this.behaviorStore.clear();
    this.reputationStore.clear();
    this.threatStore.clear();
  }
}
