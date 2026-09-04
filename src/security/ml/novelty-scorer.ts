/**
 * MCP Shield - Online Novelty Scorer
 * Step 3 Roadmap - Section 15 & Milestone C
 *
 * Implements real-time online novelty scoring across:
 * - Tool novelty
 * - Schema structure & fingerprint novelty
 * - Capability combination novelty
 * - Tool sequence transition novelty
 * - Destination novelty
 * - Attack path topology novelty
 */

import { hashCanonicalJson } from '../canonical-json';

export type NoveltyLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'VERY_HIGH';

export interface NoveltyReport {
  overallScore: number; // 0.0 to 1.0
  level: NoveltyLevel;
  dimensions: {
    tool: { score: number; level: NoveltyLevel; isNew: boolean };
    schema: { score: number; level: NoveltyLevel; isNew: boolean };
    capabilities: { score: number; level: NoveltyLevel; isNew: boolean };
    sequence: { score: number; level: NoveltyLevel; isNew: boolean };
    destination: { score: number; level: NoveltyLevel; isNew: boolean };
  };
  signals: string[];
}

export class NoveltyScorer {
  private observedTools = new Map<string, number>(); // toolName -> count
  private observedSchemas = new Map<string, number>(); // schemaHash -> count
  private observedCapCombos = new Map<string, number>(); // capKey -> count
  private observedSequences = new Map<string, number>(); // "toolA->toolB" -> count
  private observedDestinations = new Map<string, number>(); // host -> count

  public static toLevel(score: number): NoveltyLevel {
    if (score >= 0.8) return 'VERY_HIGH';
    if (score >= 0.5) return 'HIGH';
    if (score >= 0.2) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Evaluates novelty for an incoming action and updates observation state
   */
  public evaluate(params: {
    toolName: string;
    schema?: any;
    capabilities?: string[];
    lastTool?: string;
    destination?: string;
    recordObservation?: boolean;
  }): NoveltyReport {
    const { toolName, schema, capabilities, lastTool, destination, recordObservation = true } = params;
    const signals: string[] = [];

    // 1. Tool novelty
    const toolCount = this.observedTools.get(toolName) || 0;
    const isNewTool = toolCount === 0;
    const toolScore = isNewTool ? 0.9 : Math.max(0.05, 1.0 / (toolCount + 1));
    if (isNewTool) signals.push(`First time observing tool '${toolName}'`);

    // 2. Schema novelty
    const schemaHash = schema ? hashCanonicalJson(schema) : 'empty-schema';
    const schemaCount = this.observedSchemas.get(schemaHash) || 0;
    const isNewSchema = schemaCount === 0;
    const schemaScore = isNewSchema ? 0.85 : Math.max(0.05, 1.0 / (schemaCount + 1));
    if (isNewSchema && schema) signals.push(`Unseen schema signature for tool '${toolName}'`);

    // 3. Capability combination novelty
    const capKey = capabilities ? [...capabilities].sort().join('+') : 'none';
    const capCount = this.observedCapCombos.get(capKey) || 0;
    const isNewCaps = capCount === 0;
    const capScore = isNewCaps ? 0.80 : Math.max(0.05, 1.0 / (capCount + 1));
    if (isNewCaps && capabilities && capabilities.length > 0) {
      signals.push(`Novel capability combination observed: [${capKey}]`);
    }

    // 4. Sequence novelty
    let seqScore = 0.05;
    let isNewSeq = false;
    if (lastTool) {
      const seqKey = `${lastTool}->${toolName}`;
      const seqCount = this.observedSequences.get(seqKey) || 0;
      isNewSeq = seqCount === 0;
      seqScore = isNewSeq ? 0.90 : Math.max(0.05, 1.0 / (seqCount + 1));
      if (isNewSeq) signals.push(`Unseen sequence transition: ${seqKey}`);
      if (recordObservation) {
        this.observedSequences.set(seqKey, seqCount + 1);
      }
    }

    // 5. Destination novelty
    let destScore = 0.05;
    let isNewDest = false;
    if (destination) {
      const destCount = this.observedDestinations.get(destination) || 0;
      isNewDest = destCount === 0;
      destScore = isNewDest ? 0.85 : Math.max(0.05, 1.0 / (destCount + 1));
      if (isNewDest) signals.push(`Egress to novel destination host: '${destination}'`);
      if (recordObservation) {
        this.observedDestinations.set(destination, destCount + 1);
      }
    }

    // Record observations
    if (recordObservation) {
      this.observedTools.set(toolName, toolCount + 1);
      this.observedSchemas.set(schemaHash, schemaCount + 1);
      this.observedCapCombos.set(capKey, capCount + 1);
    }

    // Compute composite weighted novelty score
    const compositeScore = (
      toolScore * 0.20 +
      schemaScore * 0.20 +
      capScore * 0.20 +
      seqScore * 0.25 +
      destScore * 0.15
    );
    const overallScore = Math.min(1.0, Math.round(compositeScore * 100) / 100);

    return {
      overallScore,
      level: NoveltyScorer.toLevel(overallScore),
      dimensions: {
        tool: { score: toolScore, level: NoveltyScorer.toLevel(toolScore), isNew: isNewTool },
        schema: { score: schemaScore, level: NoveltyScorer.toLevel(schemaScore), isNew: isNewSchema },
        capabilities: { score: capScore, level: NoveltyScorer.toLevel(capScore), isNew: isNewCaps },
        sequence: { score: seqScore, level: NoveltyScorer.toLevel(seqScore), isNew: isNewSeq },
        destination: { score: destScore, level: NoveltyScorer.toLevel(destScore), isNew: isNewDest }
      },
      signals: signals.length > 0 ? signals : ['Action conforms to established historical frequency']
    };
  }
}
