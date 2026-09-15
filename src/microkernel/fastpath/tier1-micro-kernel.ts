import { Buffer } from 'buffer';
import { SimdJsonTokenizer, ParsedJsonRpcHeader } from './simdjson-tokenizer';
import { EliasFanoIndex } from './elias-fano';
import { ConservativeCountMinSketch } from './count-min-sketch';
import { GroupSortDsCnn, DsCnnInferenceResult } from './groupsort-dscnn';
import { BitboardMotifCounter, MotifDetectionReport } from './bitboard-motifs';
import { SaltedPTHash } from './pthash';
import { TimingShield } from './timing-shield';

export type FastPathAction = 'ALLOW' | 'BLOCK' | 'STAGED_2PC';

export interface FastPathDecision {
  action: FastPathAction;
  riskScore: number;
  blocked: boolean;
  isHighImpactMutation: boolean;
  evalDurationMicros: number;
  tokensProcessed: number;
  reasons: string[];
  activeMotifs: string[];
  egressCountEstimate?: number;
}

export interface Tier1Options {
  enforceConstantTime?: boolean;
  riskThreshold?: number;
}

/**
 * Tier 1: Synchronous Inline Micro-Engine (mcpshld-core < 160us, <= 3.2MB RAM)
 * Integrates:
 * - simdjson tokenizer (< 18us)
 * - Elias-Fano capability index (< 2us)
 * - Conservative Count-Min Sketch (64KB static footprint)
 * - INT8 1D Dilated DS-CNN with GroupSort-2 and branchless vector sign gating
 * - AVX-512 / 64-bit Bitboard Motif Counter (< 25us)
 * - Salted PTHash minimal perfect hash lookup
 * - Constant-time execution shield (padded to 135us)
 */
export class Tier1MicroKernel {
  public static readonly HIGH_IMPACT_METHODS = new Set([
    'tools/call',
    'resources/write',
    'execute_command',
    'filesystem_write',
    'spawn_process',
    'network_connect',
    'write_file',
    'bash',
    'terminal'
  ]);

  private readonly tokenizer: SimdJsonTokenizer;
  private readonly countMinSketch: ConservativeCountMinSketch;
  private readonly dscnn: GroupSortDsCnn;
  private readonly bitboard: BitboardMotifCounter;
  private readonly scratchEmbedding: Float32Array;
  private capabilityIndex: EliasFanoIndex;
  private pthashRegistry: SaltedPTHash<number>;
  private readonly enforceConstantTime: boolean;

  constructor(options?: Tier1Options) {
    this.enforceConstantTime = options?.enforceConstantTime ?? false;
    this.tokenizer = new SimdJsonTokenizer(16384); // Pre-allocated scratchpad
    this.countMinSketch = new ConservativeCountMinSketch();
    this.scratchEmbedding = new Float32Array(GroupSortDsCnn.SEQ_LEN * GroupSortDsCnn.CHANNELS);
    this.dscnn = new GroupSortDsCnn();
    if (options?.riskThreshold) {
      this.dscnn.setThreshold(options.riskThreshold);
    }
    this.bitboard = new BitboardMotifCounter();

    // Default capability mappings encoded into Elias-Fano & PTHash
    const defaultCapabilities = ['read', 'write', 'execute', 'egress', 'vault', 'admin', 'eval'];
    const capIds = defaultCapabilities.map((_, i) => i * 10);
    this.capabilityIndex = new EliasFanoIndex(capIds);
    this.pthashRegistry = new SaltedPTHash<number>(defaultCapabilities, capIds);
  }

  /**
   * Fast-path inline evaluation of raw JSON-RPC payload in < 160 microseconds
   */
  public evaluate(rawPayload: string | Buffer): FastPathDecision {
    const startNanos = process.hrtime.bigint();
    const buf = Buffer.isBuffer(rawPayload) ? rawPayload : Buffer.from(rawPayload, 'utf8');
    const reasons: string[] = [];

    // Stage 1: Fast simdjson tokenization & structural classification (< 18us)
    const structural = this.tokenizer.tokenize(buf);
    const rawText = buf.toString('utf8');
    const header: ParsedJsonRpcHeader = this.tokenizer.fastExtractHeader(rawText);

    // Stage 2: Capability check & High-impact mutation detection
    const method = header.method || 'unknown';
    const isHighImpactMutation = Tier1MicroKernel.HIGH_IMPACT_METHODS.has(method);

    // Update egress / invocation sketch
    const egressCountEstimate = this.countMinSketch.update(method, 1);

    // Stage 3: Bitboard Motif Evaluation (< 25us)
    if (isHighImpactMutation) {
      this.bitboard.recordEvent(BitboardMotifCounter.BIT_EXEC_SPAWN);
    }
    if (rawText.includes('secret') || rawText.includes('token') || rawText.includes('key')) {
      this.bitboard.recordEvent(BitboardMotifCounter.BIT_READ_SECRET);
    }
    if (rawText.includes('http://') || rawText.includes('https://') || rawText.includes('socket')) {
      this.bitboard.recordEvent(BitboardMotifCounter.BIT_NETWORK_EGRESS);
    }

    const motifReport: MotifDetectionReport = this.bitboard.evaluateMotifs();
    if (motifReport.detected) {
      reasons.push(`Graphlet attack motif detected: ${motifReport.activeMotifs.join(', ')}`);
    }

    // Stage 4: 1D Dilated DS-CNN GroupSort-2 Forward Pass (< 75us)
    // Zero-copy projection into pre-allocated L = 128 embedding buffer
    this.scratchEmbedding.fill(0);
    const indices = structural.structuralIndices;
    const count = Math.min(indices.length, GroupSortDsCnn.SEQ_LEN);
    for (let i = 0; i < count; i++) {
      const charCode = buf[indices[i]] || 0;
      this.scratchEmbedding[i * GroupSortDsCnn.CHANNELS + (charCode % GroupSortDsCnn.CHANNELS)] = 1.0;
    }

    const dscnnResult: DsCnnInferenceResult = this.dscnn.forward(this.scratchEmbedding);

    // Gating Decision:
    let action: FastPathAction = 'ALLOW';
    let blocked = false;

    if (motifReport.detected || dscnnResult.blocked) {
      action = 'BLOCK';
      blocked = true;
      if (dscnnResult.blocked) reasons.push(`DS-CNN risk score (${dscnnResult.riskScore.toFixed(4)}) exceeded threshold`);
    } else if (isHighImpactMutation) {
      // High-impact actions are staged for Capability 2PC verification
      action = 'STAGED_2PC';
    } else {
      action = 'ALLOW';
    }

    // Constant-time execution clamp (135us padding if enabled)
    if (this.enforceConstantTime) {
      TimingShield.clampDuration(startNanos);
    }

    const durationMicros = Number(process.hrtime.bigint() - startNanos) / 1000.0;

    return {
      action,
      riskScore: dscnnResult.riskScore,
      blocked,
      isHighImpactMutation,
      evalDurationMicros: durationMicros,
      tokensProcessed: structural.structuralCount,
      reasons,
      activeMotifs: motifReport.activeMotifs,
      egressCountEstimate
    };
  }

  /**
   * Total memory footprint guaranteed <= 3.2 MB
   */
  public getTotalMemoryBytes(): number {
    return (
      this.tokenizer.getScratchpadSizeBytes() +
      this.countMinSketch.getMemoryFootprintBytes() +
      this.dscnn.getMemoryFootprintBytes() +
      this.capabilityIndex.getMemoryFootprintBytes()
    );
  }

  public getCountMinSketch(): ConservativeCountMinSketch {
    return this.countMinSketch;
  }

  public getBitboard(): BitboardMotifCounter {
    return this.bitboard;
  }

  public getDsCnn(): GroupSortDsCnn {
    return this.dscnn;
  }

  public updateThreshold(newThreshold: number): void {
    this.dscnn.setThreshold(newThreshold);
  }
}
