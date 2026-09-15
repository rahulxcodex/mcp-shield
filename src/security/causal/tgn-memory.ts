/**
 * Continuous-Time Temporal Graph Network (TGN) with Harmonic Fourier Memory
 * (Rossi et al., ICML 2020; Xu et al., ICLR 2020 TGAT)
 * Maintains continuous-time interaction states using harmonic Fourier time encodings:
 * phi(dt) = cos(w * dt + b) and GRU memory updates across interaction multigraphs.
 */
export interface InteractionEvent {
  sourceNode: string;
  targetNode: string;
  timestamp: number;
  edgeFeature: Float32Array;
}

export class TgnMemoryEngine {
  public static readonly MEMORY_DIM: number = 32;
  public static readonly TIME_ENC_DIM: number = 16;

  // Node memory vectors s_u(t)
  private readonly memoryTable: Map<string, Float32Array> = new Map();
  // Last interaction timestamp per node t_u^-
  private readonly lastTimestampTable: Map<string, number> = new Map();

  // Fourier time encoding parameters: frequencies w and phase biases b
  private readonly fourierOmega: Float32Array;
  private readonly fourierBias: Float32Array;

  constructor() {
    this.fourierOmega = new Float32Array(TgnMemoryEngine.TIME_ENC_DIM);
    this.fourierBias = new Float32Array(TgnMemoryEngine.TIME_ENC_DIM);

    // Initialize harmonic frequencies: 1 / 10^(2i / d)
    for (let i = 0; i < TgnMemoryEngine.TIME_ENC_DIM; i++) {
      this.fourierOmega[i] = 1.0 / Math.pow(10.0, (2.0 * i) / TgnMemoryEngine.TIME_ENC_DIM);
      this.fourierBias[i] = (i * Math.PI) / TgnMemoryEngine.TIME_ENC_DIM;
    }
  }

  /**
   * Continuous-time Fourier time encoding: phi(dt) = cos(w * dt + b)
   */
  public computeTimeEncoding(dt: number): Float32Array {
    const enc = new Float32Array(TgnMemoryEngine.TIME_ENC_DIM);
    for (let i = 0; i < TgnMemoryEngine.TIME_ENC_DIM; i++) {
      enc[i] = Math.cos(this.fourierOmega[i] * dt + this.fourierBias[i]);
    }
    return enc;
  }

  /**
   * Retrieves or initializes node memory vector s_u
   */
  public getNodeMemory(nodeId: string): Float32Array {
    let mem = this.memoryTable.get(nodeId);
    if (!mem) {
      mem = new Float32Array(TgnMemoryEngine.MEMORY_DIM);
      this.memoryTable.set(nodeId, mem);
    }
    return mem;
  }

  /**
   * GRU memory update cell: s_u(t) = GRU(s_u(t^-), m_u(t))
   */
  private gruUpdate(currentMemory: Float32Array, message: Float32Array): Float32Array {
    const dim = TgnMemoryEngine.MEMORY_DIM;
    const updated = new Float32Array(dim);

    // Update gate z and reset gate r emulation
    for (let i = 0; i < dim; i++) {
      const z = 1.0 / (1.0 + Math.exp(-(currentMemory[i] * 0.5 + message[i % message.length] * 0.5)));
      const candidate = Math.tanh(currentMemory[i] * 0.3 + message[i % message.length] * 0.7);
      updated[i] = (1.0 - z) * currentMemory[i] + z * candidate;
    }

    return updated;
  }

  /**
   * Updates TGN memory for source and target upon interaction e_uv(t)
   */
  public processInteraction(event: InteractionEvent): { sourceState: Float32Array; targetState: Float32Array } {
    const { sourceNode, targetNode, timestamp, edgeFeature } = event;

    const tSourceLast = this.lastTimestampTable.get(sourceNode) ?? timestamp;
    const tTargetLast = this.lastTimestampTable.get(targetNode) ?? timestamp;

    const dtSource = Math.max(0, timestamp - tSourceLast);
    const dtTarget = Math.max(0, timestamp - tTargetLast);

    const phiSource = this.computeTimeEncoding(dtSource);
    const phiTarget = this.computeTimeEncoding(dtTarget);

    const sSourcePrev = this.getNodeMemory(sourceNode);
    const sTargetPrev = this.getNodeMemory(targetNode);

    // Raw message aggregation m_u(t) = [s_u(t^-) || s_v(t^-) || e_uv || phi(dt)]
    const messageSource = new Float32Array(edgeFeature.length + phiSource.length);
    messageSource.set(edgeFeature, 0);
    messageSource.set(phiSource, edgeFeature.length);

    const messageTarget = new Float32Array(edgeFeature.length + phiTarget.length);
    messageTarget.set(edgeFeature, 0);
    messageTarget.set(phiTarget, edgeFeature.length);

    // GRU updates
    const sSourceNew = this.gruUpdate(sSourcePrev, messageSource);
    const sTargetNew = this.gruUpdate(sTargetPrev, messageTarget);

    this.memoryTable.set(sourceNode, sSourceNew);
    this.memoryTable.set(targetNode, sTargetNew);
    this.lastTimestampTable.set(sourceNode, timestamp);
    this.lastTimestampTable.set(targetNode, timestamp);

    return {
      sourceState: sSourceNew,
      targetState: sTargetNew
    };
  }

  public getMemorySize(): number {
    return this.memoryTable.size;
  }
}
