/**
 * Conservative Update Count-Min Sketch (Cormode & Muthukrishnan, J. Algorithms 2005)
 * Maintains egress frequency and invocation tracking in an immutable 64KB static footprint.
 * Conservative update increments only the minimum counter across d hash arrays,
 * dramatically reducing overestimation error under heavy traffic.
 */
export class ConservativeCountMinSketch {
  // Static footprint: d = 4 rows, w = 4096 columns -> 16,384 32-bit integers = 65,536 bytes (64 KB)
  public static readonly DEPTH: number = 4;
  public static readonly WIDTH: number = 4096;
  public static readonly MEMORY_BYTES: number = 65536;

  private readonly table: Uint32Array;
  private readonly seeds: Uint32Array;

  constructor() {
    this.table = new Uint32Array(ConservativeCountMinSketch.DEPTH * ConservativeCountMinSketch.WIDTH);
    // 4 distinct 32-bit prime seeds for independent universal hashing
    this.seeds = new Uint32Array([0x9e3779b9, 0x85ebca6b, 0xc2b2ae35, 0x27d4eb2f]);
  }

  /**
   * MurmurHash3-inspired 32-bit integer mixer
   */
  private hash(key: string, seed: number): number {
    let h = seed;
    const len = key.length;

    for (let i = 0; i < len; i++) {
      const code = key.charCodeAt(i);
      let k = code | (code << 16);
      k = Math.imul(k, 0xcc9e2d51);
      k = (k << 15) | (k >>> 17);
      k = Math.imul(k, 0x1b873593);

      h ^= k;
      h = (h << 13) | (h >>> 19);
      h = Math.imul(h, 5) + 0xe6546b64;
    }

    h ^= len;
    h ^= h >>> 16;
    h = Math.imul(h, 0x85ebca6b);
    h ^= h >>> 13;
    h = Math.imul(h, 0xc2b2ae35);
    h ^= h >>> 16;

    return (h >>> 0) % ConservativeCountMinSketch.WIDTH;
  }

  /**
   * Conservative update: Increments only the minimum counter across the d hash rows
   */
  public update(key: string, count: number = 1): number {
    if (count <= 0) return this.estimate(key);

    const indices = new Int32Array(ConservativeCountMinSketch.DEPTH);
    let minVal = 0xffffffff;

    // 1. Locate all slots and find current minimum
    for (let row = 0; row < ConservativeCountMinSketch.DEPTH; row++) {
      const col = this.hash(key, this.seeds[row]);
      const idx = row * ConservativeCountMinSketch.WIDTH + col;
      indices[row] = idx;
      const val = this.table[idx];
      if (val < minVal) {
        minVal = val;
      }
    }

    const targetVal = minVal + count;

    // 2. Conservative update: only increase counters that do not exceed targetVal
    for (let row = 0; row < ConservativeCountMinSketch.DEPTH; row++) {
      const idx = indices[row];
      if (this.table[idx] < targetVal) {
        this.table[idx] = targetVal;
      }
    }

    return targetVal;
  }

  /**
   * Point query: Returns min_{i=0..d-1} table[i][h_i(key)]
   */
  public estimate(key: string): number {
    let minVal = 0xffffffff;

    for (let row = 0; row < ConservativeCountMinSketch.DEPTH; row++) {
      const col = this.hash(key, this.seeds[row]);
      const idx = row * ConservativeCountMinSketch.WIDTH + col;
      const val = this.table[idx];
      if (val < minVal) {
        minVal = val;
      }
    }

    return minVal === 0xffffffff ? 0 : minVal;
  }

  /**
   * Resets sketch counters to zero
   */
  public reset(): void {
    this.table.fill(0);
  }

  public getMemoryFootprintBytes(): number {
    return this.table.byteLength;
  }

  public getRawBuffer(): Uint32Array {
    return this.table;
  }
}
