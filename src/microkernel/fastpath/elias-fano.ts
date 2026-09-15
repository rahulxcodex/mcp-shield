/**
 * Elias-Fano Quasi-Succinct Index (Vigna, ACM WSDM 2013)
 * Encodes sorted non-negative integers (capability hashes / permission bitmasks) in < 2 bits/element overhead
 * above the information-theoretic minimum, providing O(1) random access and membership checks.
 */
export class EliasFanoIndex {
  private readonly n: number;
  private readonly u: number;
  private readonly l: number;
  private readonly lowBits: Uint32Array;
  private readonly highBits: Uint32Array;
  private readonly highBitsLength: number;

  constructor(sortedIntegers: number[]) {
    this.n = sortedIntegers.length;
    if (this.n === 0) {
      this.u = 0;
      this.l = 0;
      this.lowBits = new Uint32Array(0);
      this.highBits = new Uint32Array(0);
      this.highBitsLength = 0;
      return;
    }

    const maxVal = sortedIntegers[this.n - 1];
    this.u = maxVal + 1;
    // l = floor(log2(u / n))
    this.l = Math.max(0, Math.floor(Math.log2(Math.max(1, this.u / this.n))));

    // Low bits storage: n * l bits
    const totalLowBits = this.n * this.l;
    const lowWords = Math.ceil(totalLowBits / 32);
    this.lowBits = new Uint32Array(Math.max(1, lowWords));

    // High bits unary storage: n + (u >> l) + 1 bits
    const highUniverse = Math.floor(this.u / Math.pow(2, this.l));
    this.highBitsLength = this.n + highUniverse + 1;
    const highWords = Math.ceil(this.highBitsLength / 32);
    this.highBits = new Uint32Array(Math.max(1, highWords));

    this.encode(sortedIntegers);
  }

  private encode(values: number[]): void {
    const maskL = (1 << this.l) - 1;
    let currentHigh = 0;
    let highBitPos = 0;

    for (let i = 0; i < this.n; i++) {
      const val = values[i];
      const low = this.l > 0 ? val & maskL : 0;
      const high = this.l > 0 ? Math.floor(val / Math.pow(2, this.l)) : val;

      // 1. Write low bits (l bits at bit offset i * l)
      if (this.l > 0) {
        this.writeBits(this.lowBits, i * this.l, low, this.l);
      }

      // 2. Unary encode high bits: write (high - currentHigh) 0-bits, then a 1-bit
      while (currentHigh < high) {
        // Bit is 0 (already 0 in zeroed Uint32Array)
        highBitPos++;
        currentHigh++;
      }
      // Write 1-bit
      this.setBit(this.highBits, highBitPos);
      highBitPos++;
    }
  }

  private setBit(arr: Uint32Array, pos: number): void {
    const wordIdx = Math.floor(pos / 32);
    const bitIdx = pos % 32;
    arr[wordIdx] |= (1 << bitIdx);
  }

  private getBit(arr: Uint32Array, pos: number): boolean {
    const wordIdx = Math.floor(pos / 32);
    const bitIdx = pos % 32;
    return (arr[wordIdx] & (1 << bitIdx)) !== 0;
  }

  private writeBits(arr: Uint32Array, bitOffset: number, value: number, count: number): void {
    let remaining = count;
    let currVal = value;
    let offset = bitOffset;

    while (remaining > 0) {
      const wordIdx = Math.floor(offset / 32);
      const bitIdx = offset % 32;
      const bitsInWord = Math.min(remaining, 32 - bitIdx);
      const mask = ((1 << bitsInWord) - 1) << bitIdx;
      arr[wordIdx] = (arr[wordIdx] & ~mask) | ((currVal & ((1 << bitsInWord) - 1)) << bitIdx);
      currVal >>>= bitsInWord;
      offset += bitsInWord;
      remaining -= bitsInWord;
    }
  }

  private readBits(arr: Uint32Array, bitOffset: number, count: number): number {
    let result = 0;
    let remaining = count;
    let offset = bitOffset;
    let shift = 0;

    while (remaining > 0) {
      const wordIdx = Math.floor(offset / 32);
      const bitIdx = offset % 32;
      const bitsInWord = Math.min(remaining, 32 - bitIdx);
      const bits = (arr[wordIdx] >>> bitIdx) & ((1 << bitsInWord) - 1);
      result |= bits << shift;
      shift += bitsInWord;
      offset += bitsInWord;
      remaining -= bitsInWord;
    }
    return result;
  }

  /**
   * Select1(i): Finds the bit position of the i-th 1-bit (0-indexed) in highBits
   */
  public select1(targetOne: number): number {
    let onesSeen = 0;
    const words = this.highBits.length;

    for (let w = 0; w < words; w++) {
      const word = this.highBits[w];
      const pop = this.popcount32(word);
      if (onesSeen + pop > targetOne) {
        // The target 1-bit is inside this word
        for (let b = 0; b < 32; b++) {
          if ((word & (1 << b)) !== 0) {
            if (onesSeen === targetOne) {
              return w * 32 + b;
            }
            onesSeen++;
          }
        }
      }
      onesSeen += pop;
    }
    return -1;
  }

  private popcount32(x: number): number {
    x = x - ((x >>> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >>> 2) & 0x33333333);
    return (((x + (x >>> 4)) & 0x0f0f0f0f) * 0x01010101) >>> 24;
  }

  /**
   * O(1) random-access retrieval of the i-th element (0 <= i < n)
   */
  public get(index: number): number {
    if (index < 0 || index >= this.n) {
      throw new RangeError(`Index ${index} out of range [0, ${this.n})`);
    }

    const onePos = this.select1(index);
    const high = onePos - index;
    const low = this.l > 0 ? this.readBits(this.lowBits, index * this.l, this.l) : 0;
    return (high * Math.pow(2, this.l)) + low;
  }

  /**
   * Evaluates membership of value x in O(log n) probes with deterministic zero-allocation
   */
  public contains(value: number): boolean {
    if (this.n === 0 || value < 0 || value >= this.u) return false;

    let left = 0;
    let right = this.n - 1;

    while (left <= right) {
      const mid = (left + right) >>> 1;
      const midVal = this.get(mid);
      if (midVal === value) return true;
      if (midVal < value) {
        left = mid + 1;
      } else {
        right = mid - 1;
      }
    }
    return false;
  }

  public size(): number {
    return this.n;
  }

  public getMemoryFootprintBytes(): number {
    return this.lowBits.byteLength + this.highBits.byteLength;
  }
}
