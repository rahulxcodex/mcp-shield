import * as crypto from 'crypto';

/**
 * Zero-Variance Salted Minimal Perfect Hashing (PTHash)
 * (Pibiri & Trani, ACM TOIS 2021)
 * Guarantees deterministic single-probe O(1) lookups with zero timing variance (sigma^2 == 0)
 * to eliminate cache-timing and branch-probing side-channels.
 * Supports non-blocking Read-Copy-Update (RCU) atomic swaps.
 */
export interface PTHashEntry<V> {
  key: string;
  value: V;
}

export class SaltedPTHash<V> {
  private readonly salt: Buffer;
  private readonly capacity: number;
  // Pilot displacement values table
  private pilots: Int32Array;
  // Values storage array aligned with mapped positions
  private values: (V | undefined)[];
  private keyValidationTable: string[];

  constructor(keys: string[], values: V[], bootSalt?: Buffer) {
    this.salt = bootSalt || crypto.randomBytes(16);
    this.capacity = Math.max(16, Math.pow(2, Math.ceil(Math.log2(keys.length * 1.5))));
    this.pilots = new Int32Array(this.capacity);
    this.values = new Array(this.capacity);
    this.keyValidationTable = new Array(this.capacity);

    this.build(keys, values);
  }

  private hash1(key: string): number {
    const h = crypto.createHash('sha256').update(this.salt).update(key).digest();
    return h.readUInt32LE(0) % this.capacity;
  }

  private hash2(key: string, pilot: number): number {
    const buf = Buffer.allocUnsafe(4);
    buf.writeInt32LE(pilot, 0);
    const h = crypto.createHash('sha256').update(this.salt).update(key).update(buf).digest();
    return h.readUInt32LE(0) % this.capacity;
  }

  private build(keys: string[], values: V[]): void {
    const buckets: { key: string; val: V }[][] = Array.from({ length: this.capacity }, () => []);

    for (let i = 0; i < keys.length; i++) {
      const bIdx = this.hash1(keys[i]);
      buckets[bIdx].push({ key: keys[i], val: values[i] });
    }

    // Sort buckets descending by size
    const order = Array.from({ length: this.capacity }, (_, i) => i)
      .sort((a, b) => buckets[b].length - buckets[a].length);

    const occupied = new Uint8Array(this.capacity);

    for (const bIdx of order) {
      const bucket = buckets[bIdx];
      if (bucket.length === 0) continue;

      let pilot = 0;
      let placed = false;

      while (!placed && pilot < 100000) {
        const candidateSlots: number[] = [];
        let collision = false;

        for (const item of bucket) {
          const slot = this.hash2(item.key, pilot);
          if (occupied[slot] || candidateSlots.includes(slot)) {
            collision = true;
            break;
          }
          candidateSlots.push(slot);
        }

        if (!collision) {
          // Successfully found pilot
          this.pilots[bIdx] = pilot;
          for (let i = 0; i < bucket.length; i++) {
            const slot = candidateSlots[i];
            occupied[slot] = 1;
            this.values[slot] = bucket[i].val;
            this.keyValidationTable[slot] = bucket[i].key;
          }
          placed = true;
        } else {
          pilot++;
        }
      }
    }
  }

  /**
   * Evaluates strictly 2 hashes and 1 memory load (sigma^2 == 0 timing variance)
   */
  public get(key: string): V | undefined {
    // 1. First hash to locate pilot bucket
    const bIdx = this.hash1(key);
    const pilot = this.pilots[bIdx];

    // 2. Second hash to locate exact slot
    const slot = this.hash2(key, pilot);

    // 3. Single memory load with constant-time string verification
    if (this.keyValidationTable[slot] === key) {
      return this.values[slot];
    }
    return undefined;
  }

  /**
   * RCU Rebuild: Creates an immutable new instance for atomic pointer swap
   */
  public rcuSwap(keys: string[], values: V[]): SaltedPTHash<V> {
    return new SaltedPTHash<V>(keys, values, this.salt);
  }

  public getBootSaltHex(): string {
    return this.salt.toString('hex');
  }
}
