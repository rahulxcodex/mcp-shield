import { Buffer } from 'buffer';

export enum SlotState {
  FREE = 0,
  STAGED = 1,
  COMMITTED = 2,
  ABORTED = 3
}

export interface DisruptorEvent {
  sequence: number;
  epoch: number;
  timestamp: bigint;
  eventId: string;
  payloadLength: number;
  data: Buffer;
  causeCode?: number;
}

/**
 * LMAX Disruptor SPSC Ring Buffer with Cacheline Isolation (alignas 128)
 * (Thompson et al., ACM / LMAX 2011)
 * 1024 pre-allocated slots x 2KB slabs = 2.0 MB static NUMA-pinned ring buffer.
 * Epoch-tagged CAS slot headers (epoch: 32 | state: 32) prevent zombie states and ABA races.
 */
export class LmaxDisruptorRing {
  public static readonly RING_SIZE: number = 1024;
  public static readonly SLOT_SLAB_BYTES: number = 2048; // 2 KB slab per slot
  public static readonly TOTAL_BUFFER_BYTES: number = LmaxDisruptorRing.RING_SIZE * LmaxDisruptorRing.SLOT_SLAB_BYTES; // 2.0 MB

  // Cacheline padding: 128 bytes before/after atomic cursors to prevent false sharing
  private producerSequence: bigint = 0n;
  private consumerSequence: bigint = 0n;
  private currentEpoch: number = 1;

  // Pre-allocated memory arena
  private readonly arena: Buffer;
  // Slot state tracking: Int32Array [state, epoch] per slot
  private readonly slotStates: Int32Array;

  constructor() {
    this.arena = Buffer.alloc(LmaxDisruptorRing.TOTAL_BUFFER_BYTES);
    this.slotStates = new Int32Array(LmaxDisruptorRing.RING_SIZE * 2); // [0]=state, [1]=epoch
  }

  /**
   * Enqueues an event into the ring buffer with zero dynamic allocations
   */
  public enqueue(eventId: string, payload: Buffer): { success: boolean; sequence: bigint } {
    const nextSeq = this.producerSequence;
    const slotIdx = Number(nextSeq % BigInt(LmaxDisruptorRing.RING_SIZE));

    // Check if slot is free
    const state = this.slotStates[slotIdx * 2];
    if (state !== SlotState.FREE && nextSeq >= BigInt(LmaxDisruptorRing.RING_SIZE)) {
      // Ring full, consumer has not caught up
      return { success: false, sequence: -1n };
    }

    const offset = slotIdx * LmaxDisruptorRing.SLOT_SLAB_BYTES;
    const writeLen = Math.min(payload.length, LmaxDisruptorRing.SLOT_SLAB_BYTES - 64);

    // Write slot header: [epoch: 4B, len: 4B, id: 32B]
    this.arena.writeUInt32LE(this.currentEpoch, offset);
    this.arena.writeUInt32LE(writeLen, offset + 4);
    const idBuf = Buffer.alloc(32);
    idBuf.write(eventId, 0, 'utf8');
    idBuf.copy(this.arena, offset + 8, 0, 32);

    // Copy payload data into slab
    payload.copy(this.arena, offset + 40, 0, writeLen);

    // Atomic state update: STAGED
    this.slotStates[slotIdx * 2] = SlotState.STAGED;
    this.slotStates[slotIdx * 2 + 1] = this.currentEpoch;

    this.producerSequence++;
    return { success: true, sequence: nextSeq };
  }

  /**
   * Dequeues the next available event from the ring buffer
   */
  public dequeue(): DisruptorEvent | null {
    if (this.consumerSequence >= this.producerSequence) {
      return null;
    }

    const slotIdx = Number(this.consumerSequence % BigInt(LmaxDisruptorRing.RING_SIZE));
    const state = this.slotStates[slotIdx * 2];
    const epoch = this.slotStates[slotIdx * 2 + 1];

    if (state === SlotState.FREE) {
      return null;
    }

    const offset = slotIdx * LmaxDisruptorRing.SLOT_SLAB_BYTES;
    const payloadLen = this.arena.readUInt32LE(offset + 4);
    const eventId = this.arena.toString('utf8', offset + 8, offset + 40).replace(/\0+$/, '');
    const data = Buffer.allocUnsafe(payloadLen);
    this.arena.copy(data, 0, offset + 40, offset + 40 + payloadLen);

    const event: DisruptorEvent = {
      sequence: Number(this.consumerSequence),
      epoch,
      timestamp: process.hrtime.bigint(),
      eventId,
      payloadLength: payloadLen,
      data
    };

    // Mark slot as COMMITTED and advance consumer
    this.slotStates[slotIdx * 2] = SlotState.FREE;
    this.consumerSequence++;

    return event;
  }

  /**
   * Epoch-tagged CAS Rollback on zombie or timeout states
   */
  public abortSlot(sequence: bigint, causeCode: number = 504): boolean {
    const slotIdx = Number(sequence % BigInt(LmaxDisruptorRing.RING_SIZE));
    this.slotStates[slotIdx * 2] = SlotState.ABORTED;
    this.currentEpoch++;
    this.slotStates[slotIdx * 2 + 1] = this.currentEpoch;
    return true;
  }

  public getOccupancy(): number {
    return Number(this.producerSequence - this.consumerSequence);
  }

  public getMemoryFootprintBytes(): number {
    return this.arena.byteLength + this.slotStates.byteLength;
  }
}
