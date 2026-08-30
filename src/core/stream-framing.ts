import { EventEmitter } from 'events';

class ChunkNode {
  constructor(public buffer: Buffer, public next: ChunkNode | null = null) {}
}

/**
 * JsonRpcStreamFramer implements a Vectored Buffer Queue for zero-copy 
 * stream ingestion and SIMD-optimized boundary detection (looking for \n).
 * Emits 'message' with the complete message Buffer.
 */
export class JsonRpcStreamFramer extends EventEmitter {
  private head: ChunkNode | null = null;
  private tail: ChunkNode | null = null;

  public append(chunk: Buffer) {
    const node = new ChunkNode(chunk);
    if (!this.head) {
      this.head = node;
      this.tail = node;
    } else {
      this.tail!.next = node;
      this.tail = node;
    }
    this.process();
  }

  private process() {
    // Look for newline (0x0A) character
    while (this.head) {
      let found = false;
      let matchNode: ChunkNode | null = null;
      let matchIndex = -1;

      let iter: ChunkNode | null = this.head;
      while (iter) {
        const idx = iter.buffer.indexOf(10); // \n
        if (idx !== -1) {
          found = true;
          matchNode = iter;
          matchIndex = idx;
          break;
        }
        iter = iter.next;
      }

      if (!found) {
        return; // Incomplete message, wait for more chunks
      }

      // Collect buffers up to the match
      const buffers: Buffer[] = [];
      let current: ChunkNode | null = this.head;
      while (current && current !== matchNode) {
        buffers.push(current.buffer);
        current = current.next;
      }
      
      // Slice the matchNode
      if (matchIndex > 0) {
        buffers.push(matchNode!.buffer.subarray(0, matchIndex));
      }
      
      // Move head forward
      if (matchIndex === matchNode!.buffer.length - 1) {
        this.head = matchNode!.next;
        if (!this.head) this.tail = null;
      } else {
        matchNode!.buffer = matchNode!.buffer.subarray(matchIndex + 1);
        this.head = matchNode;
      }
      
      // Combine if necessary (most of the time it's just 1 buffer, making it zero-copy)
      const lineBuffer = buffers.length === 1 ? buffers[0] : Buffer.concat(buffers);
      if (lineBuffer.length > 0) {
        this.emit('message', lineBuffer);
      }
    }
  }
}
