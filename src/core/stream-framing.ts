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
  
  // Pointers for O(N) strict single-pass scanning
  private searchNode: ChunkNode | null = null;
  private searchOffset: number = 0;

  public append(chunk: Buffer) {
    const node = new ChunkNode(chunk);
    if (!this.head) {
      this.head = node;
      this.tail = node;
      this.searchNode = node;
      this.searchOffset = 0;
    } else {
      this.tail!.next = node;
      this.tail = node;
      if (!this.searchNode) {
        this.searchNode = node;
        this.searchOffset = 0;
      }
    }
    this.process();
  }

  private process() {
    // Only search starting from where we left off last time
    while (this.searchNode) {
      const idx = this.searchNode.buffer.indexOf(10, this.searchOffset); // 10 is \n
      
      if (idx === -1) {
        // Not found in this chunk. Move to next chunk to continue searching.
        this.searchNode = this.searchNode.next;
        this.searchOffset = 0;
        continue;
      }

      // We found a newline at `idx` in `this.searchNode`.
      const matchNode = this.searchNode;
      const matchIndex = idx;
      
      // Collect buffers up to the match
      const buffers: Buffer[] = [];
      let current: ChunkNode | null = this.head;
      
      while (current && current !== matchNode) {
        buffers.push(current.buffer);
        current = current.next;
      }
      
      // Slice the matchNode
      if (matchIndex > 0) {
        buffers.push(matchNode.buffer.subarray(0, matchIndex));
      }
      
      // Advance head past the matched frame
      if (matchIndex === matchNode.buffer.length - 1) {
        this.head = matchNode.next;
        if (!this.head) {
          this.tail = null;
        }
        // Update search pointers for next iteration
        this.searchNode = this.head;
        this.searchOffset = 0;
      } else {
        // Slice the remaining part of matchNode to act as the new head
        matchNode.buffer = matchNode.buffer.subarray(matchIndex + 1);
        this.head = matchNode;
        // Update search pointers
        this.searchNode = matchNode;
        this.searchOffset = 0;
      }
      
      // Combine if necessary (most of the time it's just 1 buffer, making it zero-copy)
      const lineBuffer = buffers.length === 1 ? buffers[0] : Buffer.concat(buffers);
      if (lineBuffer.length > 0) {
        this.emit('message', lineBuffer);
      }
    }
  }
}
