import { EventEmitter } from 'events';

/**
 * JsonRpcStreamFramer handles newline-delimited (\n / \r\n) JSON-RPC stream framing
 * with bounded memory safeguards (10MB max frame size) to prevent OOM/DoS.
 * Emits 'message' with each complete message Buffer.
 */
export class JsonRpcStreamFramer extends EventEmitter {
  private buffer: Buffer = Buffer.alloc(0);
  private readonly MAX_BUFFER_SIZE = 10 * 1024 * 1024; // 10MB Max Frame Size

  public append(chunk: Buffer) {
    if (this.buffer.length + chunk.length > this.MAX_BUFFER_SIZE) {
      this.buffer = Buffer.alloc(0); // Discard to prevent OOM
      this.emit('error', new Error('MAX_FRAME_SIZE_EXCEEDED: Stream frame exceeded 10MB'));
      return;
    }

    this.buffer = Buffer.concat([this.buffer, chunk]);
    this.process();
  }

  private process() {
    let newlineIndex: number;
    while ((newlineIndex = this.buffer.indexOf(10)) !== -1) { // 10 = '\n'
      let end = newlineIndex;
      if (end > 0 && this.buffer[end - 1] === 13) { // 13 = '\r'
        end--;
      }
      const frame = this.buffer.subarray(0, end);
      this.buffer = this.buffer.subarray(newlineIndex + 1);

      if (frame.length > 0) {
        this.emit('message', frame);
      }
    }
  }
}
