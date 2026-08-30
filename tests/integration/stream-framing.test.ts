import { JsonRpcStreamFramer } from '../../src/core/stream-framing';

describe('JsonRpcStreamFramer Integration & Resilience', () => {
  let framer: JsonRpcStreamFramer;

  beforeEach(() => {
    framer = new JsonRpcStreamFramer();
  });

  it('should frame a single complete newline-delimited message', (done) => {
    const message = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' });
    
    framer.on('message', (buf: Buffer) => {
      const parsed = JSON.parse(buf.toString('utf8'));
      expect(parsed).toEqual({ jsonrpc: '2.0', id: 1, method: 'ping' });
      done();
    });

    framer.append(Buffer.from(message + '\n', 'utf8'));
  });

  it('should handle byte-by-byte chunk fragmentation across split packets', (done) => {
    const payload = JSON.stringify({ jsonrpc: '2.0', id: 42, method: 'tools/list', params: { filter: 'safe' } });
    const fullBuffer = Buffer.from(payload + '\n', 'utf8');
    
    let received = false;
    framer.on('message', (buf: Buffer) => {
      const parsed = JSON.parse(buf.toString('utf8'));
      expect(parsed).toEqual({ jsonrpc: '2.0', id: 42, method: 'tools/list', params: { filter: 'safe' } });
      received = true;
    });

    // Feed 1 byte at a time
    for (let i = 0; i < fullBuffer.length; i++) {
      framer.append(fullBuffer.subarray(i, i + 1));
    }

    expect(received).toBe(true);
    done();
  });

  it('should handle high-volume burst of 100 messages packed in a single Buffer', (done) => {
    const count = 100;
    const messages: any[] = [];
    let combined = '';

    for (let i = 0; i < count; i++) {
      const msg = { jsonrpc: '2.0', id: i, method: 'call_tool', params: { name: `tool_${i}` } };
      messages.push(msg);
      combined += JSON.stringify(msg) + '\n';
    }

    const receivedMessages: any[] = [];
    framer.on('message', (buf: Buffer) => {
      receivedMessages.push(JSON.parse(buf.toString('utf8')));
      if (receivedMessages.length === count) {
        expect(receivedMessages).toEqual(messages);
        done();
      }
    });

    framer.append(Buffer.from(combined, 'utf8'));
  });

  it('should handle multi-byte UTF-8 sequences split across chunk boundaries', (done) => {
    // 🛡️ is 4 bytes in UTF-8: 0xF0 0x9F 0x9B 0xA1
    const emoji = '🛡️ Security Gateway 🔒';
    const message = JSON.stringify({ jsonrpc: '2.0', id: 99, text: emoji }) + '\n';
    const buf = Buffer.from(message, 'utf8');

    // Split right in the middle of the emoji bytes
    const splitPoint = buf.indexOf(0xF0) + 2;
    const chunk1 = buf.subarray(0, splitPoint);
    const chunk2 = buf.subarray(splitPoint);

    framer.on('message', (msgBuf: Buffer) => {
      const parsed = JSON.parse(msgBuf.toString('utf8'));
      expect(parsed.text).toBe(emoji);
      done();
    });

    framer.append(chunk1);
    framer.append(chunk2);
  });

  it('should ignore consecutive empty newlines without emitting empty frames', () => {
    const emitted: Buffer[] = [];
    framer.on('message', (buf: Buffer) => {
      emitted.push(buf);
    });

    framer.append(Buffer.from('\n\n\n{"jsonrpc":"2.0","id":1}\n\n\n', 'utf8'));
    expect(emitted.length).toBe(1);
    expect(JSON.parse(emitted[0].toString('utf8'))).toEqual({ jsonrpc: '2.0', id: 1 });
  });

  it('should emit error when frame exceeds MAX_BUFFER_SIZE (10MB) and reset buffer', (done) => {
    let errorEmitted = false;
    framer.on('error', (err: Error) => {
      expect(err.message).toContain('MAX_FRAME_SIZE_EXCEEDED');
      errorEmitted = true;
    });

    // Create a 11MB chunk without newline
    const oversizedChunk = Buffer.alloc(11 * 1024 * 1024, 65); // 11MB of 'A'
    framer.append(oversizedChunk);

    expect(errorEmitted).toBe(true);

    // Verify framer recovered and can still process valid messages
    framer.on('message', (buf: Buffer) => {
      expect(JSON.parse(buf.toString('utf8'))).toEqual({ recovered: true });
      done();
    });

    framer.append(Buffer.from('{"recovered":true}\n', 'utf8'));
  });

  it('should handle rapid alternating partial writes and burst flushes under heavy load', () => {
    const totalBatches = 50;
    const messagesPerBatch = 10;
    let totalEmitted = 0;

    framer.on('message', () => {
      totalEmitted++;
    });

    for (let b = 0; b < totalBatches; b++) {
      let batchStr = '';
      for (let m = 0; m < messagesPerBatch; m++) {
        batchStr += JSON.stringify({ batch: b, msg: m }) + '\n';
      }
      
      // Randomly split the batch string into 2-5 slices
      const sliceCount = Math.floor(Math.random() * 4) + 2;
      const sliceSize = Math.ceil(batchStr.length / sliceCount);
      
      for (let s = 0; s < sliceCount; s++) {
        const slice = batchStr.substring(s * sliceSize, (s + 1) * sliceSize);
        if (slice) {
          framer.append(Buffer.from(slice, 'utf8'));
        }
      }
    }

    expect(totalEmitted).toBe(totalBatches * messagesPerBatch);
  });

  it('should handle Windows CRLF (\\r\\n) delimited frames', (done) => {
    const payload = JSON.stringify({ jsonrpc: '2.0', id: 50, method: 'tools/list' });
    
    framer.on('message', (buf: Buffer) => {
      const parsed = JSON.parse(buf.toString('utf8'));
      expect(parsed).toEqual({ jsonrpc: '2.0', id: 50, method: 'tools/list' });
      done();
    });

    framer.append(Buffer.from(payload + '\r\n', 'utf8'));
  });

  it('should handle split CRLF across chunk boundaries (\\r in chunk 1, \\n in chunk 2)', (done) => {
    const payload = JSON.stringify({ jsonrpc: '2.0', id: 51, text: 'split-crlf' });
    const fullBuffer = Buffer.from(payload + '\r\n', 'utf8');

    // Split between \r (byte before last) and \n (last byte)
    const chunk1 = fullBuffer.subarray(0, fullBuffer.length - 1);
    const chunk2 = fullBuffer.subarray(fullBuffer.length - 1);

    framer.on('message', (buf: Buffer) => {
      const parsed = JSON.parse(buf.toString('utf8'));
      expect(parsed.text).toBe('split-crlf');
      done();
    });

    framer.append(chunk1);
    framer.append(chunk2);
  });
});
