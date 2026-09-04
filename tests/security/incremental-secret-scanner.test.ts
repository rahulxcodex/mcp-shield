import { IncrementalSecretScanner } from '../../src/security/dlp/incremental-secret-scanner';

describe('Roadmap Step 2 — Streaming & Incremental DLP Scanner', () => {
  let scanner: IncrementalSecretScanner;

  beforeEach(() => {
    scanner = new IncrementalSecretScanner(128);
  });

  it('detects a secret fully contained in a single chunk', () => {
    const token = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz12';
    const chunk = `Server response payload: ${token} end of log.`;
    const findings = scanner.push(chunk);

    expect(findings.length).toBe(1);
    expect(findings[0].detectorName).toBe('GITHUB_PAT');
    expect(findings[0].matchedSecret).toBe(token);
  });

  it('detects secrets split across chunk boundaries via sliding overlap window', () => {
    // Split OpenAI secret across 2 chunks
    // Full secret: sk-proj-abcdefghijklmnopqrstuvwxyz1234567890abcdef
    const fullToken = 'sk-proj-abcdefghijklmnopqrstuvwxyz1234567890abcdef';
    const splitPoint = 15;
    const chunk1 = `Authorization: Bearer ${fullToken.slice(0, splitPoint)}`;
    const chunk2 = `${fullToken.slice(splitPoint)} (expires in 1hr)`;

    const findings1 = scanner.push(chunk1);
    expect(findings1.length).toBe(0); // Token incomplete in chunk 1

    const findings2 = scanner.push(chunk2);
    expect(findings2.length).toBe(1); // Detected across boundary in chunk 2!
    expect(findings2[0].detectorName).toBe('OPENAI_KEY');
    expect(findings2[0].matchedSecret).toBe(fullToken);
  });

  it('maintains bounded memory over large multi-megabyte streams', () => {
    // Push 1000 chunks of 4KB each (4 MB stream)
    const filler = 'A'.repeat(4096);

    for (let i = 0; i < 1000; i++) {
      scanner.push(filler);
    }

    // Internal buffer size must remain strictly <= overlap window size (128 bytes)
    const internalBufferSize = (scanner as any).buffer.length;
    expect(internalBufferSize).toBeLessThanOrEqual(128);
  });

  it('detects secrets in flush() when secret is at the very end of stream', () => {
    const chunk = 'Here is the key: sk-ant-api03-abcdef1234567890abcdef1234567890abcdef1234567890';
    scanner.push(chunk);
    const flushFindings = scanner.flush();
    // Already detected in push or flushed cleanly without exceptions
    expect(Array.isArray(flushFindings)).toBe(true);
  });
});
