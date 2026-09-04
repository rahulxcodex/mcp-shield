import { MODULAR_SECRET_DETECTORS, ModularSecretDetector } from '../sanitizer';

export interface SecretFinding {
  detectorName: string;
  provider: string;
  matchedSecret: string;
  offset: number;
  confidence: string;
}

export class IncrementalSecretScanner {
  private buffer: string = '';
  private totalBytesProcessed: number = 0;
  private readonly overlapSize: number;
  private detectors: ModularSecretDetector[];

  constructor(overlapSize: number = 128, customDetectors?: ModularSecretDetector[]) {
    this.overlapSize = overlapSize;
    this.detectors = customDetectors || MODULAR_SECRET_DETECTORS;
  }

  /**
   * Processes an incoming streaming chunk, retaining only the tail overlap window
   */
  public push(chunk: Uint8Array | string): SecretFinding[] {
    const chunkStr = typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
    const scanWindow = this.buffer + chunkStr;
    const windowStartOffset = this.totalBytesProcessed - this.buffer.length;

    const findings = this.scanText(scanWindow, windowStartOffset);

    // Retain only the trailing overlap window in memory for cross-chunk detection
    if (scanWindow.length > this.overlapSize) {
      this.buffer = scanWindow.slice(-this.overlapSize);
    } else {
      this.buffer = scanWindow;
    }

    this.totalBytesProcessed += chunkStr.length;
    return findings;
  }

  /**
   * Flushes any remaining secrets in the final buffer
   */
  public flush(): SecretFinding[] {
    const findings = this.scanText(this.buffer, this.totalBytesProcessed - this.buffer.length);
    this.buffer = '';
    return findings;
  }

  /**
   * Resets internal streaming state
   */
  public reset(): void {
    this.buffer = '';
    this.totalBytesProcessed = 0;
  }

  /**
   * Scans a window with all registered regexes and validators
   */
  private scanText(text: string, baseOffset: number): SecretFinding[] {
    const findings: SecretFinding[] = [];
    const seenMatches = new Set<string>();

    for (const detector of this.detectors) {
      const regex = new RegExp(detector.regex.source, 'g');
      let match: RegExpExecArray | null;

      while ((match = regex.exec(text)) !== null) {
        const rawMatch = match[0];
        if (seenMatches.has(rawMatch)) continue;

        // Run pattern-specific validator if available
        if (detector.validator && !detector.validator(rawMatch)) {
          continue;
        }

        seenMatches.add(rawMatch);
        findings.push({
          detectorName: detector.name,
          provider: detector.provider,
          matchedSecret: rawMatch,
          offset: Math.max(0, baseOffset + match.index),
          confidence: detector.confidence
        });
      }
    }

    return findings;
  }
}
