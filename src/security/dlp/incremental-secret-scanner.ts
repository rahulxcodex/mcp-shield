import { MODULAR_SECRET_DETECTORS, ModularSecretDetector } from '../sanitizer';

export interface SecretFinding {
  detectorName: string;
  provider: string;
  matchedSecret: string;
  offset: number;
  confidence: string;
}

export interface CompiledDetector {
  detector: ModularSecretDetector;
  regex: RegExp;
  prefixes?: string[];
}

export class IncrementalSecretScanner {
  private buffer: string = '';
  private totalBytesProcessed: number = 0;
  private readonly overlapSize: number;
  private detectors: ModularSecretDetector[];
  private compiledDetectors: CompiledDetector[];

  constructor(overlapSize: number = 128, customDetectors?: ModularSecretDetector[]) {
    this.overlapSize = overlapSize;
    this.detectors = customDetectors || MODULAR_SECRET_DETECTORS;
    this.compiledDetectors = this.initializeCompiledDetectors(this.detectors);
  }

  private initializeCompiledDetectors(detectors: ModularSecretDetector[]): CompiledDetector[] {
    return detectors.map(detector => {
      const source = detector.regex.source;
      const flags = detector.regex.flags.includes('g') ? detector.regex.flags : detector.regex.flags + 'g';
      const regex = new RegExp(source, flags);

      // Extract literal prefix hints from regex sources for fast multi-pattern pruning
      const prefixes: string[] = [];
      if (source.includes('AKIA') || source.includes('ASIA')) prefixes.push('AKIA', 'ABIA', 'ACCA', 'ASIA');
      if (source.includes('sk-ant-')) prefixes.push('sk-ant-');
      else if (source.includes('sk-')) prefixes.push('sk-');
      if (source.includes('xox')) prefixes.push('xox');
      if (source.includes('ghp_') || source.includes('github_pat_')) prefixes.push('ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_');
      if (source.includes('AIza')) prefixes.push('AIza');
      if (source.includes('sk_live') || source.includes('sk_test')) prefixes.push('sk_live', 'sk_test', 'rk_live', 'rk_test');
      if (source.includes('PRIVATE KEY')) prefixes.push('BEGIN', 'PRIVATE KEY');
      if (source.includes('eyJh')) prefixes.push('eyJh', 'eyJb');

      return {
        detector,
        regex,
        prefixes: prefixes.length > 0 ? prefixes : undefined
      };
    });
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
   * Scans a window with pre-compiled regexes and candidate prefix pre-filtering
   */
  private scanText(text: string, baseOffset: number): SecretFinding[] {
    const findings: SecretFinding[] = [];
    const seenMatches = new Set<string>();

    for (const item of this.compiledDetectors) {
      // Fast Aho-Corasick style prefix pre-filter: skip regex if known token prefixes are absent
      if (item.prefixes && !item.prefixes.some(p => text.includes(p))) {
        continue;
      }

      const regex = item.regex;
      regex.lastIndex = 0; // Reset state for pre-compiled global RegExp
      let match: RegExpExecArray | null;

      while ((match = regex.exec(text)) !== null) {
        const rawMatch = match[0];
        if (seenMatches.has(rawMatch)) continue;

        // Run pattern-specific validator if available
        if (item.detector.validator && !item.detector.validator(rawMatch)) {
          continue;
        }

        seenMatches.add(rawMatch);
        findings.push({
          detectorName: item.detector.name,
          provider: item.detector.provider,
          matchedSecret: rawMatch,
          offset: Math.max(0, baseOffset + match.index),
          confidence: item.detector.confidence
        });
      }
    }

    return findings;
  }
}
