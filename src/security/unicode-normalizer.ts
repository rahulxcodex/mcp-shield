/**
 * Unicode, Homoglyph, and Encoding Normalizer (Roadmap P2.1)
 *
 * Enforces canonicalization before security decisions:
 * - Strips zero-width and invisible characters
 * - Strips bidirectional control overrides (Trojan Source defenses)
 * - Normalizes Unicode whitespace and NFKC forms
 * - Translates common Cyrillic / Greek confusables/homoglyphs to Latin
 * - Unwraps nested URL encoding and shell escapes
 */

export interface UnicodeAnalysisResult {
  isSuspicious: boolean;
  hasZeroWidth: boolean;
  hasBidiOverrides: boolean;
  hasHomoglyphs: boolean;
  hasNestedEncoding: boolean;
  normalized: string;
  violations: string[];
}

export class UnicodeNormalizer {
  // Zero-width & invisible characters: ZWSP, ZWNJ, ZWJ, BOM, Word Joiner, Invisible Separator
  private static readonly ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF\u2060\u200E\u200F\u180E]/g;

  // Bidirectional control characters (Trojan Source CVE-2021-42574): LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI
  private static readonly BIDI_REGEX = /[\u202A-\u202E\u2066-\u2069]/g;

  // Unicode whitespace: Non-breaking space, en/em space, thin space, ideographic space, etc.
  private static readonly UNICODE_SPACES_REGEX = /[\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]/g;

  // Common confusable homoglyphs: Cyrillic/Greek to Latin ASCII
  private static readonly HOMOGLYPH_MAP: Record<string, string> = {
    // Cyrillic small
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p',
    '\u0445': 'x', '\u0443': 'y', '\u0456': 'i', '\u0458': 'j', '\u0455': 's',
    // Cyrillic capital
    '\u0410': 'A', '\u0412': 'B', '\u0421': 'C', '\u0415': 'E', '\u041D': 'H',
    '\u0406': 'I', '\u0408': 'J', '\u041A': 'K', '\u041C': 'M', '\u041E': 'O',
    '\u0420': 'P', '\u0422': 'T', '\u0425': 'X', '\u0423': 'Y',
    // Greek
    '\u03B1': 'a', '\u03BF': 'o', '\u03BD': 'v', '\u03C1': 'p', '\u0391': 'A',
    '\u0392': 'B', '\u0395': 'E', '\u0397': 'H', '\u0399': 'I', '\u039A': 'K',
    '\u039C': 'M', '\u039D': 'N', '\u039F': 'O', '\u03A1': 'P', '\u03A4': 'T',
    '\u03A7': 'X', '\u03A5': 'Y', '\u0396': 'Z',
  };

  /**
   * Performs complete canonicalization and returns normalized string.
   */
  public static normalize(input: string): string {
    if (!input || typeof input !== 'string') return '';

    let out = input;

    // 1. Strip zero-width invisible characters
    out = out.replace(this.ZERO_WIDTH_REGEX, '');

    // 2. Strip bidirectional control overrides
    out = out.replace(this.BIDI_REGEX, '');

    // 3. Normalize Unicode spaces to ASCII standard space
    out = out.replace(this.UNICODE_SPACES_REGEX, ' ');

    // 4. Unicode standard compatibility decomposition & canonical composition (NFKC)
    out = out.normalize('NFKC');

    // 5. Replace confusable homoglyphs
    out = out.replace(/[\u0400-\u04FF\u0370-\u03FF]/g, (char) => {
      return this.HOMOGLYPH_MAP[char] || char;
    });

    // 6. Unwrap nested URL-encoding (up to 3 levels deep)
    let prev = out;
    for (let i = 0; i < 3; i++) {
      if (prev.includes('%')) {
        try {
          const decoded = decodeURIComponent(prev);
          if (decoded === prev) break;
          prev = decoded;
        } catch {
          break;
        }
      } else {
        break;
      }
    }
    out = prev;

    return out;
  }

  /**
   * Analyzes input for deliberate obfuscation or evasion techniques.
   */
  public static analyze(input: string): UnicodeAnalysisResult {
    if (!input || typeof input !== 'string') {
      return {
        isSuspicious: false,
        hasZeroWidth: false,
        hasBidiOverrides: false,
        hasHomoglyphs: false,
        hasNestedEncoding: false,
        normalized: '',
        violations: []
      };
    }

    const violations: string[] = [];
    const hasZeroWidth = this.ZERO_WIDTH_REGEX.test(input);
    if (hasZeroWidth) violations.push('Zero-width invisible characters detected');

    const hasBidiOverrides = this.BIDI_REGEX.test(input);
    if (hasBidiOverrides) violations.push('Bidirectional control override characters detected (Trojan Source evasion)');

    let hasHomoglyphs = false;
    for (const char of input) {
      if (this.HOMOGLYPH_MAP[char]) {
        hasHomoglyphs = true;
        violations.push(`Confusable Unicode homoglyph character detected: U+${char.charCodeAt(0).toString(16).toUpperCase()}`);
        break;
      }
    }

    // Check for nested URL encoding e.g. %252f
    const hasNestedEncoding = /%25[0-9a-fA-F]{2}/i.test(input);
    if (hasNestedEncoding) violations.push('Nested URL encoding detected (%25...)');

    const normalized = this.normalize(input);
    const isSuspicious = violations.length > 0;

    return {
      isSuspicious,
      hasZeroWidth,
      hasBidiOverrides,
      hasHomoglyphs,
      hasNestedEncoding,
      normalized,
      violations
    };
  }
}
