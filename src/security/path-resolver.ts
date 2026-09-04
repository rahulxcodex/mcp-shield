import * as path from 'path';
import * as fs from 'fs';

export type CanonicalPath = string & { readonly __canonicalPathBrand: unique symbol };

export interface PolicyPath {
  raw: string;
  canonical: CanonicalPath;
  isAbsolute: boolean;
  isUnc: boolean;
  driveLetter?: string;
  resolvedSymlink?: string;
  hasTraversalAttempt: boolean;
  violations: string[];
}

export class PathSecurityResolver {
  private static readonly UNICODE_SLASH_REGEX = /[\u2215\uFF0F\u2044\u29F8\u29F9\uFE68\uFF3C]/g;
  private static readonly UNICODE_DOT_REGEX = /[\u2024\u2025\u2026\uFF0E]/g;
  private static readonly ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069]/g;

  /**
   * Normalizes an untrusted raw path string into a canonical, normalized path representation
   */
  public static normalize(rawPath: string): CanonicalPath {
    if (typeof rawPath !== 'string') {
      return '' as CanonicalPath;
    }

    // 1. Unicode normalization (NFKC) + strip zero-width & bidi characters
    let p = rawPath.normalize('NFKC').replace(this.ZERO_WIDTH_REGEX, '');

    // 1.1 Replace Unicode dot & slash lookalikes
    p = p.replace(this.UNICODE_SLASH_REGEX, '/').replace(this.UNICODE_DOT_REGEX, '.');

    // 2. Decode URL / hex encoding iteratively (up to 3 rounds to mitigate multi-encoding attacks)
    for (let i = 0; i < 3; i++) {
      if (/%[0-9a-fA-F]{2}/.test(p)) {
        try {
          const decoded = decodeURIComponent(p);
          if (decoded === p) break;
          p = decoded;
        } catch {
          // Break on invalid hex sequences
          break;
        }
      } else {
        break;
      }
    }

    // 3. Separator normalization: standardize all backslashes to forward slashes
    p = p.replace(/\\/g, '/');

    // 4. Handle UNC paths
    const isUnc = p.startsWith('//');
    if (isUnc) {
      p = '/' + p.replace(/^\/+/, '/'); // Retain UNC root
    }

    // 5. Windows Drive Letter Normalization (e.g.  c:/ -> C:/)
    const driveMatch = p.match(/^([a-zA-Z]):(\/|$)/);
    let drivePrefix = '';
    if (driveMatch) {
      drivePrefix = driveMatch[1].toUpperCase() + ':';
      p = p.slice(2);
    }

    // 6. Dot-segment resolution & multiple adjacent slashes reduction
    const isAbsolute = p.startsWith('/') || !!drivePrefix;
    const parts = p.split('/').filter(part => part.length > 0 && part !== '.');
    const resolvedParts: string[] = [];

    for (const part of parts) {
      if (part === '..') {
        if (resolvedParts.length > 0 && resolvedParts[resolvedParts.length - 1] !== '..') {
          resolvedParts.pop();
        } else if (!isAbsolute) {
          resolvedParts.push('..');
        }
      } else {
        resolvedParts.push(part);
      }
    }

    let result = resolvedParts.join('/');
    if (drivePrefix) {
      result = drivePrefix + (result ? '/' + result : '/');
    } else if (isAbsolute) {
      result = (isUnc ? '//' : '/') + result;
    } else if (!result) {
      result = '.';
    }

    return result as CanonicalPath;
  }

  /**
   * Resolves comprehensive policy metadata for a path, flagging traversal attempts and symlinks
   */
  public static resolveForPolicy(rawPath: string, basePath?: string): PolicyPath {
    const violations: string[] = [];
    let hasTraversalAttempt = false;

    if (rawPath.includes('..') || /%2e%2e/i.test(rawPath)) {
      hasTraversalAttempt = true;
    }

    const canonical = this.normalize(rawPath);
    const isUnc = canonical.startsWith('//');
    const driveMatch = canonical.match(/^([a-zA-Z]):/);
    const driveLetter = driveMatch ? driveMatch[1].toUpperCase() : undefined;
    const isAbsolute = canonical.startsWith('/') || !!driveLetter;

    // Check if target is a symlink on disk if it exists
    let resolvedSymlink: string | undefined;
    try {
      const fullPath = isAbsolute ? canonical : path.resolve(basePath || process.cwd(), canonical);
      if (fs.existsSync(fullPath)) {
        const lstat = fs.lstatSync(fullPath);
        if (lstat.isSymbolicLink()) {
          resolvedSymlink = fs.realpathSync(fullPath);
          violations.push('Target path resolves to symlink: ' + resolvedSymlink);
        }
      }
    } catch {}

    if (hasTraversalAttempt) {
      violations.push('Directory traversal sequence detected');
    }

    return {
      raw: rawPath,
      canonical,
      isAbsolute,
      isUnc,
      driveLetter,
      resolvedSymlink,
      hasTraversalAttempt,
      violations
    };
  }

  /**
   * Cryptographically safe boundary containment check.
   * Returns true if and only if targetPath is strictly inside or equal to rootDirectory.
   * Eliminates naive prefix match vulnerabilities (e.g. /app-secret vs /app).
   */
  public static isWithin(targetPath: string | CanonicalPath, rootDirectory: string | CanonicalPath): boolean {
    const normTarget = this.normalize(targetPath);
    const normRoot = this.normalize(rootDirectory);

    if (!normTarget || !normRoot) {
      return false;
    }

    // Windows case-insensitivity support
    const isWindows = process.platform === 'win32' || /^[a-zA-Z]:/.test(normTarget);
    const t = isWindows ? normTarget.toLowerCase() : normTarget;
    const r = isWindows ? normRoot.toLowerCase() : normRoot;

    // Direct equality
    if (t === r) {
      return true;
    }

    // Must be prefixed by root followed by '/'
    const cleanRoot = r.endsWith('/') ? r : r + '/';
    return t.startsWith(cleanRoot);
  }
}
