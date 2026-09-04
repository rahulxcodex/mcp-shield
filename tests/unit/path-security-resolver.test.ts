import { PathSecurityResolver } from '../../src/security/path-resolver';

describe('PathSecurityResolver (Roadmap Section 4)', () => {
  const root = PathSecurityResolver.normalize('/workspace');

  it('normalizes standard paths and removes dot segments', () => {
    expect(PathSecurityResolver.normalize('/workspace/./file')).toBe('/workspace/file');
    expect(PathSecurityResolver.normalize('/workspace//file')).toBe('/workspace/file');
    expect(PathSecurityResolver.normalize('/workspace/\\file')).toBe('/workspace/file');
  });

  it('detects and blocks classic directory traversal', () => {
    const target = PathSecurityResolver.normalize('/workspace/../etc/passwd');
    expect(target).toBe('/etc/passwd');
    expect(PathSecurityResolver.isWithin(target, root)).toBe(false);

    const policy = PathSecurityResolver.resolveForPolicy('/workspace/../etc/passwd');
    expect(policy.hasTraversalAttempt).toBe(true);
    expect(policy.violations).toContain('Directory traversal sequence detected');
  });

  it('resolves encoded traversals (%2e%2e)', () => {
    const target = PathSecurityResolver.normalize('/workspace/%2e%2e/etc/passwd');
    expect(target).toBe('/etc/passwd');
    expect(PathSecurityResolver.isWithin(target, root)).toBe(false);
  });

  it('resolves multi-encoded traversals (%252e%252e)', () => {
    const target = PathSecurityResolver.normalize('/workspace/%252e%252e/etc/passwd');
    expect(target).toBe('/etc/passwd');
    expect(PathSecurityResolver.isWithin(target, root)).toBe(false);
  });

  it('resolves Unicode separator variants', () => {
    // Unicode fullwidth solidus U+FF0F and division slash U+2215
    const unicodeSlash = '/workspace\uFF0Fsub\u2215file';
    const norm = PathSecurityResolver.normalize(unicodeSlash);
    expect(norm).toBe('/workspace/sub/file');
    expect(PathSecurityResolver.isWithin(norm, root)).toBe(true);
  });

  it('handles case-insensitivity on Windows and drive paths', () => {
    const winRoot = PathSecurityResolver.normalize('C:/workspace');
    const winTarget = PathSecurityResolver.normalize('c:/workspace/sub/file.txt');
    expect(PathSecurityResolver.isWithin(winTarget, winRoot)).toBe(true);

    const escapeTarget = PathSecurityResolver.normalize('c:/windows/system32');
    expect(PathSecurityResolver.isWithin(escapeTarget, winRoot)).toBe(false);
  });

  it('handles UNC network paths correctly', () => {
    const uncPath = PathSecurityResolver.normalize('\\\\server\\share\\data.txt');
    expect(uncPath.startsWith('//server/share/data.txt') || uncPath.startsWith('/server/share/data.txt')).toBe(true);
    expect(PathSecurityResolver.isWithin(uncPath, root)).toBe(false);
  });

  it('prevents substring prefix confusion (/workspace-secret vs /workspace)', () => {
    const secretDir = PathSecurityResolver.normalize('/workspace-secret/data');
    expect(PathSecurityResolver.isWithin(secretDir, root)).toBe(false);

    const validSubDir = PathSecurityResolver.normalize('/workspace/data');
    expect(PathSecurityResolver.isWithin(validSubDir, root)).toBe(true);
  });
});
