import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as Diff from 'diff';

export interface FileIdentity {
  ino: number;
  dev: number;
  mode: number;
  exists: boolean;
  mtimeMs?: number;
  ctimeMs?: number;
  size?: number;
  sha256?: string;
}

export class COWFileSystem {
  private stagingRoot: string;
  private sessionId = crypto.randomUUID();
  private rootDir: string;

  constructor(private config?: any) {
    this.rootDir = fs.realpathSync(process.cwd());
    this.stagingRoot = this.config?.cowStagingDir || path.join(this.rootDir, '.mcp-shield', 'cow');
    this.ensureSessionDir();
  }

  private ensureSessionDir() {
    const sessionDir = path.join(this.stagingRoot, this.sessionId);
    fs.mkdirSync(sessionDir, { recursive: true });
  }

  public getSessionDir(): string {
    return path.join(this.stagingRoot, this.sessionId);
  }

  public stageWrite(originalPath: string, newContent: string): { diff: string; stagingPath: string; absoluteOriginalPath: string; originalIdentity: FileIdentity } {
    const resolvedPath = path.resolve(this.rootDir, originalPath);

    let canonicalTarget = resolvedPath;
    let identity: FileIdentity = { ino: 0, dev: 0, mode: 0, exists: false };
    let oldContent = '';
    
    if (fs.existsSync(resolvedPath)) {
      const lstat = fs.lstatSync(resolvedPath);
      // STRICT SYMLINK INVARIANT: Refuse symlink targets entirely for COW writes
      if (lstat.isSymbolicLink()) {
        throw new Error(`COW SECURITY VIOLATION: Symlink target "${originalPath}" is forbidden for copy-on-write staging.`);
      }

      canonicalTarget = fs.realpathSync(resolvedPath);
      const stat = fs.lstatSync(canonicalTarget);
      if (stat.isSymbolicLink()) {
        throw new Error(`COW SECURITY VIOLATION: Canonical target is a symlink: "${canonicalTarget}".`);
      }
      oldContent = fs.readFileSync(canonicalTarget, 'utf8');
      identity = {
        ino: stat.ino,
        dev: stat.dev,
        mode: stat.mode,
        exists: true,
        mtimeMs: stat.mtimeMs,
        ctimeMs: stat.ctimeMs,
        size: stat.size,
        sha256: crypto.createHash('sha256').update(oldContent).digest('hex')
      };
    }
    
    const rel = path.relative(this.rootDir, canonicalTarget);
    const isInside = rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel));
    if (!isInside) {
      throw new Error(`SANDBOX ESCAPE ATTEMPT: Target path "${originalPath}" resolves outside workspace root.`);
    }

    const safeHash = crypto.createHash('sha256').update(canonicalTarget).digest('hex');
    const stagingPath = path.join(this.stagingRoot, this.sessionId, `${safeHash}.staged`);

    fs.mkdirSync(path.dirname(stagingPath), { recursive: true });
    fs.writeFileSync(stagingPath, newContent, { encoding: 'utf8', mode: 0o600 });

    const diff = Diff.createTwoFilesPatch(
      canonicalTarget,
      canonicalTarget + ' (staged)',
      oldContent,
      newContent,
      'Original',
      'Staged'
    );

    return { diff, stagingPath, absoluteOriginalPath: canonicalTarget, originalIdentity: identity };
  }

  public commit(stagingPath: string, absoluteOriginalPath: string, originalIdentity?: FileIdentity): void {
    if (originalIdentity && originalIdentity.exists) {
      if (!fs.existsSync(absoluteOriginalPath)) {
        throw new Error('COW TOCTOU DETECTED: Original file was deleted before commit.');
      }
      const currentStat = fs.lstatSync(absoluteOriginalPath);
      if (currentStat.isSymbolicLink()) {
        throw new Error('COW TOCTOU DETECTED: Target was replaced with a symlink before commit.');
      }
      if (
        currentStat.ino !== originalIdentity.ino ||
        currentStat.dev !== originalIdentity.dev ||
        (originalIdentity.mtimeMs !== undefined && currentStat.mtimeMs !== originalIdentity.mtimeMs) ||
        (originalIdentity.ctimeMs !== undefined && currentStat.ctimeMs !== originalIdentity.ctimeMs) ||
        (originalIdentity.size !== undefined && currentStat.size !== originalIdentity.size)
      ) {
        throw new Error('COW TOCTOU DETECTED: File identity changed (inode swap or file replacement).');
      }
      if (originalIdentity.sha256 !== undefined) {
        const currentContent = fs.readFileSync(absoluteOriginalPath, 'utf8');
        const currentHash = crypto.createHash('sha256').update(currentContent).digest('hex');
        if (currentHash !== originalIdentity.sha256) {
          throw new Error('COW TOCTOU DETECTED: File identity changed (inode swap or file replacement).');
        }
      }
    } else if (originalIdentity && !originalIdentity.exists) {
      if (fs.existsSync(absoluteOriginalPath)) {
        throw new Error('COW TOCTOU DETECTED: File was created before commit by another process.');
      }
      // Ensure parent directory is safe, exists, and is strictly inside workspace
      const parentDir = path.dirname(absoluteOriginalPath);
      if (fs.existsSync(parentDir)) {
        const parentLstat = fs.lstatSync(parentDir);
        if (parentLstat.isSymbolicLink()) {
          throw new Error('COW TOCTOU DETECTED: Parent directory is a symlink.');
        }
        const canonicalParent = fs.realpathSync(parentDir);
        const rel = path.relative(this.rootDir, canonicalParent);
        const isInside = rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel));
        if (!isInside) {
          throw new Error('SANDBOX ESCAPE: Parent directory resolves outside workspace root.');
        }
      }
    }
    
    const canonicalTarget = fs.existsSync(absoluteOriginalPath) ? fs.realpathSync(absoluteOriginalPath) : absoluteOriginalPath;
    const rel = path.relative(this.rootDir, canonicalTarget);
    const isInside = rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel));
    if (!isInside) {
      throw new Error('SANDBOX ESCAPE: Cannot commit outside workspace root.');
    }

    const newContent = fs.readFileSync(stagingPath);
    
    // Atomic file replacement via temp file with immediate identity re-verification
    const tempFile = `${absoluteOriginalPath}.tmp.${crypto.randomBytes(4).toString('hex')}`;
    const fd = fs.openSync(tempFile, 'wx', originalIdentity?.exists ? originalIdentity.mode : 0o644);
    fs.writeSync(fd, newContent);
    fs.fsyncSync(fd);
    fs.closeSync(fd);

    // Final pre-rename validation
    if (fs.existsSync(absoluteOriginalPath)) {
      const finalStat = fs.lstatSync(absoluteOriginalPath);
      if (finalStat.isSymbolicLink()) {
        fs.unlinkSync(tempFile);
        throw new Error('COW TOCTOU DETECTED: Target was replaced with a symlink immediately before rename.');
      }
    }
    
    fs.renameSync(tempFile, absoluteOriginalPath);
    
    if (fs.existsSync(stagingPath)) {
      fs.unlinkSync(stagingPath);
    }
  }

  public discard(stagingPath: string): void {
    if (fs.existsSync(stagingPath)) {
      fs.unlinkSync(stagingPath);
    }
  }
}
