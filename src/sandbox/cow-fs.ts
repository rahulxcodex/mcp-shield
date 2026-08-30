import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as Diff from 'diff';

export class COWFileSystem {
  private cowBaseDir: string;
  private sessionId = crypto.randomUUID();
  private rootDir: string;

  constructor() {
    this.rootDir = fs.realpathSync(process.cwd());
    this.cowBaseDir = path.join(this.rootDir, '.mcp-shield', 'cow');
    this.ensureSessionDir();
  }

  private ensureSessionDir() {
    const sessionDir = path.join(this.cowBaseDir, this.sessionId);
    fs.mkdirSync(sessionDir, { recursive: true });
  }

  public getSessionDir(): string {
    return path.join(this.cowBaseDir, this.sessionId);
  }

  public stageWrite(originalPath: string, newContent: string): { diff: string; stagingPath: string; absoluteOriginalPath: string } {
    const resolvedPath = path.resolve(this.rootDir, originalPath);

    // Symlink / Path traversal validation: Target must be contained within rootDir
    let canonicalTarget = resolvedPath;
    if (fs.existsSync(resolvedPath)) {
      canonicalTarget = fs.realpathSync(resolvedPath);
    }
    
    const rel = path.relative(this.rootDir, canonicalTarget);
    const isInside = rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel));
    if (!isInside) {
      throw new Error(`SANDBOX ESCAPE ATTEMPT: Target path "${originalPath}" resolves outside workspace root.`);
    }

    const safeHash = crypto.createHash('sha256').update(resolvedPath).digest('hex');
    const stagingPath = path.join(this.cowBaseDir, this.sessionId, `${safeHash}.staged`);

    fs.mkdirSync(path.dirname(stagingPath), { recursive: true });
    fs.writeFileSync(stagingPath, newContent, { encoding: 'utf8', mode: 0o600 });

    let oldContent = '';
    if (fs.existsSync(resolvedPath)) {
      oldContent = fs.readFileSync(resolvedPath, 'utf8');
    }

    const diff = Diff.createTwoFilesPatch(
      resolvedPath,
      resolvedPath + ' (staged)',
      oldContent,
      newContent,
      'Original',
      'Staged'
    );

    return { diff, stagingPath, absoluteOriginalPath: resolvedPath };
  }

  public commit(stagingPath: string, absoluteOriginalPath: string): void {
    const canonicalTarget = fs.existsSync(absoluteOriginalPath) ? fs.realpathSync(absoluteOriginalPath) : absoluteOriginalPath;
    const rel = path.relative(this.rootDir, canonicalTarget);
    const isInside = rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel));
    if (!isInside) {
      throw new Error('SANDBOX ESCAPE: Cannot commit outside workspace root.');
    }

    const newContent = fs.readFileSync(stagingPath);
    // Atomic file replacement via temp file
    const tempFile = `${absoluteOriginalPath}.tmp.${Date.now()}`;
    fs.writeFileSync(tempFile, newContent);
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
