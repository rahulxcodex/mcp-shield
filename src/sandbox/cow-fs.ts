import * as fs from 'fs';
import * as path from 'path';
import * as Diff from 'diff';
import { v4 as uuidv4 } from 'uuid';

export class COWFileSystem {
  private cowBaseDir = path.join(process.cwd(), '.mcp-shield', 'cow');
  private sessionId = uuidv4();

  constructor() {
    this.ensureSessionDir();
  }

  private ensureSessionDir() {
    const sessionDir = path.join(this.cowBaseDir, this.sessionId);
    fs.mkdirSync(sessionDir, { recursive: true });
  }

  public getSessionDir(): string {
    return path.join(this.cowBaseDir, this.sessionId);
  }

  public stageWrite(originalPath: string, newContent: string): { diff: string, stagingPath: string } {
    const absoluteOriginalPath = path.resolve(process.cwd(), originalPath);
    
    // Use a hash of the absolute path to completely prevent directory traversal (`../`) 
    // escapes out of the staging directory.
    const safeHash = require('crypto').createHash('md5').update(absoluteOriginalPath).digest('hex');
    const safeFilename = `${safeHash}_${path.basename(absoluteOriginalPath)}`;
    
    const stagingPath = path.join(this.cowBaseDir, this.sessionId, safeFilename);
    
    fs.mkdirSync(path.dirname(stagingPath), { recursive: true });
    fs.writeFileSync(stagingPath, newContent, 'utf8');

    let oldContent = '';
    if (fs.existsSync(absoluteOriginalPath)) {
      oldContent = fs.readFileSync(absoluteOriginalPath, 'utf8');
    }

    const diff = Diff.createTwoFilesPatch(
      absoluteOriginalPath,
      absoluteOriginalPath + ' (staged)',
      oldContent,
      newContent,
      'Original',
      'Staged'
    );

    return { diff, stagingPath, absoluteOriginalPath };
  }

  public commit(absoluteOriginalPath: string, stagingPath: string): void {
    const newContent = fs.readFileSync(stagingPath);
    fs.writeFileSync(absoluteOriginalPath, newContent);
    fs.unlinkSync(stagingPath);
  }

  public discard(stagingPath: string): void {
    if (fs.existsSync(stagingPath)) {
      fs.unlinkSync(stagingPath);
    }
  }
}
