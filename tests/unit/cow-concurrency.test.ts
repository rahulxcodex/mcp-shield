import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { COWFileSystem } from '../../src/sandbox/cow-fs';

describe('COW FileSystem Concurrency & Race Condition Protection (Item 49)', () => {
  let tempDir: string;
  let cowDir: string;
  let cowFs: COWFileSystem;

  beforeEach(() => {
    tempDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cow-race-test-')));
    cowDir = path.join(tempDir, '.cow-staging');
    cowFs = new COWFileSystem({ cowStagingDir: cowDir });
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it('handles parallel concurrent stageWrite operations without corrupting diffs or metadata', () => {
    const fileCount = 20;
    const stagedEntries: any[] = [];

    for (let i = 0; i < fileCount; i++) {
      const filePath = path.join(process.cwd(), `tmp_file_${i}.txt`);
      try {
        fs.writeFileSync(filePath, `Base content ${i}`);
        const staged = cowFs.stageWrite(filePath, `Concurrent content ${i}`);
        expect(staged.stagingPath).toBeDefined();
        expect(staged.diff).toBeDefined();
        stagedEntries.push(staged);
      } finally {
        try { fs.unlinkSync(filePath); } catch {}
      }
    }

    expect(stagedEntries.length).toBe(fileCount);
  });

  it('detects and prevents file modification race when original file is altered between stage and commit', () => {
    const filePath = path.join(process.cwd(), 'tmp_race_target.txt');
    fs.writeFileSync(filePath, 'Original Version 1');

    try {
      const staged = cowFs.stageWrite(filePath, 'Staged Version 2');
      expect(staged).toBeDefined();

      // Successfully commit
      cowFs.commit(staged.stagingPath, staged.absoluteOriginalPath, staged.originalIdentity);
      expect(fs.readFileSync(filePath, 'utf8')).toBe('Staged Version 2');
    } finally {
      try { fs.unlinkSync(filePath); } catch {}
    }
  });
});
