import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { COWFileSystem } from '../../src/sandbox/cow-fs';

describe('COWFileSystem Concurrency & TOCTOU Mutex Suite', () => {
  let tempDir: string;
  let cowFs: COWFileSystem;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cow-race-test-'));
    cowFs = new COWFileSystem(tempDir);
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it('COW-01: Blocks concurrent commit race on the identical canonical path', () => {
    const targetFile = path.join(tempDir, 'data.txt');
    fs.writeFileSync(targetFile, 'initial content', 'utf8');

    const stageA = cowFs.stageWrite(targetFile, 'content A');
    const stageB = cowFs.stageWrite(targetFile, 'content B');

    // Simulate concurrent commit attempt:
    // First commit completes
    cowFs.commit(stageA.stagingPath, stageA.absoluteOriginalPath, stageA.originalIdentity);
    expect(fs.readFileSync(targetFile, 'utf8')).toBe('content A');

    // Second commit on modified target must fail identity validation (TOCTOU)
    expect(() => {
      cowFs.commit(stageB.stagingPath, stageB.absoluteOriginalPath, stageB.originalIdentity);
    }).toThrow(/COW TOCTOU DETECTED/);
  });
});
