import { COWFileSystem } from '../../src/sandbox/cow-fs';
import * as fs from 'fs';
import * as path from 'path';

describe('COWFileSystem', () => {
  let cowFs: COWFileSystem;
  const testFile = path.join(process.cwd(), '.mcp-shield-test-file.txt');

  beforeEach(() => {
    cowFs = new COWFileSystem();
    if (fs.existsSync(testFile)) {
      fs.unlinkSync(testFile);
    }
  });

  afterEach(() => {
    if (fs.existsSync(testFile)) {
      fs.unlinkSync(testFile);
    }
  });

  it('should stage a new file and generate a patch diff', () => {
    const staged = cowFs.stageWrite(testFile, 'Hello World');
    expect(staged.diff).toBeDefined();
    expect(staged.stagingPath).toBeDefined();
    expect(fs.existsSync(staged.stagingPath)).toBe(true);
    expect(fs.readFileSync(staged.stagingPath, 'utf8')).toBe('Hello World');
    
    // Commit
    cowFs.commit(staged.stagingPath, staged.absoluteOriginalPath);
    expect(fs.existsSync(testFile)).toBe(true);
    expect(fs.readFileSync(testFile, 'utf8')).toBe('Hello World');
  });

  it('should discard a staged file', () => {
    const staged = cowFs.stageWrite(testFile, 'Discard Content');
    expect(fs.existsSync(staged.stagingPath)).toBe(true);
    
    cowFs.discard(staged.stagingPath);
    expect(fs.existsSync(staged.stagingPath)).toBe(false);
  });

  it('should prevent staging files outside the workspace root', () => {
    const outsidePath = path.resolve(process.cwd(), '../../../../outside-test.txt');
    expect(() => {
      cowFs.stageWrite(outsidePath, 'Malicious payload');
    }).toThrow(/SANDBOX ESCAPE/);

    const traversalPath = path.join(process.cwd(), '../sibling-project/file.txt');
    expect(() => {
      cowFs.stageWrite(traversalPath, 'Malicious payload');
    }).toThrow(/SANDBOX ESCAPE/);
  });
});
