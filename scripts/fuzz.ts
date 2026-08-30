import fc from 'fast-check';
import * as fs from 'fs';
import * as path from 'path';
import { ASTAnalyzer } from '../src/security/ast-analyzer';

const analyzer = new ASTAnalyzer();

const dangerousVerbs = ['rm', 'shred', 'wipe', 'chmod', 'chown', 'mkfs.ext4', 'dd', 'find', 'python3', 'bash', 'source'];
const dangerousFlags = ['-rf', '-r -f', '-fr', '-R', '--recursive', '-u', '-R 777', '-c "import os; os.system(\'rm -rf /\')"', '-delete'];
const dangerousTargets = ['/', '/*', '//*', '///', '.*', '.', '..', '../..', '/etc', '/var', '/usr', '/root', '/home', '~/*', '$HOME/*'];
const wrappers = ['', 'sudo', 'sudo -u root', 'doas', 'pkexec', 'env', 'env -i', 'command', 'builtin', 'nohup', 'nice -n 5', 'stdbuf -o0', 'timeout 10s'];
const quotes = ['', '"', "'", '\\'];

const benignVerbs = ['git', 'npm', 'npx', 'cargo', 'ls', 'cat', 'echo', 'mkdir', 'touch', 'find', 'tail', 'wc'];
const benignArgs = [
  'status', 'test', 'run build', 'commit -m "fix: memory leak"', 'check',
  '-la /var/log', 'package.json | grep version', '"Hello World"',
  '-p src/utils', 'src/types.ts', '. -name "*.ts"', '-n 50 app.log'
];

const mutateVerbGenerator = fc.string().map(v => {
  if (!v) return v;
  return v;
});

const adversarialCommandArbitrary = fc.tuple(
  fc.constantFrom(...wrappers),
  fc.constantFrom(...dangerousVerbs),
  fc.constantFrom(...quotes),
  fc.constantFrom(...dangerousTargets),
  fc.integer({ min: 0, max: 7 })
).map(([wrapper, verb, q, target, choice]) => {
  const mutateVerb = (v: string) => v; // Simple for now
  
  let cmd = '';
  if (choice === 0) cmd = `${wrapper} ${mutateVerb('rm')} -rf ${q}${target}${q}`;
  else if (choice === 1) cmd = `${wrapper} ${mutateVerb('chmod')} -R 777 ${q}${target}${q}`;
  else if (choice === 2) cmd = `${wrapper} ${mutateVerb('chown')} -R root:root ${q}${target}${q}`;
  else if (choice === 3) cmd = `${wrapper} ${mutateVerb('shred')} -u ${q}${target}${q}`;
  else if (choice === 4) cmd = `${wrapper} dd if=/dev/zero of=/dev/sda bs=1M`;
  else if (choice === 5) cmd = `${wrapper} mkfs.ext4 /dev/sda1`;
  else if (choice === 6) cmd = `${wrapper} bash -c "import os; os.system('rm -rf /')"`;
  else cmd = `${wrapper} find ${target} -delete`;
  
  return cmd.trim();
});

const benignCommandArbitrary = fc.tuple(
  fc.constantFrom(...benignVerbs),
  fc.constantFrom(...benignArgs)
).map(([verb, arg]) => `${verb} ${arg}`);

console.log(`[MCP-SHIELD] Starting Property-Based Adversarial Fuzzing...`);

const seed = process.env.FUZZ_SEED ? parseInt(process.env.FUZZ_SEED, 10) : Date.now();
console.log(`Seed: ${seed}`);

try {
  fc.assert(
    fc.property(adversarialCommandArbitrary, (cmd) => {
      const result = analyzer.analyzeCommand(cmd);
      return !result.isSafe; // All adversarial commands must be blocked
    }),
    { numRuns: 1000, seed: seed }
  );
  console.log("✅ Adversarial commands blocked successfully.");

  fc.assert(
    fc.property(benignCommandArbitrary, (cmd) => {
      const result = analyzer.analyzeCommand(cmd);
      return result.isSafe; // All benign commands must pass
    }),
    { numRuns: 1000, seed: seed }
  );
  console.log("✅ Benign commands passed successfully.");
  
  process.exit(0);
} catch (e: any) {
  console.error("❌ Fuzzing failed:");
  console.error(e.message);
  
  // Persist crash
  const corpusDir = path.join(__dirname, '..', 'tests', 'security-corpus');
  fs.mkdirSync(corpusDir, { recursive: true });
  const crashFile = path.join(corpusDir, `crash-${seed}.txt`);
  fs.writeFileSync(crashFile, e.message);
  console.log(`Crash persisted to ${crashFile}`);
  
  process.exit(1);
}
