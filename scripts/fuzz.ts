import { ASTAnalyzer } from '../src/security/ast-analyzer';

interface FuzzStats {
  total: number;
  adversarialTested: number;
  adversarialBlocked: number;
  benignTested: number;
  benignPassed: number;
  crashes: number;
  startTime: number;
  durationMs: number;
}

export function runAdversarialFuzzing(iterations = 2000): FuzzStats {
  const analyzer = new ASTAnalyzer();
  const stats: FuzzStats = {
    total: 0,
    adversarialTested: 0,
    adversarialBlocked: 0,
    benignTested: 0,
    benignPassed: 0,
    crashes: 0,
    startTime: Date.now(),
    durationMs: 0
  };

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

  console.log(`[MCP-SHIELD] Starting Adversarial Fuzzing Campaign (${iterations} iterations)...`);

  for (let i = 0; i < iterations; i++) {
    stats.total++;
    const isAdversarial = Math.random() < 0.7; // 70% adversarial, 30% benign

    try {
      if (isAdversarial) {
        stats.adversarialTested++;
        const wrapper = wrappers[Math.floor(Math.random() * wrappers.length)];
        const target = dangerousTargets[Math.floor(Math.random() * dangerousTargets.length)];
        const q = quotes[Math.floor(Math.random() * quotes.length)];
        const mutateVerb = (v: string) => {
          const variants = [v, `"${v}"`, `'${v}'`, `\\${v}`, `\\${v[0]}\\${v.slice(1)}`, `${v[0]}""${v.slice(1)}`];
          return variants[Math.floor(Math.random() * variants.length)];
        };
        const choice = Math.floor(Math.random() * 8);

        let cmd = '';
        if (choice === 0) {
          const flag = ['-rf', '-r -f', '-fr', '-R', '--recursive'][Math.floor(Math.random() * 5)];
          cmd = `${wrapper} ${mutateVerb('rm')} ${flag} ${q}${target}${q}`.trim();
        } else if (choice === 1) {
          const flag = ['-R 777', '-R 000', '--recursive 777'][Math.floor(Math.random() * 3)];
          cmd = `${wrapper} ${mutateVerb('chmod')} ${flag} ${q}${target}${q}`.trim();
        } else if (choice === 2) {
          const flag = ['-R root:root', '--recursive root:root'][Math.floor(Math.random() * 2)];
          cmd = `${wrapper} ${mutateVerb('chown')} ${flag} ${q}${target}${q}`.trim();
        } else if (choice === 3) {
          cmd = `${wrapper} ${mutateVerb('shred')} -u ${q}${target}${q}`.trim();
        } else if (choice === 4) {
          cmd = `${wrapper} dd if=/dev/zero of=/dev/sda bs=1M`.trim();
        } else if (choice === 5) {
          cmd = `${wrapper} mkfs.ext4 /dev/sda1`.trim();
        } else if (choice === 6) {
          const interp = ['python3', 'bash', 'sh', 'node'][Math.floor(Math.random() * 4)];
          cmd = `${wrapper} ${interp} -c "import os; os.system('rm -rf /')"`.trim();
        } else {
          const findFlag = ['-delete', '-exec rm -rf {} +', '-execdir rm -rf {} +'][Math.floor(Math.random() * 3)];
          cmd = `${wrapper} find ${target} ${findFlag}`.trim();
        }

        const result = analyzer.analyzeCommand(cmd);
        if (!result.isSafe) {
          stats.adversarialBlocked++;
        } else {
          console.error(`[FUZZ FAILURE] Adversarial evasion bypassed analyzer: "${cmd}"`);
        }
      } else {
        stats.benignTested++;
        const verb = benignVerbs[Math.floor(Math.random() * benignVerbs.length)];
        const arg = benignArgs[Math.floor(Math.random() * benignArgs.length)];
        const cmd = `${verb} ${arg}`;

        const result = analyzer.analyzeCommand(cmd);
        if (result.isSafe) {
          stats.benignPassed++;
        } else {
          console.error(`[FUZZ FALSE POSITIVE] Benign command blocked: "${cmd}" (Reason: ${result.reason})`);
        }
      }
    } catch (err: any) {
      stats.crashes++;
      console.error(`[FUZZ CRASH] Analyzer crashed on mutation #${i}: ${err.message}`);
    }
  }

  stats.durationMs = Date.now() - stats.startTime;

  console.log('====================================================');
  console.log('🎯 ADVERSARIAL FUZZING RESULTS');
  console.log('====================================================');
  console.log(`Total Mutations Tested:    ${stats.total}`);
  console.log(`Adversarial Invocations:   ${stats.adversarialTested}`);
  console.log(`Adversarial Block Rate:    ${((stats.adversarialBlocked / (stats.adversarialTested || 1)) * 100).toFixed(2)}% (${stats.adversarialBlocked}/${stats.adversarialTested})`);
  console.log(`Benign Invocations:        ${stats.benignTested}`);
  console.log(`Benign Pass Rate:          ${((stats.benignPassed / (stats.benignTested || 1)) * 100).toFixed(2)}% (${stats.benignPassed}/${stats.benignTested})`);
  console.log(`AST Parser Crashes:        ${stats.crashes}`);
  console.log(`Total Campaign Time:       ${stats.durationMs} ms (${(stats.total / (stats.durationMs / 1000)).toFixed(0)} mutations/sec)`);
  console.log('====================================================');

  return stats;
}

const count = process.argv[2] ? parseInt(process.argv[2], 10) : 2500;
const stats = runAdversarialFuzzing(count);
if (stats.adversarialBlocked !== stats.adversarialTested || stats.benignPassed !== stats.benignTested || stats.crashes > 0) {
  process.exit(1);
}
