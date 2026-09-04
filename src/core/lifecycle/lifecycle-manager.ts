import { ChildProcess, spawn } from 'child_process';
import { EventEmitter } from 'events';

export interface LifecycleConfig {
  maxRestarts?: number;
  restartWindowMs?: number;
  allowTrustOverrides?: boolean;
}

export class LifecycleManager extends EventEmitter {
  private child: ChildProcess | null = null;
  private crashTimestamps: number[] = [];
  private maxRestarts: number;
  private restartWindowMs: number;
  private circuitBreakerTripped = false;

  constructor(
    private targetCmd: string,
    private targetArgs: string[],
    config: LifecycleConfig = {}
  ) {
    super();
    this.maxRestarts = config.maxRestarts || 5;
    this.restartWindowMs = config.restartWindowMs || 60000;
  }

  public isCircuitBreakerTripped(): boolean {
    return this.circuitBreakerTripped;
  }

  public getChild(): ChildProcess | null {
    return this.child;
  }

  public static buildSafeEnv(sourceEnv: any = process.env, options: { allowTrustOverrides?: boolean } = {}): any {
    const safeEnvAllowlist = [
      'PATH', 'PATHEXT', 'SHELL', 'PWD',
      'HOME', 'USER', 'LOGNAME', 'USERNAME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH',
      'TMP', 'TEMP', 'TMPDIR',
      'LANG', 'LC_ALL', 'LC_CTYPE', 'LC_MESSAGES', 'TZ',
      ...(options.allowTrustOverrides ? ['NODE_PATH', 'SSL_CERT_FILE'] : []),
      'XDG_DATA_HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_RUNTIME_DIR',
      'XDG_DATA_DIRS', 'XDG_CONFIG_DIRS',
      'TERM', 'COLORTERM', 'FORCE_COLOR', 'NO_COLOR', 'CI',
      'SYSTEMROOT', 'WINDIR', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA',
      'PROGRAMFILES', 'PROGRAMFILES(X86)', 'COMSPEC', 'PSMODULEPATH'
    ];

    const blockedInjectionPattern = options.allowTrustOverrides
      ? /^(LD_|DYLD_|NODE_OPTIONS|NODE_EXTRA_CA_CERTS|SSL_CERT_DIR|CURL_CA_BUNDLE|REQUESTS_CA_BUNDLE|BASH_ENV|ENV|PYTHONSTARTUP|PERL5OPT|RUBYOPT|PROMPT_COMMAND)/i
      : /^(LD_|DYLD_|NODE_OPTIONS|NODE_PATH|NODE_EXTRA_CA_CERTS|SSL_CERT_FILE|SSL_CERT_DIR|CURL_CA_BUNDLE|REQUESTS_CA_BUNDLE|BASH_ENV|ENV|PYTHONSTARTUP|PERL5OPT|RUBYOPT|PROMPT_COMMAND)/i;
    const sensitiveKeyPattern = /(KEY|SECRET|TOKEN|PASSWORD|AUTH|CREDENTIAL|PRIVATE)/i;

    const safeEnv: any = {
      PYTHONUNBUFFERED: '1',
      PYTHONIOENCODING: 'utf-8'
    };

    const sourceKeys = Object.keys(sourceEnv);

    for (const allowedKey of safeEnvAllowlist) {
      if (blockedInjectionPattern.test(allowedKey) || sensitiveKeyPattern.test(allowedKey)) {
        continue;
      }

      const matchedKey = sourceKeys.find(k => k.toUpperCase() === allowedKey.toUpperCase());
      if (matchedKey && sourceEnv[matchedKey] !== undefined) {
        const val = sourceEnv[matchedKey];
        if (val !== undefined) {
          safeEnv[allowedKey] = val;
        }
      }
    }

    return safeEnv;
  }

  public start(options: { allowTrustOverrides?: boolean } = {}): ChildProcess {
    if (this.circuitBreakerTripped) {
      throw new Error('[MCP-SHIELD] CIRCUIT BREAKER TRIPPED: Subprocess crashed repeatedly. Spawning suspended.');
    }

    const safeEnv = LifecycleManager.buildSafeEnv(process.env, options);

    this.child = spawn(this.targetCmd, this.targetArgs, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: safeEnv,
      shell: false
    });

    this.child.on('exit', (code, signal) => {
      this.recordCrash();
      this.emit('exit', code, signal);
    });

    this.child.on('error', (err) => {
      this.recordCrash();
      this.emit('error', err);
    });

    return this.child;
  }

  public kill(signal: NodeJS.Signals = 'SIGKILL'): void {
    if (this.child && !this.child.killed) {
      try {
        this.child.kill(signal);
      } catch {}
    }
  }

  private recordCrash(): void {
    const now = Date.now();
    this.crashTimestamps.push(now);
    this.crashTimestamps = this.crashTimestamps.filter(t => now - t <= this.restartWindowMs);

    if (this.crashTimestamps.length > this.maxRestarts) {
      this.circuitBreakerTripped = true;
      this.emit('circuit_breaker_tripped', { crashes: this.crashTimestamps.length, windowMs: this.restartWindowMs });
    }
  }
}
