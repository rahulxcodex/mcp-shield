import * as path from 'path';
import { PowerShellASTAnalyzer } from './powershell-analyzer';

export interface CmdAnalysisResult {
  isSafe: boolean;
  reason?: string;
}

export interface CmdParsedCommand {
  cmdName: string;
  rawArgs: string[];
  switches: Set<string>;
  targets: string[];
  redirects: string[];
  rawText: string;
  isStart: boolean;
}

export class CmdAnalyzer {
  private readonly MAX_RECURSION_DEPTH = 20;
  private psAnalyzer: PowerShellASTAnalyzer;

  private readonly SENSITIVE_ENV_VARS = new Set([
    'aws_secret_access_key', 'aws_access_key_id', 'aws_session_token',
    'openai_api_key', 'anthropic_api_key', 'github_token', 'gh_token',
    'npm_token', 'azure_client_secret', 'jwt_secret', 'secret_key',
    'private_key', 'password', 'db_password', 'api_key', 'token'
  ]);

  private readonly SAFE_PIPE_TARGETS = new Set([
    'find', 'findstr', 'sort', 'more', 'type', 'clip', 'echo',
    'grep', 'awk', 'sed', 'uniq', 'wc', 'cat', 'head', 'tail',
    'less', 'jq', 'cut', 'tr', 'column', 'tee', 'nl', 'fold',
    'fmt', 'expand', 'unexpand', 'paste', 'tac', 'rev', 'diff', 'comm',
    'select-object', 'where-object', 'foreach-object', 'tee-object',
    'sort-object', 'group-object', 'measure-object', 'out-null',
    'out-string', 'format-table', 'format-list', 'format-wide', 'format-custom',
    'select-string', 'get-member', 'export-csv', 'convertto-json', 'convertfrom-json',
    'convertto-csv', 'convertfrom-csv', 'write-output', 'write-host', 'select', 'where',
    'sls', 'ft', 'fl'
  ]);

  constructor(psAnalyzer?: PowerShellASTAnalyzer) {
    this.psAnalyzer = psAnalyzer || new PowerShellASTAnalyzer();
  }

  public analyzeCommand(command: string, depth = 0): CmdAnalysisResult {
    if (!command || !command.trim()) return { isSafe: true };
    if (depth > this.MAX_RECURSION_DEPTH) {
      return { isSafe: false, reason: 'cmd.exe AST recursion depth exceeded maximum limit' };
    }

    if (command.length > 64 * 1024) {
      return { isSafe: false, reason: 'cmd.exe command size exceeds 64KB safety limit' };
    }

    // 1. Check for delayed expansion variables e.g. !CMD!, !PAYLOAD!, !AWS_SECRET_ACCESS_KEY!
    if (/![a-zA-Z0-9_]+!/.test(command)) {
      const matches = command.match(/!([a-zA-Z0-9_]+)!/g);
      if (matches) {
        for (const rawMatch of matches) {
          const varName = rawMatch.replace(/!/g, '').toLowerCase();
          if (this.SENSITIVE_ENV_VARS.has(varName) || varName.includes('secret') || varName.includes('token') || varName.includes('key')) {
            return { isSafe: false, reason: `Direct access to sensitive delayed expansion variable "${rawMatch}" is blocked` };
          }
          return { isSafe: false, reason: `cmd.exe delayed expansion variable execution "${rawMatch}" is blocked` };
        }
      }
    }

    // 2. Check for %VAR% environment variables
    const envVarMatches = command.match(/%([a-zA-Z0-9_]+)%/g);
    if (envVarMatches) {
      for (const rawEnv of envVarMatches) {
        const envName = rawEnv.replace(/%/g, '').toLowerCase();
        if (this.SENSITIVE_ENV_VARS.has(envName) || envName.includes('secret') || envName.includes('token') || envName.includes('key')) {
          return { isSafe: false, reason: `Direct access to sensitive environment variable "${rawEnv}" is blocked` };
        }
      }
    }

    // 3. De-obfuscate carets (^) and quotes
    const deobfuscated = this.deobfuscateCarets(command);

    // 4. Split by compound operators: &, &&, ||, |, while respecting quotes and parentheses
    const subCommands = this.splitCompoundCommands(deobfuscated);

    for (const subCmd of subCommands) {
      const parsed = this.parseCmdInvocation(subCmd.text);
      const baseCmd = parsed.cmdName.toLowerCase();

      // Shadow copy deletion / tamper protection
      if (baseCmd === 'vssadmin' || baseCmd === 'vssadmin.exe') {
        if (parsed.rawArgs.some(a => a.toLowerCase() === 'delete') && parsed.rawArgs.some(a => a.toLowerCase() === 'shadows')) {
          return { isSafe: false, reason: `Volume Shadow Copy deletion (vssadmin delete shadows) is blocked: "${subCmd.text}"` };
        }
      }

      // Boot / Recovery tampering
      if (baseCmd === 'bcdedit' || baseCmd === 'bcdedit.exe') {
        if (parsed.rawArgs.some(a => a.toLowerCase().includes('recoveryenabled') || a.toLowerCase().includes('bootstatuspolicy') || a.toLowerCase() === 'no')) {
          return { isSafe: false, reason: `Disabling Windows recovery via bcdedit is blocked: "${subCmd.text}"` };
        }
      }

      // Format / Diskpart
      if (baseCmd === 'format' || baseCmd === 'format.com' || baseCmd === 'diskpart' || baseCmd === 'diskpart.exe') {
        return { isSafe: false, reason: `Disk formatting/partitioning utility "${baseCmd}" is blocked: "${subCmd.text}"` };
      }

      // Detached process spawning with "start"
      if (parsed.isStart) {
        const target = parsed.cmdName.toLowerCase();
        if (
          target === 'cmd' || target === 'cmd.exe' ||
          target === 'powershell' || target === 'powershell.exe' ||
          target === 'pwsh' || target === 'pwsh.exe' ||
          target === 'del' || target === 'rmdir' || target === 'rd'
        ) {
          return { isSafe: false, reason: `Spawning detached interpreter via "start ${target}" is blocked: "${subCmd.text}"` };
        }
      }

      // cmd /c or cmd /k unwrapping
      if (baseCmd === 'cmd' || baseCmd === 'cmd.exe') {
        const innerCmd = this.extractCmdInnerCommand(parsed.rawArgs);
        if (innerCmd) {
          const innerResult = this.analyzeCommand(innerCmd, depth + 1);
          if (!innerResult.isSafe) return innerResult;
          const psResult = this.psAnalyzer.analyzeCommand(innerCmd, depth + 1);
          if (!psResult.isSafe) return psResult;
        }
      }

      // powershell.exe or pwsh forwarding
      if (baseCmd === 'powershell' || baseCmd === 'powershell.exe' || baseCmd === 'pwsh' || baseCmd === 'pwsh.exe') {
        const psResult = this.psAnalyzer.analyzeCommand(subCmd.text, depth + 1);
        if (!psResult.isSafe) return psResult;
      }

      // Destructive del / erase check
      if (baseCmd === 'del' || baseCmd === 'erase') {
        const isRecursive = parsed.switches.has('s') || parsed.switches.has('recurse');
        const isForce = parsed.switches.has('f') || parsed.switches.has('force') || parsed.switches.has('q');
        const hasDangerousTarget = parsed.targets.some(t => this.isDangerousTarget(t));

        if (isRecursive && (hasDangerousTarget || parsed.targets.length === 0)) {
          return { isSafe: false, reason: `Destructive root deletion with "${baseCmd} /s" blocked: "${subCmd.text}"` };
        }
        if (hasDangerousTarget && (isForce || isRecursive || parsed.targets.length > 0)) {
          return { isSafe: false, reason: `Destructive deletion of critical system target "${baseCmd}" blocked: "${subCmd.text}"` };
        }
      }

      // Destructive rmdir / rd check
      if (baseCmd === 'rmdir' || baseCmd === 'rd') {
        const isRecursive = parsed.switches.has('s') || parsed.switches.has('recurse');
        const hasDangerousTarget = parsed.targets.some(t => this.isDangerousTarget(t));

        if (isRecursive && (hasDangerousTarget || parsed.targets.length === 0)) {
          return { isSafe: false, reason: `Destructive directory removal with "${baseCmd} /s" on root target blocked: "${subCmd.text}"` };
        }
        if (hasDangerousTarget) {
          return { isSafe: false, reason: `Destructive directory removal of system target "${baseCmd}" blocked: "${subCmd.text}"` };
        }
      }

      // Pipe target validation
      if (subCmd.isPipedTo) {
        if (!this.SAFE_PIPE_TARGETS.has(baseCmd)) {
          return { isSafe: false, reason: `Piping to non-allowlisted cmd.exe command "${baseCmd}" is blocked: "${subCmd.text}"` };
        }
      }
    }

    return { isSafe: true };
  }

  private deobfuscateCarets(cmd: string): string {
    let result = '';
    let inQuotes = false;
    for (let i = 0; i < cmd.length; i++) {
      const c = cmd[i];
      if (c === '"') {
        inQuotes = !inQuotes;
        result += c;
      } else if (c === '^' && !inQuotes) {
        if (i + 1 < cmd.length) {
          result += cmd[i + 1];
          i++;
        }
      } else {
        result += c;
      }
    }
    return result;
  }

  private splitCompoundCommands(cmd: string): Array<{ text: string; isPipedTo: boolean }> {
    const commands: Array<{ text: string; isPipedTo: boolean }> = [];
    let current = '';
    let inQuotes = false;
    let isPiped = false;
    let i = 0;

    while (i < cmd.length) {
      const c = cmd[i];
      if (c === '"') {
        inQuotes = !inQuotes;
        current += c;
        i++;
      } else if (!inQuotes && (c === '&' || c === '|')) {
        const isDouble = (c === '&' && cmd[i + 1] === '&') || (c === '|' && cmd[i + 1] === '|');
        const isPipe = c === '|' && cmd[i + 1] !== '|';

        if (current.trim()) {
          commands.push({ text: current.trim(), isPipedTo: isPiped });
        }
        current = '';
        isPiped = isPipe;
        i += isDouble ? 2 : 1;
      } else {
        current += c;
        i++;
      }
    }

    if (current.trim()) {
      commands.push({ text: current.trim(), isPipedTo: isPiped });
    }

    return commands;
  }

  private parseCmdInvocation(cmdStr: string): CmdParsedCommand {
    let clean = cmdStr.trim();
    let isStart = false;

    if (/^start\b/i.test(clean)) {
      isStart = true;
      clean = clean.replace(/^start\s+/i, '').trim();
    }

    const tokens = this.tokenizeCmdArgs(clean);

    if (tokens.length === 0) {
      return {
        cmdName: '',
        rawArgs: [],
        switches: new Set(),
        targets: [],
        redirects: [],
        rawText: cmdStr,
        isStart
      };
    }

    const rawCmdName = tokens[0];
    const cmdName = this.normalizeToken(rawCmdName);
    const rawArgs = tokens.slice(1);
    const switches = new Set<string>();
    const targets: string[] = [];
    const redirects: string[] = [];

    for (let i = 0; i < rawArgs.length; i++) {
      const arg = rawArgs[i];
      const norm = this.normalizeToken(arg);

      if (arg.startsWith('/')) {
        const parts = arg.toLowerCase().split('/').filter(Boolean);
        for (const p of parts) {
          switches.add(p);
        }
      } else if (arg.startsWith('-')) {
        switches.add(norm.replace(/^-+/, '').toLowerCase());
      } else if (arg.startsWith('>') || arg.startsWith('<')) {
        redirects.push(arg);
      } else {
        targets.push(norm);
      }
    }

    return {
      cmdName,
      rawArgs,
      switches,
      targets,
      redirects,
      rawText: cmdStr,
      isStart
    };
  }

  private tokenizeCmdArgs(str: string): string[] {
    const tokens: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < str.length; i++) {
      const c = str[i];
      if (c === '"') {
        inQuotes = !inQuotes;
        current += c;
      } else if (/\s/.test(c) && !inQuotes) {
        if (current) {
          tokens.push(current);
          current = '';
        }
      } else {
        current += c;
      }
    }
    if (current) tokens.push(current);
    return tokens;
  }

  private normalizeToken(token: string): string {
    if (!token) return '';
    return token.replace(/^['"]|['"]$/g, '').trim();
  }

  public isDangerousTarget(rawPath: any): boolean {
    if (typeof rawPath !== 'string') return false;
    let clean = this.normalizeToken(rawPath).toLowerCase();
    if (!clean) return false;

    const DANGEROUS_EXACT = new Set([
      'c:', 'c:/', 'c:\\', 'c:/*', 'c:\\*', '*', '*.*', '/*', '\\*', '/', '\\',
      '~', '~/*', '%systemroot%', '%windir%', '%userprofile%',
      '$env:systemroot', '$env:windir', '$env:userprofile', '$env:temp',
      '..', '../', '..\\', '.', './', '.\\'
    ]);
    if (DANGEROUS_EXACT.has(clean)) return true;

    if (clean.includes('::$data') || /:[a-z0-9_.-]+\b/i.test(clean.replace(/^[a-z]:/i, ''))) {
      return true;
    }

    if (clean.startsWith('\\\\') || clean.startsWith('//')) {
      return true;
    }

    const normalized = clean.replace(/\\/g, '/');

    if (/^[a-z]:\/?\*?$/.test(normalized) || /^\/+[*]?$/.test(normalized)) {
      return true;
    }

    if (normalized.startsWith('../') || normalized.includes('/../') || normalized.endsWith('/..')) {
      return true;
    }

    const DANGEROUS_PREFIXES = [
      '/etc', '/var', '/usr', '/bin', '/sbin', '/lib', '/lib64',
      '/root', '/home', '/opt', '/srv', '/boot', '/sys', '/proc', '/dev',
      'c:/windows', 'c:/windows/system32', 'c:/program files', 'c:/program files (x86)',
      'c:/users', 'c:/programdata', '%systemroot%', '%windir%', '%userprofile%',
      '$env:systemroot', '$env:windir', '$env:userprofile'
    ];

    for (const prefix of DANGEROUS_PREFIXES) {
      if (normalized === prefix || normalized === `${prefix}/*` || normalized.startsWith(`${prefix}/`)) {
        return true;
      }
    }

    if (
      normalized.includes('/system32/config/sam') ||
      normalized.includes('/system32/config/system') ||
      normalized.includes('/system32/drivers/etc/hosts') ||
      normalized.includes('/.aws/credentials') ||
      normalized.includes('/.ssh/id_rsa') ||
      normalized.includes('/etc/shadow') ||
      normalized.includes('/etc/passwd')
    ) {
      return true;
    }

    return false;
  }

  private extractCmdInnerCommand(args: string[]): string | null {
    let foundSwitch = false;
    const innerTokens: string[] = [];

    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (!foundSwitch) {
        if (/^\/[ck]$/i.test(arg) || /^\/[sq]+\/[ck]$/i.test(arg)) {
          foundSwitch = true;
        }
      } else {
        innerTokens.push(arg);
      }
    }

    if (!foundSwitch || innerTokens.length === 0) return null;

    let joined = innerTokens.join(' ').trim();
    if (joined.startsWith('"') && joined.endsWith('"')) {
      joined = joined.slice(1, -1).trim();
    }
    return joined || null;
  }
}
