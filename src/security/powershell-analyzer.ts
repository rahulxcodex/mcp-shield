import * as path from 'path';

export interface PowerShellAnalysisResult {
  isSafe: boolean;
  reason?: string;
}

export interface PSToken {
  type: 'word' | 'string' | 'variable' | 'env_var' | 'param' | 'pipe' | 'operator' | 'subexpr' | 'scriptblock' | 'redirection';
  value: string;
  raw: string;
}

export interface PSCommandNode {
  commandName: string;
  canonicalName: string;
  parameters: Map<string, string | boolean>;
  positionalArgs: string[];
  rawTokens: PSToken[];
  isDynamicInvocation: boolean;
  isDotSourced: boolean;
  isScriptBlock: boolean;
  isDotNetCall: boolean;
  dotNetClass?: string;
  dotNetMethod?: string;
}

export class PowerShellASTAnalyzer {
  private readonly MAX_RECURSION_DEPTH = 20;

  private readonly CMDLET_ALIASES: Record<string, string> = {
    'del': 'Remove-Item',
    'erase': 'Remove-Item',
    'rd': 'Remove-Item',
    'ri': 'Remove-Item',
    'rm': 'Remove-Item',
    'rmdir': 'Remove-Item',
    'remove-item': 'Remove-Item',

    'cat': 'Get-Content',
    'gc': 'Get-Content',
    'type': 'Get-Content',
    'get-content': 'Get-Content',

    'sc': 'Set-Content',
    'set-content': 'Set-Content',

    'ac': 'Add-Content',
    'add-content': 'Add-Content',

    'clc': 'Clear-Content',
    'clear-content': 'Clear-Content',

    'iwr': 'Invoke-WebRequest',
    'wget': 'Invoke-WebRequest',
    'curl': 'Invoke-WebRequest',
    'invoke-webrequest': 'Invoke-WebRequest',

    'irm': 'Invoke-RestMethod',
    'invoke-restmethod': 'Invoke-RestMethod',

    'iex': 'Invoke-Expression',
    'invoke-expression': 'Invoke-Expression',

    'icm': 'Invoke-Command',
    'invoke-command': 'Invoke-Command',

    'saps': 'Start-Process',
    'start': 'Start-Process',
    'start-process': 'Start-Process',

    'gps': 'Get-Process',
    'ps': 'Get-Process',
    'get-process': 'Get-Process',

    'kill': 'Stop-Process',
    'spps': 'Stop-Process',
    'stop-process': 'Stop-Process',

    'dir': 'Get-ChildItem',
    'ls': 'Get-ChildItem',
    'gci': 'Get-ChildItem',
    'get-childitem': 'Get-ChildItem',

    'copy': 'Copy-Item',
    'cp': 'Copy-Item',
    'cpi': 'Copy-Item',
    'copy-item': 'Copy-Item',

    'move': 'Move-Item',
    'mv': 'Move-Item',
    'mi': 'Move-Item',
    'move-item': 'Move-Item',

    'ren': 'Rename-Item',
    'rni': 'Rename-Item',
    'rename-item': 'Rename-Item',

    'set-executionpolicy': 'Set-ExecutionPolicy',
    'new-object': 'New-Object',
    'out-file': 'Out-File',
    'select-object': 'Select-Object',
    'select': 'Select-Object',
    'where-object': 'Where-Object',
    'where': 'Where-Object',
    '?': 'Where-Object',
    'foreach-object': 'ForEach-Object',
    'foreach': 'ForEach-Object',
    '%': 'ForEach-Object',
    'tee-object': 'Tee-Object',
    'tee': 'Tee-Object',
    'get-item': 'Get-Item',
    'gi': 'Get-Item'
  };

  private readonly SAFE_PIPE_TARGETS = new Set([
    'Select-Object', 'Where-Object', 'ForEach-Object', 'Tee-Object',
    'Sort-Object', 'Group-Object', 'Measure-Object', 'Out-Null',
    'Out-String', 'Format-Table', 'Format-List', 'Format-Wide', 'Format-Custom',
    'Select-String', 'Get-Member', 'Export-Csv', 'ConvertTo-Json', 'ConvertFrom-Json',
    'ConvertTo-Csv', 'ConvertFrom-Csv', 'Write-Output', 'Write-Host', 'select', 'where',
    'sort', 'measure', 'ft', 'fl', 'sls', 'echo',
    'grep', 'awk', 'sed', 'uniq', 'wc', 'cat', 'head', 'tail',
    'less', 'more', 'jq', 'cut', 'tr', 'column', 'tee', 'nl', 'fold',
    'fmt', 'expand', 'unexpand', 'paste', 'tac', 'rev', 'diff', 'comm', 'find', 'findstr', 'clip'
  ]);

  private readonly SENSITIVE_ENV_VARS = new Set([
    'aws_secret_access_key', 'aws_access_key_id', 'aws_session_token',
    'openai_api_key', 'anthropic_api_key', 'github_token', 'gh_token',
    'npm_token', 'azure_client_secret', 'jwt_secret', 'secret_key',
    'private_key', 'password', 'db_password', 'api_key', 'token'
  ]);

  public analyzeCommand(command: string, depth = 0): PowerShellAnalysisResult {
    if (!command || !command.trim()) return { isSafe: true };
    if (depth > this.MAX_RECURSION_DEPTH) {
      return { isSafe: false, reason: 'PowerShell AST recursion depth limit exceeded (DoS prevention)' };
    }

    if (command.length > 64 * 1024) {
      return { isSafe: false, reason: 'PowerShell command size exceeds 64KB safety limit' };
    }

    // 1. Check for encoded commands (powershell.exe -enc <base64> or pwsh -e <base64>)
    const encodedMatch = this.extractEncodedCommand(command);
    if (encodedMatch) {
      const decodedScript = this.decodeBase64(encodedMatch);
      if (decodedScript) {
        const decodedResult = this.analyzeCommand(decodedScript, depth + 1);
        if (!decodedResult.isSafe) {
          return {
            isSafe: false,
            reason: `Encoded PowerShell payload blocked: ${decodedResult.reason} (Decoded: "${decodedScript.slice(0, 100)}")`
          };
        }
      } else {
        return { isSafe: false, reason: 'Malformed or unparseable Base64 encoded PowerShell command blocked' };
      }
    }

    // 2. Tokenize the PowerShell script
    const tokens = this.tokenize(command);
    if (tokens.length === 0) return { isSafe: true };

    // 3. Scan for direct sensitive environment variable leaks e.g. $env:AWS_SECRET_ACCESS_KEY
    for (const token of tokens) {
      if (token.type === 'env_var') {
        const envName = token.value.toLowerCase();
        if (this.SENSITIVE_ENV_VARS.has(envName) || envName.includes('secret') || envName.includes('token') || envName.includes('key')) {
          return { isSafe: false, reason: `Direct access to sensitive environment variable "$env:${token.value}" is blocked` };
        }
      }
      if (token.type === 'word' && token.value.toLowerCase().startsWith('env:')) {
        const envName = token.value.slice(4).toLowerCase();
        if (this.SENSITIVE_ENV_VARS.has(envName) || envName.includes('secret') || envName.includes('token') || envName.includes('key')) {
          return { isSafe: false, reason: `Direct access to sensitive environment variable "${token.value}" is blocked` };
        }
      }
    }

    // 4. Parse pipelines and compound commands into AST command nodes
    const pipelines = this.splitIntoPipelines(tokens);

    for (const pipeline of pipelines) {
      const pipelineResult = this.analyzePipeline(pipeline, depth);
      if (!pipelineResult.isSafe) return pipelineResult;
    }

    return { isSafe: true };
  }

  private extractEncodedCommand(command: string): string | null {
    const regex = /(?:^|\s)(?:-encodedcommand|-enc|-ec|-e|-encoded)\s+([A-Za-z0-9+/=]{4,})/i;
    const match = regex.exec(command);
    return match ? match[1] : null;
  }

  private decodeBase64(encoded: string): string | null {
    try {
      const buf = Buffer.from(encoded, 'base64');
      const utf16 = buf.toString('utf16le');
      if (utf16 && /[a-zA-Z0-9_-]/.test(utf16) && !/[\x00-\x08\x0E-\x1F]/.test(utf16.replace(/\x00/g, ''))) {
        return utf16.replace(/\0/g, '').trim();
      }
      const utf8 = buf.toString('utf8');
      return utf8.trim();
    } catch {
      return null;
    }
  }

  public tokenize(input: string): PSToken[] {
    const tokens: PSToken[] = [];
    let i = 0;
    const len = input.length;

    while (i < len) {
      const char = input[i];

      // Skip whitespace
      if (/\s/.test(char)) {
        i++;
        continue;
      }

      // Comments: # single line or <# multi line #>
      if (char === '#') {
        while (i < len && input[i] !== '\n') i++;
        continue;
      }
      if (char === '<' && input[i + 1] === '#') {
        i += 2;
        while (i < len && !(input[i] === '#' && input[i + 1] === '>')) i++;
        i += 2;
        continue;
      }

      // Operators: |, ;, &&, ||, &, .
      if (char === '|' && input[i + 1] === '|') {
        tokens.push({ type: 'operator', value: '||', raw: '||' });
        i += 2;
        continue;
      }
      if (char === '&' && input[i + 1] === '&') {
        tokens.push({ type: 'operator', value: '&&', raw: '&&' });
        i += 2;
        continue;
      }
      if (char === '|') {
        tokens.push({ type: 'pipe', value: '|', raw: '|' });
        i++;
        continue;
      }
      if (char === ';') {
        tokens.push({ type: 'operator', value: ';', raw: ';' });
        i++;
        continue;
      }
      if (char === '&' && (i + 1 >= len || /\s/.test(input[i + 1]) || input[i + 1] === '{' || input[i + 1] === '$' || input[i + 1] === '(' || input[i + 1] === '"' || input[i + 1] === '\'')) {
        tokens.push({ type: 'operator', value: '&', raw: '&' });
        i++;
        continue;
      }

      // Dot-sourcing operator: only when at beginning of command / statement
      const isStartOfStatement = tokens.length === 0 || tokens[tokens.length - 1].type === 'operator' || tokens[tokens.length - 1].type === 'pipe';
      if (char === '.' && isStartOfStatement && (i + 1 < len && (/\s/.test(input[i + 1]) || input[i + 1] === '\\' || input[i + 1] === '/'))) {
        tokens.push({ type: 'operator', value: '.', raw: '.' });
        i++;
        continue;
      }

      // Redirections: >, >>, 2>&1, 2>, etc.
      if (char === '>' || (/\d/.test(char) && input[i + 1] === '>')) {
        let redir = char;
        i++;
        while (i < len && (input[i] === '>' || input[i] === '&' || /\d/.test(input[i]))) {
          redir += input[i];
          i++;
        }
        tokens.push({ type: 'redirection', value: redir, raw: redir });
        continue;
      }

      // ScriptBlock: { ... }
      if (char === '{') {
        let depth = 1;
        let start = i;
        i++;
        while (i < len && depth > 0) {
          if (input[i] === '{') depth++;
          else if (input[i] === '}') depth--;
          i++;
        }
        const blockContent = input.slice(start + 1, Math.max(start + 1, i - 1));
        tokens.push({ type: 'scriptblock', value: blockContent, raw: input.slice(start, i) });
        continue;
      }

      // Subexpression: $(...) or @(...)
      if ((char === '$' || char === '@') && input[i + 1] === '(') {
        const prefix = char;
        i += 2;
        let depth = 1;
        const start = i;
        while (i < len && depth > 0) {
          if (input[i] === '(') depth++;
          else if (input[i] === ')') depth--;
          i++;
        }
        const subContent = input.slice(start, Math.max(start, i - 1));
        tokens.push({ type: 'subexpr', value: subContent, raw: `${prefix}(${subContent})` });
        continue;
      }

      // Standalone parenthesized expression e.g. (Get-Command Remove-Item)
      const isPrecededBySpaceOrOp = tokens.length === 0 || i === 0 || /\s|[;|&{(]/.test(input[i - 1]);
      if (char === '(' && isPrecededBySpaceOrOp) {
        let depth = 1;
        let start = i;
        i++;
        while (i < len && depth > 0) {
          if (input[i] === '(') depth++;
          else if (input[i] === ')') depth--;
          i++;
        }
        const subContent = input.slice(start + 1, Math.max(start + 1, i - 1));
        tokens.push({ type: 'subexpr', value: subContent, raw: `(${subContent})` });
        continue;
      }

      // Environment variable: $env:VAR_NAME
      if (input.slice(i, i + 5).toLowerCase() === '$env:') {
        i += 5;
        let varName = '';
        while (i < len && /[a-zA-Z0-9_]/.test(input[i])) {
          varName += input[i];
          i++;
        }
        tokens.push({ type: 'env_var', value: varName, raw: `$env:${varName}` });
        continue;
      }

      // Variable: $VAR
      if (char === '$') {
        i++;
        let varName = '';
        while (i < len && /[a-zA-Z0-9_:]/.test(input[i])) {
          varName += input[i];
          i++;
        }
        tokens.push({ type: 'variable', value: varName, raw: `$${varName}` });
        continue;
      }

      // Strings: '...' or "..."
      if (char === '\'' || char === '"') {
        const quote = char;
        i++;
        let strVal = '';
        while (i < len && input[i] !== quote) {
          if (input[i] === '`' && quote === '"' && i + 1 < len) {
            strVal += input[i + 1];
            i += 2;
          } else {
            strVal += input[i];
            i++;
          }
        }
        if (i < len && input[i] === quote) {
          i++;
        }
        tokens.push({ type: 'string', value: strVal, raw: `${quote}${strVal}${quote}` });
        continue;
      }

      // Parameter: -ParamName or -Param:Value
      if (char === '-' && i + 1 < len && /[a-zA-Z]/.test(input[i + 1])) {
        let param = '-';
        i++;
        while (i < len && /[a-zA-Z0-9_:-]/.test(input[i])) {
          param += input[i];
          i++;
        }
        tokens.push({ type: 'param', value: param, raw: param });
        continue;
      }

      // Regular word / identifier / .NET type e.g. [System.IO.File]::Delete
      let word = '';
      while (i < len && !/[\s|;&{}()#<>"']/.test(input[i])) {
        word += input[i];
        i++;
      }
      if (word) {
        tokens.push({ type: 'word', value: word, raw: word });
      } else if (i < len) {
        tokens.push({ type: 'word', value: input[i], raw: input[i] });
        i++;
      }
    }

    return tokens;
  }

  private splitIntoPipelines(tokens: PSToken[]): PSCommandNode[][] {
    const pipelines: PSCommandNode[][] = [];
    let currentPipeline: PSCommandNode[] = [];
    let currentCmdTokens: PSToken[] = [];

    const flushCommand = () => {
      if (currentCmdTokens.length > 0) {
        const node = this.parseCommandNode(currentCmdTokens);
        currentPipeline.push(node);
        currentCmdTokens = [];
      }
    };

    const flushPipeline = () => {
      flushCommand();
      if (currentPipeline.length > 0) {
        pipelines.push(currentPipeline);
        currentPipeline = [];
      }
    };

    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      if (token.type === 'operator' && (token.value === ';' || token.value === '&&' || token.value === '||')) {
        flushPipeline();
      } else if (token.type === 'pipe') {
        flushCommand();
      } else {
        currentCmdTokens.push(token);
      }
    }

    flushPipeline();
    return pipelines;
  }

  private parseCommandNode(tokens: PSToken[]): PSCommandNode {
    let isDynamicInvocation = false;
    let isDotSourced = false;
    let isScriptBlock = false;
    let isDotNetCall = false;
    let dotNetClass: string | undefined;
    let dotNetMethod: string | undefined;

    let index = 0;

    if (tokens[index] && tokens[index].type === 'operator') {
      if (tokens[index].value === '&') {
        isDynamicInvocation = true;
        index++;
      } else if (tokens[index].value === '.') {
        isDotSourced = true;
        index++;
      }
    }

    if (index >= tokens.length) {
      return {
        commandName: '',
        canonicalName: '',
        parameters: new Map(),
        positionalArgs: [],
        rawTokens: tokens,
        isDynamicInvocation,
        isDotSourced,
        isScriptBlock: false,
        isDotNetCall: false
      };
    }

    const firstToken = tokens[index];
    let commandName = firstToken.value || '';

    if (firstToken.type === 'scriptblock') {
      isScriptBlock = true;
    } else if (firstToken.type === 'variable' || firstToken.type === 'subexpr') {
      isDynamicInvocation = true;
    }

    if (firstToken.raw && firstToken.raw.startsWith('[') && firstToken.raw.includes(']::')) {
      isDotNetCall = true;
      const parts = firstToken.raw.split(']::');
      dotNetClass = parts[0].replace(/^\[/, '');
      dotNetMethod = parts[1] ? parts[1].replace(/\(.*$/, '') : '';
    }

    index++;

    const parameters = new Map<string, string | boolean>();
    const positionalArgs: string[] = [];

    while (index < tokens.length) {
      const tok = tokens[index];
      if (tok.type === 'param') {
        const rawParam = tok.value.slice(1);
        let paramName = rawParam;
        let paramVal: string | boolean = true;

        if (rawParam.includes(':')) {
          const split = rawParam.split(':');
          paramName = split[0];
          const rawVal = split.slice(1).join(':').toLowerCase();
          paramVal = rawVal === '$false' || rawVal === 'false' || rawVal === '0' ? false : (rawVal === '$true' || rawVal === 'true' || rawVal === '1' ? true : rawVal);
        } else if (index + 1 < tokens.length && tokens[index + 1].type !== 'param' && tokens[index + 1].type !== 'pipe' && tokens[index + 1].type !== 'operator') {
          const lowerParam = paramName.toLowerCase();
          if (['recurse', 'rec', 'recur', 'r', 'force', 'fo', 'forc', 'f', 'whatif', 'wi', 'confirm', 'cf', 'verbose', 'debug'].includes(lowerParam)) {
            paramVal = true;
          } else {
            paramVal = tokens[index + 1].value;
            index++;
          }
        }
        parameters.set(this.canonicalizeParameterName(paramName), paramVal);
      } else if (tok.type === 'redirection') {
        if (index + 1 < tokens.length) {
          positionalArgs.push(tokens[index + 1].value);
          index++;
        }
      } else if (tok.type === 'env_var') {
        positionalArgs.push(`$env:${tok.value}`);
      } else if (tok.type === 'variable') {
        positionalArgs.push(`$${tok.value}`);
      } else {
        positionalArgs.push(tok.value);
      }
      index++;
    }

    const lowerCmd = (commandName || '').toLowerCase();
    const canonicalName = Object.prototype.hasOwnProperty.call(this.CMDLET_ALIASES, lowerCmd)
      ? this.CMDLET_ALIASES[lowerCmd]
      : commandName;

    return {
      commandName,
      canonicalName,
      parameters,
      positionalArgs,
      rawTokens: tokens,
      isDynamicInvocation,
      isDotSourced,
      isScriptBlock,
      isDotNetCall,
      dotNetClass,
      dotNetMethod
    };
  }

  private canonicalizeParameterName(param: string): string {
    const lower = param.toLowerCase();
    if (lower.startsWith('rec') || lower === 'r') return 'Recurse';
    if (lower.startsWith('forc') || lower.startsWith('fo') || lower === 'f') return 'Force';
    if (lower.startsWith('conf') || lower === 'cf') return 'Confirm';
    if (lower.startsWith('what') || lower === 'wi') return 'WhatIf';
    if (lower.startsWith('path') || lower.startsWith('pa') || lower === 'p') return 'Path';
    if (lower.startsWith('literal') || lower === 'lp') return 'LiteralPath';
    if (lower.startsWith('dest') || lower === 'd') return 'Destination';
    if (lower.startsWith('uri') || lower === 'u') return 'Uri';
    if (lower.startsWith('outf') || lower === 'o') return 'OutFile';
    if (lower.startsWith('file') || lower === 'filepath') return 'FilePath';
    if (lower.startsWith('arg') || lower === 'args') return 'ArgumentList';
    if (lower.startsWith('comm') || lower === 'c') return 'Command';
    if (lower.startsWith('enc') || lower === 'e' || lower === 'ec') return 'EncodedCommand';
    if (lower.startsWith('script') || lower === 'sb') return 'ScriptBlock';
    if (lower.startsWith('exec') || lower === 'ep') return 'ExecutionPolicy';
    return param;
  }

  public isDangerousTarget(rawPath: any): boolean {
    if (typeof rawPath !== 'string') return false;
    let clean = rawPath.replace(/^['"]|['"]$/g, '').trim().toLowerCase();
    if (!clean) return false;

    // Exact dangerous targets
    const DANGEROUS_EXACT = new Set([
      'c:', 'c:/', 'c:\\', 'c:/*', 'c:\\*', '*', '*.*', '/*', '\\*', '/', '\\',
      '~', '~/*', '%systemroot%', '%windir%', '%userprofile%', 'systemroot', 'windir', 'userprofile',
      '$env:systemroot', '$env:windir', '$env:userprofile', '$env:temp',
      '..', '../', '..\\', '.', './', '.\\'
    ]);
    if (DANGEROUS_EXACT.has(clean)) return true;

    // Alternate Data Streams (ADS) e.g. ::$DATA or :hidden.exe
    if (clean.includes('::$data') || /:[a-z0-9_.-]+\b/i.test(clean.replace(/^[a-z]:/i, ''))) {
      return true;
    }

    // UNC & Device paths e.g. \\127.0.0.1\c$, \\localhost, \\?\C:\, \\.\PhysicalDrive0
    if (clean.startsWith('\\\\') || clean.startsWith('//')) {
      return true;
    }

    const normalized = clean.replace(/\\/g, '/');

    // Drive roots e.g. C:, C:/, D:/*
    if (/^[a-z]:\/?\*?$/.test(normalized) || /^\/+[*]?$/.test(normalized)) {
      return true;
    }

    // Upward traversals
    if (normalized.startsWith('../') || normalized.includes('/../') || normalized.endsWith('/..')) {
      return true;
    }

    // Sensitive Windows & Unix directory roots
    const DANGEROUS_PREFIXES = [
      '/etc', '/var', '/usr', '/bin', '/sbin', '/lib', '/lib64',
      '/root', '/home', '/opt', '/srv', '/boot', '/sys', '/proc', '/dev',
      'c:/windows', 'c:/windows/system32', 'c:/program files', 'c:/program files (x86)',
      'c:/program', 'c:/progra~1', 'c:/window~1',
      'c:/users', 'c:/programdata', '%systemroot%', '%windir%', '%userprofile%',
      '$env:systemroot', '$env:windir', '$env:userprofile'
    ];

    for (const prefix of DANGEROUS_PREFIXES) {
      if (normalized === prefix || normalized === `${prefix}/*` || normalized.startsWith(`${prefix}/`)) {
        return true;
      }
    }

    // Sensitive files
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

  private analyzePipeline(pipeline: PSCommandNode[], depth: number): PowerShellAnalysisResult {
    if (pipeline.length === 0) return { isSafe: true };

    for (let i = 0; i < pipeline.length; i++) {
      const node = pipeline[i];
      const isFirst = i === 0;

      // 1. Block .NET dynamic execution & reflection
      if (node.isDotNetCall) {
        const cls = (node.dotNetClass || '').toLowerCase();
        const mtd = (node.dotNetMethod || '').toLowerCase();
        if (
          cls.includes('process') || cls.includes('assembly') || cls.includes('file') ||
          cls.includes('webclient') || cls.includes('httpclient') || cls.includes('socket')
        ) {
          return { isSafe: false, reason: `Direct .NET method call [${node.dotNetClass}]::${node.dotNetMethod} is blocked` };
        }
      }

      // 2. Block dynamic invocations with variables, subexpressions, or script blocks
      if (node.isDynamicInvocation) {
        if (node.rawTokens.some(t => t.type === 'variable' || t.type === 'subexpr')) {
          return { isSafe: false, reason: `Dynamic command invocation & variable execution is blocked: "${node.rawTokens.map(t => t.raw).join(' ')}"` };
        }
      }

      if (node.isScriptBlock) {
        const innerScript = node.commandName;
        const innerResult = this.analyzeCommand(innerScript, depth + 1);
        if (!innerResult.isSafe) {
          return { isSafe: false, reason: `Script block execution blocked: ${innerResult.reason}` };
        }
      }

      for (const tok of node.rawTokens) {
        if (tok.type === 'subexpr') {
          const subResult = this.analyzeCommand(tok.value, depth + 1);
          if (!subResult.isSafe) {
            return { isSafe: false, reason: `Subexpression $(${tok.value}) blocked: ${subResult.reason}` };
          }
          return { isSafe: false, reason: `Command substitution / subexpression is blocked: "${tok.raw}"` };
        }
      }

      // 3. Dot-sourcing .ps1 or untrusted script paths
      if (node.isDotSourced) {
        const scriptTarget = node.positionalArgs[0] || node.commandName;
        return { isSafe: false, reason: `Dot-sourcing script execution "${scriptTarget}" is blocked` };
      }

      // 4. Execution of .ps1 files directly
      if (String(node.commandName || '').toLowerCase().endsWith('.ps1')) {
        return { isSafe: false, reason: `Direct execution of PowerShell script file "${node.commandName}" is blocked` };
      }

      // 5. Evaluate canonical cmdlets
      const cmd = String(node.canonicalName || '').toLowerCase();

      // powershell.exe / pwsh unwrapping & file execution check
      if (cmd === 'powershell' || cmd === 'powershell.exe' || cmd === 'pwsh' || cmd === 'pwsh.exe') {
        const rawTokens = node.rawTokens;
        const cIndex = rawTokens.findIndex(t => t.type === 'param' && (t.value.toLowerCase() === '-c' || t.value.toLowerCase() === '-command'));
        if (cIndex !== -1 && cIndex + 1 < rawTokens.length) {
          const innerCommandStr = rawTokens.slice(cIndex + 1).map(t => t.raw).join(' ');
          const innerResult = this.analyzeCommand(innerCommandStr, depth + 1);
          if (!innerResult.isSafe) return innerResult;
        }

        const fileParam = node.parameters.get('FilePath');
        const execPolicyParam = node.parameters.get('ExecutionPolicy');

        if (execPolicyParam && (String(execPolicyParam).toLowerCase() === 'bypass' || String(execPolicyParam).toLowerCase() === 'unrestricted')) {
          return { isSafe: false, reason: `Bypassing PowerShell execution policy is blocked` };
        }

        if (fileParam && String(fileParam).toLowerCase().endsWith('.ps1')) {
          return { isSafe: false, reason: `Executing untrusted script file "${fileParam}" is blocked` };
        }

        if (node.positionalArgs.some(a => a.toLowerCase().endsWith('.ps1'))) {
          return { isSafe: false, reason: `Executing script file "${node.positionalArgs.find(a => a.toLowerCase().endsWith('.ps1'))}" is blocked` };
        }
      }

      // Invoke-Expression (iex)
      if (cmd === 'invoke-expression') {
        return { isSafe: false, reason: `Dynamic evaluation primitive "Invoke-Expression" (iex) is blocked` };
      }

      // Invoke-Command (icm)
      if (cmd === 'invoke-command') {
        return { isSafe: false, reason: `Remote / ScriptBlock evaluation "Invoke-Command" is blocked` };
      }

      // Set-ExecutionPolicy
      if (cmd === 'set-executionpolicy') {
        return { isSafe: false, reason: `Altering PowerShell execution policy is blocked` };
      }

      // New-Object (e.g. Net.WebClient)
      if (cmd === 'new-object') {
        const targetType = (node.positionalArgs[0] || '').toLowerCase();
        if (targetType.includes('net.webclient') || targetType.includes('diagnostics.process') || targetType.includes('automation')) {
          return { isSafe: false, reason: `Instantiating dangerous .NET object "${targetType}" is blocked` };
        }
      }

      // Remove-Item (del, rm, ri, rd, rmdir, erase)
      if (cmd === 'remove-item') {
        const isRecurse = node.parameters.get('Recurse') === true || node.parameters.has('Recurse');
        const isForce = node.parameters.get('Force') === true || node.parameters.has('Force');
        const pathParam = node.parameters.get('Path');
        const litPathParam = node.parameters.get('LiteralPath');
        const pathArg = typeof pathParam === 'string' ? pathParam : (typeof litPathParam === 'string' ? litPathParam : undefined);
        const allTargets = [...(pathArg ? [pathArg] : []), ...node.positionalArgs];

        const hasDangerousTarget = allTargets.some(t => this.isDangerousTarget(t));
        if (isRecurse && (hasDangerousTarget || allTargets.length === 0)) {
          return { isSafe: false, reason: `Destructive recursive deletion "Remove-Item" on root/system target blocked` };
        }
        if (hasDangerousTarget && isForce) {
          return { isSafe: false, reason: `Forced deletion of critical system target blocked` };
        }
      }

      // Start-Process (saps, start)
      if (cmd === 'start-process') {
        const fileParam = node.parameters.get('FilePath');
        const fileTarget = (typeof fileParam === 'string' ? fileParam : (node.positionalArgs[0] || '')).toLowerCase();
        if (
          fileTarget === 'powershell' || fileTarget === 'powershell.exe' ||
          fileTarget === 'pwsh' || fileTarget === 'pwsh.exe' ||
          fileTarget === 'cmd' || fileTarget === 'cmd.exe' ||
          fileTarget === 'bash' || fileTarget === 'sh'
        ) {
          return { isSafe: false, reason: `Spawning detached interpreter shell via Start-Process ("${fileTarget}") is blocked` };
        }
      }

      // Invoke-WebRequest (iwr, curl, wget) and Invoke-RestMethod (irm)
      if (cmd === 'invoke-webrequest' || cmd === 'invoke-restmethod') {
        if (pipeline.length > 1) {
          const nextNodes = pipeline.slice(i + 1);
          if (nextNodes.some(n => n.canonicalName.toLowerCase() === 'invoke-expression' || n.canonicalName.toLowerCase() === 'powershell' || n.canonicalName.toLowerCase() === 'pwsh' || n.canonicalName.toLowerCase() === 'cmd')) {
            return { isSafe: false, reason: `Piping web download (${node.canonicalName}) directly into execution is blocked` };
          }
        }
      }

      // Set-Content / Add-Content / Out-File writing to sensitive destinations
      if (cmd === 'set-content' || cmd === 'add-content' || cmd === 'out-file') {
        const pathParam = node.parameters.get('Path');
        const litPathParam = node.parameters.get('LiteralPath');
        const dest = (typeof pathParam === 'string' ? pathParam : (typeof litPathParam === 'string' ? litPathParam : (node.positionalArgs[0] || '')));
        if (this.isDangerousTarget(dest)) {
          return { isSafe: false, reason: `Writing content to protected system path "${dest}" is blocked` };
        }
      }

      // Get-Content on sensitive files or SAM/SYSTEM or env provider
      if (cmd === 'get-content') {
        const pathParam = node.parameters.get('Path');
        const litPathParam = node.parameters.get('LiteralPath');
        const target = (typeof pathParam === 'string' ? pathParam : (typeof litPathParam === 'string' ? litPathParam : (node.positionalArgs[0] || ''))).toLowerCase();
        if (
          target.includes('sam') || target.includes('system32\\config') || target.includes('system32/config') ||
          target.includes('ntds.dit') || target.includes('.aws\\credentials') || target.includes('.aws/credentials') ||
          target.includes('id_rsa') || target.includes('.ssh') || target.startsWith('env:')
        ) {
          return { isSafe: false, reason: `Reading sensitive credentials with Get-Content ("${target}") is blocked` };
        }
      }

      // Get-ChildItem env: / dir env:
      if (cmd === 'get-childitem' || cmd === 'get-item') {
        const pathParam = node.parameters.get('Path');
        const target = (typeof pathParam === 'string' ? pathParam : (node.positionalArgs[0] || '')).toLowerCase();
        if (target === 'env:' || target === 'env:\\' || target.startsWith('env:') || target.includes('env:*')) {
          return { isSafe: false, reason: `Dumping environment variables via Get-ChildItem env: is blocked` };
        }
      }

      // Pipeline validation: non-first commands in a pipe must be allowlisted safe targets
      if (!isFirst) {
        if (!this.SAFE_PIPE_TARGETS.has(node.canonicalName) && !this.SAFE_PIPE_TARGETS.has(node.commandName)) {
          return { isSafe: false, reason: `Piping to non-allowlisted PowerShell command "${node.commandName}" is blocked` };
        }
      }
    }

    return { isSafe: true };
  }
}
