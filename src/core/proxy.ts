import { spawn, ChildProcess } from 'child_process';
import { JsonRpcStreamFramer } from './stream-framing';
import { PolicyEngine } from '../security/policy-engine';
import { ASTAnalyzer } from '../security/ast-analyzer';
import { SecretSanitizer } from '../security/sanitizer';
import { PromptBridge } from '../tui/prompt-bridge';
import { SessionLogger } from '../audit/session-logger';
import { COWFileSystem } from '../sandbox/cow-fs';

import { RateLimiter } from '../security/rate-limiter';
import { DashboardServer } from '../dashboard/server';
import { ContainerSandbox } from '../sandbox/container-sandbox';

export interface Lifecycle {
  start(): Promise<number>;
  stop(): Promise<void>;
}

export class ProxyServer implements Lifecycle {
  private child: ChildProcess | null = null;
  private inboundFramer = new JsonRpcStreamFramer();
  private outboundFramer = new JsonRpcStreamFramer();
  
  private policyEngine = new PolicyEngine();
  private astAnalyzer = new ASTAnalyzer();
  private sanitizer = new SecretSanitizer();
  private logger = new SessionLogger();
  private cowFs = new COWFileSystem();
  private rateLimiter = new RateLimiter(15, 60000); // Max 15 calls per minute per tool
  private dashboard: DashboardServer | null = null;

  constructor(
    private targetCmd: string,
    private targetArgs: string[],
    private options: { enableDashboard?: boolean } = {}
  ) {
    this.setupFramers();
  }

  private logAndBroadcast(event: any) {
    this.logger.log(event);
    if (this.dashboard) {
      this.dashboard.broadcast(event);
    }
  }

  private setupFramers() {
    this.inboundFramer.on('error', (err: Error) => {
      this.logAndBroadcast({ type: 'stream_error', stream: 'inbound', reason: err.message });
      this.sendErrorToHost(null, -32000, `STREAM ERROR: ${err.message}`);
    });

    this.outboundFramer.on('error', (err: Error) => {
      this.logAndBroadcast({ type: 'stream_error', stream: 'outbound', reason: err.message });
    });

    this.inboundFramer.on('message', async (buffer: Buffer) => {
      let message: any = null;
      try {
        const msgStr = buffer.toString('utf8');
        message = JSON.parse(msgStr);
      } catch (err) {
        this.logAndBroadcast({ type: 'parse_error', reason: 'Failed to parse JSON from inbound stream, dropping payload.' });
        this.sendErrorToHost(null, -32700, 'Parse error: Invalid JSON received');
        return;
      }

      try {
        if (message.method === 'call_tool' && message.params && message.params.name) {
          const toolName = message.params.name;
          const args = message.params.arguments || {};
          
          // Apply DLP sanitization to inbound arguments before logging or TUI bridging
          // This prevents secrets typed by the user/LLM from leaking to plaintext logs
          const sanitizedArgsStr = this.sanitizer.sanitize(JSON.stringify(args));
          const sanitizedArgs = JSON.parse(sanitizedArgsStr);
          
          this.logAndBroadcast({ type: 'tool_call_intercepted', toolName, payload: sanitizedArgs });

          // -1. Rate Limit Check (Runaway loop prevention)
          if (!this.rateLimiter.checkLimit(toolName)) {
             this.logAndBroadcast({ type: 'rate_limit_exceeded', toolName, reason: 'LLM appears to be stuck in a runaway loop.' });
             this.sendErrorToHost(message.id, -32000, `RATE LIMIT EXCEEDED: Runaway loop detected for tool '${toolName}'. Session paused.`);
             return; // Drop the request
          }

          // 0. Honey-Token DLP Check
          if (this.sanitizer.checkHoneyTokens(JSON.stringify(args))) {
             this.logAndBroadcast({ type: 'honey_token_triggered', toolName, reason: 'LLM attempted to use a decoy credential.' });
             this.sendErrorToHost(message.id, -32000, `SECURITY QUARANTINE: Honey-token accessed! Session terminated.`);
             if (this.child) { this.child.kill('SIGKILL'); }
             return;
          }
          
          // 0.5 Egress Network Firewall
          const egressCheck = this.policyEngine.checkEgress(args);
          if (egressCheck.isBlocked) {
             this.logAndBroadcast({ type: 'egress_blocked', toolName, reason: `Blocked domain access: ${egressCheck.domain}` });
             this.sendErrorToHost(message.id, -32000, `EGRESS FIREWALL BLOCKED: Unauthorized access to ${egressCheck.domain}`);
             return;
          }

          // 1. Evaluate Policy
          const securityResult = this.policyEngine.evaluateToolCall(toolName, args);
          const action = securityResult.decision;

          // 2. AST Firewall
          const isShellTool = /bash|shell|terminal|exec|run|do_cmd|cmd/i.test(toolName);
          if (isShellTool && (args.command || args.cmd)) {
             const cmd = args.command || args.cmd || '';
             const astResult = this.astAnalyzer.analyzeCommand(cmd);
             if (!astResult.isSafe) {
                this.logAndBroadcast({ type: 'ast_blocked', toolName, reason: astResult.reason });
                this.sendErrorToHost(message.id, -32000, `AST FIREWALL BLOCKED: ${astResult.reason}`);
                return;
             }
          }

          // Apply Rule Action
          if (action === 'block') {
             this.logAndBroadcast({ type: 'policy_blocked', toolName, ruleId: securityResult.ruleId, reason: securityResult.reasonCode });
             this.sendErrorToHost(message.id, -32000, `SECURITY POLICY BLOCKED: Rule '${securityResult.ruleId}' triggered.`);
             return;
          } else if (action === 'prompt') {
             const result = await PromptBridge.ask(
                `Intercepted ${toolName}`,
                `Tool: ${toolName}\nArgs: ${JSON.stringify(sanitizedArgs, null, 2)}`,
                'HIGH'
             );
             if (result.action !== 'approve') {
                this.logAndBroadcast({ type: 'user_denied', toolName, ruleId: securityResult.ruleId });
                this.sendErrorToHost(message.id, -32000, `USER DENIED: Execution rejected by human operator.`);
                return;
             }
             this.logAndBroadcast({ type: 'user_allowed', toolName, ruleId: securityResult.ruleId });
          } else if (action === 'sandbox') {
             const targetPath = args.path || args.file || args.filename || args.filepath || args.target;
             const content = args.content || args.text || args.data;
             if (targetPath && typeof content === 'string') {
                const staged = this.cowFs.stageWrite(targetPath, content);
                this.logAndBroadcast({ type: 'cow_staged', toolName, payload: staged });
                
                const result = await PromptBridge.ask(
                   `Sandbox Write: ${toolName}`,
                   `Tool: ${toolName}\nTarget: ${targetPath}`,
                   'HIGH',
                   staged.diff
                );
                if (result.action === 'approve') {
                   this.cowFs.commit(staged.stagingPath, staged.absoluteOriginalPath);
                   this.logAndBroadcast({ type: 'cow_committed', toolName, payload: { path: staged.absoluteOriginalPath } });
                   this.sendSuccessToHost(message.id, { content: [{ type: 'text', text: 'File changes approved and written.' }] });
                } else {
                   this.cowFs.discard(staged.stagingPath);
                   this.logAndBroadcast({ type: 'cow_discarded', toolName });
                   this.sendErrorToHost(message.id, -32000, 'USER DENIED: Staged file changes rejected.');
                }
                return;
             } else {
                // Fail-Closed: Do NOT fall through to unisolated execution!
                this.logAndBroadcast({ type: 'sandbox_blocked', toolName, reason: 'Sandbox write action requested but target path or content was missing.' });
                this.sendErrorToHost(message.id, -32000, 'SANDBOX POLICY BLOCKED: Missing path or content for staged execution.');
                return;
             }
          }
        }
        
        // Restore tokenized secrets in inbound tool call parameters before sending to downstream server
        if (message.method === 'call_tool') {
           const payloadStr = JSON.stringify(message.params);
           const restoredStr = this.sanitizer.restore(payloadStr);
           message.params = JSON.parse(restoredStr);
        }
        
        // Pass to child stdin
        const output = JSON.stringify(message) + '\n';
        if (this.child && this.child.stdin && this.child.stdin.writable) {
          try {
            this.child.stdin.write(output);
          } catch (writeErr: any) {
            this.logAndBroadcast({ type: 'stream_error', reason: `Failed to write to child stdin: ${writeErr.message}` });
          }
        }
      } catch (err: any) {
        this.logAndBroadcast({ type: 'internal_error', reason: err.message });
        if (message && message.id) {
          this.sendErrorToHost(message.id, -32603, `Internal Security Gateway Error: ${err.message}`);
        }
        return;
      }
    });

    this.outboundFramer.on('message', async (buffer: Buffer) => {
      try {
        const msgStr = buffer.toString('utf8');
        const message = JSON.parse(msgStr);
        
        // DLP Sanitization on outputs back to host
        if (message.result) {
           const resultStr = JSON.stringify(message.result);
           const sanitizedStr = this.sanitizer.sanitize(resultStr);
           message.result = JSON.parse(sanitizedStr);
        }
        
        const output = JSON.stringify(message) + '\n';
        try {
          process.stdout.write(output);
        } catch {}
      } catch (err) {
        this.logAndBroadcast({ type: 'parse_error', reason: 'Failed to parse JSON from outbound stream, dropping payload.' });
        return;
      }
    });
  }

  private sendErrorToHost(id: any, code: number, message: string) {
     const errorPayload = { jsonrpc: '2.0', id, error: { code, message } };
     try {
       process.stdout.write(JSON.stringify(errorPayload) + '\n');
     } catch {}
  }

  private sendSuccessToHost(id: any, result: any) {
     const successPayload = { jsonrpc: '2.0', id, result };
     try {
       process.stdout.write(JSON.stringify(successPayload) + '\n');
     } catch {}
  }

  public static buildSafeEnv(sourceEnv: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
     // Explicit Allowlist for POSIX / Linux / Ubuntu and Windows
     const safeEnvAllowlist = [
       // 1. Path & Shell Execution
       'PATH', 'PATHEXT', 'SHELL', 'PWD',
       
       // 2. User Identity & Directories
       'HOME', 'USER', 'LOGNAME', 'USERNAME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH',
       
       // 3. Temporary Storage
       'TMP', 'TEMP', 'TMPDIR',
       
       // 4. Locales, Character Encodings, Timezone
       'LANG', 'LC_ALL', 'LC_CTYPE', 'LC_MESSAGES', 'TZ',
       
       // 5. Node.js Runtime & Module Resolution
       'NODE_PATH', 'NODE_EXTRA_CA_CERTS',
       
       // 6. TLS / SSL CA Certificate Trust Stores
       'SSL_CERT_FILE', 'SSL_CERT_DIR', 'CURL_CA_BUNDLE', 'REQUESTS_CA_BUNDLE',
       
       // 7. XDG Base Directory Standard (Linux/Ubuntu)
       'XDG_DATA_HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_RUNTIME_DIR',
       'XDG_DATA_DIRS', 'XDG_CONFIG_DIRS',
       
       // 8. Terminal, TUI & Output Capabilities
       'TERM', 'COLORTERM', 'FORCE_COLOR', 'NO_COLOR', 'CI',
       
       // 9. Windows Operating System Essentials
       'SYSTEMROOT', 'WINDIR', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA',
       'PROGRAMFILES', 'PROGRAMFILES(X86)', 'COMSPEC', 'PSMODULEPATH'
     ];

     // Dangerous runtime injection vectors that MUST NEVER be inherited
     const blockedInjectionPattern = /^(LD_|DYLD_|NODE_OPTIONS|BASH_ENV|ENV|PYTHONSTARTUP|PERL5OPT|RUBYOPT|PROMPT_COMMAND)/i;
     
     // Sensitive credential patterns to reject even if somehow requested
     const sensitiveKeyPattern = /(KEY|SECRET|TOKEN|PASSWORD|AUTH|CREDENTIAL|PRIVATE)/i;

     const safeEnv: NodeJS.ProcessEnv = {
       // Safe execution defaults for child runtimes to prevent stdio deadlocks
       PYTHONUNBUFFERED: '1',
       PYTHONIOENCODING: 'utf-8'
     };

     const sourceKeys = Object.keys(sourceEnv);

     for (const allowedKey of safeEnvAllowlist) {
       // Skip if it matches injection vectors or sensitive patterns
       if (blockedInjectionPattern.test(allowedKey) || sensitiveKeyPattern.test(allowedKey)) {
         continue;
       }

       // Case-insensitive matching for cross-platform resilience
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

  public async stop(): Promise<void> {
    if (this.dashboard) {
      try { await this.dashboard.stop(); } catch {}
    }
    if (this.policyEngine) {
      try { this.policyEngine.close(); } catch {}
    }
  }

  public start(): Promise<number> {
    return new Promise((resolve, reject) => {
      if (this.options.enableDashboard || process.env.MCP_SHIELD_ENABLE_DASHBOARD === 'true') {
        this.dashboard = new DashboardServer();
        this.dashboard.start();
      }

      const config = this.policyEngine.getConfig();
      const containerConfig = (config.sandbox as any)?.container;
      const containerSandbox = new ContainerSandbox(containerConfig || {});
      const { cmd, args } = containerSandbox.spawnProcess(this.targetCmd, this.targetArgs);

      this.child = spawn(cmd, args, {
        stdio: ['pipe', 'pipe', process.stderr],
        env: ProxyServer.buildSafeEnv()
      });

      this.child.on('error', (err) => {
         console.error(`[MCP-SHIELD] Failed to spawn target process: ${err.message}`);
         this.stop();
         reject(err);
      });

      if (this.child.stdin) {
        this.child.stdin.on('error', () => {
          // Suppress EPIPE on child stdin disconnect
        });
      }

      process.stdin.on('data', (chunk: Buffer) => {
        this.inboundFramer.append(chunk);
      });

      process.stdin.on('end', () => {
        if (this.child && this.child.stdin && !this.child.stdin.destroyed && this.child.stdin.writable) {
          try {
            this.child.stdin.end();
          } catch {}
        }
      });

      if (this.child.stdout) {
        this.child.stdout.on('data', (chunk: Buffer) => {
          this.outboundFramer.append(chunk);
        });
      }

      this.child.on('exit', (code, signal) => {
        this.stop();
        if (code !== null) {
          resolve(code);
        } else if (signal === 'SIGINT') {
          resolve(130);
        } else if (signal === 'SIGTERM') {
          resolve(143);
        } else {
          resolve(1);
        }
      });

      const handleShutdown = (signal: string) => {
        if (this.child) {
          try {
            this.child.kill(signal as NodeJS.Signals);
          } catch {}
          
          // Grace period before escalating to force kill
          const killTimer = setTimeout(() => {
            try {
              if (this.child && !this.child.killed) {
                this.child.kill('SIGKILL');
              }
            } catch {}
            this.stop();
            resolve(signal === 'SIGINT' ? 130 : 143);
          }, 3000);
          killTimer.unref();
        } else {
          this.stop();
          resolve(signal === 'SIGINT' ? 130 : 143);
        }
      };

      process.on('SIGINT', () => handleShutdown('SIGINT'));
      process.on('SIGTERM', () => handleShutdown('SIGTERM'));
    });
  }
}
