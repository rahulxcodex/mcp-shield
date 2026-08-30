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

export class ProxyServer {
  private child: ChildProcess | null = null;
  private inboundFramer = new JsonRpcStreamFramer();
  private outboundFramer = new JsonRpcStreamFramer();
  
  private policyEngine = new PolicyEngine();
  private astAnalyzer = new ASTAnalyzer();
  private sanitizer = new SecretSanitizer();
  private logger = new SessionLogger();
  private cowFs = new COWFileSystem();
  private rateLimiter = new RateLimiter(15, 60000); // Max 15 calls per minute per tool
  private dashboard = new DashboardServer();

  constructor(private targetCmd: string, private targetArgs: string[]) {
    this.setupFramers();
    this.dashboard.start();
  }

  private logAndBroadcast(event: any) {
    this.logger.log(event);
    this.dashboard.broadcast(event);
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
             this.stop();
             process.exit(1);
          }
          
          // 0.5 Egress Network Firewall
          const egressCheck = this.policyEngine.checkEgress(args);
          if (egressCheck.isBlocked) {
             this.logAndBroadcast({ type: 'egress_blocked', toolName, reason: `Blocked domain access: ${egressCheck.domain}` });
             this.sendErrorToHost(message.id, -32000, `EGRESS FIREWALL BLOCKED: Unauthorized access to ${egressCheck.domain}`);
             return;
          }

          // 1. Evaluate Policy
          const { action, rule } = this.policyEngine.evaluateToolCall(toolName, args);

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
             this.logAndBroadcast({ type: 'policy_blocked', toolName, ruleId: rule?.id, reason: rule?.name });
             this.sendErrorToHost(message.id, -32000, `SECURITY POLICY BLOCKED: Rule '${rule?.name}' triggered.`);
             return;
          } else if (action === 'prompt') {
             const result = await PromptBridge.ask(
                `Intercepted ${toolName}`,
                `Tool: ${toolName}\nArgs: ${JSON.stringify(sanitizedArgs, null, 2)}`,
                rule?.riskLevel || 'HIGH'
             );
             if (result.action !== 'approve') {
                this.logAndBroadcast({ type: 'user_denied', toolName, ruleId: rule?.id });
                this.sendErrorToHost(message.id, -32000, `USER DENIED: Execution rejected by human operator.`);
                return;
             }
             this.logAndBroadcast({ type: 'user_allowed', toolName, ruleId: rule?.id });
          } else if (action === 'sandbox') {
             if (args.path && args.content) {
                const staged = this.cowFs.stageWrite(args.path, args.content);
                this.logAndBroadcast({ type: 'cow_staged', toolName, payload: staged });
                
                const result = await PromptBridge.ask(
                   `Sandbox Write: ${toolName}`,
                   `Tool: ${toolName}\nTarget: ${args.path}`,
                   rule?.riskLevel || 'HIGH',
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

  public stop(): void {
    if (this.dashboard) {
      try { this.dashboard.stop(); } catch {}
    }
    if (this.policyEngine) {
      try { this.policyEngine.close(); } catch {}
    }
  }

  public start() {
    const config = this.policyEngine.getConfig();
    const containerConfig = (config.sandbox as any)?.container;
    const containerSandbox = new ContainerSandbox(containerConfig || {});
    const { cmd, args } = containerSandbox.spawnProcess(this.targetCmd, this.targetArgs);

    this.child = spawn(cmd, args, {
      stdio: ['pipe', 'pipe', process.stderr],
      env: process.env
    });

    this.child.on('error', (err) => {
       console.error(`[MCP-SHIELD] Failed to spawn target process: ${err.message}`);
       this.stop();
       process.exit(1);
    });

    if (this.child.stdin) {
      this.child.stdin.on('error', () => {
        // Suppress EPIPE on child stdin disconnect
      });
    }

    process.stdin.on('data', (chunk: Buffer) => {
      this.inboundFramer.append(chunk);
    });

    if (this.child.stdout) {
      this.child.stdout.on('data', (chunk: Buffer) => {
        this.outboundFramer.append(chunk);
      });
    }

    this.child.on('exit', (code) => {
      this.stop();
      process.exit(code ?? 0);
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
          process.exit(1);
        }, 3000);
        killTimer.unref();
      } else {
        this.stop();
        process.exit(0);
      }
    };

    process.on('SIGINT', () => handleShutdown('SIGINT'));
    process.on('SIGTERM', () => handleShutdown('SIGTERM'));
  }
}
