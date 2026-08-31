import { spawn, ChildProcess } from 'child_process';
import { JsonRpcStreamFramer } from './stream-framing';
import { ASTAnalyzer } from '../security/ast-analyzer';
import { PromptBridge } from '../tui/prompt-bridge';
import { COWFileSystem } from '../sandbox/cow-fs';
import { DashboardServer } from '../dashboard/server';
import { ContainerSandbox } from '../sandbox/container-sandbox';
import { SecuritySession } from './session';
import { RequestDispatcher } from './dispatcher';
import { EvaluationContext, Evidence } from '../security/policy-engine';
import { ConfigLoader } from '../security/config';
import { NetworkEgressProxy } from '../security/network-proxy';
import { CapabilityInferencer } from '../security/capabilities';

export interface Lifecycle {
  start(): Promise<number>;
  stop(): Promise<void>;
}

/**
 * Explicit Pipeline Representations:
 * 1. RawSecurityInput: Raw, unmodified input evaluated for AST safety, SSRF/egress, rate limits, and security rules.
 * 2. SanitizedLogContextInput: Redacted representation for logs, audit trails, and TUI prompt bridge.
 * 3. RestoredExecutionInput: Selectively restored arguments passed to downstream tools with explicit trust & secret access.
 */
export type RawSecurityInput = Record<string, any>;
export type SanitizedLogContextInput = Record<string, any>;
export type RestoredExecutionInput = Record<string, any>;

export class ProxyServer implements Lifecycle {
  private child: ChildProcess | null = null;
  private inboundFramer = new JsonRpcStreamFramer();
  private outboundFramer = new JsonRpcStreamFramer();
  
  private session: SecuritySession;
  private astAnalyzer = new ASTAnalyzer();
  private cowFs = new COWFileSystem();
  private dashboard: DashboardServer | null = null;
  private dispatcher: RequestDispatcher;
  private networkEgressProxy: NetworkEgressProxy;

  constructor(
    private targetCmd: string,
    private targetArgs: string[],
    private options: { enableDashboard?: boolean } = {}
  ) {
    const config = ConfigLoader.load();
    this.session = new SecuritySession(config, targetCmd, targetArgs);
    this.dispatcher = new RequestDispatcher(
      this.handleInboundMessage.bind(this),
      this.sendErrorToHost.bind(this)
    );
    this.networkEgressProxy = new NetworkEgressProxy(this.session.policyEngine);
  }

  private logAndBroadcast(event: any) {
    this.session.logger.log(event);
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
        message = JSON.parse(buffer.toString('utf8'));
      } catch (err) {
        this.logAndBroadcast({ type: 'parse_error', reason: 'Failed to parse JSON from inbound stream, dropping payload.' });
        this.sendErrorToHost(null, -32700, 'Parse error: Invalid JSON received');
        return;
      }
      this.dispatcher.enqueue(message);
    });

    this.outboundFramer.on('message', async (buffer: Buffer) => {
      try {
        const message = JSON.parse(buffer.toString('utf8'));
        
        // Intercept tools/list response
        if (message.id !== undefined && message.result && message.result.tools) {
           for (const tool of message.result.tools) {
              try {
                 this.session.registerTool(tool.name, tool.description || '', tool.inputSchema || {});
              } catch (e: any) {
                 this.logAndBroadcast({ type: 'schema_violation', reason: e.message });
                 // Schema changed dynamically! Terminate session!
                 if (this.child) { this.child.kill('SIGKILL'); }
              }
           }
        }

        // DLP Sanitization on outputs back to host
        if (message.result) {
           const resultStr = JSON.stringify(message.result);
           const sanitizedStr = this.session.sanitizer.sanitize(resultStr);
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

  private async handleInboundMessage(message: any) {
    try {
      const state = this.session.getState();
      
      // Basic state machine enforcement
      if (state !== 'READY' && state !== 'DEGRADED') {
        if (message.method === 'initialize' && state === 'INITIALIZING') {
           // allow initialization to proceed through to the server
        } else if (message.method === 'notifications/initialized' || message.method === 'ping') {
           // allow post-init and pings
        } else {
           if (message.id) {
             this.sendErrorToHost(message.id, -32002, `Server is not ready. Current state: ${state}`);
           }
           return;
        }
      }

      if (message.method === 'call_tool' && message.params && message.params.name) {
        const toolName = message.params.name;
        
        // 1. Extract RAW SECURITY INPUT (Evaluated for all security checks)
        const rawArgs: RawSecurityInput = message.params.arguments || {};
        const registeredTool = this.session.toolRegistry.get(toolName);
        
        // 2. Generate SANITIZED LOG CONTEXT INPUT (For safe logging & TUI)
        const sanitizedArgsStr = this.session.sanitizer.sanitize(JSON.stringify(rawArgs));
        const sanitizedArgs: SanitizedLogContextInput = JSON.parse(sanitizedArgsStr);
        
        this.logAndBroadcast({ type: 'tool_call_intercepted', toolName, payload: sanitizedArgs });

        if (registeredTool) {
           const inferred = registeredTool.inferredCapabilities;
           if (inferred) {
             this.session.updateObservedCapabilities(toolName, inferred);
           }
        }

        const evidence: Evidence[] = [];

        // -1. Rate Limit Check (Runaway loop prevention)
        if (!this.session.rateLimiter.checkLimit(toolName)) {
           evidence.push({ detector: 'rate-limiter', finding: `RATE_LIMIT_EXCEEDED: Runaway loop detected for tool '${toolName}'.`, risk: 'CRITICAL' });
        }

        // 0. Honey-Token DLP Check (Evaluated against RawSecurityInput)
        if (this.session.sanitizer.checkHoneyTokens(JSON.stringify(rawArgs))) {
           evidence.push({ detector: 'sanitizer', finding: 'HONEY_TOKEN_ACCESSED: LLM attempted to use a decoy credential.', risk: 'CRITICAL' });
        }
        
        // 0.5 Egress Network Firewall (URL/argument-level check against RawSecurityInput)
        const egressCheck = this.session.policyEngine.checkEgress(rawArgs);
        if (egressCheck.isBlocked) {
           evidence.push({ detector: 'url-egress-filter', finding: `EGRESS_BLOCKED: Unauthorized destination ${egressCheck.domain || 'endpoint'}: ${egressCheck.reason || ''}`, risk: 'CRITICAL' });
        }

        // 2. AST Firewall (Evaluated against RawSecurityInput commands)
        if (registeredTool?.inferredCapabilities.shellExecution || /bash|shell|terminal|exec|run|do_cmd|cmd/i.test(toolName)) {
           const cmd = rawArgs.command || rawArgs.cmd || '';
           const astResult = this.astAnalyzer.analyzeCommand(cmd);
           if (!astResult.isSafe) {
              const risk = astResult.reason?.includes('ARBITRARY_CODE_EXECUTION') ? 'HIGH' : 'CRITICAL';
              evidence.push({ detector: 'ast-analyzer', finding: astResult.reason || 'AST_BLOCKED', risk });
           }
        }
        
        // 3. Capability Attestation Check
        if (registeredTool?.trustLevel === 'SUSPICIOUS') {
           evidence.push({ detector: 'capability-attestation', finding: 'CAPABILITY_MISMATCH: Inferred capabilities exceed declared capabilities.', risk: 'HIGH' });
        }

        // Evaluate Policy Unified Engine against RawSecurityInput
        const evaluationContext: EvaluationContext = {
           toolName,
           capabilities: registeredTool ? Object.keys(registeredTool.inferredCapabilities).filter((k) => (registeredTool.inferredCapabilities as any)[k]) : undefined,
           args: rawArgs,
           evidence
        };

        let securityResult: any;
        try {
           securityResult = this.session.policyEngine.evaluate(evaluationContext);
        } catch (e: any) {
           // Fail-closed invariant
           securityResult = { decision: 'block', detector: 'policy-engine', reasonCode: `FAIL_CLOSED_EXCEPTION: ${e.message}` };
        }

        const action = securityResult.decision;

        const printMarketingBlock = (toolName: string, args: any, risk: string, reason: string) => {
           const red = '\x1b[31m';
           const bold = '\x1b[1m';
           const reset = '\x1b[0m';
           
           const cmdStr = (args.command || args.cmd || JSON.stringify(args)).substring(0, 150);
           
           const msg = `
${red}${bold}⚠ MCP-SHIELD BLOCKED${reset}

${bold}Tool:${reset} ${toolName}

${bold}Command:${reset}
${cmdStr}

${bold}Risk:${reset} ${red}${bold}${risk}${reset}

${bold}Reason:${reset}
${reason}

${bold}Action:${reset}
${red}BLOCKED${reset}
`;
           try { process.stderr.write(msg + '\n'); } catch {}
        };

        if (action === 'quarantine') {
           printMarketingBlock(toolName, rawArgs, 'CRITICAL', securityResult.reasonCode);
           this.logAndBroadcast({ type: 'quarantine', toolName, reason: securityResult.reasonCode });
           this.sendErrorToHost(message.id, -32000, `SECURITY QUARANTINE: ${securityResult.reasonCode}`);
           if (this.child) { this.child.kill('SIGKILL'); }
           return;
        } else if (action === 'block') {
           printMarketingBlock(toolName, rawArgs, 'HIGH', securityResult.reasonCode);
           this.logAndBroadcast({ type: 'policy_blocked', toolName, ruleId: securityResult.ruleId, reason: securityResult.reasonCode });
           this.sendErrorToHost(message.id, -32000, `SECURITY POLICY BLOCKED: ${securityResult.reasonCode}`);
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
           const targetPath = rawArgs.path || rawArgs.file || rawArgs.filename || rawArgs.filepath || rawArgs.target;
           const content = rawArgs.content || rawArgs.text || rawArgs.data;
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
                 this.cowFs.commit(staged.stagingPath, staged.absoluteOriginalPath, staged.originalIdentity);
                 this.logAndBroadcast({ type: 'cow_committed', toolName, payload: { path: staged.absoluteOriginalPath } });
                 this.sendSuccessToHost(message.id, { content: [{ type: 'text', text: 'File changes approved and written.' }] });
              } else {
                 this.cowFs.discard(staged.stagingPath);
                 this.logAndBroadcast({ type: 'cow_discarded', toolName });
                 this.sendErrorToHost(message.id, -32000, 'USER DENIED: Staged file changes rejected.');
              }
              return;
           } else {
              this.logAndBroadcast({ type: 'sandbox_blocked', toolName, reason: 'Sandbox write action requested but target path or content was missing.' });
              this.sendErrorToHost(message.id, -32000, 'SANDBOX POLICY BLOCKED: Missing path or content for staged execution.');
              return;
           }
        }
      }
      
      // 3. RESTORED EXECUTION INPUT: Granular Trust & Capability-Aware Secret Restoration
      if (message.method === 'call_tool') {
         const toolName = message.params.name;
         const registeredTool = this.session.toolRegistry.get(toolName);
         
         const isTrusted = registeredTool?.trustLevel === 'TRUSTED';
         const hasSecretCapability = registeredTool?.declaredCapabilities.secretAccess || registeredTool?.inferredCapabilities.secretAccess;
         
         if (isTrusted && hasSecretCapability) {
            // Restore tokenized secrets only for TRUSTED tools with explicit secret access capability
            const payloadStr = JSON.stringify(message.params);
            const restoredStr = this.session.sanitizer.restore(payloadStr);
            message.params = JSON.parse(restoredStr);
            this.logAndBroadcast({ type: 'secret_restored', toolName, trustLevel: registeredTool.trustLevel });
         } else if (isTrusted && !hasSecretCapability) {
            this.logAndBroadcast({
              type: 'secret_restoration_skipped',
              toolName,
              reason: 'Tool is TRUSTED but does not have declared secretAccess capability; masked tokens retained.'
            });
         } else {
            this.logAndBroadcast({
              type: 'secret_restoration_denied',
              toolName,
              reason: `Server trust level is ${registeredTool?.trustLevel || 'UNKNOWN'}; masked tokens retained.`
            });
         }
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
    }
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
     const safeEnvAllowlist = [
       'PATH', 'PATHEXT', 'SHELL', 'PWD',
       'HOME', 'USER', 'LOGNAME', 'USERNAME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH',
       'TMP', 'TEMP', 'TMPDIR',
       'LANG', 'LC_ALL', 'LC_CTYPE', 'LC_MESSAGES', 'TZ',
       'NODE_PATH', 'NODE_EXTRA_CA_CERTS',
       'SSL_CERT_FILE', 'SSL_CERT_DIR', 'CURL_CA_BUNDLE', 'REQUESTS_CA_BUNDLE',
       'XDG_DATA_HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_RUNTIME_DIR',
       'XDG_DATA_DIRS', 'XDG_CONFIG_DIRS',
       'TERM', 'COLORTERM', 'FORCE_COLOR', 'NO_COLOR', 'CI',
       'SYSTEMROOT', 'WINDIR', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA',
       'PROGRAMFILES', 'PROGRAMFILES(X86)', 'COMSPEC', 'PSMODULEPATH'
     ];

     const blockedInjectionPattern = /^(LD_|DYLD_|NODE_OPTIONS|BASH_ENV|ENV|PYTHONSTARTUP|PERL5OPT|RUBYOPT|PROMPT_COMMAND)/i;
     const sensitiveKeyPattern = /(KEY|SECRET|TOKEN|PASSWORD|AUTH|CREDENTIAL|PRIVATE)/i;

     const safeEnv: NodeJS.ProcessEnv = {
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

  public async start(): Promise<number> {
    this.setupFramers();
    await this.session.start();
    
    let proxyPort = 0;
    if (this.session.policyEngine.getConfig().egress?.enabled) {
      proxyPort = await this.networkEgressProxy.start();
    }

    return new Promise((resolve, reject) => {
      this.session.transitionState('INITIALIZING');
      if (this.options.enableDashboard || process.env.MCP_SHIELD_ENABLE_DASHBOARD === 'true') {
        this.dashboard = new DashboardServer();
        this.dashboard.start();
      }

      const config = this.session.policyEngine.getConfig();
      const containerConfig = (config.sandbox as any)?.container;
      const containerSandbox = new ContainerSandbox(containerConfig || {});
      const { cmd, args } = containerSandbox.spawnProcess(this.targetCmd, this.targetArgs);

      if (containerSandbox.isEnabled()) {
        try {
          process.stderr.write('[MCP-SHIELD] 🛡️  Container Sandbox Active: Running in ephemeral Docker container (--cap-drop=ALL, network=none).\n');
        } catch {}
      } else {
        try {
          process.stderr.write('[MCP-SHIELD] ℹ️  Host Execution Mode: Container isolation is disabled (default). Enforcing AST command firewall and DLP secret sanitization on stdio stream.\n');
        } catch {}
      }

      const childEnv = ProxyServer.buildSafeEnv();
      if (proxyPort > 0) {
        childEnv['HTTP_PROXY'] = `http://127.0.0.1:${proxyPort}`;
        childEnv['HTTPS_PROXY'] = `http://127.0.0.1:${proxyPort}`;
      }

      this.child = spawn(cmd, args, {
        stdio: ['pipe', 'pipe', process.stderr],
        env: childEnv
      });

      this.child.on('error', (err) => {
         console.error(`[MCP-SHIELD] Failed to spawn target process: ${err.message}`);
         this.stop();
         reject(err);
      });

      if (this.child.stdin) {
        this.child.stdin.on('error', () => {
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
        this.session.transitionState('CLOSED');
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
        this.session.transitionState('CLOSING');
        if (this.child) {
          try {
            this.child.kill(signal as NodeJS.Signals);
          } catch {}
          
          const killTimer = setTimeout(() => {
            try {
              if (this.child && !this.child.killed) {
                this.child.kill('SIGKILL');
              }
            } catch {}
            this.stop();
            this.session.transitionState('CLOSED');
            resolve(signal === 'SIGINT' ? 130 : 143);
          }, 3000);
          killTimer.unref();
        } else {
          this.stop();
          this.session.transitionState('CLOSED');
          resolve(signal === 'SIGINT' ? 130 : 143);
        }
      };

      process.on('SIGINT', () => handleShutdown('SIGINT'));
      process.on('SIGTERM', () => handleShutdown('SIGTERM'));
      
      this.session.transitionState('READY');
      this.session.logger.startSession(this.session.policyEngine.getConfig(), Array.from(this.session.toolRegistry.keys()));
    });
  }

  public async stop(): Promise<void> {
    if (this.networkEgressProxy) {
      try { await this.networkEgressProxy.stop(); } catch {}
    }
    if (this.dashboard) {
      try { await this.dashboard.stop(); } catch {}
    }
    if (this.session && this.session.policyEngine) {
      try { this.session.policyEngine.close(); } catch {}
    }
    if (this.session && this.session.logger) {
      this.session.logger.endSession();
    }
  }
}
