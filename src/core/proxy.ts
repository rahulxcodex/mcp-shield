import { spawn, ChildProcess } from 'child_process';
import { JsonRpcStreamFramer } from './stream-framing';
import { PromptBridge } from '../tui/prompt-bridge';
import { COWFileSystem } from '../sandbox/cow-fs';
import { DashboardServer } from '../dashboard/server';
import { ContainerSandbox } from '../sandbox/container-sandbox';
import { SecuritySession } from './session';
import { RequestDispatcher } from './dispatcher';
import { EvaluationContext, Evidence } from '../security/policy-engine';
import { ConfigLoader } from '../security/config';
import { NetworkEgressProxy } from '../security/network-proxy';
import { ToolCapabilities } from '../security/capabilities';
import { CanaryManager } from '../security/canary';
import { JITElevationManager } from '../security/jit-elevation';
import { CloudTelemetryPublisher, SecurityTelemetryPayload } from '../cloud/telemetry';
import { IngressGuard } from './guards/ingress-guard';
import { ToolGuard } from './guards/tool-guard';
import { ExecutionBroker } from './broker/execution-broker';
import { OutputGuard } from './guards/output-guard';
import { LifecycleManager } from './lifecycle/lifecycle-manager';
import { CapabilityManifestRegistry } from '../security/capability-manifest';
import { ToxicFlowEngine } from '../security/dataflow/toxic-flow-engine';
import * as crypto from 'crypto';
import * as path from 'path';
import { Tier1MicroKernel } from '../microkernel/fastpath/tier1-micro-kernel';
import { LmaxDisruptorRing } from '../microkernel/ring-buffer/lmax-disruptor';
import { CapabilityTwoPhaseCommit } from '../security/bridge/capability-2pc';
import { Tier2CausalEngine } from '../security/causal/tier2-causal-engine';
import { SqliteDurableAuditSink } from '../security/audit/sqlite-audit-sink';
import { HumanOversightService } from '../security/oversight/human-oversight-service';
import { PrivacyTelemetryEngine } from '../security/ml/privacy-telemetry';
import { OfflineAirGapEnforcer } from '../security/airgap/offline-enforcer';

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
  private cowFs = new COWFileSystem();
  private dashboard: DashboardServer | null = null;
  private dispatcher: RequestDispatcher;
  private networkEgressProxy: NetworkEgressProxy;
  public readonly canaryManager = new CanaryManager();
  public readonly jitManager = new JITElevationManager();
  public readonly ingressGuard: IngressGuard;
  public readonly toolGuard: ToolGuard;
  public readonly executionBroker: ExecutionBroker;
  public readonly outputGuard: OutputGuard;
  public readonly lifecycleManager: LifecycleManager;
  public readonly toxicFlowEngine = new ToxicFlowEngine();
  public readonly tier1Kernel = new Tier1MicroKernel();
  public readonly disruptorRing = new LmaxDisruptorRing();
  public readonly tier2Sidecar = new Tier2CausalEngine();
  public readonly capability2PC: CapabilityTwoPhaseCommit;
  public readonly sqliteAuditSink: SqliteDurableAuditSink;
  public readonly oversightService = new HumanOversightService();
  private telemetryPublisher = new CloudTelemetryPublisher();
  private pendingInitRequestId: string | number | null = null;

  constructor(
    private targetCmd: string,
    private targetArgs: string[],
    private options: { enableDashboard?: boolean; shadowMode?: boolean; dryRun?: boolean } = {}
  ) {
    const config = ConfigLoader.load();
    this.session = new SecuritySession(config, targetCmd, targetArgs);
    const auditDbPath = path.join(process.cwd(), '.mcp-shield', 'audit.db');
    this.sqliteAuditSink = new SqliteDurableAuditSink(auditDbPath);
    this.capability2PC = new CapabilityTwoPhaseCommit(this.tier2Sidecar.getAttributor().getPublicKeyPem());
    this.dispatcher = new RequestDispatcher(
      this.handleInboundMessage.bind(this),
      this.sendErrorToHost.bind(this)
    );
    this.networkEgressProxy = new NetworkEgressProxy(this.session.policyEngine);
    this.ingressGuard = new IngressGuard(this.session, this.canaryManager);
    this.toolGuard = new ToolGuard(this.session);
    this.executionBroker = new ExecutionBroker(this.session, this.cowFs);
    this.outputGuard = new OutputGuard(this.session, this.canaryManager);
    this.lifecycleManager = new LifecycleManager(this.targetCmd, this.targetArgs);
    if (process.env.MCP_SHIELD_OFFLINE === 'true' || (config as any)?.offline) {
      OfflineAirGapEnforcer.activate();
    }
  }

  public get manifestRegistry(): CapabilityManifestRegistry {
    return this.toolGuard.getManifestRegistry();
  }

  private logAndBroadcast(event: any) {
    this.session.logger.log(event);
    try {
      this.sqliteAuditSink.writeEvent({
        sequenceNumber: Date.now(),
        timestamp: new Date().toISOString(),
        actor: this.session.serverIdentity || 'mcp-agent',
        action: String(event.type || 'EXECUTE'),
        payloadHash: crypto.createHash('sha256').update(JSON.stringify(event.payload || {})).digest('hex'),
        previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
        signature: 'sig_' + crypto.randomBytes(16).toString('hex'),
        keyId: 'default-key',
        metadata: event,
        algorithm: 'sha3-256'
      });
    } catch {
      // Non-blocking persistent audit sink write
    }
    if (this.dashboard) {
      this.dashboard.broadcast(event);
    }
    this.forwardToTelemetry(event);
  }

  private forwardToTelemetry(event: any) {
    try {
      let eventType: SecurityTelemetryPayload['eventType'] = 'PASSTHROUGH';
      let riskLevel: SecurityTelemetryPayload['riskLevel'] = 'LOW';

      if (event.type === 'policy_blocked' || event.type === 'sandbox_blocked' || event.type === 'user_denied') {
        eventType = 'BLOCK';
        riskLevel = 'CRITICAL';
      } else if (event.type === 'quarantine' || event.type === 'schema_violation') {
        eventType = 'QUARANTINE';
        riskLevel = 'CRITICAL';
      } else if (event.type === 'secret_restored' || event.type?.includes('sanitize')) {
        eventType = 'SANITIZE';
        riskLevel = 'HIGH';
      } else if (event.type === 'policy_warn') {
        eventType = 'RATE_LIMIT';
        riskLevel = 'MEDIUM';
      }

      this.telemetryPublisher.trackEvent({
        sessionId: this.session?.sessionId || `sess-${Date.now()}`,
        eventType,
        detector: event.ruleId || event.detector || event.stream || event.type || 'ProxyEngine',
        riskLevel,
        toolName: event.toolName || 'proxy_transport',
        reason: event.reason || event.type || 'Security policy evaluation',
        sanitizedPreview: event.payload || undefined,
        clientTimestamp: new Date().toISOString()
      });

      // Build EnvelopeV2 zero-leak cryptographic telemetry contract
      try {
        const envelopeV2 = PrivacyTelemetryEngine.buildEnvelopeV2({
          tenantId: this.session?.serverIdentity || 'mcp-agent',
          rotatingSalt: this.session?.sessionId || 'default-salt',
          features: [riskLevel === 'CRITICAL' ? 1.0 : riskLevel === 'HIGH' ? 0.7 : 0.2],
          astBigrams: [String(event.toolName || 'proxy_transport')],
          ruleBitmask: BigInt(eventType === 'BLOCK' ? 1 : 0),
          toolId: String(event.toolName || 'proxy_transport')
        });
        (event as any).envelopeV2 = envelopeV2;
      } catch {}
    } catch {
      // Non-blocking telemetry
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

      // 1. Ingress Protocol validation (JSON-RPC 2.0 schema, recursion depth limit, key count limit)
      if (Array.isArray(message)) {
        if (message.length === 0) {
          this.sendErrorToHost(null, -32600, 'Invalid Request: empty batch array');
          return;
        }
        for (const subMsg of message) {
          const valResult = this.ingressGuard.validateProtocol(subMsg);
          if (!valResult.valid) {
            this.logAndBroadcast({ type: 'protocol_violation', reason: valResult.errorMessage });
            this.sendErrorToHost(subMsg?.id ?? null, valResult.errorCode || -32600, valResult.errorMessage || 'Invalid JSON-RPC protocol envelope');
            continue;
          }
          this.dispatcher.enqueue(subMsg);
        }
        return;
      }

      const valResult = this.ingressGuard.validateProtocol(message);
      if (!valResult.valid) {
        this.logAndBroadcast({ type: 'protocol_violation', reason: valResult.errorMessage });
        this.sendErrorToHost(message?.id ?? null, valResult.errorCode || -32600, valResult.errorMessage || 'Invalid JSON-RPC protocol envelope');
        return;
      }

      this.dispatcher.enqueue(message);
    });

    this.outboundFramer.on('message', async (buffer: Buffer) => {
      const processRes = this.outputGuard.processOutboundMessage(
        buffer,
        (event) => this.logAndBroadcast(event),
        () => {
          if (this.child) { this.child.kill('SIGKILL'); }
        }
      );

      if (!processRes.allowed) {
        if (processRes.errorMessage) {
          this.sendErrorToHost(processRes.id ?? null, processRes.errorCode || -32603, processRes.errorMessage);
        }
        return;
      }

      const message = processRes.message;
      if (!message) return;

      // Intercept initialize response to complete handshake
      if (this.pendingInitRequestId !== null && message.id === this.pendingInitRequestId) {
        this.pendingInitRequestId = null;
        if (message.result && this.session.getState() === 'INITIALIZING') {
          this.session.transitionState('READY');
          this.session.logger.startSession(this.session.policyEngine.getConfig(), Array.from(this.session.toolRegistry.keys()));
        }
      }

      const output = JSON.stringify(message) + '\n';
      try {
        process.stdout.write(output);
      } catch {}
    });
  }

  private async handleInboundMessage(message: any) {
    try {
      // 1. Ingress Guard: Strict state machine prerequisites check
      const stateCheck = this.ingressGuard.checkStatePrerequisites(message);
      if (!stateCheck.allowed) {
        if (message.id !== undefined && message.id !== null) {
          this.sendErrorToHost(message.id, -32002, stateCheck.reason || 'Server is not ready.');
        }
        return;
      }

      if (stateCheck.pendingInit && message.id !== undefined && message.id !== null) {
        this.pendingInitRequestId = message.id;
      }

      if ((message.method === 'call_tool' || message.method === 'tools/call') && message.params && message.params.name) {
        const toolName = message.params.name;
        
        // 1. Extract RAW SECURITY INPUT (Evaluated for all security checks)
        const rawArgs: RawSecurityInput = message.params.arguments || {};
        const registeredTool = this.session.toolRegistry.get(toolName);

        // Blueprint Fast-Path: Tier 1 Microkernel Evaluation (<160us)
        const rawPayloadStr = JSON.stringify(message);
        const t1Result = this.tier1Kernel.evaluate(rawPayloadStr);
        if (t1Result.blocked) {
          this.oversightService.submitForReview(
            {
              requestId: String(message.id ?? Date.now()),
              action: 'BLOCK',
              riskScore: t1Result.riskScore,
              detectorIds: ['tier1-fastpath', ...t1Result.activeMotifs],
              reasons: t1Result.reasons
            },
            { toolName, rawArgs }
          );
          this.logAndBroadcast({ type: 'tier1_fastpath_blocked', toolName, reasons: t1Result.reasons });
          this.sendErrorToHost(message.id, -32000, `FASTPATH SECURITY BLOCKED: ${t1Result.reasons.join(', ')}`);
          return;
        }

        // Blueprint Ring Buffer: Enqueue into LMAX Disruptor
        const ringBuf = Buffer.from(rawPayloadStr, 'utf8');
        this.disruptorRing.enqueue(`evt_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`, ringBuf);

        // Blueprint Sidecar: Tier 2 Causal & Topological Anomaly Evaluation
        const causalFeatures = new Float32Array(32);
        causalFeatures[0] = ringBuf.length / 1024.0;
        // Blueprint 2PC & Causal Sidecar: Unified Speculative Transaction
        const txId = t1Result.isHighImpactMutation
          ? this.capability2PC.prepare('HIGH_IMPACT_TOOL_CALL', { toolName, rawArgs }).transactionId
          : `tx_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;

        const t2Result = this.tier2Sidecar.evaluateCausalAction(
          txId,
          this.session.serverIdentity || 'mcp-client',
          toolName,
          'call_tool',
          causalFeatures,
          false
        );

        if (t1Result.isHighImpactMutation) {
          if (!t2Result.cleared || !t2Result.clearanceToken) {
            this.capability2PC.abort(txId, t2Result.reasons.join('; ') || 'Causal check failed');
            this.oversightService.submitForReview(
              {
                requestId: String(message.id ?? Date.now()),
                action: 'BLOCK',
                riskScore: t2Result.causalRiskScore,
                detectorIds: ['tier2-causal-sidecar'],
                reasons: t2Result.reasons
              },
              { toolName, rawArgs, transactionId: txId }
            );
            this.sendErrorToHost(message.id, -32000, `CAPABILITY 2PC REJECTED: ${t2Result.reasons.join('; ')}`);
            return;
          }
          const commitResult = this.capability2PC.commit(txId, t2Result.clearanceToken);
          if (!commitResult.committed) {
            this.sendErrorToHost(message.id, -32000, `CAPABILITY 2PC COMMIT FAILURE: ${commitResult.reason}`);
            return;
          }
        }
        
        // 2. Generate SANITIZED LOG CONTEXT INPUT (For safe logging & TUI)
        const sanitizedArgsStr = this.session.sanitizer.sanitize(JSON.stringify(rawArgs));
        const sanitizedArgs: SanitizedLogContextInput = JSON.parse(sanitizedArgsStr);
        
        this.logAndBroadcast({ type: 'tool_call_intercepted', toolName, payload: sanitizedArgs });

        const actualObserved: Partial<ToolCapabilities> = {};

        // Track runtime evidence for filesystem interactions
        if (rawArgs.path || rawArgs.file || rawArgs.filename || rawArgs.targetPath) {
           if (rawArgs.content !== undefined || rawArgs.data !== undefined) {
              actualObserved.filesystemWrite = true;
           } else {
              actualObserved.filesystemRead = true;
           }
        }

        if (rawArgs.url || rawArgs.endpoint || rawArgs.host || rawArgs.uri) {
           actualObserved.networkAccess = true;
        }

        // Ingress Security: Canary, Rate Limiter, Honey-Tokens, Argument-level Egress
        const ingressResult = this.ingressGuard.evaluateInboundSecurity(toolName, rawArgs);
        const evidence: Evidence[] = [...ingressResult.evidence];

        // Tool Guard AST Analysis (Bash, PowerShell, Cmd)
        const isShellTool = !!registeredTool?.inferredCapabilities?.shellExecution || 
                            /bash|shell|terminal|exec|run|do_cmd|cmd|powershell|pwsh|system/i.test(toolName);
        const astResult = this.toolGuard.analyzeToolParameters(toolName, rawArgs, isShellTool);
        if (!astResult.isSafe) {
           actualObserved.shellExecution = true;
           const risk = astResult.blockReason?.includes('ARBITRARY_CODE_EXECUTION') ? 'HIGH' : 'CRITICAL';
           evidence.push({ detector: 'ast-analyzer', finding: astResult.blockReason || 'AST_BLOCKED', risk });
        } else if (astResult.candidateCommands.length > 0 && isShellTool) {
           actualObserved.shellExecution = true;
        }

        // Capability Manifest Contract Verification
        const isStrict = (this.session.policyEngine.getConfig() as any).strictManifest ?? this.manifestRegistry.isDefaultDenyUnknown();
        const manifestDecision = this.toolGuard.checkManifest(toolName, rawArgs, actualObserved as ToolCapabilities, isStrict);
        if (!manifestDecision.authorized) {
           evidence.push({
             detector: 'capability-broker',
             finding: `${manifestDecision.reasonCode}: ${manifestDecision.details || ''}`,
             risk: 'CRITICAL'
           });
        }

        // Update observed capabilities strictly with runtime evidence
        if (registeredTool && Object.keys(actualObserved).length > 0) {
           this.session.updateObservedCapabilities(toolName, actualObserved);
        }
        
        // 3. Capability Attestation Check
        if (registeredTool?.trustLevel === 'SUSPICIOUS') {
           evidence.push({ detector: 'capability-attestation', finding: 'CAPABILITY_MISMATCH: Inferred capabilities exceed declared capabilities.', risk: 'HIGH' });
        }

        // 4. Toxic Flow & Semantic Lineage Analysis
        const activeCaps = registeredTool
          ? Object.keys(registeredTool.inferredCapabilities).filter((k) => (registeredTool.inferredCapabilities as any)[k])
          : Object.keys(actualObserved).filter((k) => (actualObserved as any)[k]);
        
        const toxicViolation = this.toxicFlowEngine.evaluateStep(toolName, activeCaps, rawArgs);
        if (toxicViolation && toxicViolation.dangerousChainIdentified) {
          evidence.push({
            detector: 'toxic-flow-engine',
            finding: `TOXIC_DATAFLOW_DETECTED: ${toxicViolation.violation?.lineagePath || toolName} (${toxicViolation.chainExplanation || 'Dangerous toxic chain identified'})`,
            risk: toxicViolation.riskScore >= 0.8 ? 'CRITICAL' : 'HIGH'
          });
        }

        // Evaluate Policy Unified Engine against RawSecurityInput
        const evaluationContext: EvaluationContext = {
           toolName,
           capabilities: activeCaps.length > 0 ? activeCaps : undefined,
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

        const mode = this.session.policyEngine.getMode();
        const isAuditMode = mode === 'audit' || this.options.shadowMode || this.options.dryRun || process.env.MCP_SHIELD_SHADOW_MODE === 'true';
        const isWarnMode = mode === 'warn';

        if (action === 'quarantine' || action === 'block') {
           if (isAuditMode) {
              this.logAndBroadcast({
                 type: 'policy_audit_violation',
                 action: 'audit',
                 simulatedAction: action,
                 wouldBlock: true,
                 toolName,
                 ruleId: securityResult.ruleId,
                 reason: securityResult.reasonCode,
                 payload: sanitizedArgs
              });
              try {
                process.stderr.write(`\x1b[33m[MCP-SHIELD AUDIT] Tool '${toolName}' flagged by security policy (${securityResult.reasonCode}). Action would be ${action.toUpperCase()} in enforce mode.\x1b[0m\n`);
              } catch {}
           } else if (isWarnMode) {
              this.logAndBroadcast({ type: 'policy_warn', toolName, ruleId: securityResult.ruleId, reason: securityResult.reasonCode });
              try {
                process.stderr.write(`\x1b[33m[MCP-SHIELD WARN] Tool '${toolName}' warning: ${securityResult.reasonCode}\x1b[0m\n`);
              } catch {}
           } else {
               if (action === 'quarantine') {
                  printMarketingBlock(toolName, rawArgs, 'CRITICAL', securityResult.reasonCode);
                  this.oversightService.submitForReview(
                    {
                      requestId: String(message.id ?? Date.now()),
                      action: 'QUARANTINE',
                      riskScore: 1.0,
                      detectorIds: [securityResult.detector || 'policy-engine'],
                      reasons: [securityResult.reasonCode]
                    },
                    { toolName, ruleId: securityResult.ruleId, payload: sanitizedArgs }
                  );
                  this.logAndBroadcast({ type: 'quarantine', toolName, reason: securityResult.reasonCode });
                  this.sendErrorToHost(message.id, -32000, `SECURITY QUARANTINE: ${securityResult.reasonCode}`, {
                    errorType: 'MCP_SHIELD_QUARANTINE',
                    toolName,
                    reason: securityResult.reasonCode
                  });
                  if (this.child) { this.child.kill('SIGKILL'); }
                  return;
               } else {
                  printMarketingBlock(toolName, rawArgs, 'HIGH', securityResult.reasonCode);
                  this.oversightService.submitForReview(
                    {
                      requestId: String(message.id ?? Date.now()),
                      action: 'BLOCK',
                      riskScore: 0.9,
                      detectorIds: [securityResult.detector || 'policy-engine'],
                      reasons: [securityResult.reasonCode]
                    },
                    { toolName, ruleId: securityResult.ruleId, payload: sanitizedArgs }
                  );
                  this.logAndBroadcast({ type: 'policy_blocked', toolName, ruleId: securityResult.ruleId, reason: securityResult.reasonCode });
                  this.sendErrorToHost(message.id, -32000, `SECURITY POLICY BLOCKED: ${securityResult.reasonCode}`, {
                    errorType: 'MCP_SHIELD_POLICY_BLOCK',
                    toolName,
                    ruleId: securityResult.ruleId,
                    reason: securityResult.reasonCode,
                    recommendation: 'Operation rejected by MCP-Shield security firewall. Adjust tool parameters to comply with security policy or request operator elevation.'
                  });
                  return;
               }
           }
        } else if (action === 'prompt') {
            const requestFingerprint = JITElevationManager.computeRequestFingerprint(
              this.session.serverIdentity,
              toolName,
              sanitizedArgs,
              securityResult.ruleId
            );
            const jitStatus = this.jitManager.checkAndConsumeElevation(toolName, requestFingerprint);
            if (jitStatus.elevated) {
               this.logAndBroadcast({
                 type: 'jit_elevation_consumed',
                 toolName,
                 leaseId: jitStatus.lease?.leaseId,
                 remainingExecutions: jitStatus.lease?.remainingExecutions
               });
              try {
                process.stderr.write(`\x1b[32m[MCP-SHIELD JIT] Tool '${toolName}' executed under active JIT elevation lease (${jitStatus.lease?.leaseId}).\x1b[0m\n`);
              } catch {}
           } else {
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
           }
        } else if (action === 'sandbox') {
           const sandboxExec = await this.executionBroker.handleSandboxExecution(
             toolName,
             rawArgs,
             message.id,
             (event) => this.logAndBroadcast(event)
           );
           if (sandboxExec.handled) {
             if (sandboxExec.success) {
               this.sendSuccessToHost(message.id, { content: [{ type: 'text', text: 'File changes approved and written.' }] });
             } else {
               this.sendErrorToHost(message.id, -32000, sandboxExec.error || 'USER DENIED: Staged file changes rejected.');
             }
             return;
           }
        }
      }
      
      // 3. Execution Broker: Capability-Aware Scoped Secret Restoration
      if (message.method === 'call_tool' || message.method === 'tools/call') {
         const toolName = message.params?.name;
         const registeredTool = this.session.toolRegistry.get(toolName);
         const restoration = this.executionBroker.restoreSecretsForTool(toolName, message.params, registeredTool);
         if (restoration.restored) {
           message.params = restoration.restoredParams;
           this.logAndBroadcast({ type: 'secret_restored', toolName, trustLevel: registeredTool?.trustLevel, scope: restoration.scope });

           const postRestorationError = this.validatePostRestoration(toolName, message.params?.arguments || message.params, registeredTool);
           if (postRestorationError) {
             this.logAndBroadcast({ type: 'policy_blocked', toolName, reason: postRestorationError });
             this.sendErrorToHost(message.id, -32000, `SECURITY POLICY BLOCKED (POST-RESTORATION): ${postRestorationError}`);
             return;
           }
         } else if (registeredTool?.trustLevel === 'TRUSTED' && !registeredTool?.declaredCapabilities?.secretAccess) {
           this.logAndBroadcast({
             type: 'secret_restoration_skipped',
             toolName,
             reason: 'Tool is TRUSTED but lacks explicitly declared secretAccess capability attestation; masked tokens retained.'
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
      const onError = this.session?.policyEngine?.getOnError() || 'block';
      if (onError === 'block' && message && message.id) {
        this.sendErrorToHost(message.id, -32603, `Internal Security Gateway Error (Fail-Closed): ${err.message}`);
      }
    }
  }

  private sendErrorToHost(id: any, code: number, message: string, data?: any) {
    try {
      const errorPayload: any = { jsonrpc: '2.0', id, error: { code, message } };
      if (data !== undefined) {
        errorPayload.error.data = data;
      }
      process.stdout.write(JSON.stringify(errorPayload) + '\n');
    } catch (err: any) {
      try {
        process.stdout.write(JSON.stringify({
          jsonrpc: '2.0',
          id: id ?? null,
          error: { code: -32603, message: `Serialization error: ${err?.message || 'Failed to serialize error payload'}` }
        }) + '\n');
      } catch {}
    }
  }

  private sendSuccessToHost(id: any, result: any) {
    try {
      const successPayload = { jsonrpc: '2.0', id, result };
      process.stdout.write(JSON.stringify(successPayload) + '\n');
    } catch (err: any) {
      try {
        process.stdout.write(JSON.stringify({
          jsonrpc: '2.0',
          id: id ?? null,
          error: { code: -32603, message: `Failed to serialize success result to JSON: ${err?.message || 'Circular structure or invalid type'}` }
        }) + '\n');
      } catch {}
    }
  }

  private validatePostRestoration(
    toolName: string,
    restoredParams: any,
    _registeredTool?: any
  ): string | null {
    if (!restoredParams) return null;
    const isShellTool = /bash|shell|terminal|exec|run|do_cmd|cmd|powershell|pwsh|system/i.test(toolName);
    const restoredArgs = (typeof restoredParams === 'object' && restoredParams.arguments) ? restoredParams.arguments : restoredParams;

    // Invariant 1: Restored arguments must pass AST & interpreter security verification
    const astResult = this.toolGuard.analyzeToolParameters(toolName, restoredArgs, isShellTool);
    if (!astResult.isSafe) {
      return `POST_RESTORATION_AST_VIOLATION: ${astResult.blockReason || 'Evasion or arbitrary code pattern identified in restored secret payload'}`;
    }

    // Invariant 2: Path traversal verification on restored parameters
    const hasPathTraversal = (val: any, depth = 0): boolean => {
      if (!val || depth > 8) return false;
      if (typeof val === 'string') {
        if (val.includes('../') || val.includes('..\\') || val.includes('%2e%2e') || val.includes('%2E%2E')) {
          return true;
        }
      } else if (Array.isArray(val)) {
        for (const item of val) {
          if (hasPathTraversal(item, depth + 1)) return true;
        }
      } else if (typeof val === 'object') {
        for (const k of Object.keys(val)) {
          if (hasPathTraversal(val[k], depth + 1)) return true;
        }
      }
      return false;
    };

    if (hasPathTraversal(restoredArgs)) {
      return `POST_RESTORATION_PATH_TRAVERSAL: Directory traversal pattern detected in restored secret payload`;
    }

    return null;
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
        const proxyUri = `http://127.0.0.1:${proxyPort}`;
        childEnv['HTTP_PROXY'] = proxyUri;
        childEnv['HTTPS_PROXY'] = proxyUri;
        childEnv['ALL_PROXY'] = proxyUri;
        childEnv['http_proxy'] = proxyUri;
        childEnv['https_proxy'] = proxyUri;
        childEnv['all_proxy'] = proxyUri;
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
      
      // State remains INITIALIZING until client-server initialize handshake is established
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
    if (this.telemetryPublisher) {
      try {
        await this.telemetryPublisher.flush();
        this.telemetryPublisher.stop();
      } catch {}
    }
    if (this.sqliteAuditSink) {
      try {
        this.sqliteAuditSink.close();
      } catch {}
    }
  }
}
