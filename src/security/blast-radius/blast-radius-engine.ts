export interface BlastRadiusReport {
  score: number; // 0.0 to 1.0
  modifiableFiles: string[];
  spawnableProcesses: string[];
  reachableCredentials: string[];
  reachableDestinations: string[];
  destructiveCapabilities: string[];
  reachableDownstreamTools: string[];
  persistenceMechanisms: string[];
  highRiskFlag: boolean;
  rationale: string[];
}

export interface BlastRadiusInputs {
  toolName: string;
  capabilities: string[];
  args?: Record<string, unknown>;
  chainDepth?: number;
  availableTools?: string[];
}

export class BlastRadiusEngine {
  private static DESTRUCTIVE_KEYWORDS = new Set([
    'delete', 'remove', 'rm', 'unlink', 'drop', 'truncate', 'format',
    'overwrite', 'purge', 'destroy', 'wipe', 'reset', 'kill'
  ]);

  private static CREDENTIAL_PATTERNS = [
    /\.aws\/credentials/i,
    /\.ssh\/(?:id_rsa|id_ed25519|authorized_keys)/i,
    /\.env(?:\.local|\.production)?/i,
    /\.kube\/config/i,
    /\.docker\/config\.json/i,
    /token|secret|password|api[_-]?key/i
  ];

  private static PERSISTENCE_PATTERNS = [
    /\/etc\/cron/i,
    /\/var\/spool\/cron/i,
    /\/etc\/systemd\/system/i,
    /\.bashrc|\.zshrc|\.profile/i,
    /CurrentVersion\\Run/i,
    /LaunchAgents|LaunchDaemons/i,
    /schtasks/i
  ];

  /**
   * Calculates comprehensive multi-vector blast radius for a candidate tool execution
   */
  public static calculate(inputs: BlastRadiusInputs): BlastRadiusReport {
    const { toolName, capabilities, args = {}, chainDepth = 0, availableTools = [] } = inputs;
    const rationale: string[] = [];

    const modifiableFiles: string[] = [];
    const spawnableProcesses: string[] = [];
    const reachableCredentials: string[] = [];
    const reachableDestinations: string[] = [];
    const destructiveCapabilities: string[] = [];
    const persistenceMechanisms: string[] = [];

    const argsStr = JSON.stringify(args);

    // 1. Files modifiable
    if (capabilities.includes('filesystem:write') || capabilities.includes('filesystem:delete')) {
      const pathArg = (args.path || args.file || args.targetPath || args.destination) as string;
      if (pathArg) {
        modifiableFiles.push(String(pathArg));
      } else {
        modifiableFiles.push('unbounded_filesystem_scope');
        rationale.push('Tool possesses write capability without bounded target path argument');
      }
    }

    // 2. Spawnable processes
    if (capabilities.includes('process:spawn') || capabilities.includes('shell:execute')) {
      const cmdArg = (args.command || args.cmd || args.script || args.executable) as string;
      if (cmdArg) {
        spawnableProcesses.push(String(cmdArg).slice(0, 100));
      } else {
        spawnableProcesses.push('arbitrary_child_processes');
        rationale.push('Tool possesses process execution capability with unrestricted commands');
      }
    }

    // 3. Reachable credentials
    for (const pat of this.CREDENTIAL_PATTERNS) {
      if (pat.test(argsStr) || pat.test(toolName)) {
        reachableCredentials.push(pat.source);
        rationale.push(`Candidate action references sensitive credential asset (${pat.source})`);
      }
    }

    // 4. Network destinations reachable
    if (capabilities.includes('network:outbound') || capabilities.includes('network:egress')) {
      const urlArg = (args.url || args.destination || args.host || args.endpoint) as string;
      if (urlArg) {
        reachableDestinations.push(String(urlArg));
      } else {
        reachableDestinations.push('unrestricted_egress');
        rationale.push('Tool possesses network egress without bounded destination argument');
      }
    }

    // 5. Destructive capabilities
    for (const cap of capabilities) {
      for (const kw of this.DESTRUCTIVE_KEYWORDS) {
        if (cap.toLowerCase().includes(kw)) {
          destructiveCapabilities.push(cap);
          rationale.push(`Tool possesses destructive capability '${cap}'`);
          break;
        }
      }
    }
    if (this.DESTRUCTIVE_KEYWORDS.has(toolName.toLowerCase())) {
      destructiveCapabilities.push(toolName);
    }

    // 6. Persistence mechanisms
    for (const pat of this.PERSISTENCE_PATTERNS) {
      if (pat.test(argsStr)) {
        persistenceMechanisms.push(pat.source);
        rationale.push(`Action accesses system persistence mechanism (${pat.source})`);
      }
    }

    // 7. Reachable downstream tools
    const downstreamTools = availableTools.filter((t) => t !== toolName);
    const reachableDownstreamTools = capabilities.includes('agent:delegate') || capabilities.includes('tools:orchestrate')
      ? downstreamTools
      : [];

    // Scoring formula:
    // Score combines 7 weighted vectors:
    // Destructive (0.25) + Process (0.20) + Credential (0.20) + Egress (0.15) + Persistence (0.10) + Downstream (0.10)
    let score = 0.0;
    if (destructiveCapabilities.length > 0) score += 0.25;
    if (spawnableProcesses.length > 0) score += 0.20;
    if (reachableCredentials.length > 0) score += 0.20;
    if (reachableDestinations.length > 0) score += 0.15;
    if (persistenceMechanisms.length > 0) score += 0.10;
    if (reachableDownstreamTools.length > 0) score += 0.10;

    // Chain depth amplification: deeper kill-chains multiply blast impact
    if (chainDepth > 1) {
      score = Math.min(1.0, score * (1 + (chainDepth - 1) * 0.15));
    }

    const highRiskFlag = score >= 0.5 || destructiveCapabilities.length > 0 || persistenceMechanisms.length > 0;

    return {
      score: Math.min(1.0, Math.max(0.0, Number(score.toFixed(3)))),
      modifiableFiles,
      spawnableProcesses,
      reachableCredentials,
      reachableDestinations,
      destructiveCapabilities,
      reachableDownstreamTools,
      persistenceMechanisms,
      highRiskFlag,
      rationale
    };
  }
}
