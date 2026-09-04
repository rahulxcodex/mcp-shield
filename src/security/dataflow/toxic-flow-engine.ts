import * as crypto from 'crypto';

export type TaintTag =
  | 'TAINT_CREDENTIAL'
  | 'TAINT_SENSITIVE_FILE'
  | 'TAINT_DATABASE_RECORD'
  | 'TAINT_PII'
  | 'TAINT_UNTRUSTED_REMOTE'
  | 'TAINT_PROMPT_INJECTION';

export type SourceType =
  | 'FILESYSTEM'
  | 'DATABASE'
  | 'VAULT'
  | 'EXTERNAL_NETWORK'
  | 'USER_PROMPT'
  | 'TOOL_OUTPUT';

export type SinkType =
  | 'NETWORK_EGRESS'
  | 'FILESYSTEM_DESTRUCTIVE'
  | 'PROCESS_EXECUTION'
  | 'DATABASE_MUTATION';

export interface TaintedObject {
  id: string;
  originTool: string;
  sourceType: SourceType;
  tags: Set<TaintTag>;
  contentHash: string;
  rawSample?: string;
  extractedTokens: Set<string>;
  lineage: string[]; // ['read_database', 'compress_payload', 'encode_b64']
  timestamp: number;
}

export interface ToxicFlowViolation {
  violationId: string;
  isDangerous: boolean;
  sourceTool: string;
  sourceType: SourceType;
  sinkTool: string;
  sinkType: SinkType;
  lineagePath: string; // e.g. "query_database -> transform -> compress -> upload"
  taintTags: TaintTag[];
  riskScore: number;
  explanation: string;
  contributingNodes: string[];
}

export class ToxicFlowEngine {
  private taintedObjects: Map<string, TaintedObject> = new Map();
  private callHistory: Array<{
    toolName: string;
    capabilities: string[];
    args: Record<string, any>;
    output?: any;
    timestamp: number;
  }> = [];

  /**
   * Resets internal taint tracking registry and history.
   */
  public reset(): void {
    this.taintedObjects.clear();
    this.callHistory = [];
  }

  /**
   * Evaluates an in-flight tool step with semantic dataflow tracking across accumulated session calls.
   */
  public evaluateStep(
    toolName: string,
    capabilities: string[] = [],
    args: Record<string, any> = {},
    output?: any
  ): {
    action: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
    riskScore: number;
    dangerousChainIdentified: boolean;
    violation?: ToxicFlowViolation;
    chainExplanation?: string;
  } {
    const step = {
      toolName,
      capabilities,
      args,
      output,
      timestamp: Date.now(),
    };
    this.callHistory.push(step);

    const capsLower = capabilities.map(c => c.toLowerCase());
    const nameLower = toolName.toLowerCase();

    // 1. Identify if current tool is a Source
    const isSource = this.classifySource(nameLower, capsLower, args);
    if (isSource) {
      this.createTaintedObject(toolName, isSource.sourceType, isSource.tags, args, output);
    }

    // 2. Identify if current tool is a Transformation that receives prior tainted object
    const isTransform = this.classifyTransformation(nameLower, capsLower);
    if (isTransform) {
      this.propagateTaintThroughTransform(toolName, args, output);
    }

    // 3. Identify if current tool is a Sink
    const isSink = this.classifySink(nameLower, capsLower, args);
    if (isSink && this.taintedObjects.size > 0) {
      const toxicFlow = this.detectToxicFlowToSink(toolName, isSink, args);
      if (toxicFlow) {
        return {
          action: 'BLOCK',
          riskScore: toxicFlow.riskScore,
          dangerousChainIdentified: true,
          violation: toxicFlow,
          chainExplanation: toxicFlow.explanation,
        };
      }
    }

    return {
      action: 'ALLOW',
      riskScore: 0.1,
      dangerousChainIdentified: false,
    };
  }

  /**
   * Evaluates a declarative attack path with semantic data lineage verification.
   */
  public evaluateDeclarativePath(path: {
    id?: string;
    objective?: string;
    nodes: Array<{ id: string; toolName: string; capabilities: string[] }>;
    edges?: Array<{ from: string; to: string; dataFlow?: string }>;
  }): {
    action: 'ALLOW' | 'BLOCK';
    riskScore: number;
    dangerousChainIdentified: boolean;
    chainExplanation?: string;
  } {
    if (!path.nodes || path.nodes.length === 0) {
      return { action: 'ALLOW', riskScore: 0.0, dangerousChainIdentified: false };
    }

    let sourceNode: { id: string; toolName: string; capabilities: string[] } | null = null;
    let sinkNode: { id: string; toolName: string; capabilities: string[] } | null = null;
    const transformNodes: string[] = [];

    for (const node of path.nodes) {
      const nLower = node.toolName.toLowerCase();
      const cLower = node.capabilities.map(c => c.toLowerCase());

      if (!sourceNode && this.classifySource(nLower, cLower, {})) {
        sourceNode = node;
      } else if (this.classifySink(nLower, cLower, {})) {
        sinkNode = node;
      } else if (this.classifyTransformation(nLower, cLower)) {
        transformNodes.push(node.toolName);
      }
    }

    if (sourceNode && sinkNode) {
      const pathLineage = path.nodes.map(n => n.toolName).join(' -> ');
      const isExfil = path.objective === 'exfiltration' || transformNodes.length > 0;
      const explanation = `DANGEROUS MULTI-TOOL CHAIN: Semantic attack path detected across ${path.nodes.length} nodes (Source: ${sourceNode.toolName} -> Sink: ${sinkNode.toolName}). Objective: [${path.objective || 'exfiltration'}]. Path: ${pathLineage}`;

      return {
        action: 'BLOCK',
        riskScore: isExfil ? 0.95 : 0.88,
        dangerousChainIdentified: true,
        chainExplanation: explanation,
      };
    }

    return {
      action: 'ALLOW',
      riskScore: 0.1,
      dangerousChainIdentified: false,
    };
  }

  // --- INTERNAL SEMANTIC CLASSIFIERS ---

  private classifySource(
    name: string,
    caps: string[],
    args: Record<string, any>
  ): { sourceType: SourceType; tags: TaintTag[] } | null {
    if (
      caps.some(c => c === 'database' || c === 'db' || /\b(?:database|sql|postgres|mysql|sqlite)\b/i.test(c)) ||
      /\b(?:database|db|query|sql)\b/i.test(name)
    ) {
      return { sourceType: 'DATABASE', tags: ['TAINT_DATABASE_RECORD'] };
    }

    if (
      caps.some(c => c === 'secret' || c === 'vault' || c === 'credential' || /\b(?:secret|vault|credential|token)\b/i.test(c)) ||
      /\b(?:secret|vault|fetch_secret|credential)\b/i.test(name)
    ) {
      return { sourceType: 'VAULT', tags: ['TAINT_CREDENTIAL'] };
    }

    if (
      caps.some(c => c === 'read' || c === 'filesystem_read' || /\bread(?:_file)?\b/i.test(c)) ||
      /\bread(?:_file)?\b|get_file|\bcat\b/i.test(name)
    ) {
      return { sourceType: 'FILESYSTEM', tags: ['TAINT_SENSITIVE_FILE'] };
    }

    return null;
  }

  private classifyTransformation(name: string, caps: string[]): boolean {
    return (
      caps.some(c => /\b(?:transform|compression|compress|encode|export|zip|base64)\b/i.test(c)) ||
      /\b(?:transform|compress|export|zip|encode|base64)\b/i.test(name)
    );
  }

  private classifySink(
    name: string,
    caps: string[],
    args: Record<string, any>
  ): SinkType | null {
    if (
      caps.some(c => /\b(?:network|upload|egress|http|webhook|socket)\b/i.test(c)) ||
      /\b(?:upload|post|send|curl|webhook|http|network)\b/i.test(name)
    ) {
      return 'NETWORK_EGRESS';
    }

    if (
      caps.some(c => c === 'destructive' || /\b(?:delete|destroy|truncate|unlink|drop)\b/i.test(c) || c === 'rm') ||
      /\b(?:delete|destroy|truncate|unlink|drop)\b/i.test(name) ||
      /(?:^|_)rm(?:_|$)/i.test(name)
    ) {
      return 'FILESYSTEM_DESTRUCTIVE';
    }

    if (
      caps.some(c => /\b(?:shell|subprocess|exec|eval|binary)\b/i.test(c)) ||
      /\b(?:exec|eval|bash|cmd|powershell|spawn)\b/i.test(name)
    ) {
      return 'PROCESS_EXECUTION';
    }

    return null;
  }

  private createTaintedObject(
    toolName: string,
    sourceType: SourceType,
    tags: TaintTag[],
    args: Record<string, any>,
    output?: any
  ): TaintedObject {
    const id = `taint-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const rawData = JSON.stringify(output || args);
    const contentHash = crypto.createHash('sha256').update(rawData).digest('hex');

    const tokens = new Set<string>();
    // Extract non-trivial tokens from source
    const words = rawData.match(/[A-Za-z0-9_\-\.]{6,}/g) || [];
    for (const w of words) {
      tokens.add(w.toLowerCase());
    }

    const taintedObj: TaintedObject = {
      id,
      originTool: toolName,
      sourceType,
      tags: new Set(tags),
      contentHash,
      rawSample: rawData.slice(0, 200),
      extractedTokens: tokens,
      lineage: [toolName],
      timestamp: Date.now(),
    };

    this.taintedObjects.set(id, taintedObj);
    return taintedObj;
  }

  private propagateTaintThroughTransform(
    toolName: string,
    args: Record<string, any>,
    output?: any
  ): void {
    const rawArgs = JSON.stringify(args).toLowerCase();

    for (const [id, tainted] of this.taintedObjects.entries()) {
      let isCrossToolTransfer = false;

      // Check token intersection
      for (const token of tainted.extractedTokens) {
        if (rawArgs.includes(token)) {
          isCrossToolTransfer = true;
          break;
        }
      }

      // If this tool immediately follows source/transform in history
      if (!isCrossToolTransfer && this.callHistory.length >= 2) {
        const prevCall = this.callHistory[this.callHistory.length - 2];
        if (tainted.lineage[tainted.lineage.length - 1] === prevCall.toolName) {
          isCrossToolTransfer = true;
        }
      }

      if (isCrossToolTransfer) {
        tainted.lineage.push(toolName);
        if (output) {
          const rawOut = JSON.stringify(output).toLowerCase();
          const outWords = rawOut.match(/[A-Za-z0-9_\-\.]{6,}/g) || [];
          for (const w of outWords) {
            tainted.extractedTokens.add(w);
          }
        }
      }
    }
  }

  private detectToxicFlowToSink(
    sinkToolName: string,
    sinkType: SinkType,
    args: Record<string, any>
  ): ToxicFlowViolation | null {
    const rawArgs = JSON.stringify(args).toLowerCase();

    for (const [id, tainted] of this.taintedObjects.entries()) {
      let hasDataLineage = false;

      // 1. Check direct token containment in sink arguments
      for (const token of tainted.extractedTokens) {
        if (rawArgs.includes(token)) {
          hasDataLineage = true;
          break;
        }
      }

      // 2. Check sequential execution lineage (source/transform -> sink in recent calls)
      if (!hasDataLineage && this.callHistory.length >= 2) {
        const lastStep = tainted.lineage[tainted.lineage.length - 1];
        const recentHistory = this.callHistory.slice(-5).map(c => c.toolName);
        if (recentHistory.includes(lastStep)) {
          hasDataLineage = true;
        }
      }

      if (hasDataLineage) {
        const fullLineage = [...tainted.lineage, sinkToolName];
        const lineagePath = fullLineage.join(' -> ');
        const tagsArray = Array.from(tainted.tags);

        const explanation = `TOXIC FLOW DETECTED: Tainted data from [${tainted.originTool}] (${tainted.sourceType}) flowed through [${lineagePath}] into dangerous sink [${sinkToolName}] (${sinkType}).`;

        return {
          violationId: `violation-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
          isDangerous: true,
          sourceTool: tainted.originTool,
          sourceType: tainted.sourceType,
          sinkTool: sinkToolName,
          sinkType,
          lineagePath,
          taintTags: tagsArray,
          riskScore: 0.96,
          explanation,
          contributingNodes: fullLineage,
        };
      }
    }

    return null;
  }
}
