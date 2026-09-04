/**
 * MCP Shield - Machine Learning Feature Extraction Pipeline
 * Step 3 Roadmap - Sections 2.1 - 2.4 & Milestone A
 *
 * Extracts versioned, reproducible tabular feature vectors across:
 * - Tool features (schema complexity, capability flags, publisher trust)
 * - Request features (entropy, encodings, shell metacharacters, prompt-injection signals)
 * - Behavioral features (tool sequence sliding windows, multi-step transition chains)
 * - Provenance features (schema/binary fingerprints, historical violations)
 */

import * as crypto from 'crypto';
import { ToolCapabilities } from '../capabilities';
import { SecurityEvidence } from '../evidence';
import { isSpecialIpRepresentation } from '../ip-utils';

export const FEATURE_SCHEMA_VERSION = '1.0.0';

export interface ToolContext {
  toolName: string;
  schema?: any;
  declaredCapabilities?: ToolCapabilities;
  inferredCapabilities?: ToolCapabilities;
  effectiveCapabilities?: ToolCapabilities;
  publisherIdentity?: string;
  publisherTrustScore?: number; // 0.0 to 1.0
  serverAgeDays?: number;
  historicalIncidentCount?: number;
  hasSchemaDrift?: boolean;
}

export interface RequestPayloadContext {
  rawBody: string | Record<string, any>;
  extractedCommands?: string[];
  extractedPaths?: string[];
  candidateUrls?: string[];
  secretFindingsCount?: number;
  deterministicEvidence?: SecurityEvidence[];
}

export interface BehavioralSequenceContext {
  toolHistory: string[]; // chronological tool invocations
  capabilityHistory?: string[]; // e.g. ['filesystem.read', 'process.spawn', 'network.egress']
  destinations?: string[];
}

export interface ProvenanceContext {
  binaryHashChanged?: boolean;
  dependencyGraphChanged?: boolean;
  schemaFingerprintChanged?: boolean;
  firstSeenTimestamp?: number;
  deploymentHistoryScore?: number; // 0.0 to 1.0 (1.0 = mature/stable)
  previousViolationsCount?: number;
}

export interface FeatureVector {
  schemaVersion: string;
  timestamp: number;
  values: Record<string, number>;
  denseVector: number[];
  featureNames: string[];
}

export class FeatureExtractor {
  public static readonly FEATURE_NAMES: string[] = [
    // 2.1 Tool Features (14)
    'tool_schema_complexity',
    'tool_param_count',
    'tool_cap_fs_read',
    'tool_cap_fs_write',
    'tool_cap_process_spawn',
    'tool_cap_network_egress',
    'tool_cap_secret_access',
    'tool_cap_db_access',
    'tool_destructive_capability',
    'tool_capability_mismatch',
    'tool_schema_drift',
    'tool_publisher_trust',
    'tool_server_age_days',
    'tool_historical_incidents',

    // 2.2 Request Features (11)
    'req_payload_size_bytes',
    'req_entropy',
    'req_encoding_count',
    'req_url_count',
    'req_ip_literals',
    'req_special_ip_rep',
    'req_shell_metachars',
    'req_interpreter_transitions',
    'req_path_traversal_indicators',
    'req_secret_findings',
    'req_prompt_injection_signals',

    // 2.3 Behavioral Transition Features (10)
    'seq_unique_tools_last_5',
    'seq_unique_tools_last_10',
    'seq_trans_read_to_network',
    'seq_trans_read_encode_network',
    'seq_trans_db_to_export',
    'seq_trans_db_export_upload',
    'seq_trans_fs_archive_upload',
    'seq_trans_new_cap_external_dest',
    'seq_velocity_ops_per_min',
    'seq_unseen_tool_transition',

    // 2.4 Provenance Features (7)
    'prov_binary_hash_changed',
    'prov_dep_graph_changed',
    'prov_schema_fingerprint_changed',
    'prov_publisher_identity_score',
    'prov_first_seen_days',
    'prov_deployment_history_score',
    'prov_previous_violations'
  ];

  /**
   * Calculates Shannon entropy of a string (in bits per byte, 0.0 to 8.0)
   */
  public static calculateEntropy(input: string): number {
    if (!input || input.length === 0) return 0.0;
    const freq: Record<string, number> = {};
    for (let i = 0; i < input.length; i++) {
      const char = input[i];
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0.0;
    const len = input.length;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 1000) / 1000;
  }

  /**
   * Extracts schema complexity (node count + depth)
   */
  public static calculateSchemaComplexity(schema: any): { complexity: number; paramCount: number } {
    if (!schema || typeof schema !== 'object') {
      return { complexity: 0, paramCount: 0 };
    }

    let nodes = 0;
    let params = 0;
    const traverse = (obj: any, depth = 0) => {
      if (!obj || depth > 10) return;
      nodes++;
      if (obj.properties && typeof obj.properties === 'object') {
        const keys = Object.keys(obj.properties);
        params += keys.length;
        for (const k of keys) {
          traverse(obj.properties[k], depth + 1);
        }
      }
      if (obj.items && typeof obj.items === 'object') {
        traverse(obj.items, depth + 1);
      }
    };

    traverse(schema);
    return { complexity: nodes, paramCount: params };
  }

  /**
   * Counts common encodings (Base64, URL percent-encoding, Hex strings)
   */
  public static countEncodings(text: string): number {
    if (!text) return 0;
    let count = 0;
    // URL hex escapes (%20, %2e, etc)
    const urlMatches = text.match(/%[0-9a-fA-F]{2}/g);
    if (urlMatches) count += urlMatches.length;

    // Hex literals (0x41, \x41)
    const hexMatches = text.match(/(?:0x|\\x)[0-9a-fA-F]{2}/g);
    if (hexMatches) count += hexMatches.length;

    // Base64-like blocks (>= 24 chars of valid base64)
    const b64Matches = text.match(/[A-Za-z0-9+/]{24,}={0,2}/g);
    if (b64Matches) count += b64Matches.length * 2;

    return count;
  }

  /**
   * Scans for prompt injection heuristics
   */
  public static countPromptInjectionSignals(text: string): number {
    if (!text) return 0;
    const patterns = [
      /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i,
      /disregard\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i,
      /you\s+are\s+now\s+in\s+developer\s+mode/i,
      /bypass\s+(?:all\s+)?security\s+rules/i,
      /system\s+prompt\s*:/i,
      /system\s+override/i,
      /<system>[\s\S]*?<\/system>/i,
      /jailbreak/i,
      /DAN\s+mode/i,
      /do\s+anything\s+now/i
    ];

    let signals = 0;
    for (const pat of patterns) {
      if (pat.test(text)) signals++;
    }
    return signals;
  }

  /**
   * Extracts the complete typed feature vector
   */
  public static extractFeatures(params: {
    tool: ToolContext;
    request: RequestPayloadContext;
    behavior?: BehavioralSequenceContext;
    provenance?: ProvenanceContext;
  }): FeatureVector {
    const { tool, request, behavior, provenance } = params;

    const rawString = typeof request.rawBody === 'string'
      ? request.rawBody
      : JSON.stringify(request.rawBody || {});

    const schemaMetrics = this.calculateSchemaComplexity(tool.schema);
    const entropy = this.calculateEntropy(rawString);
    const encodingCount = this.countEncodings(rawString);

    // Shell metacharacters: ; & | ` $ ( ) < > \n \r
    const shellMetaMatches = rawString.match(/[;&|`$()<>\n\r]/g);
    const shellMetachars = shellMetaMatches ? shellMetaMatches.length : 0;

    // Traversal indicators: ../, ..\, %2e%2e
    const traversalMatches = rawString.match(/(?:\.\.[\/\\]|%2e%2e[\/\\]|\.\.%2f|\.\.%5c)/gi);
    const traversalCount = traversalMatches ? traversalMatches.length : 0;

    // URL count
    const urlMatches = rawString.match(/https?:\/\/[^\s"'>]+/gi);
    const urlCount = (urlMatches ? urlMatches.length : 0) + (request.candidateUrls ? request.candidateUrls.length : 0);

    // IP literals
    const ipMatches = rawString.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
    const ipLiteralCount = ipMatches ? ipMatches.length : 0;

    // Special IP representations (0x7f, octal, dword)
    let specialIpCount = 0;
    if (ipMatches) {
      for (const ip of ipMatches) {
        if (isSpecialIpRepresentation(ip)) specialIpCount++;
      }
    }
    const hexOrDwordIp = rawString.match(/\b(?:0x[0-9a-fA-F]{1,8}|0[0-7]{6,11}|\d{10})\b/g);
    if (hexOrDwordIp) {
      for (const candidate of hexOrDwordIp) {
        if (isSpecialIpRepresentation(candidate)) specialIpCount++;
      }
    }

    // Prompt injection signals
    const promptInjectionSignals = this.countPromptInjectionSignals(rawString);

    // Interpreter transitions
    let interpTransitions = 0;
    if (request.extractedCommands) {
      for (const cmd of request.extractedCommands) {
        if (/(?:bash|sh|cmd\.exe|powershell|pwsh|python|perl|node|ruby|php)\s+-c/i.test(cmd)) {
          interpTransitions++;
        }
      }
    }

    // Capabilities
    const effCap = tool.effectiveCapabilities || tool.inferredCapabilities || {
      filesystemRead: false,
      filesystemWrite: false,
      shellExecution: false,
      networkAccess: false,
      processSpawn: false,
      destructiveOperation: false,
      secretAccess: false
    };

    const declaredCap = tool.declaredCapabilities;
    let capabilityMismatch = 0;
    if (declaredCap) {
      // If declared does not include inferred critical flags
      if (effCap.networkAccess && !declaredCap.networkAccess) capabilityMismatch += 1;
      if (effCap.filesystemWrite && !declaredCap.filesystemWrite) capabilityMismatch += 1;
      if (effCap.shellExecution && !declaredCap.shellExecution) capabilityMismatch += 1;
      if (effCap.processSpawn && !declaredCap.processSpawn) capabilityMismatch += 1;
    }

    // Database access heuristic
    const isDbAccess = /sql|database|postgres|mysql|sqlite|mongo|dynamo|redis/i.test(tool.toolName) ? 1 : 0;

    // Destructive score
    let destructiveScore = effCap.destructiveOperation ? 1.0 : 0.0;
    if (/delete|drop|truncate|purge|destroy|rmdir|unlink/i.test(tool.toolName) || /rm\s+-rf|del\s+\/f/i.test(rawString)) {
      destructiveScore = 1.0;
    }

    // Behavioral sequence features
    const toolHistory = behavior?.toolHistory || [];
    const fullSequence = [...toolHistory, tool.toolName].join(' -> ').toLowerCase();
    const last5 = toolHistory.slice(-5);
    const last10 = toolHistory.slice(-10);
    const uniqueLast5 = new Set(last5).size;
    const uniqueLast10 = new Set(last10).size;

    // Derived transitions
    const hasEgressTarget = urlCount > 0 || /(?:https?:\/\/|curl|wget|nc\s+|upload|post|fetch)/i.test(rawString) || effCap.networkAccess;
    const transReadToNetwork = ((/read/.test(fullSequence) && hasEgressTarget) || /read.*->.*(?:network|fetch|curl|http|post|send|upload)/.test(fullSequence)) ? 1 : 0;
    const transReadEncodeNetwork = ((/read/.test(fullSequence) && /(?:encode|base64|compress|tar|zip)/.test(fullSequence) && hasEgressTarget) || /read.*->.*(?:encode|base64|compress|tar|zip).*->.*(?:network|upload|post)/.test(fullSequence)) ? 1 : 0;
    const transDbToExport = (/database|db|sql/.test(fullSequence) && /export|dump|select|backup/.test(fullSequence)) || (isDbAccess && /export|dump|select|backup/i.test(rawString)) ? 1 : 0;
    const transDbExportUpload = (((isDbAccess > 0) || /database|db|sql/.test(fullSequence)) && hasEgressTarget) || /database.*->.*(?:export|dump).*->.*(?:upload|post|curl|network)/.test(fullSequence) ? 1 : 0;
    const transFsArchiveUpload = ((/file|read/.test(fullSequence) && /(?:tar|zip|archive)/.test(fullSequence) && hasEgressTarget) || /(?:file|read).*->.*(?:tar|zip|archive).*->.*(?:upload|post|send)/.test(fullSequence)) ? 1 : 0;
    const transNewCapExternalDest = (capabilityMismatch > 0 && hasEgressTarget) ? 1 : 0;

    // Construct feature dictionary
    const values: Record<string, number> = {
      // 2.1 Tool
      tool_schema_complexity: schemaMetrics.complexity,
      tool_param_count: schemaMetrics.paramCount,
      tool_cap_fs_read: effCap.filesystemRead ? 1 : 0,
      tool_cap_fs_write: effCap.filesystemWrite ? 1 : 0,
      tool_cap_process_spawn: effCap.processSpawn ? 1 : 0,
      tool_cap_network_egress: effCap.networkAccess ? 1 : 0,
      tool_cap_secret_access: effCap.secretAccess ? 1 : 0,
      tool_cap_db_access: isDbAccess,
      tool_destructive_capability: destructiveScore,
      tool_capability_mismatch: capabilityMismatch,
      tool_schema_drift: tool.hasSchemaDrift ? 1 : 0,
      tool_publisher_trust: tool.publisherTrustScore ?? 0.5,
      tool_server_age_days: tool.serverAgeDays ?? 30,
      tool_historical_incidents: tool.historicalIncidentCount ?? 0,

      // 2.2 Request
      req_payload_size_bytes: Buffer.byteLength(rawString, 'utf8'),
      req_entropy: entropy,
      req_encoding_count: encodingCount,
      req_url_count: urlCount,
      req_ip_literals: ipLiteralCount,
      req_special_ip_rep: specialIpCount,
      req_shell_metachars: shellMetachars,
      req_interpreter_transitions: interpTransitions,
      req_path_traversal_indicators: traversalCount,
      req_secret_findings: request.secretFindingsCount ?? 0,
      req_prompt_injection_signals: promptInjectionSignals,

      // 2.3 Behavioral Transitions
      seq_unique_tools_last_5: uniqueLast5,
      seq_unique_tools_last_10: uniqueLast10,
      seq_trans_read_to_network: transReadToNetwork,
      seq_trans_read_encode_network: transReadEncodeNetwork,
      seq_trans_db_to_export: transDbToExport,
      seq_trans_db_export_upload: transDbExportUpload,
      seq_trans_fs_archive_upload: transFsArchiveUpload,
      seq_trans_new_cap_external_dest: transNewCapExternalDest,
      seq_velocity_ops_per_min: toolHistory.length,
      seq_unseen_tool_transition: toolHistory.length > 0 && !toolHistory.includes(tool.toolName) ? 1 : 0,

      // 2.4 Provenance
      prov_binary_hash_changed: provenance?.binaryHashChanged ? 1 : 0,
      prov_dep_graph_changed: provenance?.dependencyGraphChanged ? 1 : 0,
      prov_schema_fingerprint_changed: provenance?.schemaFingerprintChanged ? 1 : 0,
      prov_publisher_identity_score: provenance?.deploymentHistoryScore ?? 0.8,
      prov_first_seen_days: provenance?.firstSeenTimestamp
        ? Math.max(0, Math.floor((Date.now() - provenance.firstSeenTimestamp) / (1000 * 60 * 60 * 24)))
        : 14,
      prov_deployment_history_score: provenance?.deploymentHistoryScore ?? 0.9,
      prov_previous_violations: provenance?.previousViolationsCount ?? 0
    };

    const denseVector = this.FEATURE_NAMES.map(name => values[name] ?? 0);

    return {
      schemaVersion: FEATURE_SCHEMA_VERSION,
      timestamp: Date.now(),
      values,
      denseVector,
      featureNames: [...this.FEATURE_NAMES]
    };
  }
}
