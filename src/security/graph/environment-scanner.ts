/**
 * MCP Shield - Environment-Specific Attack Discovery Scanner
 * Step 3 Roadmap - Section 17 & Milestone D
 *
 * Scans customer MCP environments, constructs an attack graph from tool capabilities,
 * enumerates dangerous multi-tool compositions, and generates actionable remediations.
 */

import { SecurityGraph, AttackGraphNode, AttackGraphEdge, AttackPathAnalysisResult } from './security-graph';
import { ToolCapabilities } from '../capabilities';

export interface DiscoveredTool {
  name: string;
  description?: string;
  capabilities: ToolCapabilities;
  destinationHosts?: string[];
  accessedAssets?: string[];
}

export interface AttackDiscoveryReport {
  scannedToolCount: number;
  criticalPathsFound: number;
  highestRiskScore: number;
  attackPaths: Array<{
    title: string;
    path: string[];
    riskScore: number;
    blastRadius: number;
    policyViolations: string[];
    syntheticPayload: Record<string, any>;
    remediation: string;
  }>;
  summary: string;
}

export class EnvironmentAttackScanner {
  /**
   * Scans an array of discovered tools in an MCP environment and constructs the capability graph
   */
  public static scanEnvironment(tools: DiscoveredTool[]): AttackDiscoveryReport {
    const graph = new SecurityGraph();

    // 1. Add common asset and destination sink nodes
    graph.addNode({ type: 'asset', id: 'asset:credentials', name: 'Credential Store / Environment Vault' });
    graph.addNode({ type: 'asset', id: 'asset:local_database', name: 'Internal Database Store' });
    graph.addNode({ type: 'destination', id: 'dest:external_internet', name: 'Untrusted External Internet Sink' });

    // 2. Populate tools and edges
    for (const tool of tools) {
      const toolNodeId = `tool:${tool.name}`;
      graph.addNode({
        type: 'tool',
        id: toolNodeId,
        name: tool.name,
        properties: {
          capabilities: Object.entries(tool.capabilities)
            .filter(([_, v]) => v)
            .map(([k]) => k)
        }
      });

      // Asset access edges
      if (tool.capabilities.secretAccess || /secret|vault|key|auth|cred/i.test(tool.name)) {
        graph.addEdge({
          source: 'asset:credentials',
          target: toolNodeId,
          relation: 'CAN_READ'
        });
      }

      if (tool.capabilities.filesystemRead) {
        graph.addEdge({
          source: 'asset:credentials',
          target: toolNodeId,
          relation: 'CAN_READ'
        });
      }

      if (/sql|db|database|mongo|postgres/i.test(tool.name)) {
        graph.addEdge({
          source: 'asset:local_database',
          target: toolNodeId,
          relation: 'CAN_READ'
        });
      }

      // Inter-tool composition: data passing or capability chains
      for (const other of tools) {
        if (tool.name === other.name) continue;
        const otherNodeId = `tool:${other.name}`;

        // If tool A reads and tool B spawns/executes/egresses
        if (tool.capabilities.filesystemRead && (other.capabilities.networkAccess || other.capabilities.shellExecution)) {
          graph.addEdge({
            source: toolNodeId,
            target: otherNodeId,
            relation: 'CAN_INVOKE'
          });
        }

        // If tool A transforms/encodes and tool B has egress
        if (/transform|encode|zip|tar|format|convert/i.test(tool.name) && other.capabilities.networkAccess) {
          graph.addEdge({
            source: toolNodeId,
            target: otherNodeId,
            relation: 'CAN_INVOKE'
          });
        }
      }

      // Egress edges
      if (tool.capabilities.networkAccess || /curl|fetch|http|post|upload/i.test(tool.name)) {
        graph.addEdge({
          source: toolNodeId,
          target: 'dest:external_internet',
          relation: 'CAN_CONTACT'
        });
      }
    }

    // 3. Enumerate critical attack paths from sensitive assets to external sinks
    const startNodes = ['asset:credentials', 'asset:local_database'];
    const endNodes = ['dest:external_internet'];
    const discoveredPaths: AttackDiscoveryReport['attackPaths'] = [];

    for (const start of startNodes) {
      for (const end of endNodes) {
        const analysis = graph.evaluateAttackPath(start, end);
        if (analysis.pathExists) {
          const syntheticPayload = {
            attackVector: 'COMPOSED_CAPABILITY_EXFILTRATION',
            stages: analysis.path.map(id => ({
              target: id,
              action: id.startsWith('tool:') ? 'invoke_with_staging_buffer' : 'access_resource'
            }))
          };

          const remediation = analysis.remediationRecommendation ||
            `Isolate tool nodes in chain [${analysis.path.join(' -> ')}] with zero-trust egress and filesystem scoping policies`;

          discoveredPaths.push({
            title: `Critical Exfiltration Chain (${start} -> ${end})`,
            path: analysis.path,
            riskScore: analysis.riskScore,
            blastRadius: analysis.blastRadiusScore,
            policyViolations: analysis.policyViolations,
            syntheticPayload,
            remediation
          });
        }
      }
    }

    // Sort by risk descending
    discoveredPaths.sort((a, b) => b.riskScore - a.riskScore);
    const highestRiskScore = discoveredPaths.length > 0 ? discoveredPaths[0].riskScore : 0;

    return {
      scannedToolCount: tools.length,
      criticalPathsFound: discoveredPaths.length,
      highestRiskScore,
      attackPaths: discoveredPaths,
      summary: discoveredPaths.length > 0
        ? `Found ${discoveredPaths.length} dangerous attack path composition(s) across ${tools.length} environment tools (Peak Risk: ${highestRiskScore}/100)`
        : `Environment capability graph is clean: no multi-tool attack paths from sensitive assets to external sinks.`
    };
  }
}
