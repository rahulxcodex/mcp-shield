/**
 * MCP Shield - MCP Protocol Adapter
 * Step 3 Roadmap - Section 18 & Milestone D
 *
 * Normalizes MCP JSON-RPC protocol requests (tools/call, tools/list, resources/read)
 * into canonical Kernel requests.
 */

import { ProtocolAdapter, CanonicalKernelRequest } from '../agent-security-kernel';

export class McpProtocolAdapter implements ProtocolAdapter {
  public readonly protocol = 'mcp';

  public normalize(rawRpc: any): CanonicalKernelRequest {
    const params = rawRpc?.params || {};
    const toolName = typeof params.name === 'string' ? params.name : (rawRpc?.method || 'unknown_mcp_action');
    const args = params.arguments && typeof params.arguments === 'object' ? params.arguments : {};

    const candidateCommands: string[] = [];
    const candidatePaths: string[] = [];
    const candidateUrls: string[] = [];
    let destination: string | undefined;

    for (const [k, v] of Object.entries(args)) {
      const lower = k.toLowerCase();
      if (typeof v === 'string') {
        if (['cmd', 'command', 'exec', 'script', 'shell', 'code'].includes(lower)) {
          candidateCommands.push(v);
        } else if (['path', 'file', 'filepath', 'dest', 'filename'].includes(lower)) {
          candidatePaths.push(v);
        } else if (['url', 'uri', 'endpoint', 'host'].includes(lower)) {
          candidateUrls.push(v);
          try {
            destination = new URL(v).hostname;
          } catch {
            destination = v;
          }
        }
      }
    }

    return {
      protocol: 'mcp',
      callerIdentity: rawRpc?.clientInfo?.name || 'mcp-client',
      actionName: toolName,
      parameters: args,
      candidateCommands,
      candidatePaths,
      candidateUrls,
      destination,
      metadata: {
        jsonrpcId: rawRpc?.id,
        method: rawRpc?.method
      }
    };
  }
}
