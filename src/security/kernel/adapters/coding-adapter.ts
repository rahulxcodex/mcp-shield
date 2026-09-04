/**
 * MCP Shield - Coding Agent Protocol Adapter
 * Step 3 Roadmap - Section 18 & Milestone D
 *
 * Normalizes coding assistant tasks (run_command, edit_file, read_file, git_operation)
 * into canonical Kernel requests.
 */

import { ProtocolAdapter, CanonicalKernelRequest } from '../agent-security-kernel';

export interface CodingAgentPayload {
  operation: 'run_command' | 'edit_file' | 'write_file' | 'read_file' | 'git';
  command?: string;
  filePath?: string;
  fileContent?: string;
  gitArgs?: string[];
  cwd?: string;
}

export class CodingProtocolAdapter implements ProtocolAdapter {
  public readonly protocol = 'coding';

  public normalize(raw: CodingAgentPayload): CanonicalKernelRequest {
    const candidateCommands: string[] = [];
    const candidatePaths: string[] = [];
    const candidateUrls: string[] = [];

    if (raw.command) {
      candidateCommands.push(raw.command);
      // Extract any URLs from command
      const urlMatches = raw.command.match(/https?:\/\/[^\s"'>]+/gi);
      if (urlMatches) candidateUrls.push(...urlMatches);
    }
    if (raw.filePath) {
      candidatePaths.push(raw.filePath);
    }

    return {
      protocol: 'coding',
      callerIdentity: 'coding-agent-runner',
      actionName: `coding_${raw.operation}`,
      parameters: {
        operation: raw.operation,
        command: raw.command,
        filePath: raw.filePath,
        cwd: raw.cwd
      },
      candidateCommands,
      candidatePaths,
      candidateUrls,
      metadata: {
        capabilities: [
          raw.command ? 'shellExecution' : null,
          ['edit_file', 'write_file'].includes(raw.operation) ? 'filesystemWrite' : null,
          raw.operation === 'read_file' ? 'filesystemRead' : null
        ].filter(Boolean)
      }
    };
  }
}
