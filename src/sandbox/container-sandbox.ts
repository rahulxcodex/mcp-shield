import { spawn, ChildProcess, execSync } from 'child_process';
import * as path from 'path';

export interface ContainerSandboxOptions {
  enabled?: boolean;
  image?: string;
  network?: 'none' | 'bridge' | 'host';
  readOnlyRoot?: boolean;
  memoryLimit?: string;
  cpuQuota?: string;
  dropCapabilities?: string[];
  noNewPrivileges?: boolean;
  workspaceMount?: string;
  tmpfsMounts?: string[];
  user?: string;
  env?: Record<string, string>;
}

export class ContainerSandbox {
  private options: Required<ContainerSandboxOptions>;

  constructor(customOptions: ContainerSandboxOptions = {}) {
    this.options = {
      enabled: customOptions.enabled ?? false,
      image: customOptions.image || 'node:20-alpine',
      network: customOptions.network || 'none',
      readOnlyRoot: customOptions.readOnlyRoot ?? true,
      memoryLimit: customOptions.memoryLimit || '512m',
      cpuQuota: customOptions.cpuQuota || '1.0',
      dropCapabilities: customOptions.dropCapabilities || ['ALL'],
      noNewPrivileges: customOptions.noNewPrivileges ?? true,
      workspaceMount: customOptions.workspaceMount || process.cwd(),
      tmpfsMounts: customOptions.tmpfsMounts || ['/tmp', '/run'],
      user: customOptions.user || '1000:1000',
      env: customOptions.env || {}
    };
  }

  public isAvailable(): boolean {
    try {
      execSync('docker --version', { stdio: 'ignore' });
      return true;
    } catch {
      return false;
    }
  }

  public buildDockerArgs(targetCmd: string, targetArgs: string[]): string[] {
    const dockerArgs: string[] = ['run', '--rm', '-i'];

    // 1. Network isolation (Mitigate complex exfiltration & DNS rebinding)
    if (this.options.network) {
      dockerArgs.push(`--network=${this.options.network}`);
    }

    // 2. Read-only root filesystem (Mitigate host modification & persistence)
    if (this.options.readOnlyRoot) {
      dockerArgs.push('--read-only');
    }

    // 3. Capability dropping & privilege restrictions
    for (const cap of this.options.dropCapabilities) {
      dockerArgs.push(`--cap-drop=${cap}`);
    }

    if (this.options.noNewPrivileges) {
      dockerArgs.push('--security-opt=no-new-privileges');
    }

    // 4. Resource limits (Mitigate DoS, fork bombs & token/CPU burn)
    dockerArgs.push('--pids-limit=128');
    if (this.options.memoryLimit) {
      dockerArgs.push(`--memory=${this.options.memoryLimit}`);
    }
    if (this.options.cpuQuota) {
      dockerArgs.push(`--cpus=${this.options.cpuQuota}`);
    }

    // 5. Ephemeral tmpfs mounts
    for (const tmpfs of this.options.tmpfsMounts) {
      dockerArgs.push(`--tmpfs=${tmpfs}:rw,noexec,nosuid,size=64m`);
    }

    // 6. Workspace volume mounting
    if (this.options.workspaceMount) {
      const normalizedPath = path.resolve(this.options.workspaceMount).replace(/\\/g, '/');
      dockerArgs.push('-v', `${normalizedPath}:/workspace:rw`);
      dockerArgs.push('-w', '/workspace');
    }

    // 7. Unprivileged user execution
    if (this.options.user) {
      dockerArgs.push('--user', this.options.user);
    }

    // 8. Environment variables
    for (const [k, v] of Object.entries(this.options.env)) {
      dockerArgs.push('-e', `${k}=${v}`);
    }

    // 9. Base image and command
    dockerArgs.push(this.options.image);
    dockerArgs.push(targetCmd, ...targetArgs);

    return dockerArgs;
  }

  public spawnProcess(targetCmd: string, targetArgs: string[]): { cmd: string; args: string[] } {
    if (this.options.enabled) {
      if (!this.isAvailable()) {
        throw new Error(
          `[MCP-SHIELD] Zero-Trust Isolation Error: Container sandboxing is enabled in policy, but Docker daemon is unreachable. Refusing unisolated host execution.`
        );
      }
      return {
        cmd: 'docker',
        args: this.buildDockerArgs(targetCmd, targetArgs)
      };
    }

    // Raw execution when container isolation is explicitly disabled
    return {
      cmd: targetCmd,
      args: targetArgs
    };
  }
}
