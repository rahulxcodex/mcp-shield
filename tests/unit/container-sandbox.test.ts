import { ContainerSandbox } from '../../src/sandbox/container-sandbox';

describe('ContainerSandbox', () => {
  it('should generate secure Docker CLI arguments with network isolation and dropped capabilities', () => {
    const sandbox = new ContainerSandbox({
      enabled: true,
      image: 'node:20-alpine',
      network: 'none',
      readOnlyRoot: true,
      dropCapabilities: ['ALL'],
      noNewPrivileges: true,
      memoryLimit: '256m',
      cpuQuota: '0.5',
      user: '1000:1000'
    });

    const dockerArgs = sandbox.buildDockerArgs('npx', ['@modelcontextprotocol/server-filesystem', '/workspace']);
    
    expect(dockerArgs).toContain('run');
    expect(dockerArgs).toContain('--rm');
    expect(dockerArgs).toContain('-i');
    expect(dockerArgs).toContain('--network=none');
    expect(dockerArgs).toContain('--read-only');
    expect(dockerArgs).toContain('--cap-drop=ALL');
    expect(dockerArgs).toContain('--security-opt=no-new-privileges');
    expect(dockerArgs).toContain('--memory=256m');
    expect(dockerArgs).toContain('--cpus=0.5');
    expect(dockerArgs).toContain('--user');
    expect(dockerArgs).toContain('1000:1000');
    expect(dockerArgs).toContain('node:20-alpine');
    expect(dockerArgs).toContain('npx');
    expect(dockerArgs).toContain('@modelcontextprotocol/server-filesystem');
  });

  it('should fallback to host command execution when disabled', () => {
    const sandbox = new ContainerSandbox({ enabled: false });
    const result = sandbox.spawnProcess('node', ['server.js']);

    expect(result.cmd).toBe('node');
    expect(result.args).toEqual(['server.js']);
  });

  it('should mount workspace directory into container', () => {
    const sandbox = new ContainerSandbox({
      enabled: true,
      workspaceMount: '/custom/workspace'
    });

    const dockerArgs = sandbox.buildDockerArgs('cat', ['file.txt']);
    const volumeIndex = dockerArgs.indexOf('-v');
    expect(volumeIndex).toBeGreaterThan(-1);
    expect(dockerArgs[volumeIndex + 1]).toContain('/workspace:rw');
    expect(dockerArgs).toContain('-w');
    expect(dockerArgs).toContain('/workspace');
  });
});
