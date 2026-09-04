import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { OSEnforcer } from '../../src/security/os-enforcer';

describe('OSEnforcer - Kernel & Operating System Boundary Enforcement', () => {
  let enforcer: OSEnforcer;
  let tempDir: string;

  beforeEach(() => {
    enforcer = new OSEnforcer();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-os-enforcer-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  describe('Seccomp Profile Generation', () => {
    it('generates a valid default seccomp-bpf JSON profile', () => {
      const profileJson = enforcer.generateSeccompProfile();
      const parsed = JSON.parse(profileJson);

      expect(parsed.defaultAction).toBe('SCMP_ACT_ERRNO');
      expect(Array.isArray(parsed.architectures)).toBe(true);
      expect(parsed.architectures).toContain('SCMP_ARCH_X86_64');
      expect(Array.isArray(parsed.syscalls)).toBe(true);

      const allowedRule = parsed.syscalls.find((r: any) => r.action === 'SCMP_ACT_ALLOW');
      expect(allowedRule).toBeDefined();
      expect(allowedRule.names).toContain('read');
      expect(allowedRule.names).toContain('openat');

      const blockedRule = parsed.syscalls.find((r: any) => r.action === 'SCMP_ACT_ERRNO');
      expect(blockedRule).toBeDefined();
      expect(blockedRule.names).toContain('ptrace');
      expect(blockedRule.names).toContain('mount');
    });

    it('respects custom seccomp profile overrides', () => {
      const profileJson = enforcer.generateSeccompProfile({
        defaultAction: 'SCMP_ACT_KILL',
        allowedSyscalls: ['read', 'write'],
        blockedSyscalls: ['reboot'],
      });
      const parsed = JSON.parse(profileJson);

      expect(parsed.defaultAction).toBe('SCMP_ACT_KILL');
      const allowed = parsed.syscalls.find((r: any) => r.action === 'SCMP_ACT_ALLOW');
      expect(allowed.names).toEqual(['read', 'write']);
      const blocked = parsed.syscalls.find((r: any) => r.action === 'SCMP_ACT_ERRNO');
      expect(blocked.names).toEqual(['reboot']);
    });
  });

  describe('AppArmor Profile Generation & Execution', () => {
    it('generates an AppArmor profile with specified network and path constraints', () => {
      const profile = enforcer.generateAppArmorProfile('mcp_sandbox_agent', {
        allowNetwork: false,
        allowSubprocesses: false,
        denyPaths: ['/etc/shadow', '/root/**'],
        readOnlyPaths: ['/usr/share/**'],
        readWritePaths: ['/tmp/mcp-workspace/**'],
      });

      expect(profile).toContain('profile mcp_sandbox_agent flags=(attach_disconnected,enforce)');
      expect(profile).toContain('deny network,');
      expect(profile).toContain('deny /etc/shadow rwx,');
      expect(profile).toContain('deny /root/** rwx,');
      expect(profile).toContain('/usr/share/** r,');
      expect(profile).toContain('/tmp/mcp-workspace/** rw,');
      expect(profile).toContain('deny /bin/** x,');
    });

    it('generates an AppArmor profile allowing network and subshell execution when requested', () => {
      const profile = enforcer.generateAppArmorProfile('mcp_permissive_agent', {
        allowNetwork: true,
        allowSubprocesses: true,
      });

      expect(profile).toContain('network inet tcp,');
      expect(profile).toContain('/bin/** ix,');
    });

    it('reports AppArmor availability cleanly without throwing', () => {
      const isAvailable = enforcer.isAppArmorAvailable();
      expect(typeof isAvailable).toBe('boolean');
    });

    it('wraps execution command with aa-exec or fallback', () => {
      const wrapped = enforcer.wrapAppArmorExec('test_profile', 'bash', ['-c', 'echo safe']);
      expect(wrapped.executable).toBeDefined();
      expect(Array.isArray(wrapped.args)).toBe(true);
    });
  });

  describe('Secure File Descriptor Opening & TOCTOU Defense', () => {
    it('safely opens, reads, and closes a valid file within jail boundaries', () => {
      const targetFile = path.join(tempDir, 'safe-file.txt');
      fs.writeFileSync(targetFile, 'Secure MCP Telemetry Content', 'utf8');

      const fd = enforcer.openSecurely(targetFile, { jailRoot: tempDir });
      expect(fd).toBeGreaterThanOrEqual(0);

      const buffer = enforcer.readSecurely(fd, 32);
      expect(buffer.toString('utf8')).toBe('Secure MCP Telemetry Content');

      expect(() => enforcer.closeSecurely(fd)).not.toThrow();
    });

    it('blocks path traversal when target escapes designated jailRoot', () => {
      const subDir = path.join(tempDir, 'sandbox');
      fs.mkdirSync(subDir);
      const outsideFile = path.join(tempDir, 'outside.txt');
      fs.writeFileSync(outsideFile, 'Sensitive Secret', 'utf8');

      expect(() => {
        enforcer.openSecurely(outsideFile, { jailRoot: subDir });
      }).toThrow(/Path traversal violation/);
    });

    it('blocks symlink traversal when allowSymlinks is false', () => {
      const targetFile = path.join(tempDir, 'target.txt');
      const symlinkFile = path.join(tempDir, 'link.txt');
      fs.writeFileSync(targetFile, 'Real Target', 'utf8');

      try {
        fs.symlinkSync(targetFile, symlinkFile);
        expect(() => {
          enforcer.openSecurely(symlinkFile, { allowSymlinks: false });
        }).toThrow(/Symlink traversal blocked/);
      } catch (err: any) {
        // On Windows without SeCreateSymbolicLinkPrivilege, symlinkSync may throw EPERM
        if (err.code !== 'EPERM') {
          throw err;
        }
      }
    });
  });

  describe('Landlock Linux Sandboxing', () => {
    it('generates declarative Landlock ruleset configuration with path boundaries', () => {
      const config = enforcer.generateLandlockConfig({
        readOnlyPaths: ['/usr', '/lib'],
        readWritePaths: ['/workspace/data'],
        executePaths: ['/usr/bin/node'],
      });

      expect(config.abiVersion).toBe(3);
      expect(config.handledAccessFs).toContain('LANDLOCK_ACCESS_FS_EXECUTE');
      expect(config.rules.some(r => r.path === '/usr')).toBe(true);
      expect(config.rules.some(r => r.path === '/workspace/data')).toBe(true);
    });

    it('wraps execution command with bubblewrap/bwrap containment', () => {
      const wrapped = enforcer.wrapLandlockBwrap('node', ['server.js'], {
        readOnlyPaths: ['/etc/ssl'],
        readWritePaths: ['/tmp/scratch'],
      });

      expect(wrapped.executable).toBe('bwrap');
      expect(wrapped.args).toContain('--unshare-all');
      expect(wrapped.args).toContain('--die-with-parent');
      expect(wrapped.args).toContain('server.js');
    });
  });

  describe('Linux Namespaces & Network Isolation', () => {
    it('generates unshare namespace options for PID, Mount, and Network', () => {
      const ns = enforcer.generateNamespaceConfig({
        pid: true,
        mount: true,
        net: true,
        ipc: true,
        uts: true,
        user: true,
      });

      expect(ns.unshareArgs).toContain('--mount');
      expect(ns.unshareArgs).toContain('--pid');
      expect(ns.unshareArgs).toContain('--net');
      expect(ns.flags).toContain('CLONE_NEWPID');
    });

    it('wraps execution with network namespace isolation', () => {
      const wrapped = enforcer.wrapNetworkNamespaceExec('curl', ['https://evil.com']);
      expect(wrapped.executable).toBe('unshare');
      expect(wrapped.args).toContain('--net');
    });
  });

  describe('Read-Only Rootfs & OverlayFS', () => {
    it('generates read-only bind mount and overlayfs staging commands', () => {
      const cfg = enforcer.generateReadOnlyRootfsConfig({
        rootPath: '/',
        workspacePath: '/app',
      });

      expect(cfg.rootMount).toBe('ro,bind');
      expect(cfg.tmpfsMounts).toContain('/tmp');
      expect(cfg.mountCommands.some(c => c.includes('ro'))).toBe(true);
      expect(cfg.mountCommands.some(c => c.includes('overlay'))).toBe(true);
    });
  });

  describe('MicroVM Containment Options', () => {
    it('generates Firecracker and Cloud-Hypervisor microVM configurations', () => {
      const fcConfig = enforcer.generateFirecrackerConfig({
        kernelImagePath: '/vmlinux',
        rootfsPath: '/rootfs.ext4',
        vcpus: 2,
        memSizeMib: 512,
        enableNetwork: false,
      });

      const parsedFc = JSON.parse(fcConfig);
      expect(parsedFc['boot-source'].kernel_image_path).toBe('/vmlinux');
      expect(parsedFc.drives[0].is_read_only).toBe(true);
      expect(parsedFc['machine-config'].vcpu_count).toBe(2);

      const chConfig = enforcer.generateCloudHypervisorConfig({
        kernelImagePath: '/vmlinux',
        rootfsPath: '/rootfs.ext4',
        vcpus: 4,
        memSizeMib: 1024,
      });
      const parsedCh = JSON.parse(chConfig);
      expect(parsedCh.kernel.path).toBe('/vmlinux');
      expect(parsedCh.cpus.boot_vcpus).toBe(4);
    });

    it('builds composite hardened execution command incorporating all active layers', () => {
      const cmd = enforcer.buildHardenedExecutionCommand('node', ['app.js'], {
        landlock: { readOnlyPaths: ['/usr'] },
        networkIsolation: true,
        namespaces: { pid: true },
      });

      expect(typeof cmd.executable).toBe('string');
      expect(cmd.args.length).toBeGreaterThan(2);
    });
  });
});
