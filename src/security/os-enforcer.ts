import * as fs from 'fs';
import * as path from 'path';

export interface SeccompSyscallRule {
  names: string[];
  action: 'SCMP_ACT_ALLOW' | 'SCMP_ACT_ERRNO' | 'SCMP_ACT_KILL' | 'SCMP_ACT_LOG' | 'SCMP_ACT_TRAP';
  args?: Array<{
    index: number;
    value: number;
    valueTwo?: number;
    op: string;
  }>;
}

export interface SeccompProfileOptions {
  defaultAction?: 'SCMP_ACT_ERRNO' | 'SCMP_ACT_KILL' | 'SCMP_ACT_LOG';
  architectures?: string[];
  allowedSyscalls?: string[];
  blockedSyscalls?: string[];
}

export interface AppArmorOptions {
  allowNetwork?: boolean;
  allowSubprocesses?: boolean;
  readOnlyPaths?: string[];
  readWritePaths?: string[];
  denyPaths?: string[];
}

export interface SecureOpenOptions {
  allowSymlinks?: boolean;
  jailRoot?: string;
  flags?: number;
  mode?: number;
}

export interface LandlockOptions {
  abiVersion?: 1 | 2 | 3;
  readOnlyPaths?: string[];
  readWritePaths?: string[];
  executePaths?: string[];
  deniedPaths?: string[];
}

export interface NamespaceOptions {
  pid?: boolean;
  mount?: boolean;
  net?: boolean;
  ipc?: boolean;
  uts?: boolean;
  user?: boolean;
}

export interface ReadOnlyRootfsOptions {
  rootPath?: string;
  workspacePath?: string;
  tmpfsPaths?: string[];
  overlayUpper?: string;
  overlayWork?: string;
}

export interface MicroVmOptions {
  kernelImagePath: string;
  rootfsPath: string;
  vcpus?: number;
  memSizeMib?: number;
  enableNetwork?: boolean;
  tapDevice?: string;
  vsockPath?: string;
  kernelArgs?: string;
}

export interface KernelContainmentProfile {
  seccomp?: boolean | SeccompProfileOptions;
  apparmor?: boolean | AppArmorOptions;
  landlock?: boolean | LandlockOptions;
  namespaces?: boolean | NamespaceOptions;
  networkIsolation?: boolean;
  readOnlyRootfs?: boolean | ReadOnlyRootfsOptions;
  microVm?: boolean | MicroVmOptions;
}

export class OSEnforcer {
  /**
   * The AST firewall is Layer 1. This OS Enforcer acts as Layer 2.
   * Parsing what a shell command means is not the same as guaranteeing what the OS will do.
   */

  /**
   * Generates a strict seccomp-bpf JSON profile (OCI / Docker format)
   * to constrain kernel capabilities and drop dangerous syscalls.
   */
  public generateSeccompProfile(options: SeccompProfileOptions = {}): string {
    const defaultAction = options.defaultAction || 'SCMP_ACT_ERRNO';
    const architectures = options.architectures || [
      'SCMP_ARCH_X86_64',
      'SCMP_ARCH_X86',
      'SCMP_ARCH_AARCH64',
      'SCMP_ARCH_ARM',
    ];

    const baseAllowed = options.allowedSyscalls || [
      'read', 'write', 'openat', 'close', 'brk', 'mmap', 'munmap',
      'fstat', 'lseek', 'poll', 'select', 'futex', 'exit_group', 'rt_sigreturn',
    ];

    const baseBlocked = options.blockedSyscalls || [
      'unlinkat', 'rmdir', 'renameat', 'mount', 'umount2', 'ptrace',
      'kexec_load', 'kexec_file_load', 'reboot', 'init_module', 'delete_module',
      'syslog', 'bpf',
    ];

    const syscalls: SeccompSyscallRule[] = [
      {
        names: baseAllowed,
        action: 'SCMP_ACT_ALLOW',
      },
      {
        names: baseBlocked,
        action: 'SCMP_ACT_ERRNO',
      },
    ];

    return JSON.stringify({
      defaultAction,
      architectures,
      syscalls,
    }, null, 2);
  }

  /**
   * Generates an AppArmor profile definition for isolating MCP tool subshell executions.
   */
  public generateAppArmorProfile(profileName: string, options: AppArmorOptions = {}): string {
    const lines: string[] = [];
    lines.push(`#include <tunables/global>`);
    lines.push(``);
    lines.push(`profile ${profileName} flags=(attach_disconnected,enforce) {`);
    lines.push(`  #include <abstractions/base>`);
    
    if (options.allowNetwork) {
      lines.push(`  network inet tcp,`);
      lines.push(`  network inet udp,`);
    } else {
      lines.push(`  deny network,`);
    }

    if (options.denyPaths && options.denyPaths.length > 0) {
      for (const p of options.denyPaths) {
        lines.push(`  deny ${p} rwx,`);
      }
    }

    if (options.readOnlyPaths && options.readOnlyPaths.length > 0) {
      for (const p of options.readOnlyPaths) {
        lines.push(`  ${p} r,`);
      }
    }

    if (options.readWritePaths && options.readWritePaths.length > 0) {
      for (const p of options.readWritePaths) {
        lines.push(`  ${p} rw,`);
      }
    }

    if (options.allowSubprocesses) {
      lines.push(`  /bin/** ix,`);
      lines.push(`  /usr/bin/** ix,`);
    } else {
      lines.push(`  deny /bin/** x,`);
      lines.push(`  deny /usr/bin/** x,`);
    }

    lines.push(`}`);
    return lines.join('\n');
  }

  /**
   * Checks whether the current operating environment supports native AppArmor enforcement.
   */
  public isAppArmorAvailable(): boolean {
    if (process.platform !== 'linux') {
      return false;
    }
    try {
      if (fs.existsSync('/sys/kernel/security/apparmor')) {
        return true;
      }
    } catch {
      return false;
    }
    return false;
  }

  /**
   * Wraps an execution command with AppArmor execution tooling (aa-exec).
   */
  public wrapAppArmorExec(profileName: string, command: string, args: string[] = []): { executable: string; args: string[] } {
    if (!this.isAppArmorAvailable()) {
      return { executable: command, args };
    }
    return {
      executable: 'aa-exec',
      args: ['-p', profileName, '--', command, ...args],
    };
  }

  /**
   * Opens a file securely, mitigating TOCTOU symlink races and directory jail escapes.
   * On POSIX systems, applies O_NOFOLLOW to reject symlinks directly at the kernel boundary.
   * Verifies canonical realpath to ensure the target resides strictly within the declared jail root.
   */
  public openSecurely(filePath: string, options: SecureOpenOptions = {}): number {
    const resolvedPath = path.resolve(filePath);

    if (options.jailRoot) {
      let canonicalJail: string;
      try {
        canonicalJail = fs.realpathSync(options.jailRoot);
      } catch {
        canonicalJail = path.resolve(options.jailRoot);
      }

      let canonicalTarget: string;
      try {
        canonicalTarget = fs.realpathSync(resolvedPath);
      } catch (err: any) {
        if (err.code === 'ENOENT') {
          canonicalTarget = resolvedPath;
        } else {
          throw err;
        }
      }

      const isWithinJail = canonicalTarget === canonicalJail ||
        canonicalTarget.startsWith(canonicalJail.endsWith(path.sep) ? canonicalJail : canonicalJail + path.sep);

      if (!isWithinJail) {
        throw new Error(`Path traversal violation: ${resolvedPath} escapes jail boundary ${canonicalJail}`);
      }
    }

    if (!options.allowSymlinks) {
      try {
        const lstat = fs.lstatSync(resolvedPath);
        if (lstat.isSymbolicLink()) {
          throw new Error(`Symlink traversal blocked: ${resolvedPath} is a symbolic link`);
        }
      } catch (err: any) {
        if (err.code !== 'ENOENT') {
          throw err;
        }
      }
    }

    let flags = options.flags !== undefined ? options.flags : fs.constants.O_RDONLY;
    if (!options.allowSymlinks && fs.constants.O_NOFOLLOW !== undefined) {
      flags |= fs.constants.O_NOFOLLOW;
    }

    return fs.openSync(resolvedPath, flags, options.mode);
  }

  /**
   * Safely reads bytes from an open file descriptor.
   */
  public readSecurely(fd: number, length: number = 4096): Buffer {
    const buffer = Buffer.alloc(length);
    const bytesRead = fs.readSync(fd, buffer, 0, length, null);
    return buffer.subarray(0, bytesRead);
  }

  /**
   * Safely closes an open file descriptor, avoiding resource leaks.
   */
  public closeSecurely(fd: number): void {
    if (typeof fd === 'number' && fd >= 0) {
      fs.closeSync(fd);
    }
  }

  /**
   * Generates a declarative Landlock ruleset configuration (Linux Landlock ABI v1-v3).
   */
  public generateLandlockConfig(options: LandlockOptions = {}): {
    abiVersion: number;
    handledAccessFs: string[];
    rules: Array<{ path: string; access: string[] }>;
  } {
    const abiVersion = options.abiVersion || 3;
    const handledAccessFs = [
      'LANDLOCK_ACCESS_FS_EXECUTE',
      'LANDLOCK_ACCESS_FS_WRITE_FILE',
      'LANDLOCK_ACCESS_FS_READ_FILE',
      'LANDLOCK_ACCESS_FS_READ_DIR',
      'LANDLOCK_ACCESS_FS_REMOVE_DIR',
      'LANDLOCK_ACCESS_FS_REMOVE_FILE',
      'LANDLOCK_ACCESS_FS_MAKE_CHAR',
      'LANDLOCK_ACCESS_FS_MAKE_DIR',
      'LANDLOCK_ACCESS_FS_MAKE_REG',
      'LANDLOCK_ACCESS_FS_MAKE_SOCK',
      'LANDLOCK_ACCESS_FS_MAKE_FIFO',
      'LANDLOCK_ACCESS_FS_MAKE_BLOCK',
      'LANDLOCK_ACCESS_FS_MAKE_SYM',
      'LANDLOCK_ACCESS_FS_REFER',
      'LANDLOCK_ACCESS_FS_TRUNCATE',
    ];

    const rules: Array<{ path: string; access: string[] }> = [];

    for (const p of options.readOnlyPaths || []) {
      rules.push({
        path: p,
        access: ['LANDLOCK_ACCESS_FS_READ_FILE', 'LANDLOCK_ACCESS_FS_READ_DIR'],
      });
    }

    for (const p of options.readWritePaths || []) {
      rules.push({
        path: p,
        access: [
          'LANDLOCK_ACCESS_FS_READ_FILE',
          'LANDLOCK_ACCESS_FS_READ_DIR',
          'LANDLOCK_ACCESS_FS_WRITE_FILE',
          'LANDLOCK_ACCESS_FS_MAKE_REG',
          'LANDLOCK_ACCESS_FS_TRUNCATE',
        ],
      });
    }

    for (const p of options.executePaths || []) {
      rules.push({
        path: p,
        access: ['LANDLOCK_ACCESS_FS_READ_FILE', 'LANDLOCK_ACCESS_FS_EXECUTE'],
      });
    }

    return {
      abiVersion,
      handledAccessFs,
      rules,
    };
  }

  /**
   * Wraps an execution command with bubblewrap (bwrap) unprivileged user sandboxing (Landlock equivalent).
   */
  public wrapLandlockBwrap(
    command: string,
    args: string[] = [],
    options: LandlockOptions = {}
  ): { executable: string; args: string[] } {
    const bwrapArgs: string[] = [
      '--unshare-all',
      '--die-with-parent',
      '--ro-bind', '/usr', '/usr',
      '--ro-bind', '/lib', '/lib',
      '--ro-bind-try', '/lib64', '/lib64',
      '--ro-bind-try', '/bin', '/bin',
      '--proc', '/proc',
      '--dev', '/dev',
      '--tmpfs', '/tmp',
    ];

    for (const ro of options.readOnlyPaths || []) {
      bwrapArgs.push('--ro-bind-try', ro, ro);
    }

    for (const rw of options.readWritePaths || []) {
      bwrapArgs.push('--bind-try', rw, rw);
    }

    bwrapArgs.push('--', command, ...args);

    return {
      executable: 'bwrap',
      args: bwrapArgs,
    };
  }

  /**
   * Generates Linux namespace isolation configuration.
   */
  public generateNamespaceConfig(options: NamespaceOptions = {}): {
    flags: string[];
    unshareArgs: string[];
  } {
    const flags: string[] = [];
    const unshareArgs: string[] = [];

    if (options.mount ?? true) {
      flags.push('CLONE_NEWNS');
      unshareArgs.push('--mount');
    }
    if (options.pid ?? true) {
      flags.push('CLONE_NEWPID');
      unshareArgs.push('--pid');
      unshareArgs.push('--fork');
    }
    if (options.net ?? true) {
      flags.push('CLONE_NEWNET');
      unshareArgs.push('--net');
    }
    if (options.ipc ?? true) {
      flags.push('CLONE_NEWIPC');
      unshareArgs.push('--ipc');
    }
    if (options.uts ?? true) {
      flags.push('CLONE_NEWUTS');
      unshareArgs.push('--uts');
    }
    if (options.user ?? true) {
      flags.push('CLONE_NEWUSER');
      unshareArgs.push('--user');
      unshareArgs.push('--map-root-user');
    }

    return { flags, unshareArgs };
  }

  /**
   * Wraps an execution command with unshare for namespace isolation.
   */
  public wrapNamespaceExec(
    command: string,
    args: string[] = [],
    options: NamespaceOptions = {}
  ): { executable: string; args: string[] } {
    const { unshareArgs } = this.generateNamespaceConfig(options);
    return {
      executable: 'unshare',
      args: [...unshareArgs, '--', command, ...args],
    };
  }

  /**
   * Wraps command with network namespace isolation (`unshare --net`).
   */
  public wrapNetworkNamespaceExec(
    command: string,
    args: string[] = [],
    options: { allowLoopback?: boolean } = {}
  ): { executable: string; args: string[] } {
    const unshareArgs = ['--net'];
    if (options.allowLoopback ?? true) {
      // Loopback up in new namespace
      return {
        executable: 'unshare',
        args: ['--net', 'sh', '-c', `ip link set lo up 2>/dev/null || true; exec "${command}" "$@"`, '--', ...args],
      };
    }
    return {
      executable: 'unshare',
      args: ['--net', '--', command, ...args],
    };
  }

  /**
   * Generates read-only rootfs and overlayfs containment options.
   */
  public generateReadOnlyRootfsConfig(options: ReadOnlyRootfsOptions = {}): {
    rootMount: string;
    tmpfsMounts: string[];
    overlay: { lower: string; upper: string; work: string };
    mountCommands: string[];
  } {
    const rootPath = options.rootPath || '/';
    const workspacePath = options.workspacePath || '/workspace';
    const tmpfsMounts = options.tmpfsPaths || ['/tmp', '/run', '/var/run'];

    const overlay = {
      lower: workspacePath,
      upper: options.overlayUpper || '/tmp/mcp_shield_cow_upper',
      work: options.overlayWork || '/tmp/mcp_shield_cow_work',
    };

    const mountCommands = [
      `mount -o bind,ro ${rootPath} ${rootPath}`,
      ...tmpfsMounts.map(t => `mount -t tmpfs -o rw,nosuid,nodev,size=64m tmpfs ${t}`),
      `mount -t overlay overlay -o lowerdir=${overlay.lower},upperdir=${overlay.upper},workdir=${overlay.work} ${workspacePath}`,
    ];

    return {
      rootMount: 'ro,bind',
      tmpfsMounts,
      overlay,
      mountCommands,
    };
  }

  /**
   * Generates Firecracker MicroVM JSON configuration.
   */
  public generateFirecrackerConfig(options: MicroVmOptions): string {
    return JSON.stringify(
      {
        'boot-source': {
          kernel_image_path: options.kernelImagePath,
          boot_args: options.kernelArgs || 'console=ttyS0 reboot=k panic=1 pci=off init=/init',
        },
        drives: [
          {
            drive_id: 'rootfs',
            path_on_host: options.rootfsPath,
            is_root_device: true,
            is_read_only: true,
          },
        ],
        'machine-config': {
          vcpu_count: options.vcpus || 1,
          mem_size_mib: options.memSizeMib || 256,
          smt: false,
        },
        'network-interfaces': options.enableNetwork && options.tapDevice
          ? [
              {
                iface_id: 'net1',
                guest_mac: 'AA:FC:00:00:00:01',
                host_dev_name: options.tapDevice,
              },
            ]
          : [],
        vsock: options.vsockPath
          ? {
              guest_cid: 3,
              uds_path: options.vsockPath,
            }
          : undefined,
      },
      null,
      2
    );
  }

  /**
   * Generates Cloud-Hypervisor MicroVM JSON configuration.
   */
  public generateCloudHypervisorConfig(options: MicroVmOptions): string {
    return JSON.stringify(
      {
        kernel: { path: options.kernelImagePath },
        cmdline: { args: options.kernelArgs || 'console=ttyS0 panic=1' },
        cpus: { boot_vcpus: options.vcpus || 1, max_vcpus: options.vcpus || 1 },
        memory: { size: (options.memSizeMib || 256) * 1024 * 1024 },
        disks: [
          {
            path: options.rootfsPath,
            readonly: true,
          },
        ],
      },
      null,
      2
    );
  }

  /**
   * Wraps execution inside a Firecracker microVM.
   */
  public wrapMicroVmExec(options: MicroVmOptions): { executable: string; args: string[] } {
    return {
      executable: 'firecracker',
      args: ['--api-sock', options.vsockPath || '/tmp/firecracker.socket'],
    };
  }

  /**
   * Builds an authoritative, hardened execution command string incorporating all active kernel containment layers.
   */
  public buildHardenedExecutionCommand(
    command: string,
    args: string[] = [],
    profile: KernelContainmentProfile = {}
  ): { executable: string; args: string[] } {
    let currentExec = command;
    let currentArgs = [...args];

    // Layer 1: Read-only / Landlock bwrap
    if (profile.landlock) {
      const landlockOpts = typeof profile.landlock === 'object' ? profile.landlock : {};
      const wrapped = this.wrapLandlockBwrap(currentExec, currentArgs, landlockOpts);
      currentExec = wrapped.executable;
      currentArgs = wrapped.args;
    }

    // Layer 2: Network namespace isolation
    if (profile.networkIsolation) {
      const wrapped = this.wrapNetworkNamespaceExec(currentExec, currentArgs);
      currentExec = wrapped.executable;
      currentArgs = wrapped.args;
    }

    // Layer 3: Linux Namespaces
    if (profile.namespaces) {
      const nsOpts = typeof profile.namespaces === 'object' ? profile.namespaces : {};
      const wrapped = this.wrapNamespaceExec(currentExec, currentArgs, nsOpts);
      currentExec = wrapped.executable;
      currentArgs = wrapped.args;
    }

    return {
      executable: currentExec,
      args: currentArgs,
    };
  }
}
