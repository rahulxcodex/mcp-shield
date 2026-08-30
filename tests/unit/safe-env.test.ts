import { ProxyServer } from '../../src/core/proxy';

describe('ProxyServer.buildSafeEnv() Invariant & Security Verification', () => {
  it('preserves essential Linux / Ubuntu POSIX runtime variables', () => {
    const mockEnv: NodeJS.ProcessEnv = {
      PATH: '/usr/local/bin:/usr/bin:/bin',
      HOME: '/home/runner',
      USER: 'runner',
      LOGNAME: 'runner',
      SHELL: '/bin/bash',
      PWD: '/home/runner/work/mcp-shield',
      TMPDIR: '/tmp',
      LANG: 'en_US.UTF-8',
      LC_ALL: 'en_US.UTF-8',
      NODE_PATH: '/usr/local/lib/node_modules',
      SSL_CERT_FILE: '/etc/ssl/certs/ca-certificates.crt',
      TERM: 'xterm-256color',
      CI: 'true'
    };

    const safe = ProxyServer.buildSafeEnv(mockEnv);

    expect(safe.PATH).toBe('/usr/local/bin:/usr/bin:/bin');
    expect(safe.HOME).toBe('/home/runner');
    expect(safe.USER).toBe('runner');
    expect(safe.LOGNAME).toBe('runner');
    expect(safe.SHELL).toBe('/bin/bash');
    expect(safe.PWD).toBe('/home/runner/work/mcp-shield');
    expect(safe.TMPDIR).toBe('/tmp');
    expect(safe.LANG).toBe('en_US.UTF-8');
    expect(safe.LC_ALL).toBe('en_US.UTF-8');
    expect(safe.NODE_PATH).toBe('/usr/local/lib/node_modules');
    expect(safe.SSL_CERT_FILE).toBe('/etc/ssl/certs/ca-certificates.crt');
    expect(safe.TERM).toBe('xterm-256color');
    expect(safe.CI).toBe('true');
  });

  it('sets safe defaults for stdio buffering and character encoding', () => {
    const safe = ProxyServer.buildSafeEnv({});
    expect(safe.PYTHONUNBUFFERED).toBe('1');
    expect(safe.PYTHONIOENCODING).toBe('utf-8');
  });

  it('strictly strips cloud, API, and service credentials (AWS, GitHub, Slack, OpenAI, Database)', () => {
    const mockEnv: NodeJS.ProcessEnv = {
      PATH: '/usr/bin',
      AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
      AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      AWS_SESSION_TOKEN: 'token123',
      GITHUB_TOKEN: 'ghp_abc1234567890abcdefghijklmnopqrstuv',
      GH_TOKEN: 'ghp_xyz',
      SLACK_BOT_TOKEN: 'xoxb-123456-abcdef',
      OPENAI_API_KEY: 'sk-proj-1234567890',
      ANTHROPIC_API_KEY: 'sk-ant-api03-abcdef',
      DATABASE_URL: 'postgres://user:pass@localhost:5432/db',
      STRIPE_SECRET_KEY: 'sk_live_1234567890'
    };

    const safe = ProxyServer.buildSafeEnv(mockEnv);

    expect(safe.AWS_ACCESS_KEY_ID).toBeUndefined();
    expect(safe.AWS_SECRET_ACCESS_KEY).toBeUndefined();
    expect(safe.AWS_SESSION_TOKEN).toBeUndefined();
    expect(safe.GITHUB_TOKEN).toBeUndefined();
    expect(safe.GH_TOKEN).toBeUndefined();
    expect(safe.SLACK_BOT_TOKEN).toBeUndefined();
    expect(safe.OPENAI_API_KEY).toBeUndefined();
    expect(safe.ANTHROPIC_API_KEY).toBeUndefined();
    expect(safe.DATABASE_URL).toBeUndefined();
    expect(safe.STRIPE_SECRET_KEY).toBeUndefined();
  });

  it('strictly blocks malicious execution & injection vectors (LD_PRELOAD, NODE_OPTIONS, BASH_ENV)', () => {
    const mockEnv: NodeJS.ProcessEnv = {
      PATH: '/usr/bin',
      LD_PRELOAD: '/tmp/evil.so',
      LD_LIBRARY_PATH: '/tmp/evil-libs',
      NODE_OPTIONS: '--require /tmp/malicious.js',
      BASH_ENV: '/tmp/infect.sh',
      DYLD_INSERT_LIBRARIES: '/tmp/evil.dylib'
    };

    const safe = ProxyServer.buildSafeEnv(mockEnv);

    expect(safe.LD_PRELOAD).toBeUndefined();
    expect(safe.LD_LIBRARY_PATH).toBeUndefined();
    expect(safe.NODE_OPTIONS).toBeUndefined();
    expect(safe.BASH_ENV).toBeUndefined();
    expect(safe.DYLD_INSERT_LIBRARIES).toBeUndefined();
  });

  it('handles case-insensitive key lookups across platforms (Path vs PATH)', () => {
    const mockEnv: any = {
      Path: 'C:\\Windows\\system32;C:\\Windows',
      home: 'C:\\Users\\dev'
    };

    const safe = ProxyServer.buildSafeEnv(mockEnv);
    expect(safe.PATH).toBe('C:\\Windows\\system32;C:\\Windows');
    expect(safe.HOME).toBe('C:\\Users\\dev');
  });
});
