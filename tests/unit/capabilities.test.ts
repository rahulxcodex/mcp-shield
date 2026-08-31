import { CapabilityInferencer, ToolCapabilities } from '../../src/security/capabilities';

describe('CapabilityInferencer (Schema-First Inference)', () => {
  it('infers shellExecution from schema parameter names even if tool name is deceptive (e.g. calculate_metrics)', () => {
    const deceptiveToolSchema = {
      type: 'object',
      properties: {
        command: { type: 'string', description: 'Metrics calculation expression or shell command' }
      },
      required: ['command']
    };

    const caps = CapabilityInferencer.infer('calculate_metrics', deceptiveToolSchema, 'Calculate telemetry metrics');
    expect(caps.shellExecution).toBe(true);
    expect(caps.destructiveOperation).toBe(false);
  });

  it('infers networkAccess from schema url/endpoint properties', () => {
    const networkToolSchema = {
      type: 'object',
      properties: {
        url: { type: 'string', format: 'uri', description: 'Remote data endpoint' }
      },
      required: ['url']
    };

    const caps = CapabilityInferencer.infer('get_data', networkToolSchema, 'Fetch data item');
    expect(caps.networkAccess).toBe(true);
  });

  it('infers filesystemWrite from schema content/destination properties', () => {
    const writeToolSchema = {
      type: 'object',
      properties: {
        destination: { type: 'string', description: 'Target file location' },
        content: { type: 'string', description: 'File contents to write' }
      },
      required: ['destination', 'content']
    };

    const caps = CapabilityInferencer.infer('save_state', writeToolSchema, 'Save persistent state');
    expect(caps.filesystemWrite).toBe(true);
  });

  it('infers secretAccess from schema credential properties', () => {
    const secretToolSchema = {
      type: 'object',
      properties: {
        api_key: { type: 'string', description: 'API authentication token' }
      },
      required: ['api_key']
    };

    const caps = CapabilityInferencer.infer('authenticate_service', secretToolSchema, 'Authenticate service token');
    expect(caps.secretAccess).toBe(true);
  });

  it('correctly calculates trust level: TRUSTED when declared covers inferred', () => {
    const declared: ToolCapabilities = {
      filesystemRead: true,
      filesystemWrite: true,
      shellExecution: false,
      networkAccess: false,
      processSpawn: false,
      destructiveOperation: false,
      secretAccess: false
    };

    const inferred: ToolCapabilities = {
      filesystemRead: true,
      filesystemWrite: false,
      shellExecution: false,
      networkAccess: false,
      processSpawn: false,
      destructiveOperation: false,
      secretAccess: false
    };

    const trust = CapabilityInferencer.calculateTrustLevel(declared, inferred);
    expect(trust).toBe('TRUSTED');
  });

  it('correctly flags SUSPICIOUS when inferred capability is missing from declared attestation', () => {
    const declared: ToolCapabilities = {
      filesystemRead: true,
      filesystemWrite: false,
      shellExecution: false, // Declares NO shell execution
      networkAccess: false,
      processSpawn: false,
      destructiveOperation: false,
      secretAccess: false
    };

    const inferred: ToolCapabilities = {
      filesystemRead: true,
      filesystemWrite: false,
      shellExecution: true, // But schema has 'command' parameter!
      networkAccess: false,
      processSpawn: false,
      destructiveOperation: false,
      secretAccess: false
    };

    const trust = CapabilityInferencer.calculateTrustLevel(declared, inferred);
    expect(trust).toBe('SUSPICIOUS');
  });

  it('correctly flags UNTRUSTED when no declarations are provided', () => {
    const declared: ToolCapabilities = {
      filesystemRead: false,
      filesystemWrite: false,
      shellExecution: false,
      networkAccess: false,
      processSpawn: false,
      destructiveOperation: false,
      secretAccess: false
    };

    const inferred: ToolCapabilities = {
      filesystemRead: true,
      filesystemWrite: false,
      shellExecution: false,
      networkAccess: false,
      processSpawn: false,
      destructiveOperation: false,
      secretAccess: false
    };

    const trust = CapabilityInferencer.calculateTrustLevel(declared, inferred);
    expect(trust).toBe('UNTRUSTED');
  });
});
