import { ProtocolValidator } from '../../src/core/protocol-validator';
import { ProxyServer } from '../../src/core/proxy';

describe('Protocol Validator & Proxy Error Resilience', () => {
  describe('ProtocolValidator Circular Reference & Throwing Getter Resilience', () => {
    const validator = new ProtocolValidator();

    test('fails closed with -32600 when arguments object has a circular reference', () => {
      const circularArgs: any = { a: 1 };
      circularArgs.self = circularArgs;

      const message = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'test_tool',
          arguments: circularArgs
        }
      };

      const result = validator.validateInbound(message);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe(-32600);
      expect(result.errorMessage).toMatch(/nesting depth limit|Failed to serialize arguments/);
    });

    test('fails closed with -32600 when arguments object contains throwing getters or BigInt', () => {
      const throwingArgs = {
        get badProp() {
          throw new Error('Getter explosion');
        }
      };

      const message = {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: {
          name: 'test_tool',
          arguments: throwingArgs
        }
      };

      const result = validator.validateInbound(message);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe(-32600);
      expect(result.errorMessage).toContain('throwing getter');
    });

    test('fails closed when arguments payload exceeds max size limit', () => {
      const hugeString = 'A'.repeat(600 * 1024);
      const message = {
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: {
          name: 'test_tool',
          arguments: { data: hugeString }
        }
      };

      const result = validator.validateInbound(message);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe(-32600);
      expect(result.errorMessage).toContain('exceeds maximum allowed');
    });
  });

  describe('Proxy Server Serialization Failure Resilience', () => {
    test('sendSuccessToHost emits fallback error response rather than hanging when result is circular', () => {
      const proxy = new ProxyServer('node', ['-e', 'process.exit(0)'], { enableDashboard: false });

      const stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation((_chunk: any) => true);

      const circularResult: any = { data: 'ok' };
      circularResult.loop = circularResult;

      // Access private sendSuccessToHost
      (proxy as any).sendSuccessToHost('req-123', circularResult);

      expect(stdoutSpy).toHaveBeenCalled();
      const writtenText = stdoutSpy.mock.calls[0][0] as string;
      const parsed = JSON.parse(writtenText);

      expect(parsed.id).toBe('req-123');
      expect(parsed.error).toBeDefined();
      expect(parsed.error.code).toBe(-32603);
      expect(parsed.error.message).toContain('Failed to serialize success result to JSON');

      stdoutSpy.mockRestore();
    });

    test('sendErrorToHost emits fallback error response when error data is circular', () => {
      const proxy = new ProxyServer('node', ['-e', 'process.exit(0)'], { enableDashboard: false });

      const stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation((_chunk: any) => true);

      const circularData: any = { detail: 'fatal' };
      circularData.self = circularData;

      // Access private sendErrorToHost
      (proxy as any).sendErrorToHost('req-err-456', -32000, 'Custom error', circularData);

      expect(stdoutSpy).toHaveBeenCalled();
      const writtenText = stdoutSpy.mock.calls[0][0] as string;
      const parsed = JSON.parse(writtenText);

      expect(parsed.id).toBe('req-err-456');
      expect(parsed.error).toBeDefined();
      expect(parsed.error.code).toBe(-32603);
      expect(parsed.error.message).toContain('Serialization error');

      stdoutSpy.mockRestore();
    });
  });
});
