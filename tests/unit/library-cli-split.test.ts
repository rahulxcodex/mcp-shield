describe('Library and CLI Separation (Roadmap Section 9)', () => {
  it('imports library exports with zero CLI`side effects or argument evaluation', () => {
    const originalArgv = process.argv;
    process.argv = ['node', 'mcp-shield', '--help-unknown-flag'];

    try {
      const lib = require('../../src/index');
      expect(lib.ProxyServer).toBeDefined();
      expect(lib.SecurityPipeline).toBeDefined();
      expect(lib.SecurityRuntime).toBeDefined();
      expect(lib.PathSecurityResolver).toBeDefined();
      expect(lib.canonicalizeJson).toBeDefined();
      expect(lib.UnifiedInterpreterClassifier).toBeDefined();
    } finally {
      process.argv = originalArgv;
    }
  });
});
