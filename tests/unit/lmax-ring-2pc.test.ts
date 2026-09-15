import { Buffer } from 'buffer';
import * as crypto from 'crypto';
import {
  LmaxDisruptorRing,
  SlotState,
  CapabilityTwoPhaseCommit
} from '../../src';

describe('Lock-Free Ring Buffer & Capability 2PC Bridge Suite (Blueprint Section 3 & 5)', () => {
  describe('LmaxDisruptorRing (2.0 MB NUMA-Pinned SPSC Ring)', () => {
    it('maintains 2.0MB static allocation footprint', () => {
      const ring = new LmaxDisruptorRing();
      expect(ring.getMemoryFootprintBytes()).toBeGreaterThanOrEqual(2.0 * 1024 * 1024);
    });

    it('enqueues and dequeues events in strict FIFO order', () => {
      const ring = new LmaxDisruptorRing();
      const payload1 = Buffer.from('event-payload-1', 'utf8');
      const payload2 = Buffer.from('event-payload-2', 'utf8');

      const res1 = ring.enqueue('tx_001', payload1);
      const res2 = ring.enqueue('tx_002', payload2);

      expect(res1.success).toBe(true);
      expect(res2.success).toBe(true);
      expect(ring.getOccupancy()).toBe(2);

      const evt1 = ring.dequeue();
      expect(evt1).not.toBeNull();
      expect(evt1!.eventId).toBe('tx_001');
      expect(evt1!.data.toString('utf8')).toBe('event-payload-1');

      const evt2 = ring.dequeue();
      expect(evt2).not.toBeNull();
      expect(evt2!.eventId).toBe('tx_002');
      expect(evt2!.data.toString('utf8')).toBe('event-payload-2');

      expect(ring.getOccupancy()).toBe(0);
      expect(ring.dequeue()).toBeNull();
    });

    it('performs epoch-tagged CAS rollback on aborted transactions', () => {
      const ring = new LmaxDisruptorRing();
      const res = ring.enqueue('tx_zombie', Buffer.from('zombie-data'));
      expect(res.success).toBe(true);

      const aborted = ring.abortSlot(res.sequence, 504);
      expect(aborted).toBe(true);
    });
  });

  describe('CapabilityTwoPhaseCommit (2PC Speculative Sandboxing)', () => {
    it('stages mutation in PREPARE and commits upon valid Ed25519 token', () => {
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
      const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
      const tpc = new CapabilityTwoPhaseCommit(publicKeyPem, 50);

      // 1. Prepare
      const staged = tpc.prepare('filesystem_write', { path: '/tmp/test.txt', content: 'hello' });
      expect(staged.phase).toBe('PREPARED');
      expect(staged.cowBuffer).toBeDefined();

      // 2. Generate valid Ed25519 clearance token
      const msg = Buffer.from(`2PC_CLEARANCE:${staged.transactionId}`, 'utf8');
      const tokenHex = crypto.sign(null, msg, privateKey).toString('hex');

      // 3. Commit
      const commitRes = tpc.commit(staged.transactionId, tokenHex);
      expect(commitRes.committed).toBe(true);
      expect(commitRes.phase).toBe('COMMITTED');
    });

    it('rejects commit with invalid clearance token', () => {
      const tpc = new CapabilityTwoPhaseCommit(undefined, 50);
      const staged = tpc.prepare('spawn_process', { cmd: 'cat /etc/passwd' });

      const commitRes = tpc.commit(staged.transactionId, 'deadbeefbadtoken');
      expect(commitRes.committed).toBe(false);
      expect(commitRes.phase).toBe('ABORTED');
      expect(commitRes.reason).toContain('Invalid Ed25519');
    });

    it('auto-aborts when 30ms SLA window is exceeded', async () => {
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
      const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
      // Strict 10ms timeout for test
      const tpc = new CapabilityTwoPhaseCommit(publicKeyPem, 10);

      const staged = tpc.prepare('network_connect', { host: 'internal.corp' });

      // Wait 15ms
      await new Promise((r) => setTimeout(r, 15));

      const msg = Buffer.from(`2PC_CLEARANCE:${staged.transactionId}`, 'utf8');
      const tokenHex = crypto.sign(null, msg, privateKey).toString('hex');

      const commitRes = tpc.commit(staged.transactionId, tokenHex);
      expect(commitRes.committed).toBe(false);
      expect(commitRes.phase).toBe('ABORTED');
      expect(commitRes.reason).toContain('timeout exceeded');
    });
  });
});
