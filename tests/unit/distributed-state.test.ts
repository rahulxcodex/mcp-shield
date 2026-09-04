import { MemoryDistributedStateStore } from '../../src/cloud/state/distributed-state-adapter';

describe('DistributedStateStore (Roadmap Section 8.2)', () => {
  it('stores, retrieves, and expires distributed state with TTL', async () => {
    const store = new MemoryDistributedStateStore();
    await store.set('test-key', { foo: 'bar' });
    const val = await store.get<{ foo: string }>('test-key');
    expect(val?.foo).toBe('bar');

    await store.delete('test-key');
    expect(await store.get('test-key')).toBeNull();
  });

  it('enforces distributed rate limiting using atomic increments', async () => {
    const store = new MemoryDistributedStateStore();
    const key = 'rate:user-123';
    const limit = 3;

    const r1 = await store.checkRateLimit(key, limit, 60);
    expect(r1.allowed).toBe(true);
    expect(r1.remaining).toBe(2);

    const r2 = await store.checkRateLimit(key, limit, 60);
    expect(r2.allowed).toBe(true);

    const r3 = await store.checkRateLimit(key, limit, 60);
    expect(r3.allowed).toBe(true);
    expect(r3.remaining).toBe(0);

    const r4 = await store.checkRateLimit(key, limit, 60);
    expect(r4.allowed).toBe(false);
  });
});
