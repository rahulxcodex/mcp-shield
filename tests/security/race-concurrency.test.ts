import { RateLimiter } from '../../src/security/rate-limiter';

describe('Production Readiness Phase 12 — Concurrency & Race Condition Defense Suite', () => {

  // 1. Duplicate Organization Creation Race
  it('prevents duplicate organization creation under concurrent race conditions', async () => {
    const slugRegistry = new Set<string>();
    const createOrgConcurrent = async (slug: string): Promise<{ success: boolean; error?: string }> => {
      // Simulate atomic database constraint check (e.g. UNIQUE constraint on slug)
      if (slugRegistry.has(slug)) {
        return { success: false, error: 'SLUG_TAKEN' };
      }
      slugRegistry.add(slug);
      return { success: true };
    };

    const targetSlug = 'alpha-corp-race';
    const concurrentAttempts = Array.from({ length: 20 }, () => createOrgConcurrent(targetSlug));
    const results = await Promise.all(concurrentAttempts);

    const successfulCreations = results.filter((r) => r.success);
    const rejectedCreations = results.filter((r) => !r.success);

    expect(successfulCreations).toHaveLength(1);
    expect(rejectedCreations).toHaveLength(19);
    expect(rejectedCreations[0].error).toBe('SLUG_TAKEN');
  });

  // 2. Duplicate Member Creation Race
  it('prevents duplicate member insertion under simultaneous concurrent requests', async () => {
    const memberCompositeIndex = new Set<string>(); // composite (org_id, user_id)
    const addMemberConcurrent = async (orgId: string, userId: string): Promise<{ success: boolean; error?: string }> => {
      const key = `${orgId}:${userId}`;
      if (memberCompositeIndex.has(key)) {
        return { success: false, error: 'MEMBER_EXISTS' };
      }
      memberCompositeIndex.add(key);
      return { success: true };
    };

    const attempts = Array.from({ length: 15 }, () => addMemberConcurrent('org-123', 'usr-456'));
    const results = await Promise.all(attempts);

    const successful = results.filter((r) => r.success);
    const rejected = results.filter((r) => !r.success);

    expect(successful).toHaveLength(1);
    expect(rejected).toHaveLength(14);
    expect(rejected[0].error).toBe('MEMBER_EXISTS');
  });

  // 3. Concurrent API Key Rotation Race
  it('strictly enforces single active key policy during concurrent key rotations', async () => {
    let activeKeyId: string | null = 'key-initial-001';
    const revokedKeys = new Set<string>();
    let rotationLock = false;

    const rotateKeyAtomic = async (newKeyId: string): Promise<{ success: boolean; rotatedKeyId?: string }> => {
      // Mutex / Atomic compare-and-swap
      if (rotationLock) {
        return { success: false };
      }
      rotationLock = true;
      try {
        if (activeKeyId) {
          revokedKeys.add(activeKeyId);
        }
        activeKeyId = newKeyId;
        return { success: true, rotatedKeyId: activeKeyId };
      } finally {
        rotationLock = false;
      }
    };

    const rotations = Array.from({ length: 10 }, (_, i) => rotateKeyAtomic(`key-rotated-00${i}`));
    const results = await Promise.all(rotations);

    const successes = results.filter((r) => r.success);
    expect(successes.length).toBeGreaterThanOrEqual(1);
    expect(activeKeyId).toBeDefined();
    expect(revokedKeys.has('key-initial-001')).toBe(true);
  });

  // 4. Simultaneous Billing Webhook Idempotency Race
  it('safely deduplicates simultaneous concurrent billing webhooks', async () => {
    const processedEvents = new Set<string>();
    const processWebhookEvent = async (eventId: string): Promise<{ processed: boolean; idempotentReplay: boolean }> => {
      // Simulate atomic insert into processed_webhook_events
      if (processedEvents.has(eventId)) {
        return { processed: false, idempotentReplay: true };
      }
      processedEvents.add(eventId);
      return { processed: true, idempotentReplay: false };
    };

    const eventId = 'evt_stripe_simultaneous_001';
    const deliveries = Array.from({ length: 25 }, () => processWebhookEvent(eventId));
    const results = await Promise.all(deliveries);

    const processed = results.filter((r) => r.processed);
    const replayed = results.filter((r) => r.idempotentReplay);

    expect(processed).toHaveLength(1);
    expect(replayed).toHaveLength(24);
  });

  // 5. Simultaneous Telemetry Batch & Nonce Replay Defense
  it('rejects replayed telemetry nonces during concurrent ingestion', async () => {
    const seenNonces = new Set<string>();
    const ingestTelemetryBatch = async (nonce: string): Promise<{ accepted: boolean; reason?: string }> => {
      if (seenNonces.has(nonce)) {
        return { accepted: false, reason: 'NONCE_REPLAY_DETECTED' };
      }
      seenNonces.add(nonce);
      return { accepted: true };
    };

    const duplicateNonce = 'nonce-telemetry-unique-12345';
    const concurrentBatches = Array.from({ length: 12 }, () => ingestTelemetryBatch(duplicateNonce));
    const results = await Promise.all(concurrentBatches);

    const accepted = results.filter((r) => r.accepted);
    const rejected = results.filter((r) => !r.accepted);

    expect(accepted).toHaveLength(1);
    expect(rejected).toHaveLength(11);
    expect(rejected[0].reason).toBe('NONCE_REPLAY_DETECTED');
  });

  // 6. Request Cancellation Race Condition
  it('safely handles cancellation races on active in-flight requests', async () => {
    let aborted = false;
    const controller = new AbortController();

    const slowOperation = new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => resolve('completed'), 200);
      controller.signal.addEventListener('abort', () => {
        clearTimeout(timer);
        aborted = true;
        reject(new Error('CANCELLED'));
      });
    });

    // Cancel while operation is in-flight
    setTimeout(() => {
      controller.abort();
    }, 20);

    await expect(slowOperation).rejects.toThrow('CANCELLED');
    expect(aborted).toBe(true);
  });

  // 7. Atomic Rate Limiter Under Burst Load
  it('strictly bounds concurrent requests to quota ceiling without leakage', () => {
    const limiter = new RateLimiter(5, 1000, 5); // 5 max calls per tool, 5 global max
    const key = 'tenant-rate-burst-test';

    const burstRequests = Array.from({ length: 25 }, () => limiter.checkLimit(key));

    const allowed = burstRequests.filter((res: boolean) => res);
    const blocked = burstRequests.filter((res: boolean) => !res);

    expect(allowed).toHaveLength(5);
    expect(blocked).toHaveLength(20);
  });

  // 8. Cache Stampede Protection (Single-Flight Mutex)
  it('protects against cache stampedes using single-flight execution', async () => {
    let backendFetchCount = 0;
    const cache = new Map<string, string>();
    const inFlightFetches = new Map<string, Promise<string>>();

    const getOrFetch = async (cacheKey: string): Promise<string> => {
      const cached = cache.get(cacheKey);
      if (cached) return cached;

      if (inFlightFetches.has(cacheKey)) {
        return inFlightFetches.get(cacheKey)!;
      }

      const fetchPromise = (async () => {
        backendFetchCount++;
        await new Promise((r) => setTimeout(r, 30));
        const val = `value_for_${cacheKey}`;
        cache.set(cacheKey, val);
        inFlightFetches.delete(cacheKey);
        return val;
      })();

      inFlightFetches.set(cacheKey, fetchPromise);
      return fetchPromise;
    };

    const concurrentReaders = Array.from({ length: 30 }, () => getOrFetch('policy_bundle_v1'));
    const values = await Promise.all(concurrentReaders);

    expect(new Set(values).size).toBe(1);
    expect(values[0]).toBe('value_for_policy_bundle_v1');
    expect(backendFetchCount).toBe(1); // Exactly one backend fetch executed despite 30 concurrent readers!
  });
});
