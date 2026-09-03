import { generateApiKey, hashApiKey, verifyKeyHash } from '../cloud-dashboard/src/lib/api-keys';
import { globalRateLimiter } from '../cloud-dashboard/src/lib/rate-limiter';
import { idempotencyStore } from '../cloud-dashboard/src/lib/idempotency';
import crypto from 'crypto';

async function runSecuritySanityChecks() {
  console.log('='.repeat(70));
  console.log('🛡️  MCP-SHIELD P0 SECURITY & HARDENING SUITE');
  console.log('='.repeat(70));

  let totalTests = 0;
  let passedTests = 0;

  function assert(name: string, condition: boolean) {
    totalTests++;
    if (condition) {
      console.log(`  [PASS] ${name}`);
      passedTests++;
    } else {
      console.error(`  [FAIL] ${name}`);
      process.exitCode = 1;
    }
  }

  // 1. API Key Cryptographic Hashing
  console.log('\n[1] API Key SHA-256 Hashing & Zero-Plaintext Storage');
  const key = generateApiKey({ name: 'Production Fleet', clientType: 'Claude', expiresInDays: 90, seats: 25 });
  assert('Key generated with unique mcp_live_ prefix', key.keyPrefix.startsWith('mcp_live_'));
  assert('Raw key is not equal to hash', key.rawKey !== key.keyHash);
  assert('Key hash is 64-character hex (SHA-256)', key.keyHash.length === 64 && /^[0-9a-f]{64}$/.test(key.keyHash));
  assert('verifyKeyHash authenticates matching raw key', verifyKeyHash(key.rawKey, key.keyHash));
  assert('verifyKeyHash rejects tampered key', !verifyKeyHash(key.rawKey + '_tampered', key.keyHash));
  assert('verifyKeyHash rejects empty key', !verifyKeyHash('', key.keyHash));

  // 2. Sliding Window Rate Limiting
  console.log('\n[2] In-Memory Rate Limiting Guard');
  const testKey = 'test_rate_ip_' + Date.now();
  const res1 = globalRateLimiter.check(testKey, 3, 1000);
  const res2 = globalRateLimiter.check(testKey, 3, 1000);
  const res3 = globalRateLimiter.check(testKey, 3, 1000);
  const res4 = globalRateLimiter.check(testKey, 3, 1000);
  assert('First 3 requests within window are allowed', res1.allowed && res2.allowed && res3.allowed);
  assert('4th request exceeds limit and is rejected (429)', !res4.allowed && res4.remaining === 0);

  // 3. Payment and Webhook Idempotency
  console.log('\n[3] Payment & Webhook Idempotency Protection');
  const paymentId = 'pay_' + crypto.randomBytes(8).toString('hex');
  const firstAcquire = idempotencyStore.acquire(`test_rzp:${paymentId}`, { plan: 'enterprise' });
  const secondAcquire = idempotencyStore.acquire(`test_rzp:${paymentId}`, { plan: 'enterprise' });
  assert('First payment processing event acquires lock', firstAcquire === true);
  assert('Duplicate payment processing event is blocked (idempotent)', secondAcquire === false);
  assert('Store confirms event existence', idempotencyStore.has(`test_rzp:${paymentId}`) === true);

  // 4. Timing-Safe Comparison Defense
  console.log('\n[4] Timing-Safe Comparison Resistance');
  const secret = 'super_secret_test_key_12345';
  const expectedHmac = crypto.createHmac('sha256', secret).update('payload_test').digest('hex');
  const bufA = Buffer.from(expectedHmac, 'hex');
  const bufB = Buffer.from(expectedHmac, 'hex');
  const tamperedHmac = expectedHmac.substring(0, expectedHmac.length - 2) + '00';
  const bufTampered = Buffer.from(tamperedHmac, 'hex');
  assert('timingSafeEqual validates identical HMACs', crypto.timingSafeEqual(bufA, bufB));
  assert('timingSafeEqual detects manipulated signature bit', !crypto.timingSafeEqual(bufA, bufTampered));

  console.log('\n' + '='.repeat(70));
  console.log(`SUMMARY: ${passedTests}/${totalTests} Security Invariants Passed`);
  console.log('='.repeat(70));

  if (passedTests !== totalTests) {
    process.exit(1);
  }
}

runSecuritySanityChecks();
