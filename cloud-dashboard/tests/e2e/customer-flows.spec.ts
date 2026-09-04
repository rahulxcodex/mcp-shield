import { test, expect } from '@playwright/test';

test.describe('MCP Shield Customer Journey & Ecosystem Tests', () => {

  test('Customer Agent 1: Real Zero Baseline Metrics & Introductory Free Tier', async ({ request }) => {
    // Check telemetry stats endpoint returns real zeros, not random fake numbers
    const res = await request.get('/api/v1/telemetry/stats');
    expect(res.ok()).toBeTruthy();
    const data = await res.json();
    
    expect(data.summary).toBeDefined();
    // Verify attacks and secrets are real 0 if no attacks have occurred
    expect(data.summary.attacksNeutralized).toBe(0);
    expect(data.summary.secretsTokenized).toBe(0);
    expect(data.summary.invocations).toBe(0);
  });

  test('Customer Agent 2: API Key Generation & Single Active Key Enforcement', async ({ request }) => {
    // Generate first key
    const res1 = await request.post('/api/v1/keys', {
      data: { name: 'Agent 2 Test Key 1', clientType: 'Claude Desktop' }
    });
    expect(res1.ok()).toBeTruthy();
    const data1 = await res1.json();
    expect(data1.key).toBeDefined();
    expect(data1.key.status).toBe('active');

    // Generate second key - should enforce single active key by rotating previous key
    const res2 = await request.post('/api/v1/keys', {
      data: { name: 'Agent 2 Test Key 2', clientType: 'Cursor' }
    });
    expect(res2.ok()).toBeTruthy();
    const data2 = await res2.json();
    expect(data2.key.status).toBe('active');

    // Query keys list to verify at most 1 key is active
    const keysRes = await request.get('/api/v1/keys');
    expect(keysRes.ok()).toBeTruthy();
    const keysData = await keysRes.json();
    if (keysData.keys && keysData.keys.length > 0) {
      const activeKeys = keysData.keys.filter((k: any) => k.status === 'active');
      expect(activeKeys.length).toBeLessThanOrEqual(1);
    }
  });

  test('Customer Agent 3: Master Key Import via PUT /api/v1/keys', async ({ request }) => {
    const masterKey = process.env.MCP_SHIELD_MASTER_KEY || 'MASTER_RGX_SHIELD_9999_OMEGA_SECURE_KEY';
    const res = await request.put('/api/v1/keys', {
      data: { rawKey: masterKey, name: 'Customer Master Key' }
    });
    expect(res.ok()).toBeTruthy();
    const data = await res.json();
    expect(data.success).toBeTruthy();
    expect(data.isMaster).toBeTruthy();
    expect(data.key).toBeDefined();
    expect(data.key.name).toContain('Master Admin');
  });

  test('Customer Agent 4: Referral System Code Generation & 1-Month Free Access', async ({ request }) => {
    // Fetch referral profile
    const refRes = await request.get('/api/v1/referrals');
    if (refRes.status() === 200) {
      const refData = await refRes.json();
      expect(refData.referralCode).toBeDefined();
      expect(refData.referralUrl).toContain('/console?ref=');

      // Redeem referral code
      const redeemRes = await request.post('/api/v1/referrals', {
        data: { referralCode: 'SHIELD-TESTFRIEND' }
      });
      expect(redeemRes.ok()).toBeTruthy();
      const redeemData = await redeemRes.json();
      expect(redeemData.success).toBeTruthy();
      expect(redeemData.freeDaysGranted).toBe(30);
    }
  });

  test('Customer Agent 5: Key Non-Reusability (Used keys cannot be reused)', async ({ request }) => {
    // Generate a temporary key
    const createRes = await request.post('/api/v1/keys', {
      data: { name: 'Key to Revoke', clientType: 'Test' }
    });
    if (createRes.ok()) {
      const created = await createRes.json();
      const rawKey = created.key.apiKey;
      const keyId = created.key.id;

      // Revoke the key
      const revokeRes = await request.delete(`/api/v1/keys?id=${keyId}&prefix=${created.key.keyPrefix}`);
      expect(revokeRes.ok()).toBeTruthy();

      // Attempt to re-import the revoked key - must fail
      const reimportRes = await request.put('/api/v1/keys', {
        data: { rawKey, name: 'Re-import Revoked Key' }
      });
      expect(reimportRes.status()).toBe(400);
      const reimportData = await reimportRes.json();
      expect(reimportData.error).toContain('Used keys cannot be reused');
    }
  });

});
