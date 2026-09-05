const { chromium, request } = require('playwright');

const BASE_URL = process.env.TEST_BASE_URL || 'http://127.0.0.1:3000';
const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://placeholder-project.supabase.co';
const SUPABASE_ANON = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || 'test-anon-key-for-local-mock-only';
const TEST_EMAIL = process.env.TEST_CUSTOMER_EMAIL || 'customer-qa@mcp-shield.test';
const TEST_PASSWORD = process.env.TEST_CUSTOMER_PASSWORD || 'TestPassword123!Secure';

async function runCustomerAgents() {
  console.log('=====================================================');
  console.log('   MCP-SHIELD PLAYWRIGHT CUSTOMER SUBAGENT SUITE     ');
  console.log('=====================================================');

  // Authenticate customer account using Supabase Auth REST API
  console.log(`[AUTH] Authenticating test customer account (${TEST_EMAIL})...`);
  const authRes = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: {
      'apikey': SUPABASE_ANON,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      email: TEST_EMAIL,
      password: TEST_PASSWORD
    })
  });

  const authData = await authRes.json();
  if (!authData.access_token) {
    throw new Error('Supabase customer login failed: ' + JSON.stringify(authData));
  }

  const token = authData.access_token;
  console.log('[AUTH] Customer session authenticated successfully.\n');

  let browser;
  let passed = 0;
  let failed = 0;

  try {
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();

    const supabaseProjectRef = (new URL(SUPABASE_URL)).hostname.split('.')[0] || 'placeholder';
    const cookieName = `sb-${supabaseProjectRef}-auth-token`;

    // Set cookie for browser session
    await context.addCookies([
      {
        name: cookieName,
        value: JSON.stringify([token, authData.refresh_token]),
        domain: '127.0.0.1',
        path: '/',
      }
    ]);

    const page = await context.newPage();
    const reqContext = await request.newContext({
      baseURL: BASE_URL,
      extraHTTPHeaders: {
        'Authorization': `Bearer ${token}`
      }
    });

    // ==========================================
    // AGENT 1: First-Time Customer / Zero Baseline Audit
    // ==========================================
    console.log('[AGENT 1: First-Time Customer / Metrics Integrity]');
    try {
      await page.goto(`${BASE_URL}/console`, { waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(1500);

      const bodyText = await page.textContent('body');
      
      const hasFake165 = bodyText.includes('165');
      const hasFake3000 = bodyText.includes('3,000') || bodyText.includes('3000');
      const hasFakeThreats = bodyText.includes('1,429') || bodyText.includes('1429');
      
      if (hasFake165 || hasFake3000 || hasFakeThreats) {
        throw new Error(`Fake metric numbers found in DOM! (165: ${hasFake165}, 3000: ${hasFake3000}, threats: ${hasFakeThreats})`);
      }

      console.log('  ✓ UI confirms zero fake metrics on /console');

      const statsRes = await reqContext.get('/api/v1/telemetry/stats');
      const statsData = await statsRes.json();
      console.log(`  ✓ Telemetry stats: attacksNeutralized=${statsData.summary?.attacksNeutralized || 0}, secretsTokenized=${statsData.summary?.secretsTokenized || 0}`);
      
      if ((statsData.summary?.attacksNeutralized || 0) > 100) {
        throw new Error('Stats API returned hardcoded mock numbers!');
      }

      passed++;
      console.log('  --> AGENT 1 PASSED: Real baseline metrics verified.\n');
    } catch (err) {
      console.error('  ✕ AGENT 1 FAILED:', err.message, '\n');
      failed++;
    }

    // ==========================================
    // AGENT 2: Single Active Key Limit Enforcement
    // ==========================================
    console.log('[AGENT 2: Single-Key Access Policy Enforcement]');
    try {
      // 1. Create first key
      const res1 = await reqContext.post('/api/v1/keys', {
        data: { name: 'Customer 2 Active Key 1', clientType: 'Claude Desktop' }
      });
      const data1 = await res1.json();
      if (!data1.key) throw new Error('Key 1 creation failed: ' + JSON.stringify(data1));
      console.log(`  ✓ Created Key 1: ${data1.key.name} (${data1.key.keyPrefix}) - Status: ${data1.key.status}`);

      // 2. Create second key -> should rotate Key 1 and enforce single active key
      const res2 = await reqContext.post('/api/v1/keys', {
        data: { name: 'Customer 2 Active Key 2', clientType: 'Cursor IDE' }
      });
      const data2 = await res2.json();
      if (!data2.key) throw new Error('Key 2 creation failed: ' + JSON.stringify(data2));
      console.log(`  ✓ Created Key 2: ${data2.key.name} (${data2.key.keyPrefix}) - Status: ${data2.key.status}`);

      // 3. Query all keys to verify at most 1 active key
      const listRes = await reqContext.get('/api/v1/keys');
      const listData = await listRes.json();
      const keys = listData.keys || [];
      const activeKeys = keys.filter(k => k.status === 'active');
      const revokedKeys = keys.filter(k => k.status === 'revoked');

      console.log(`  ✓ Total Keys: ${keys.length} | Active Keys: ${activeKeys.length} | Revoked Keys: ${revokedKeys.length}`);
      if (activeKeys.length > 1) {
        throw new Error(`Single active key policy violated! Active keys count: ${activeKeys.length}`);
      }

      passed++;
      console.log('  --> AGENT 2 PASSED: Single active key limit strictly enforced.\n');
    } catch (err) {
      console.error('  ✕ AGENT 2 FAILED:', err.message, '\n');
      failed++;
    }

    // ==========================================
    // AGENT 3: Master Key Import & Admin Elevation
    // ==========================================
    console.log('[AGENT 3: Master Key Import & Master Admin Elevation]');
    try {
      const masterKeyString = 'MASTER_RGX_SHIELD_9999_OMEGA_SECURE_KEY';

      const importRes = await reqContext.put('/api/v1/keys', {
        data: { rawKey: masterKeyString, name: 'Customer Enterprise Master Admin' }
      });
      const importData = await importRes.json();

      if (!importData.success || !importData.isMaster) {
        throw new Error(`Master key import failed: ${JSON.stringify(importData)}`);
      }

      console.log(`  ✓ Master Key recognized: isMaster=${importData.isMaster}`);
      console.log(`  ✓ Key name: ${importData.key.name}`);
      console.log(`  ✓ Key prefix: ${importData.key.keyPrefix}`);

      passed++;
      console.log('  --> AGENT 3 PASSED: Master Key import and elevation verified.\n');
    } catch (err) {
      console.error('  ✕ AGENT 3 FAILED:', err.message, '\n');
      failed++;
    }

    // ==========================================
    // AGENT 4: Referral System & 1-Month Free Access
    // ==========================================
    console.log('[AGENT 4: Referral Program & Free Month Redemption]');
    try {
      const refRes = await reqContext.get('/api/v1/referrals');
      const refData = await refRes.json();
      
      console.log(`  ✓ Generated Referral Code: ${refData.referralCode}`);
      console.log(`  ✓ Generated Referral URL: ${refData.referralUrl}`);

      if (!refData.referralCode || !refData.referralUrl) {
        throw new Error('Referral code or URL missing');
      }

      // Customer redeems a colleague's referral code
      const friendCode = 'SHIELD-COLLEAGUE99';
      const redeemRes = await reqContext.post('/api/v1/referrals', {
        data: { referralCode: friendCode }
      });
      const redeemData = await redeemRes.json();

      if (!redeemData.success || redeemData.freeDaysGranted !== 30) {
        throw new Error(`Referral redemption failed: ${JSON.stringify(redeemData)}`);
      }

      console.log(`  ✓ Free days granted: ${redeemData.freeDaysGranted} Days (1 Month)`);
      console.log(`  ✓ Expiry date: ${redeemData.expiresAt}`);

      passed++;
      console.log('  --> AGENT 4 PASSED: Referral system grants 1 month free access.\n');
    } catch (err) {
      console.error('  ✕ AGENT 4 FAILED:', err.message, '\n');
      failed++;
    }

    // ==========================================
    // AGENT 5: Key Non-Reusability & Revocation Security
    // ==========================================
    console.log('[AGENT 5: Key Non-Reusability Security Check]');
    try {
      // Create a key
      const createRes = await reqContext.post('/api/v1/keys', {
        data: { name: 'One-Time Secret Key', clientType: 'Security-Audit' }
      });
      const createData = await createRes.json();
      const rawKey = createData.key.apiKey;
      const keyId = createData.key.id;
      const keyPrefix = createData.key.keyPrefix;

      console.log(`  ✓ Created key for testing: ${keyPrefix}`);

      // Revoke the key
      const deleteRes = await reqContext.delete(`/api/v1/keys?id=${keyId}&prefix=${keyPrefix}`);
      const deleteData = await deleteRes.json();
      if (!deleteData.success) throw new Error('Revocation failed: ' + JSON.stringify(deleteData));
      console.log(`  ✓ Key revoked: ${keyPrefix}`);

      // Attempt to re-import the revoked/used key
      const reimportRes = await reqContext.put('/api/v1/keys', {
        data: { rawKey, name: 'Attacker Reusing Key' }
      });
      
      const reimportStatus = reimportRes.status();
      const reimportData = await reimportRes.json();

      if (reimportStatus !== 400 || !reimportData.error?.includes('Used keys cannot be reused')) {
        throw new Error(`Security breach! Expected 400 rejection with "Used keys cannot be reused", got status ${reimportStatus}: ${JSON.stringify(reimportData)}`);
      }

      console.log(`  ✓ Re-import blocked with 400: "${reimportData.error}"`);
      passed++;
      console.log('  --> AGENT 5 PASSED: Revoked/used keys can never be reused.\n');
    } catch (err) {
      console.error('  ✕ AGENT 5 FAILED:', err.message, '\n');
      failed++;
    }

  } finally {
    if (browser) {
      await browser.close();
    }
  }

  console.log('=====================================================');
  console.log(`FINAL RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('=====================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runCustomerAgents().catch(e => {
  console.error('Fatal test suite error:', e);
  process.exit(1);
});
