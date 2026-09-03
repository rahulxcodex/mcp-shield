const { chromium } = require('playwright');
const { DashboardServer } = require('../dist/dashboard/server');
const WebSocket = require('ws');

async function runPlaywrightSecurityTest() {
  console.log('--- Starting Playwright End-to-End Security Verification ---');

  // 1. Start DashboardServer on a dynamic port
  const server = new DashboardServer(0);
  const port = await server.start();
  const token = server.getAuthToken();
  console.log(`[DashboardServer] Started on port ${port} with token ${token.substring(0, 6)}...`);

  let browser;
  try {
    // 2. Launch headless Chromium
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();

    // 3. Navigate with authentication token in query string
    const targetUrl = `http://127.0.0.1:${port}/?token=${token}`;
    console.log(`[Playwright] Navigating to ${targetUrl}`);
    const response = await page.goto(targetUrl);

    // Verify 302 redirect stripped token from address bar
    const finalUrl = page.url();
    console.log(`[Playwright] Landed on: ${finalUrl}`);
    if (finalUrl.includes('token=')) {
      throw new Error(`SECURITY FAILURE: Token was not stripped from URL: ${finalUrl}`);
    }
    console.log('[Playwright] PASS: Token was stripped from browser URL (Cookie session established).');

    // 4. Wait for WebSocket connection indicator
    await page.waitForSelector('#ws-status', { timeout: 5000 });
    const wsStatusText = await page.locator('#ws-status').innerText();
    console.log(`[Playwright] Initial WebSocket Status: ${wsStatusText}`);

    // 5. Connect as client and broadcast malicious XSS payload
    const wsClient = new WebSocket(`ws://127.0.0.1:${port}/?token=${token}`);
    await new Promise((resolve, reject) => {
      wsClient.on('open', resolve);
      wsClient.on('error', reject);
    });

    const maliciousEvent = {
      type: 'BLOCK_ATTACK',
      toolName: '<img src=x onerror="window.__xss_detected=true">malicious_tool',
      reason: '<script>window.__xss_detected=true</script>Injection payload intercepted',
      payload: { cmd: 'rm -rf /', tag: '<svg onload="window.__xss_detected=true">' }
    };

    console.log('[Playwright] Emitting malicious event over WebSocket...');
    server.broadcast(maliciousEvent);

    // Give browser time to process event and render DOM
    await page.waitForTimeout(1000);

    // 6. Verify that no script execution occurred
    const xssTriggered = await page.evaluate(() => window.__xss_detected);
    if (xssTriggered) {
      throw new Error('SECURITY VULNERABILITY DETECTED: Stored XSS payload executed in browser!');
    }
    console.log('[Playwright] PASS: window.__xss_detected is undefined (No XSS execution).');

    // 7. Verify text is sanitized and rendered as safe HTML entities
    const eventCardText = await page.locator('#events-container').innerText();
    if (!eventCardText.includes('malicious_tool') || !eventCardText.includes('Injection payload intercepted')) {
      throw new Error('Event card was not found in DOM or text was corrupted.');
    }
    console.log('[Playwright] PASS: Event rendered safely into DOM with escaped entities.');

    // 8. Test unauthenticated request rejection
    const unauthContext = await browser.newContext();
    const unauthPage = await unauthContext.newPage();
    const unauthRes = await unauthPage.goto(`http://127.0.0.1:${port}/`);
    if (unauthRes.status() !== 401) {
      throw new Error(`SECURITY FAILURE: Unauthenticated access was not rejected with 401 (got ${unauthRes.status()})`);
    }
    console.log('[Playwright] PASS: Unauthenticated request rejected with HTTP 401.');

    wsClient.close();
    console.log('--- ALL PLAYWRIGHT SECURITY TESTS PASSED SUCCESSFULLY ---');
  } finally {
    if (browser) await browser.close();
    await server.stop();
  }
}

runPlaywrightSecurityTest().catch((err) => {
  console.error('Playwright Security Test Failed:', err);
  process.exit(1);
});
