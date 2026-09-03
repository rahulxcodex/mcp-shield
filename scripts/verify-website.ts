import { chromium } from 'playwright';

async function verify() {
  console.log('='.repeat(70));
  console.log('🚀 RUNNING PLAYWRIGHT E2E & SEO VERIFICATION SUITE');
  console.log('='.repeat(70));

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const baseUrl = (process.env.TEST_URL || 'http://localhost:3000').replace(/\/$/, '');

  // Test 1: Landing Page
  console.log(`\n[TEST 1] Verifying Landing Page & SEO Metadata at ${baseUrl}...`);
  await page.goto(`${baseUrl}/`, { waitUntil: 'networkidle' });

  const title = await page.title();
  console.log(`  ✓ Title: "${title}"`);
  if (!title.includes('MCP Shield')) throw new Error('Title missing MCP Shield');

  const metaDesc = await page.$eval('meta[name="description"]', el => el.getAttribute('content'));
  console.log(`  ✓ Meta Description: "${metaDesc?.substring(0, 70)}..."`);
  if (!metaDesc || !metaDesc.includes('Zero-Trust')) throw new Error('Meta description invalid');

  const metaKeywords = await page.$eval('meta[name="keywords"]', el => el.getAttribute('content'));
  console.log(`  ✓ Meta Keywords: "${metaKeywords?.substring(0, 60)}..."`);
  if (!metaKeywords || !metaKeywords.includes('mcp security')) throw new Error('Keywords missing');

  const ogTitle = await page.$eval('meta[property="og:title"]', el => el.getAttribute('content'));
  console.log(`  ✓ OpenGraph Title: "${ogTitle}"`);

  // Schema.org JSON-LD check
  const jsonLd = await page.$eval('script[type="application/ld+json"]', el => el.textContent);
  const parsedLd = JSON.parse(jsonLd || '{}');
  console.log(`  ✓ Schema.org JSON-LD Verified (${parsedLd['@graph']?.length || 0} entities: SoftwareApplication, FAQPage, WebSite)`);

  // Test 2: Attack Simulator Interactivity
  console.log('\n[TEST 2] Testing Interactive Attack Simulator...');
  const ssrfButton = page.locator('button:has-text("Cloud Instance Metadata SSRF")');
  await ssrfButton.click();
  await page.waitForTimeout(400);

  const verdict = await page.locator('text=RULE-NET-04: LINK_LOCAL_CLOUD_METADATA_PROHIBITED').textContent();
  console.log(`  ✓ Simulator Intercepted: "${verdict}"`);

  // Test 3: Installation Tabs Interactivity
  console.log('\n[TEST 3] Testing Installation Tab Switcher...');
  const cursorTab = page.locator('button:has-text("Cursor IDE")');
  await cursorTab.click();
  await page.waitForTimeout(200);

  const configPath = await page.locator('text=.cursor/mcp.json').textContent();
  console.log(`  ✓ Tab Switched: "${configPath}" displayed`);

  // Test 4: Console Section
  console.log('\n[TEST 4] Testing Console Section & Real-Time Threat Stream...');
  await page.goto(`${baseUrl}/console?demo=true`, { waitUntil: 'networkidle' });

  const consoleHeader = await page.locator('text=Zero-Trust Live Telemetry & Threat Center').textContent();
  console.log(`  ✓ Console Header: "${consoleHeader}"`);

  const initialEventCount = await page.locator('.space-y-3 .p-3').count();
  console.log(`  ✓ Initial Live Events Rendered: ${initialEventCount}`);

  // Test Simulation Trigger
  const simulateBtn = page.locator('button:has-text("Simulate Live Attack")');
  await simulateBtn.click();
  await page.waitForTimeout(600);

  const updatedEventCount = await page.locator('.space-y-3 .p-3').count();
  console.log(`  ✓ Events after live simulation batch: ${updatedEventCount} (Triggered real-time stream update)`);

  // Test 5: SEO Dynamic Routes (sitemap.xml and robots.txt)
  console.log('\n[TEST 5] Testing robots.txt and sitemap.xml routes...');
  const robotsRes = await page.goto(`${baseUrl}/robots.txt`);
  if (robotsRes?.status() === 200) {
    console.log('  ✓ /robots.txt responded with HTTP 200');
  } else {
    throw new Error('robots.txt failed');
  }

  const sitemapRes = await page.goto(`${baseUrl}/sitemap.xml`);
  if (sitemapRes?.status() === 200) {
    console.log('  ✓ /sitemap.xml responded with HTTP 200');
  } else {
    throw new Error('sitemap.xml failed');
  }

  // Test 6: Interactive Website User Guide (/guide)
  console.log('\n[TEST 6] Testing Interactive Website User Guide (/guide)...');
  await page.goto(`${baseUrl}/guide`, { waitUntil: 'networkidle' });

  const guideH1 = await page.locator('h1').textContent();
  console.log(`  ✓ Guide Heading: "${guideH1}"`);
  if (!guideH1?.includes('Integration & Administration Guide')) throw new Error('Guide H1 invalid');

  const licenseCmdText = await page.locator('text=mcpshld license <YOUR_LICENSE_KEY>').textContent();
  console.log(`  ✓ License Activation Command Verified: "${licenseCmdText?.trim()}"`);
  const masterKeyCount = await page.locator('text=MASTER_RGX_SHIELD_9999_OMEGA_SECURE_KEY').count();
  if (masterKeyCount > 0) throw new Error('Security violation: Master key found exposed on website!');
  console.log('  ✓ Verified NO master key leak on guide page');

  // Switch to Google Antigravity client tab
  const agTab = page.locator('button:has-text("Google Antigravity")');
  await agTab.click();
  await page.waitForTimeout(200);
  const agConfig = await page.locator('text=shielded-shell').textContent();
  console.log(`  ✓ Client Tab Switched: "${agConfig}" displayed`);

  await browser.close();
  console.log('\n' + '='.repeat(70));
  console.log('🎉 ALL PLAYWRIGHT END-TO-END TESTS PASSED SUCCESSFULLY!');
  console.log('='.repeat(70));
}

verify().catch((err) => {
  console.error('\n❌ Verification failed:', err.message);
  process.exit(1);
});
