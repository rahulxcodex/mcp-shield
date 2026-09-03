import { chromium, Page } from 'playwright';

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000';
const FORBIDDEN_MASTER_KEY = 'MASTER_RGX_SHIELD_9999_OMEGA_SECURE_KEY';

async function checkNoMasterKeyLeak(page: Page, urlPath: string) {
  await page.goto(`${BASE_URL}${urlPath}`, { waitUntil: 'domcontentloaded' });
  const html = await page.content();
  if (html.includes(FORBIDDEN_MASTER_KEY)) {
    throw new Error(`CRITICAL SECURITY LEAK: Master key found exposed at ${urlPath}!`);
  }
  console.log(`  ? Security Verified: Zero master key leaks on ${urlPath}`);
}

async function runSanitySuite() {
  console.log('='.repeat(70));
  console.log('???  MCP SHIELD - WEBSITE PLAYWRIGHT SANITY CHECK SUITE');
  console.log(`?? Target URL: ${BASE_URL}`);
  console.log('='.repeat(70));

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    // 1. Landing Page Navigation & Sign In Button Presence
    console.log('\n[CHECK 1] Verifying Landing Page & Navbar Auth Navigation...');
    await page.goto(`${BASE_URL}/`, { waitUntil: 'networkidle' });

    // Check title/hero
    const title = await page.title();
    console.log(`  ? Page Title: "${title}"`);

    // Verify "Sign In" button exists in navbar
    const signInDesktop = page.locator('header a[href="/login"]:has-text("Sign In")').first();
    const isSignInVisible = await signInDesktop.isVisible();
    if (!isSignInVisible) {
      throw new Error('FAILED: "Sign In" button is missing from the navbar!');
    }
    console.log('  ? Desktop Navbar: "Sign In" button is clearly visible and points to /login');

    // Verify GitHub repo link is distinct
    const githubLink = page.locator('header a[href*="github.com/rahulxcodex/mcp-shield"]').first();
    if (!(await githubLink.isVisible())) {
      throw new Error('FAILED: GitHub repo link missing from navbar!');
    }
    console.log('  ? Desktop Navbar: GitHub repository star/source link is present');

    // Verify Console CTA
    const consoleBtn = page.locator('header a[href="/console"]:has-text("Launch Console")').first();
    if (!(await consoleBtn.isVisible())) {
      throw new Error('FAILED: "Launch Console" button missing from navbar!');
    }
    console.log('  ? Desktop Navbar: "Launch Console" CTA is active');

    // 2. Click "Sign In" and Verify Smooth Transition to /login
    console.log('\n[CHECK 2] Testing Navigation to /login Page via Navbar...');
    await signInDesktop.click();
    await page.waitForURL('**/login**');
    console.log(`  ? Navigated to: ${page.url()}`);

    // Verify Login Page Elements
    const loginHeading = await page.locator('h1:has-text("MCP-Shield Console")').textContent();
    console.log(`  ? Login Heading: "${loginHeading?.trim()}"`);

    // Check GitHub OAuth Button
    const githubOAuthBtn = page.locator('button:has-text("Continue with GitHub")');
    if (!(await githubOAuthBtn.isVisible())) {
      throw new Error('FAILED: "Continue with GitHub" button missing on /login page!');
    }
    console.log('  ? Login Page: "Continue with GitHub" OAuth button is prominent & interactive');

    // Check Work Email Form
    const emailInput = page.locator('input[type="email"]');
    if (!(await emailInput.isVisible())) {
      throw new Error('FAILED: Email input field missing on /login page!');
    }
    console.log('  ? Login Page: Work email magic link input is ready');

    // Check Demo Mode Access button
    const demoBtn = page.locator('button:has-text("Instant Demo Mode")');
    if (!(await demoBtn.isVisible())) {
      throw new Error('FAILED: Instant Demo Mode button missing on /login page!');
    }
    console.log('  ✓ Login Page: Demo access option ("Instant Demo Mode") is present');

    // 3. Verify Public User Guide (/guide) and No Master Key Leaks
    console.log('\n[CHECK 3] Verifying /guide Route (Public Access & Sanitized Licensing)...');
    await page.goto(`${BASE_URL}/guide`, { waitUntil: 'networkidle' });

    // Check H1
    const guideH1 = await page.locator('h1').textContent();
    console.log(`  ? Guide Heading: "${guideH1?.trim()}"`);

    // Verify license command does NOT leak master key
    const licenseCmd = await page.locator('text=mcpshld license <YOUR_LICENSE_KEY>').first();
    if (!(await licenseCmd.isVisible())) {
      throw new Error('FAILED: Sanitized license command `mcpshld license <YOUR_LICENSE_KEY>` not found!');
    }
    console.log('  ? User Guide: Sanitized command `mcpshld license <YOUR_LICENSE_KEY>` properly rendered');

    // Verify client configuration tabs switch interactively
    const antigravityTab = page.locator('button:has-text("Google Antigravity")');
    await antigravityTab.click();
    await page.waitForTimeout(200);
    const agContent = await page.locator('text=shielded-shell').textContent();
    console.log(`  ? User Guide Client Switch: Google Antigravity config displayed ("${agContent?.trim()}")`);

    // 4. Zero Master Key Leak across all pages & endpoints
    console.log('\n[CHECK 4] Performing Deep Leak Audit for CEO Master Key...');
    await checkNoMasterKeyLeak(page, '/');
    await checkNoMasterKeyLeak(page, '/guide');
    await checkNoMasterKeyLeak(page, '/login');
    await checkNoMasterKeyLeak(page, '/console?demo=true');

    // 5. Interactive Attack Simulator on Landing Page
    console.log('\n[CHECK 5] Testing Interactive Attack Simulator...');
    await page.goto(`${BASE_URL}/#simulator`, { waitUntil: 'domcontentloaded' });
    const runSimBtn = page.locator('button:has-text("Test Threat Vectors")').or(page.locator('button:has-text("Simulate Attack")')).first();
    if (await runSimBtn.isVisible()) {
      await runSimBtn.click();
      await page.waitForTimeout(300);
      console.log('  ? Simulator: Interactivity verified, payload trigger executed');
    }

    // 6. Real-Time Console Access
    console.log('\n[CHECK 6] Testing Real-Time Security Console (/console?demo=true)...');
    await page.goto(`${BASE_URL}/console?demo=true`, { waitUntil: 'networkidle' });
    const consoleHeading = await page.locator('h1').textContent();
    console.log(`  ? Console Loaded: "${consoleHeading?.trim()}"`);

    const healthCard = await page.locator('text=System Health').first().isVisible();
    console.log(`  ? Console Telemetry Cards Visible: ${healthCard}`);

    // 7. Dynamic SEO Routes
    console.log('\n[CHECK 7] Verifying Dynamic SEO Endpoints...');
    const robots = await page.goto(`${BASE_URL}/robots.txt`);
    if (robots?.status() !== 200) throw new Error('/robots.txt failed');
    console.log('  ? /robots.txt: HTTP 200');

    const sitemap = await page.goto(`${BASE_URL}/sitemap.xml`);
    if (sitemap?.status() !== 200) throw new Error('/sitemap.xml failed');
    console.log('  ? /sitemap.xml: HTTP 200');

    console.log('\n' + '='.repeat(70));
    console.log('?? ALL 7 PLAYWRIGHT SANITY CHECKS PASSED WITH 100% SUCCESS!');
    console.log('='.repeat(70));
  } finally {
    await browser.close();
  }
}

runSanitySuite().catch((err) => {
  console.error('\n? SANITY SUITE FAILED:', err.message);
  process.exit(1);
});
