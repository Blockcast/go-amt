const { test, expect, chromium } = require('@playwright/test');

test.describe('IWA Verification Tests', () => {
  let context;
  let page;
  const chromePath = process.env.CHROME_PATH || '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary';
  const userDataDir = '/tmp/chrome-iwa-test-profile';

  // Collect all console messages and errors
  const consoleMessages = [];
  const consoleErrors = [];
  const pageErrors = [];

  test.beforeAll(async () => {
    console.log('\n🔍 Starting IWA verification...\n');

    // Launch with persistent context to use the manually installed IWA
    context = await chromium.launchPersistentContext(userDataDir, {
      executablePath: chromePath,
      headless: false,
      acceptDownloads: true,
      ignoreHTTPSErrors: true,
      args: [
        '--enable-features=IsolatedWebApps,IsolatedWebAppDevMode,DirectSocketsInServiceWorkers,MulticastInDirectSockets',
        '--enable-experimental-web-platform-features',
        '--ignore-certificate-errors',
        '--no-first-run',
        '--no-default-browser-check',
        '--enable-logging=stderr',
        '--v=1',
      ],
    });

    page = context.pages()[0] || await context.newPage();

    // Capture all console messages
    page.on('console', msg => {
      const type = msg.type();
      const text = msg.text();
      consoleMessages.push({ type, text });
      
      if (type === 'error') {
        consoleErrors.push(text);
      }
      
      // Log to test output
      const emoji = {
        'log': '💬',
        'info': 'ℹ️',
        'warn': '⚠️',
        'error': '❌',
        'debug': '🔍'
      }[type] || '📝';
      console.log(`${emoji} [${type}] ${text}`);
    });

    // Capture page errors
    page.on('pageerror', error => {
      pageErrors.push(error.message);
      console.error('❌ [Page Error]', error.message);
    });
  });

  test.afterAll(async () => {
    if (context) {
      await context.close();
    }
  });

  test('should navigate to installed IWA', async () => {
    console.log('\n📱 Navigating to IWA...\n');
    
    await page.goto('https://localhost:8445', {
      waitUntil: 'networkidle',
      timeout: 30000,
    });

    // Wait a bit for app to initialize
    await page.waitForTimeout(3000);

    // Check if we're in an isolated-app context
    const url = page.url();
    console.log(`\n📍 Current URL: ${url}\n`);
    
    // For IWA, URL should start with isolated-app://
    // But for dev mode via https, it might just be https://
    expect(url).toMatch(/^(isolated-app:|https:)/);
  });

  test('should have no Service Worker registration errors', async () => {
    console.log('\n🔍 Checking for Service Worker errors...\n');
    
    // Check console errors
    const swErrors = consoleErrors.filter(msg => 
      msg.includes('Service Worker') || 
      msg.includes('ServiceWorker') ||
      msg.includes('service-worker')
    );

    if (swErrors.length > 0) {
      console.error('\n❌ Service Worker errors found:');
      swErrors.forEach(err => console.error(`   ${err}`));
      console.error('');
    }

    expect(swErrors).toHaveLength(0);
  });

  test('should have Service Worker registered', async () => {
    console.log('\n🔍 Checking Service Worker registration...\n');
    
    // Check console for success messages
    const swSuccess = consoleMessages.filter(msg => 
      msg.text.includes('Service Worker registered') ||
      msg.text.includes('Service Worker active') ||
      msg.text.includes('[SW] Activating')
    );

    console.log(`\n✓ Found ${swSuccess.length} Service Worker success messages\n`);
    
    swSuccess.forEach(msg => {
      console.log(`   ✓ ${msg.text}`);
    });

    expect(swSuccess.length).toBeGreaterThan(0);

    // Also check programmatically
    const registration = await page.evaluate(() => {
      return navigator.serviceWorker.ready.then(reg => {
        return {
          scope: reg.scope,
          active: !!reg.active,
          installing: !!reg.installing,
          waiting: !!reg.waiting,
        };
      }).catch(err => null);
    });

    console.log('\n📊 Service Worker status:', JSON.stringify(registration, null, 2), '\n');
    
    expect(registration).toBeTruthy();
    expect(registration.active).toBe(true);
  });

  test('should have Direct Sockets API available in Service Worker', async () => {
    console.log('\n🔍 Checking Direct Sockets API availability...\n');
    
    // Look for API check messages in console
    const apiMessages = consoleMessages.filter(msg => 
      msg.text.includes('Direct Sockets') ||
      msg.text.includes('UDPSocket') ||
      msg.text.includes('TCPSocket')
    );

    console.log(`\n✓ Found ${apiMessages.length} Direct Sockets API messages\n`);
    
    apiMessages.forEach(msg => {
      console.log(`   ${msg.text}`);
    });

    // Check if there's a success message
    const hasDirectSockets = consoleMessages.some(msg => 
      msg.text.includes('Direct Sockets API available')
    );

    console.log(`\n📊 Direct Sockets API available: ${hasDirectSockets ? '✅' : '❌'}\n`);
    
    expect(hasDirectSockets).toBe(true);
  });

  test('should have no page errors', async () => {
    console.log('\n🔍 Checking for page errors...\n');
    
    if (pageErrors.length > 0) {
      console.error('\n❌ Page errors found:');
      pageErrors.forEach(err => console.error(`   ${err}`));
      console.error('');
    }

    expect(pageErrors).toHaveLength(0);
  });

  test('should have no CSP violations', async () => {
    console.log('\n🔍 Checking for CSP violations...\n');
    
    const cspErrors = consoleErrors.filter(msg => 
      msg.includes('Content Security Policy') ||
      msg.includes('CSP') ||
      msg.includes('violates the following')
    );

    if (cspErrors.length > 0) {
      console.error('\n❌ CSP violations found:');
      cspErrors.forEach(err => console.error(`   ${err}`));
      console.error('');
    }

    expect(cspErrors).toHaveLength(0);
  });

  test('should have app title visible', async () => {
    console.log('\n🔍 Checking app UI elements...\n');
    
    // Check for the title
    const title = await page.textContent('h1').catch(() => null);
    console.log(`\n📝 App title: ${title}\n`);
    
    expect(title).toBeTruthy();
    expect(title).toContain('Blockcast');
  });

  test('should display full console log summary', async () => {
    console.log('\n╔════════════════════════════════════════════════════════════╗');
    console.log('║  COMPLETE CONSOLE LOG                                      ║');
    console.log('╚════════════════════════════════════════════════════════════╝\n');
    
    consoleMessages.forEach(msg => {
      const prefix = {
        'log': '  ',
        'info': 'ℹ️ ',
        'warn': '⚠️ ',
        'error': '❌',
        'debug': '🔍'
      }[msg.type] || '📝';
      
      console.log(`${prefix} ${msg.text}`);
    });
    
    console.log('\n╔════════════════════════════════════════════════════════════╗');
    console.log(`║  Summary: ${consoleMessages.length} total messages, ${consoleErrors.length} errors, ${pageErrors.length} page errors`);
    console.log('╚════════════════════════════════════════════════════════════╝\n');
    
    // This test always passes, it's just for logging
    expect(true).toBe(true);
  });
});

