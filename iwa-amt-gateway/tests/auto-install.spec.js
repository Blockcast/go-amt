const { test, expect, chromium } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

test.describe('Auto-Install IWA using Web App Installation API', () => {
  let context;
  let page;
  const chromePath = process.env.CHROME_PATH || '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary';
  const userDataDir = '/tmp/chrome-iwa-auto-install';

  test.beforeAll(async () => {
    console.log('\n🚀 Setting up auto-install test...\n');
    
    // Clean up old profile
    if (fs.existsSync(userDataDir)) {
      fs.rmSync(userDataDir, { recursive: true, force: true });
      console.log('✓ Cleaned up old profile');
    }

    // Launch with persistent context
    context = await chromium.launchPersistentContext(userDataDir, {
      executablePath: chromePath,
      headless: false,
      acceptDownloads: true,
      ignoreHTTPSErrors: true,
      args: [
        // IWA and Direct Sockets features
        '--enable-features=IsolatedWebApps,IsolatedWebAppDevMode,DirectSocketsInServiceWorkers,MulticastInDirectSockets,WebAppInstallation',
        
        // Experimental features
        '--enable-experimental-web-platform-features',
        
        // SSL
        '--ignore-certificate-errors',
        
        // No dialogs
        '--no-first-run',
        '--no-default-browser-check',
        
        // Enable logging
        '--enable-logging=stderr',
        '--v=1',
      ],
    });

    page = context.pages()[0] || await context.newPage();
    
    // Listen for all console messages
    page.on('console', msg => {
      const type = msg.type();
      const text = msg.text();
      const emoji = {
        'log': '💬',
        'info': 'ℹ️',
        'warn': '⚠️',
        'error': '❌',
        'debug': '🔍'
      }[type] || '📝';
      console.log(`${emoji} [Console ${type}] ${text}`);
    });

    // Listen for page errors
    page.on('pageerror', error => {
      console.error('❌ [Page Error]', error.message);
    });

    // Listen for dialog events (install prompts)
    page.on('dialog', async dialog => {
      console.log(`\n🔔 Dialog appeared: ${dialog.type()}`);
      console.log(`   Message: ${dialog.message()}`);
      
      // Accept all dialogs automatically
      await dialog.accept();
      console.log('   ✓ Dialog accepted\n');
    });

    console.log('✓ Browser launched\n');
  });

  test.afterAll(async () => {
    if (context) {
      await context.close();
    }
  });

  test('should attempt to install IWA using Web App Installation API', async () => {
    console.log('📱 Navigating to auto-install page...\n');
    
    // Navigate to the auto-install page with autoinstall flag
    await page.goto('https://localhost:8445/auto-install.html?autoinstall=true', {
      waitUntil: 'networkidle',
    });

    console.log('✓ Page loaded\n');
    
    // Wait a bit for auto-install to trigger
    await page.waitForTimeout(3000);
    
    // Check the status div for results
    const statusText = await page.locator('#status').innerText();
    console.log('\n📊 Installation Status:');
    console.log(statusText);
    
    // Check for success indicators
    const hasNavigatorInstall = statusText.includes('navigator.install()');
    const hasBeforeInstallPrompt = statusText.includes('beforeinstallprompt');
    
    console.log(`\n✓ navigator.install available: ${hasNavigatorInstall ? '✅' : '❌'}`);
    console.log(`✓ beforeinstallprompt available: ${hasBeforeInstallPrompt ? '✅' : '❌'}`);
    
    // Wait for any additional prompts or windows
    await page.waitForTimeout(2000);
    
    // Check if new IWA window opened
    const contexts = context.pages();
    console.log(`\n📱 Open pages: ${contexts.length}`);
    
    for (const p of contexts) {
      const url = p.url();
      console.log(`   - ${url}`);
      
      if (url.startsWith('isolated-app://')) {
        console.log('\n✅ SUCCESS! IWA window detected!\n');
        
        // Get console logs from IWA
        p.on('console', msg => {
          console.log(`📱 [IWA Console] ${msg.text()}`);
        });
        
        await p.waitForTimeout(2000);
      }
    }
    
    // Keep browser open for manual inspection
    console.log('\n⏸️  Browser will stay open for 30 seconds for inspection...\n');
    await page.waitForTimeout(30000);
  });

  test('should check installation APIs and capabilities', async () => {
    console.log('🔍 Checking installation APIs...\n');
    
    await page.goto('https://localhost:8445/auto-install.html', {
      waitUntil: 'networkidle',
    });

    // Click the check API button
    await page.click('#checkApiButton');
    await page.waitForTimeout(2000);
    
    const statusText = await page.locator('#status').innerText();
    console.log('\n📊 API Check Results:');
    console.log(statusText);
    
    // Evaluate APIs directly
    const apiCheck = await page.evaluate(() => {
      return {
        hasNavigatorInstall: typeof navigator.install !== 'undefined',
        hasBeforeInstallPrompt: typeof window.BeforeInstallPromptEvent !== 'undefined',
        hasGetInstalledRelatedApps: typeof navigator.getInstalledRelatedApps !== 'undefined',
        standalone: navigator.standalone,
        userAgent: navigator.userAgent,
      };
    });
    
    console.log('\n📋 Direct API Check:');
    console.log(JSON.stringify(apiCheck, null, 2));
    
    await page.waitForTimeout(5000);
  });
});

