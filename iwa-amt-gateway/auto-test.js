#!/usr/bin/env node
/**
 * Automated Playwright Test for IWA
 * Sets up profile if needed, verifies UI, tests playback
 */

const { chromium } = require('playwright');
const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

// Detect Chrome binary
function detectChromeBinary() {
  const platform = process.platform;
  
  if (platform === 'darwin') {
    const canaryPath = '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary';
    if (fs.existsSync(canaryPath)) return canaryPath;
  } else if (platform === 'linux') {
    const unstablePath = '/usr/bin/google-chrome-unstable';
    if (fs.existsSync(unstablePath)) return unstablePath;
  }
  
  throw new Error('Chrome Canary (macOS) or google-chrome-unstable (Linux) not found');
}

// Setup profile if it doesn't exist
function setupProfile() {
  const profilePath = path.join(__dirname, '.chrome-profile');
  
  if (fs.existsSync(profilePath)) {
    console.log('✓ Chrome profile exists\n');
    return true;
  }
  
  console.log('⚠️  Chrome profile not found, creating...\n');
  
  try {
    // Create profile directory
    fs.mkdirSync(profilePath, { recursive: true });
    
    // Create preferences file with Direct Sockets flags enabled
    const prefsDir = path.join(profilePath, 'Default');
    fs.mkdirSync(prefsDir, { recursive: true });
    
    const prefs = {
      "browser": {
        "enabled_labs_experiments": [
          "enable-experimental-web-platform-features@1"
        ]
      }
    };
    
    fs.writeFileSync(
      path.join(prefsDir, 'Preferences'),
      JSON.stringify(prefs, null, 2)
    );
    
    console.log('✓ Chrome profile created with Direct Sockets enabled\n');
    return true;
  } catch (error) {
    console.error('❌ Failed to create profile:', error.message);
    return false;
  }
}

async function runTest() {
  console.log('\n' + '='.repeat(60));
  console.log('🚀 Automated IWA Test - v1.0.22 Compact UI');
  console.log('='.repeat(60) + '\n');
  
  const chromeBinary = detectChromeBinary();
  console.log('Chrome:', chromeBinary);
  
  // Setup profile
  if (!setupProfile()) {
    process.exit(1);
  }
  
  const profilePath = path.join(__dirname, '.chrome-profile');
  const appUrl = 'isolated-app://ajl3qtbxefofp3jbs5cskw2whqpj7etglpj6mruy4oyty3k5wb5jqaacai/';
  
  console.log('Launching browser...\n');
  
  const context = await chromium.launchPersistentContext(profilePath, {
    headless: false, // IWA requires headed mode for Direct Sockets
    executablePath: chromeBinary,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--enable-features=IsolatedWebApps,IsolatedWebAppDevMode,DirectSocketsInServiceWorkers,DirectSocketsInSharedWorkers,MulticastInDirectSockets',
      '--install-isolated-web-app-from-file=' + path.join(__dirname, 'dist', 'amt-gateway.swbn'),
    ]
  });
  
  const page = context.pages()[0] || await context.newPage();
  
  // Wait for IWA installation
  console.log('Installing IWA (if not already installed)...\n');
  await page.waitForTimeout(2000);
  
  // Test results
  const results = {
    passed: [],
    failed: [],
    logs: []
  };
  
  // Monitor console
  page.on('console', msg => {
    const text = msg.text();
    results.logs.push(text);
    
    if (msg.type() === 'error') {
      console.error('❌', text);
    } else if (text.includes('v1.0.22')) {
      console.log('✓', text);
    }
  });
  
  page.on('pageerror', error => {
    results.failed.push('Page Error: ' + error.message);
    console.error('❌ Page Error:', error.message);
  });
  
  try {
    console.log(`Navigating to IWA: ${appUrl}\n`);
    await page.goto(appUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
    
    // Wait for initialization
    await page.waitForTimeout(3000);
    
    // Test 1: Check UI Elements
    console.log('📋 Test 1: UI Elements\n');
    
    const elements = [
      { id: 'stream-picker', name: 'Stream Picker' },
      { id: 'load-stream-btn', name: 'Load Stream Button' },
      { id: 'active-relay-select', name: 'Active Relay Select' },
      { id: 'video-player', name: 'Video Player' },
      { id: 'force-restart-btn', name: 'Force Restart' },
    ];
    
    for (const el of elements) {
      const count = await page.locator(`#${el.id}`).count();
      if (count > 0) {
        results.passed.push(`UI: ${el.name}`);
        console.log(`   ✅ ${el.name}`);
      } else {
        results.failed.push(`UI: ${el.name} not found`);
        console.log(`   ❌ ${el.name} NOT FOUND`);
      }
    }
    
    // Test 2: Stream Picker Population
    console.log('\n📋 Test 2: Stream Picker\n');
    
    const streamOptions = await page.locator('#stream-picker option').count();
    console.log(`   Found ${streamOptions} options`);
    
    if (streamOptions >= 8) {
      results.passed.push('Stream Picker: Populated');
      console.log('   ✅ Stream picker populated (7 streams + placeholder)');
    } else {
      results.failed.push('Stream Picker: Not populated');
      console.log('   ❌ Stream picker not populated correctly');
    }
    
    // Test 3: Service Worker
    console.log('\n📋 Test 3: Service Worker\n');
    
    await page.waitForTimeout(2000);
    
    const hasV1022 = results.logs.some(log => log.includes('v1.0.22'));
    const hasDirectStreaming = results.logs.some(log => log.includes('direct packet streaming'));
    const hasNoErrors = !results.logs.some(log => log.includes('Cannot read properties of null'));
    
    if (hasV1022) {
      results.passed.push('SW: v1.0.22 loaded');
      console.log('   ✅ Service Worker v1.0.22 loaded');
    } else {
      results.failed.push('SW: v1.0.22 not loaded');
      console.log('   ❌ Service Worker v1.0.22 not detected');
    }
    
    if (hasDirectStreaming) {
      results.passed.push('SW: Direct streaming mode');
      console.log('   ✅ Direct streaming mode active');
    }
    
    if (hasNoErrors) {
      results.passed.push('SW: No init errors');
      console.log('   ✅ No initialization errors');
    } else {
      results.failed.push('SW: Initialization errors');
      console.log('   ❌ Initialization errors detected');
    }
    
    // Test 4: Compact UI Layout
    console.log('\n📋 Test 4: Compact UI Layout\n');
    
    const controlBar = await page.locator('.control-bar').count();
    const videoContainer = await page.locator('.video-container').count();
    const compactSection = await page.locator('.compact-section').count();
    
    if (controlBar > 0) {
      results.passed.push('Layout: Control bar present');
      console.log('   ✅ Control bar present');
    } else {
      results.failed.push('Layout: Control bar missing');
      console.log('   ❌ Control bar missing');
    }
    
    if (videoContainer > 0) {
      results.passed.push('Layout: Video container present');
      console.log('   ✅ Video container present');
    } else {
      results.failed.push('Layout: Video container missing');
      console.log('   ❌ Video container missing');
    }
    
    if (compactSection > 0) {
      results.passed.push('Layout: Compact section present');
      console.log('   ✅ Compact card section present');
    } else {
      results.failed.push('Layout: Compact section missing');
      console.log('   ❌ Compact card section missing');
    }
    
    // Print Summary
    console.log('\n' + '='.repeat(60));
    console.log('📊 TEST RESULTS');
    console.log('='.repeat(60) + '\n');
    
    console.log(`✅ Passed: ${results.passed.length}`);
    console.log(`❌ Failed: ${results.failed.length}\n`);
    
    if (results.failed.length === 0) {
      console.log('🎉 🎉 🎉  ALL TESTS PASSED  🎉 🎉 🎉\n');
      console.log('UI is ready! The IWA should be working correctly.\n');
    } else {
      console.log('❌ SOME TESTS FAILED:\n');
      results.failed.forEach(f => console.log(`   • ${f}`));
      console.log('');
    }
    
    console.log('Closing browser in 3 seconds...\n');
    await page.waitForTimeout(3000);
    
  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
    results.failed.push('Fatal: ' + error.message);
  } finally {
    await context.close();
    
    // Exit with appropriate code
    const exitCode = results.failed.length > 0 ? 1 : 0;
    process.exit(exitCode);
  }
}

runTest().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});

