/**
 * Playwright UI Verification Test
 * Verifies IWA loads correctly with new UI elements
 */

const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

// Detect Chrome binary
function detectChromeBinary() {
  const platform = process.platform;
  
  if (platform === 'darwin') {
    // macOS - Chrome Canary
    const canaryPath = '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary';
    if (fs.existsSync(canaryPath)) {
      return canaryPath;
    }
  } else if (platform === 'linux') {
    // Linux - google-chrome-unstable
    const unstablePath = '/usr/bin/google-chrome-unstable';
    if (fs.existsSync(unstablePath)) {
      return unstablePath;
    }
  }
  
  throw new Error('Chrome Canary (macOS) or google-chrome-unstable (Linux) not found');
}

async function verifyUI() {
  const chromeBinary = detectChromeBinary();
  console.log('Using Chrome:', chromeBinary);
  
  const profilePath = path.join(__dirname, '.chrome-profile');
  
  if (!fs.existsSync(profilePath)) {
    console.error('❌ Chrome profile not found. Run: npm run setup');
    process.exit(1);
  }
  
  console.log('Launching Chrome with persistent profile...\n');
  
  const context = await chromium.launchPersistentContext(profilePath, {
    headless: false,
    executablePath: chromeBinary,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
    ]
  });
  
  const page = context.pages()[0] || await context.newPage();
  
  // Monitor console for errors
  const consoleErrors = [];
  const uiErrors = [];
  
  page.on('console', msg => {
    const text = msg.text();
    if (msg.type() === 'error') {
      consoleErrors.push(text);
      console.error('❌ Console Error:', text);
    } else if (text.includes('v1.0.21')) {
      console.log('✓', text);
    }
  });
  
  page.on('pageerror', error => {
    uiErrors.push(error.message);
    console.error('❌ Page Error:', error.message);
  });
  
  try {
    // Navigate to IWA
    const appUrl = 'isolated-app://aergiaqbhaptfnlodbmpencrkilnaoejhhkmklnfohadnofj3qglqa';
    console.log(`Navigating to: ${appUrl}\n`);
    
    await page.goto(appUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
    
    // Wait for app initialization
    await page.waitForTimeout(3000);
    
    console.log('\n📋 Verifying UI Elements...\n');
    
    // Check critical elements
    const checks = [
      { id: 'force-restart-btn', name: 'Force Restart button' },
      { id: 'relay-address', name: 'Relay Address input' },
      { id: 'relay-name', name: 'Relay Name input' },
      { id: 'add-relay-btn', name: 'Add Relay button' },
      { id: 'disconnect-relay-btn', name: 'Disconnect Relay button' },
      { id: 'relay-list', name: 'Relay List dropdown' },
      { id: 'stream-picker', name: 'Stream Picker dropdown' },
      { id: 'load-stream-btn', name: 'Load Stream button' },
      { id: 'source-address', name: 'Source Address input' },
      { id: 'group-address', name: 'Group Address input' },
      { id: 'media-port', name: 'Media Port input' },
      { id: 'join-group-btn', name: 'Join Group button' },
      { id: 'leave-group-btn', name: 'Leave Group button' },
      { id: 'refresh-playback-btn', name: 'Refresh Playback button' },
      { id: 'group-list', name: 'Group List dropdown' },
      { id: 'video-player', name: 'Video Player' },
    ];
    
    let passCount = 0;
    let failCount = 0;
    
    for (const check of checks) {
      const element = await page.locator(`#${check.id}`).count();
      if (element > 0) {
        console.log(`✅ ${check.name}`);
        passCount++;
      } else {
        console.log(`❌ ${check.name} - NOT FOUND`);
        failCount++;
      }
    }
    
    console.log(`\n📊 Results: ${passCount} passed, ${failCount} failed\n`);
    
    // Check for stream picker options
    console.log('🔍 Checking Stream Picker...\n');
    const streamOptions = await page.locator('#stream-picker option').count();
    console.log(`   Found ${streamOptions} options (expected 8: 1 placeholder + 7 streams)`);
    if (streamOptions >= 8) {
      console.log('✅ Stream picker populated correctly\n');
    } else {
      console.log('❌ Stream picker not populated correctly\n');
      failCount++;
    }
    
    // Check for Service Worker version
    console.log('🔍 Checking Service Worker version...\n');
    await page.waitForTimeout(1000);
    const hasCorrectVersion = consoleErrors.length === 0 && 
                              !uiErrors.some(e => e.includes('Cannot read properties of null'));
    
    if (hasCorrectVersion) {
      console.log('✅ No UI initialization errors\n');
    } else {
      console.log('❌ UI initialization errors detected\n');
      failCount++;
    }
    
    // Summary
    console.log('\n' + '='.repeat(60));
    if (failCount === 0 && consoleErrors.length === 0 && uiErrors.length === 0) {
      console.log('✅ ✅ ✅  ALL CHECKS PASSED  ✅ ✅ ✅');
      console.log('='.repeat(60) + '\n');
      console.log('UI is ready to use! Try selecting a stream from the dropdown.\n');
    } else {
      console.log('❌ ❌ ❌  VERIFICATION FAILED  ❌ ❌ ❌');
      console.log('='.repeat(60) + '\n');
      console.log(`Failures: ${failCount}`);
      console.log(`Console Errors: ${consoleErrors.length}`);
      console.log(`Page Errors: ${uiErrors.length}\n`);
    }
    
    // Keep browser open for manual testing
    console.log('Browser will remain open for manual testing.');
    console.log('Close the browser window when done.\n');
    
    await page.waitForTimeout(300000); // Wait 5 minutes
    
  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
    process.exit(1);
  } finally {
    await context.close();
  }
}

verifyUI().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});


