#!/usr/bin/env node
/**
 * Simple manual test - Just open IWA and auto-play verified stream
 * Keep browser open for manual inspection
 */

const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

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

function setupProfile() {
  const profilePath = path.join(__dirname, '.chrome-profile');
  if (fs.existsSync(profilePath)) return true;
  
  console.log('⚠️  Creating Chrome profile...');
  fs.mkdirSync(profilePath, { recursive: true });
  const prefsDir = path.join(profilePath, 'Default');
  fs.mkdirSync(prefsDir, { recursive: true});
  
  const prefs = {
    "browser": {
      "enabled_labs_experiments": ["enable-experimental-web-platform-features@1"]
    }
  };
  
  fs.writeFileSync(path.join(prefsDir, 'Preferences'), JSON.stringify(prefs, null, 2));
  console.log('✓ Profile created\n');
  return true;
}

async function runManualTest() {
  console.log('\n' + '='.repeat(70));
  console.log('🎥 MANUAL STREAM TEST - Verified Stream (Big Buck Bunny)');
  console.log('='.repeat(70) + '\n');
  
  const chromeBinary = detectChromeBinary();
  if (!setupProfile()) process.exit(1);
  
  const profilePath = path.join(__dirname, '.chrome-profile');
  const appUrl = 'isolated-app://ajl3qtbxefofp3jbs5cskw2whqpj7etglpj6mruy4oyty3k5wb5jqaacai/';
  
  console.log('🚀 Launching Chrome Canary...\n');
  console.log('Stream: amt://83.97.94.146@232.1.2.3:1234');
  console.log('Relay: 162.250.137.254:2268\n');
  
  const context = await chromium.launchPersistentContext(profilePath, {
    headless: false,
    executablePath: chromeBinary,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--enable-features=IsolatedWebApps,IsolatedWebAppDevMode,DirectSocketsInServiceWorkers,DirectSocketsInSharedWorkers,MulticastInDirectSockets',
      '--install-isolated-web-app-from-file=' + path.join(__dirname, 'dist', 'amt-gateway.swbn'),
    ]
  });
  
  const page = context.pages()[0] || await context.newPage();
  
  // Monitor console
  let packetCount = 0;
  let lastUpdate = Date.now();
  
  page.on('console', msg => {
    const text = msg.text();
    
    if (text.includes('v1.0.24')) {
      console.log('✓', text);
    }
    
    if (text.includes('packets buffered') || text.includes('Received') || text.includes('Appended')) {
      console.log('📊', text);
    }
    
    if (text.includes('Starting direct')) {
      console.log('✓', text);
    }
    
    if (text.includes('Stats:') || text.includes('UI updated')) {
      console.log('📈', text);
    }
    
    if (msg.type() === 'error') {
      console.error('❌', text);
    }
  });
  
  try {
    console.log('Loading IWA...\n');
    await page.goto(appUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.waitForTimeout(3000);
    
    console.log('✅ IWA loaded\n');
    console.log('Auto-selecting verified stream (Big Buck Bunny)...\n');
    
    // Get all stream options
    const options = await page.locator('#stream-picker option').allTextContents();
    console.log('Available streams:', options);
    
    // Big Buck Bunny should be at PRELOADED_STREAMS[0], which means value="0"
    // (The placeholder "-- Choose a stream --" has value="")
    console.log('\nSelecting Big Buck Bunny (value="0")...\n');
    await page.selectOption('#stream-picker', '0');
    await page.waitForTimeout(500);
    
    // Verify selection
    const selectedValue = await page.locator('#stream-picker').inputValue();
    const selectedOption = await page.locator('#stream-picker option:checked').textContent();
    console.log(`Selected value: "${selectedValue}"`);
    console.log(`Selected option: "${selectedOption}"\n`);
    
    // Check if join button is enabled
    const isJoinBtnEnabled = await page.locator('#join-group-btn').isEnabled();
    console.log(`Join button enabled: ${isJoinBtnEnabled}\n`);
    
    if (!isJoinBtnEnabled) {
      throw new Error('Join button is disabled! Stream selection may have failed.');
    }
    
    await page.click('#join-group-btn');
    
    console.log('✅ Stream loading...\n');
    console.log('Monitoring for 30 seconds...\n');
    console.log('---\n');
    
    // Monitor for 30 seconds
    for (let i = 0; i < 30; i++) {
      await page.waitForTimeout(1000);
      
      // Read stats every 5 seconds
      if (i % 5 === 0) {
        const packets = await page.locator('#packets-count').textContent();
        const bytes = await page.locator('#bytes-count').textContent();
        const throughput = await page.locator('#throughput').textContent();
        const uptime = await page.locator('#connection-time').textContent();
        
        console.log(`[${i}s] Packets: ${packets}, Data: ${bytes}, Throughput: ${throughput}, Uptime: ${uptime}`);
      }
    }
    
    console.log('\n---\n');
    console.log('✅ Monitoring complete\n');
    console.log('Browser will stay open for manual inspection.');
    console.log('Press Ctrl+C to close.\n');
    
    // Keep open indefinitely
    await page.waitForTimeout(1000000);
    
  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
  } finally {
    // Don't close - let user inspect
  }
}

runManualTest().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});

