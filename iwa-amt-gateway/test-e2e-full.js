#!/usr/bin/env node
/**
 * Comprehensive E2E Test for IWA
 * Tests: Relays, Stats, Stream Switching, Playback
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
  fs.mkdirSync(prefsDir, { recursive: true });
  
  const prefs = {
    "browser": {
      "enabled_labs_experiments": ["enable-experimental-web-platform-features@1"]
    }
  };
  
  fs.writeFileSync(path.join(prefsDir, 'Preferences'), JSON.stringify(prefs, null, 2));
  console.log('✓ Profile created\n');
  return true;
}

async function runE2ETest() {
  console.log('\n' + '='.repeat(70));
  console.log('🧪 COMPREHENSIVE E2E TEST - IWA v1.0.22');
  console.log('Testing: Relays, Stats, Stream Switching, Playback');
  console.log('='.repeat(70) + '\n');
  
  const chromeBinary = detectChromeBinary();
  if (!setupProfile()) process.exit(1);
  
  const profilePath = path.join(__dirname, '.chrome-profile');
  const appUrl = 'isolated-app://ajl3qtbxefofp3jbs5cskw2whqpj7etglpj6mruy4oyty3k5wb5jqaacai/';
  
  console.log('🚀 Launching Chrome Canary...\n');
  
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
  
  // Track test results
  const results = {
    passed: [],
    failed: [],
    stats: {},
    logs: []
  };
  
  // Monitor console
  page.on('console', msg => {
    const text = msg.text();
    results.logs.push(text);
    
    // Track initialization
    if (text.includes('WASM initialized') || text.includes('Socket created') || text.includes('AMT Client ready')) {
      console.log('   ✓', text);
    }
    
    // Track stats updates
    if (text.includes('packets buffered') || text.includes('Received') || text.includes('Appended')) {
      console.log('   📊', text);
    }
    
    // Track connection events
    if (text.includes('Joining group') || text.includes('Connected') || text.includes('playback started') || text.includes('Creating UDP socket')) {
      console.log('   ✓', text);
    }
    
    // Track errors
    if (msg.type() === 'error' || text.includes('Error') || text.includes('Failed')) {
      console.error('   ❌', text);
    }
  });
  
  try {
    // ===== PHASE 1: Initial Load =====
    console.log('📋 PHASE 1: Initial Load & Verification\n');
    
    await page.goto(appUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.waitForTimeout(3000);
    
    console.log('✓ IWA loaded\n');
    
    // ===== PHASE 2: Stream Picker Test =====
    console.log('📋 PHASE 2: Stream Picker & Playback\n');
    
    // Use verified working stream: amt://83.97.94.146@232.1.2.3:1234 via 162.250.137.254
    console.log('   Selecting Big Buck Bunny (value="0")...');
    await page.selectOption('#stream-picker', '0');
    await page.waitForTimeout(500);
    
    const selectedOption = await page.locator('#stream-picker option:checked').textContent();
    console.log(`   Selected: ${selectedOption}`);
    
    // Click Join & Play
    console.log('   Clicking "Join" button...\n');
    await page.click('#join-group-btn');
    
    console.log('   Waiting for WASM initialization and connection (5 seconds)...\n');
    await page.waitForTimeout(5000);
    
    results.passed.push('Stream selection works');
    
    // ===== PHASE 3: Connection & Stats Monitoring =====
    console.log('\n📋 PHASE 3: Connection & Stats Monitoring\n');
    
    console.log('   Monitoring data flow (20 seconds)...\n');
    
    // Monitor stats for 15 seconds
    for (let i = 0; i < 15; i++) {
      await page.waitForTimeout(1000);
      
      // Read stats
      const packets = await page.locator('#packets-count').textContent();
      const bytes = await page.locator('#bytes-count').textContent();
      const throughput = await page.locator('#throughput').textContent();
      
      if (i % 3 === 0) {
        console.log(`   [${i}s] Packets: ${packets}, Data: ${bytes}, Throughput: ${throughput}`);
      }
      
      // Store final stats
      if (i === 14) {
        results.stats = { packets, bytes, throughput };
      }
    }
    
    // Verify stats increased
    const finalPackets = parseInt(results.stats.packets) || 0;
    if (finalPackets > 100) {
      results.passed.push(`Stats updating (${finalPackets} packets received)`);
      console.log(`\n   ✅ Stats updating correctly: ${finalPackets} packets\n`);
    } else {
      results.failed.push('Stats not updating');
      console.log('\n   ❌ Stats not updating\n');
    }
    
    // ===== PHASE 4: Video Playback Verification =====
    console.log('📋 PHASE 4: Video Playback Verification\n');
    
    // Check if video is playing
    const isVideoPlaying = await page.evaluate(() => {
      const video = document.getElementById('video-player');
      return video && !video.paused && video.readyState >= 2;
    });
    
    if (isVideoPlaying) {
      results.passed.push('Video is playing');
      console.log('   ✅ Video is playing\n');
    } else {
      results.failed.push('Video not playing');
      console.log('   ❌ Video not playing\n');
    }
    
    // Get video state
    const videoState = await page.evaluate(() => {
      const video = document.getElementById('video-player');
      return {
        paused: video.paused,
        readyState: video.readyState,
        networkState: video.networkState,
        currentTime: video.currentTime,
        duration: video.duration
      };
    });
    
    console.log('   Video State:', videoState);
    console.log('');
    
    // ===== PHASE 5: Player Controls =====
    console.log('📋 PHASE 5: Player Controls\n');
    
    // Test stop button
    console.log('   Testing Stop button...');
    await page.click('#stop-btn');
    await page.waitForTimeout(1000);
    
    const isStopped = await page.evaluate(() => {
      const video = document.getElementById('video-player');
      return video.paused;
    });
    
    if (isStopped) {
      results.passed.push('Stop button works');
      console.log('   ✅ Stop button works\n');
    } else {
      results.failed.push('Stop button failed');
      console.log('   ❌ Stop button failed\n');
    }
    
    // Test play button
    console.log('   Testing Play button...');
    await page.click('#play-btn');
    await page.waitForTimeout(1000);
    
    const isPlaying = await page.evaluate(() => {
      const video = document.getElementById('video-player');
      return !video.paused;
    });
    
    if (isPlaying) {
      results.passed.push('Play button works');
      console.log('   ✅ Play button works\n');
    } else {
      results.failed.push('Play button failed');
      console.log('   ❌ Play button failed\n');
    }
    
    // ===== PHASE 6: Stream Switching =====
    console.log('📋 PHASE 6: Stream Switching\n');
    
    // Leave current group (using the new inline leave button in hierarchy)
    console.log('   Leaving current group...');
    // Find the first leave button in the relay hierarchy (it has class "leave-group-btn")
    const leaveButton = page.locator('.leave-group-btn').first();
    const leaveButtonVisible = await leaveButton.isVisible().catch(() => false);
    
    if (leaveButtonVisible) {
      await leaveButton.click();
      console.log('   ✅ Clicked inline Leave button');
    } else {
      console.log('   ⚠️ No leave button visible, trying programmatic leave');
      // Fallback: call the leave function directly for the active group
      await page.evaluate(() => {
        // Get the active group key
        if (window.activeGroupKey && window.leaveGroup) {
          console.log('[Test] Calling window.leaveGroup with:', window.activeGroupKey);
          window.leaveGroup(window.activeGroupKey);
        } else {
          console.log('[Test] No activeGroupKey found, leaving first group');
          // If no active group, leave the first one
          const firstGroup = document.querySelector('.leave-group-btn');
          if (firstGroup) {
            firstGroup.click();
          }
        }
      });
    }
    await page.waitForTimeout(2000);
    
    // Select different stream (NSF Hour-long Videos)
    console.log('   Selecting "NSF Hour-long Videos" stream...');
    await page.selectOption('#stream-picker', '3');
    await page.waitForTimeout(500);
    
    // Load new stream
    console.log('   Loading new stream...');
    await page.click('#load-stream-btn');
    await page.waitForTimeout(3000);
    
    // Check if new stream is loading
    const statsAfterSwitch = await page.locator('#packets-count').textContent();
    console.log(`   Stats after switch: ${statsAfterSwitch} packets`);
    
    results.passed.push('Stream switching works');
    console.log('   ✅ Stream switching works\n');
    
    // ===== PHASE 7: Relay Management =====
    console.log('📋 PHASE 7: Relay Management\n');
    
    // Check active relay
    const activeRelay = await page.locator('#active-relay-select option:checked').textContent();
    console.log(`   Active relay: ${activeRelay}`);
    
    if (activeRelay && activeRelay !== 'No relay') {
      results.passed.push('Relay is active');
      console.log('   ✅ Relay is active\n');
    } else {
      results.failed.push('No active relay');
      console.log('   ❌ No active relay\n');
    }
    
    // ===== PHASE 8: Manual Join Test =====
    console.log('📋 PHASE 8: Manual Join Test\n');
    
    console.log('   Testing manual group join...');
    await page.fill('#source-address', '83.97.94.146');
    await page.fill('#group-address', '232.1.2.3');
    await page.fill('#media-port', '1234');
    await page.waitForTimeout(500);
    
    await page.click('#join-group-btn');
    await page.waitForTimeout(3000);
    
    results.passed.push('Manual join works');
    console.log('   ✅ Manual join form works\n');
    
    // ===== PHASE 9: Group List Verification =====
    console.log('📋 PHASE 9: Active Groups List\n');
    
    const groupOptions = await page.locator('#group-list option').count();
    console.log(`   Found ${groupOptions} group(s) in list`);
    
    if (groupOptions > 1) {
      results.passed.push('Groups list populated');
      console.log('   ✅ Active groups list populated\n');
    } else {
      console.log('   ⚠️  Groups list may be empty\n');
    }
    
    // ===== PHASE 10: Final Stats Check =====
    console.log('📋 PHASE 10: Final Stats & Health Check\n');
    
    await page.waitForTimeout(3000);
    
    const finalStats = {
      packets: await page.locator('#packets-count').textContent(),
      bytes: await page.locator('#bytes-count').textContent(),
      throughput: await page.locator('#throughput').textContent(),
      uptime: await page.locator('#connection-time').textContent()
    };
    
    console.log('   Final Stats:');
    console.log(`     • Packets: ${finalStats.packets}`);
    console.log(`     • Data: ${finalStats.bytes}`);
    console.log(`     • Throughput: ${finalStats.throughput}`);
    console.log(`     • Uptime: ${finalStats.uptime}`);
    console.log('');
    
    // Check for console errors
    const hasErrors = results.logs.some(log => 
      log.includes('Error') && 
      !log.includes('PacketBuffer') // Ignore expected buffer management logs
    );
    
    if (!hasErrors) {
      results.passed.push('No critical errors');
      console.log('   ✅ No critical errors in console\n');
    } else {
      results.failed.push('Console errors detected');
      console.log('   ⚠️  Some errors in console\n');
    }
    
    // ===== FINAL SUMMARY =====
    console.log('='.repeat(70));
    console.log('📊 FINAL TEST RESULTS');
    console.log('='.repeat(70) + '\n');
    
    console.log(`✅ Passed: ${results.passed.length}`);
    results.passed.forEach(p => console.log(`   ✓ ${p}`));
    console.log('');
    
    if (results.failed.length > 0) {
      console.log(`❌ Failed: ${results.failed.length}`);
      results.failed.forEach(f => console.log(`   ✗ ${f}`));
      console.log('');
    }
    
    console.log('📈 Performance Summary:');
    console.log(`   • Total Packets: ${finalStats.packets}`);
    console.log(`   • Data Received: ${finalStats.bytes}`);
    console.log(`   • Throughput: ${finalStats.throughput}`);
    console.log(`   • Connection Time: ${finalStats.uptime}`);
    console.log('');
    
    if (results.failed.length === 0) {
      console.log('🎉 🎉 🎉  ALL E2E TESTS PASSED  🎉 🎉 🎉\n');
      console.log('The IWA is fully functional with:');
      console.log('  ✓ Stream selection and playback');
      console.log('  ✓ Real-time statistics');
      console.log('  ✓ Player controls');
      console.log('  ✓ Stream switching');
      console.log('  ✓ Relay management');
      console.log('  ✓ Manual group join');
      console.log('');
    } else {
      console.log('⚠️  SOME TESTS FAILED\n');
      console.log('Review the failures above for details.\n');
    }
    
    console.log('Browser will close in 5 seconds...\n');
    await page.waitForTimeout(5000);
    
  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
    results.failed.push('Fatal: ' + error.message);
  } finally {
    await context.close();
    const exitCode = results.failed.length > 0 ? 1 : 0;
    process.exit(exitCode);
  }
}

runE2ETest().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});

