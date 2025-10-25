// test-consumer-playback.js - Test video playback via external consumer app

const { chromium } = require('playwright');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

// Detect Chrome binary
function detectChromeBinary() {
  const platform = os.platform();
  if (platform === 'darwin') {
    return '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary';
  } else if (platform === 'linux') {
    try {
      return execSync('which google-chrome-unstable', { encoding: 'utf-8' }).trim();
    } catch (e) {
      console.error('❌ google-chrome-unstable not found');
      process.exit(1);
    }
  }
}

const CHROME_BINARY = detectChromeBinary();
const BUNDLE_PATH = path.join(__dirname, 'dist', 'amt-gateway.swbn');
const appUrl = 'isolated-app://ajl3qtbxefofp3jbs5cskw2whqpj7etglpj6mruy4oyty3k5wb5jqaacai/';

async function testConsumerPlayback() {
  console.log('╔══════════════════════════════════════════════════════════════════╗');
  console.log('║             Test Video Playback via Consumer App                 ║');
  console.log('╚══════════════════════════════════════════════════════════════════╝\n');

  const userDataDir = path.join(os.homedir(), '.chrome-iwa-persistent');
  
  const context = await chromium.launchPersistentContext(userDataDir, {
    headless: false,
    executablePath: CHROME_BINARY,
    args: [
      '--enable-features=IsolatedWebApps,IsolatedWebAppDevMode,DirectSockets',
      '--enable-experimental-web-platform-features',
      `--install-isolated-web-app-from-file=${BUNDLE_PATH}`,
    ],
  });

  const iwaPage = context.pages()[0] || await context.newPage();
  const consumerPage = await context.newPage();

  try {
    // Step 1: Open IWA
    console.log('Step 1: Opening IWA...');
    await iwaPage.goto(appUrl);
    await iwaPage.waitForTimeout(2000);

    // Verify Direct Sockets
    const hasDirectSockets = await iwaPage.evaluate(() => {
      return window.directSocketsStatus === 'available';
    });

    if (!hasDirectSockets) {
      console.log('   ❌ Direct Sockets not available');
      return;
    }
    console.log('   ✅ Direct Sockets available\n');

    // Step 2: Connect to AMT stream
    console.log('Step 2: Connecting to AMT stream...');
    await iwaPage.fill('#sourceIp', '83.97.94.146');
    await iwaPage.fill('#groupIp', '232.1.2.3');
    await iwaPage.fill('#mediaPort', '1234');
    await iwaPage.click('#connectBtn');
    
    await iwaPage.waitForTimeout(3000);

    const connectionStatus = await iwaPage.evaluate(() => {
      return document.querySelector('#status')?.textContent || '';
    });

    if (!connectionStatus.includes('Connected')) {
      console.log('   ❌ AMT connection failed');
      return;
    }
    console.log('   ✅ Connected to AMT stream\n');

    // Step 3: Wait for packets
    console.log('Step 3: Waiting for data packets...');
    await iwaPage.waitForTimeout(3000);

    const packetsReceived = await iwaPage.evaluate(() => {
      const logs = Array.from(document.querySelectorAll('#logArea div'));
      const packetLogs = logs.filter(log => log.textContent.includes('Received packet'));
      return packetLogs.length;
    });

    console.log(`   📦 Packets received: ${packetsReceived}`);
    if (packetsReceived === 0) {
      console.log('   ⚠️  No packets received yet, waiting longer...');
      await iwaPage.waitForTimeout(5000);
    }

    // Step 4: Check TCP server status
    console.log('\nStep 4: Checking TCP server status...');
    const serverStatus = await iwaPage.evaluate(() => {
      return new Promise((resolve) => {
        const logArea = document.querySelector('#logArea');
        if (logArea) {
          const logs = logArea.textContent;
          const tcpStarted = logs.includes('[TCP Server]') && logs.includes('Started');
          resolve({ tcpStarted, logs });
        } else {
          resolve({ tcpStarted: false });
        }
      });
    });

    if (serverStatus.tcpStarted) {
      console.log('   ✅ TCP server started\n');
    } else {
      console.log('   ⚠️  TCP server status unclear\n');
    }

    // Step 5: Open Consumer App
    console.log('Step 5: Opening Consumer App...');
    await consumerPage.goto('http://localhost:3000');
    await consumerPage.waitForTimeout(1000);
    console.log('   ✅ Consumer app loaded\n');

    // Step 6: Connect consumer to IWA's TCP server
    console.log('Step 6: Connecting consumer to IWA TCP server...');
    
    // Select TCP and fill in the stream details
    await consumerPage.selectOption('#serverType', 'tcp');
    await consumerPage.fill('#groupIp', '232.1.2.3');
    await consumerPage.fill('#mediaPort', '1234');
    await consumerPage.click('#connectBtn');
    
    await consumerPage.waitForTimeout(2000);

    // Step 7: Monitor playback status
    console.log('\nStep 7: Monitoring playback...\n');
    console.log('═══════════════════════════════════════════════════════════════════');

    // Listen to console messages from consumer app
    consumerPage.on('console', msg => {
      const text = msg.text();
      if (text.includes('[Consumer App]') || text.includes('[MPEG-TS Player]')) {
        console.log(`   ${text}`);
      }
    });

    // Wait and check for video playback
    await consumerPage.waitForTimeout(5000);

    const playbackStatus = await consumerPage.evaluate(() => {
      const statusDiv = document.querySelector('#statusDisplay');
      const video = document.querySelector('#videoPlayer');
      
      return {
        status: statusDiv?.textContent || '',
        videoReady: video?.readyState || 0,
        videoNetworkState: video?.networkState || 0,
        videoError: video?.error ? video.error.message : null,
        videoCurrentTime: video?.currentTime || 0,
        videoPaused: video?.paused
      };
    });

    console.log('\n═══════════════════════════════════════════════════════════════════');
    console.log('  PLAYBACK RESULTS');
    console.log('═══════════════════════════════════════════════════════════════════\n');
    console.log(`   Status: ${playbackStatus.status}`);
    console.log(`   Video Ready State: ${playbackStatus.videoReady} (4=HAVE_ENOUGH_DATA)`);
    console.log(`   Network State: ${playbackStatus.videoNetworkState} (2=LOADING, 3=NO_SOURCE)`);
    console.log(`   Current Time: ${playbackStatus.videoCurrentTime}s`);
    console.log(`   Paused: ${playbackStatus.videoPaused}`);
    
    if (playbackStatus.videoError) {
      console.log(`   ❌ Error: ${playbackStatus.videoError}`);
    }

    if (playbackStatus.videoReady >= 3 && playbackStatus.videoCurrentTime > 0) {
      console.log('\n   ✅ VIDEO PLAYBACK WORKING!\n');
    } else if (playbackStatus.status.includes('Playing')) {
      console.log('\n   ⚠️  Player started but needs more buffering...\n');
    } else {
      console.log('\n   ❌ Video playback not working\n');
    }

    console.log('═══════════════════════════════════════════════════════════════════\n');
    console.log('🎥 Browser windows remain open for manual inspection');
    console.log('   - IWA: AMT gateway with Direct Sockets');
    console.log('   - Consumer: External video player');
    console.log('\nPress Ctrl+C to exit...\n');

    await consumerPage.waitForTimeout(60000);

  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    // Don't close - leave open for inspection
  }
}

testConsumerPlayback().catch(console.error);


