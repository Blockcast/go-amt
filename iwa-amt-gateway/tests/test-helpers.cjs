// test-helpers.js
// Reusable Playwright helpers for IWA testing

const { chromium } = require('playwright');
const path = require('path');
const os = require('os');
const fs = require('fs');

/**
 * Get Chrome/Chromium executable path
 */
function getChromePath() {
  if (process.platform === 'darwin') {
    return '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary';
  } else {
    return '/usr/bin/google-chrome-unstable';
  }
}

/**
 * Get bundle path and ID
 */
function getBundleInfo() {
  const bundlePath = path.join(__dirname, '..', 'dist', 'amt-gateway.swbn');
  const bundleId = '63iw7l6wiyrz6hutdaxubhxqh6tgthrxdfnqs5re4jupqxsdrr5aaaic';
  
  return { bundlePath, bundleId };
}

/**
 * Get the persistent test profile directory
 */
function getTestProfileDir() {
  return path.join(__dirname, '..', '.test-profile');
}

/**
 * Check if test profile exists and has IWA installed
 */
function isTestProfileReady() {
  const profileDir = getTestProfileDir();
  return fs.existsSync(profileDir);
}

/**
 * Install IWA using persistent test profile
 * 
 * NOTE: This requires the test profile to be set up first.
 * Run: npm run test:setup-profile
 */
async function installIWA(options = {}) {
  const {
    headless = false,
    timeout = 30000
  } = options;
  
  const { bundleId } = getBundleInfo();
  const profileDir = getTestProfileDir();
  
  // Check if profile exists
  if (!isTestProfileReady()) {
    throw new Error(
      'Test profile not found. Run setup first:\n' +
      '  npm run test:setup-profile\n' +
      'Or:\n' +
      '  node tests/setup-test-profile.js'
    );
  }
  
  const chromePath = getChromePath();
  
  console.log(`  Using test profile: ${profileDir}`);
  console.log(`  Bundle ID: ${bundleId}`);
  
  const context = await chromium.launchPersistentContext(profileDir, {
    executablePath: chromePath,
    headless,
    args: [
      // IWA support
      '--enable-features=IsolatedWebApps',
      '--enable-features=IsolatedWebAppDevMode',
      
      // Direct Sockets support
      '--enable-features=DirectSocketsInServiceWorkers',
      '--enable-features=DirectSockets',
      '--enable-features=MulticastInDirectSockets',
      
      // Other useful flags
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-background-timer-throttling',
      '--disable-backgrounding-occluded-windows',
      '--disable-renderer-backgrounding'
    ],
    ignoreHTTPSErrors: true
  });
  
  // Open IWA (should already be installed in this profile)
  const page = await context.newPage();
  const iwaUrl = `isolated-app://${bundleId}/`;
  
  console.log(`  Opening IWA: ${iwaUrl}`);
  await page.goto(iwaUrl, { waitUntil: 'domcontentloaded', timeout });
  
  // Wait for service worker to be ready
  await page.waitForTimeout(2000);
  
  return { context, page, bundleId, userDataDir: profileDir };
}

/**
 * Wait for service worker to be active
 */
async function waitForServiceWorker(page, timeout = 10000) {
  await page.waitForFunction(() => {
    return navigator.serviceWorker.controller !== null;
  }, { timeout });
  
  console.log('  ✓ Service worker active');
}

/**
 * Check if Direct Sockets API is available
 */
async function checkDirectSocketsAPI(page) {
  const available = await page.evaluate(async () => {
    // Send message to service worker to check
    if (!navigator.serviceWorker.controller) {
      return { error: 'No service worker controller' };
    }
    
    return new Promise((resolve) => {
      const channel = new MessageChannel();
      channel.port1.onmessage = (event) => {
        resolve(event.data);
      };
      
      navigator.serviceWorker.controller.postMessage({
        type: 'CHECK_API',
        data: {}
      }, [channel.port2]);
      
      // Timeout
      setTimeout(() => resolve({ error: 'Timeout' }), 5000);
    });
  });
  
  if (available.error) {
    console.error('  ✗ Direct Sockets check failed:', available.error);
    return false;
  }
  
  if (available.available && available.hasUDP) {
    console.log('  ✓ Direct Sockets API available');
    return true;
  } else {
    console.error('  ✗ Direct Sockets API NOT available');
    return false;
  }
}

/**
 * Send test packet via service worker
 */
async function sendTestPacket(page, data) {
  return await page.evaluate(async (packetData) => {
    return new Promise((resolve) => {
      const channel = new MessageChannel();
      channel.port1.onmessage = (event) => {
        resolve(event.data);
      };
      
      navigator.serviceWorker.controller.postMessage({
        type: 'SEND_UDP',
        data: {
          buffer: new Uint8Array(packetData).buffer,
          remoteAddress: '127.0.0.1',
          remotePort: 5000
        }
      }, [channel.port2]);
    });
  }, data);
}

/**
 * Get server status from service worker
 */
async function getServerStatus(page) {
  return await page.evaluate(async () => {
    return new Promise((resolve) => {
      const channel = new MessageChannel();
      channel.port1.onmessage = (event) => {
        resolve(event.data);
      };
      
      navigator.serviceWorker.controller.postMessage({
        type: 'GET_SERVER_STATUS'
      }, [channel.port2]);
      
      setTimeout(() => resolve({ error: 'Timeout' }), 5000);
    });
  });
}

/**
 * Clean up test environment
 */
async function cleanup(context, userDataDir) {
  if (context) {
    await context.close();
  }
  
  // Clean up user data dir
  if (userDataDir && fs.existsSync(userDataDir)) {
    try {
      fs.rmSync(userDataDir, { recursive: true, force: true });
    } catch (err) {
      console.warn('Failed to clean up user data dir:', err.message);
    }
  }
}

module.exports = {
  installIWA,
  waitForServiceWorker,
  checkDirectSocketsAPI,
  sendTestPacket,
  getServerStatus,
  cleanup,
  getBundleInfo,
  getChromePath,
  getTestProfileDir,
  isTestProfileReady
};

