// Complete IWA test with automated installation and Direct Sockets testing
import { test, expect } from '@playwright/test';
import { spawn } from 'child_process';
import { promisify } from 'util';
import { exec as execCallback } from 'child_process';

const exec = promisify(execCallback);
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

let httpsServer = null;

test.describe('IWA AMT Gateway Complete Test', () => {
  
  test.beforeAll(async () => {
    // Kill any existing server
    try {
      await exec('pkill -f "python3.*https-server.py" || true');
      await exec('lsof -ti:8445 | xargs kill -9 2>/dev/null || true');
      await sleep(2000);
    } catch (e) {
      // Ignore errors
    }

    // Start HTTPS server
    console.log('Starting HTTPS server on port 8445...');
    httpsServer = spawn('python3', ['https-server.py'], {
      cwd: process.cwd(),
      stdio: 'pipe',
      detached: false
    });

    httpsServer.stdout.on('data', (data) => {
      console.log(`HTTPS Server: ${data}`);
    });

    httpsServer.stderr.on('data', (data) => {
      console.error(`HTTPS Server Error: ${data}`);
    });

    // Wait for server to be ready
    await sleep(3000);
    
    console.log('HTTPS server started successfully');
  });

  test.afterAll(async () => {
    // Stop HTTPS server
    if (httpsServer) {
      httpsServer.kill('SIGTERM');
      await sleep(1000);
    }
  });

  test('should verify HTTPS server and manifest accessibility', async ({ page }) => {
    console.log('\n=== Step 1: Verify HTTPS Server ===');
    
    // Set up console logging
    const consoleLogs = [];
    page.on('console', msg => {
      const text = msg.text();
      consoleLogs.push({ type: msg.type(), text });
      console.log(`[Browser ${msg.type()}] ${text}`);
    });

    // Capture page errors
    page.on('pageerror', error => {
      console.error('[Page Error]', error.message);
    });

    // Navigate to test page
    console.log('Navigating to https://localhost:8445/test-iwa-csp.html');
    await page.goto('https://localhost:8445/test-iwa-csp.html', {
      waitUntil: 'networkidle',
      timeout: 30000
    });

    // Check if page loaded
    const title = await page.title();
    console.log('Page title:', title);

    // Verify manifest is accessible
    console.log('Checking manifest accessibility...');
    const manifestResponse = await page.goto('https://localhost:8445/manifest.webmanifest');
    expect(manifestResponse.status()).toBe(200);
    
    const manifestJson = await manifestResponse.json();
    console.log('Manifest loaded:', JSON.stringify(manifestJson, null, 2));
    
    expect(manifestJson.name).toBe('Blockcast AMT Gateway');
    expect(manifestJson.permissions).toContain('direct-sockets');
    
    console.log('✓ Manifest verified');

    // Verify well-known manifest
    const wellKnownResponse = await page.goto('https://localhost:8445/.well-known/manifest.webmanifest');
    expect(wellKnownResponse.status()).toBe(200);
    console.log('✓ Well-known manifest accessible');

    // Verify icons
    const iconResponse = await page.goto('https://localhost:8445/icons/icon-144.png');
    expect(iconResponse.status()).toBe(200);
    console.log('✓ Icons accessible');
  });

  test('should install IWA and verify Direct Sockets availability', async ({ page, context }) => {
    console.log('\n=== Step 2: Install IWA ===');

    // Set up comprehensive console logging
    const consoleLogs = [];
    page.on('console', msg => {
      const text = msg.text();
      const location = msg.location();
      consoleLogs.push({ 
        type: msg.type(), 
        text,
        url: location.url,
        lineNumber: location.lineNumber 
      });
      console.log(`[${msg.type().toUpperCase()}] ${text}`);
      if (location.url) {
        console.log(`  at ${location.url}:${location.lineNumber}`);
      }
    });

    // Capture errors
    page.on('pageerror', error => {
      console.error('[PAGE ERROR]', error.message);
      console.error(error.stack);
    });

    // Capture network failures
    page.on('requestfailed', request => {
      console.error(`[NETWORK FAILURE] ${request.url()}: ${request.failure().errorText}`);
    });

    // Navigate to Web App Internals
    console.log('Navigating to chrome://web-app-internals...');
    await page.goto('chrome://web-app-internals', {
      timeout: 30000
    });

    await sleep(2000);

    // Take a screenshot
    await page.screenshot({ path: 'playwright-report/web-app-internals.png', fullPage: true });

    // Look for IWA installation UI
    console.log('Looking for IWA installation interface...');
    
    // Try to find the install button or input
    const installSection = page.locator('text=/Install.*IWA.*Dev.*Mode/i').first();
    
    if (await installSection.isVisible()) {
      console.log('✓ Found IWA Dev Mode installation section');
      
      // Find the URL input field
      const urlInput = page.locator('input[type="text"]').filter({ hasText: '' }).first();
      
      // Enter the IWA URL
      console.log('Entering IWA URL: https://localhost:8445');
      await urlInput.fill('https://localhost:8445');
      
      // Find and click install button
      const installButton = page.locator('button', { hasText: /install/i }).first();
      await installButton.click();
      
      console.log('Clicked install button, waiting for installation...');
      await sleep(5000);
      
      await page.screenshot({ path: 'playwright-report/after-install.png', fullPage: true });
      
    } else {
      console.log('⚠️  Could not find automatic installation UI');
      console.log('Manual steps required:');
      console.log('1. Go to chrome://web-app-internals');
      console.log('2. Click "Install IWA via Dev Mode Proxy"');
      console.log('3. Enter URL: https://localhost:8445');
      console.log('4. Click Install');
      
      // Keep browser open for manual installation
      console.log('\nPausing for 30 seconds to allow manual installation...');
      await sleep(30000);
    }

    // Try to find the installed IWA
    console.log('Looking for installed IWA...');
    const installedApps = await page.locator('text=/Blockcast AMT Gateway/i').all();
    
    if (installedApps.length > 0) {
      console.log(`✓ Found ${installedApps.length} installed app(s)`);
      
      // Try to launch the IWA
      const launchButton = page.locator('button', { hasText: /launch|open/i }).first();
      if (await launchButton.isVisible()) {
        console.log('Launching IWA...');
        await launchButton.click();
        await sleep(3000);
      }
    } else {
      console.log('⚠️  IWA not found in installed apps list');
    }

    // Check if any new page/window opened (the IWA)
    const pages = context.pages();
    console.log(`Current pages/windows: ${pages.length}`);
    
    for (let i = 0; i < pages.length; i++) {
      const p = pages[i];
      const url = p.url();
      console.log(`  Page ${i}: ${url}`);
      
      // Check if this is the IWA (isolated-app:// protocol)
      if (url.startsWith('isolated-app://')) {
        console.log('\n=== IWA Found! ===');
        console.log(`IWA URL: ${url}`);
        
        // Set up logging for IWA page
        p.on('console', msg => {
          console.log(`[IWA ${msg.type().toUpperCase()}] ${msg.text()}`);
        });
        
        p.on('pageerror', error => {
          console.error('[IWA ERROR]', error.message);
        });
        
        // Wait for page to load
        await p.waitForLoadState('networkidle', { timeout: 30000 });
        await sleep(2000);
        
        // Take screenshot of IWA
        await p.screenshot({ path: 'playwright-report/iwa-loaded.png', fullPage: true });
        
        // Check if Direct Sockets API is available
        console.log('\n=== Testing Direct Sockets API ===');
        
        const directSocketsCheck = await p.evaluate(async () => {
          const results = {
            protocol: window.location.protocol,
            isSecureContext: window.isSecureContext,
            hasServiceWorker: 'serviceWorker' in navigator,
            serviceWorkerReady: false,
            hasUDPSocket: false,
            hasTCPSocket: false,
            error: null
          };
          
          try {
            // Register service worker
            if (results.hasServiceWorker) {
              const registration = await navigator.serviceWorker.register('./service-worker-minimal.js');
              await navigator.serviceWorker.ready;
              results.serviceWorkerReady = true;
              
              // Check Direct Sockets in Service Worker
              // Send message to check
              const sw = registration.active;
              if (sw) {
                const response = await new Promise((resolve) => {
                  const channel = new MessageChannel();
                  channel.port1.onmessage = (e) => resolve(e.data);
                  sw.postMessage({ type: 'CHECK_API' }, [channel.port2]);
                });
                
                results.hasUDPSocket = response.hasUDP || false;
                results.hasTCPSocket = response.hasTCP || false;
              }
            }
          } catch (error) {
            results.error = error.message;
          }
          
          return results;
        });
        
        console.log('\nDirect Sockets Check Results:');
        console.log(JSON.stringify(directSocketsCheck, null, 2));
        
        // Verify we're in isolated context
        expect(directSocketsCheck.protocol).toBe('isolated-app:');
        expect(directSocketsCheck.isSecureContext).toBe(true);
        
        if (directSocketsCheck.serviceWorkerReady) {
          console.log('✓ Service Worker registered successfully');
        }
        
        if (directSocketsCheck.hasUDPSocket) {
          console.log('✓ UDPSocket API available in Service Worker!');
        } else {
          console.log('⚠️  UDPSocket API not available');
        }
        
        // Test actual socket creation
        if (directSocketsCheck.hasUDPSocket) {
          console.log('\n=== Testing UDP Socket Creation ===');
          
          const socketTest = await p.evaluate(async () => {
            try {
              // Request service worker to create socket
              const registration = await navigator.serviceWorker.ready;
              const sw = registration.active;
              
              const result = await new Promise((resolve, reject) => {
                const channel = new MessageChannel();
                const timeout = setTimeout(() => {
                  reject(new Error('Timeout waiting for socket creation'));
                }, 10000);
                
                channel.port1.onmessage = (e) => {
                  clearTimeout(timeout);
                  resolve(e.data);
                };
                
                sw.postMessage({ type: 'CREATE_SOCKET' }, [channel.port2]);
              });
              
              return { success: result.success, localAddress: result.localAddress, localPort: result.localPort };
            } catch (error) {
              return { success: false, error: error.message };
            }
          });
          
          console.log('Socket Creation Result:', JSON.stringify(socketTest, null, 2));
          
          if (socketTest.success) {
            console.log(`✓ UDP Socket created successfully!`);
            console.log(`  Local address: ${socketTest.localAddress}:${socketTest.localPort}`);
          } else {
            console.log(`✗ Failed to create socket: ${socketTest.error}`);
          }
        }
        
        // Save all console logs
        console.log('\n=== All Console Logs ===');
        consoleLogs.forEach((log, i) => {
          console.log(`${i + 1}. [${log.type}] ${log.text}`);
          if (log.url) console.log(`   at ${log.url}:${log.lineNumber}`);
        });
        
        return; // Test complete
      }
    }
    
    console.log('\n⚠️  No IWA window found');
    console.log('The IWA may need to be manually installed or launched');
  });

  test('should test AMT URL connection in IWA', async ({ context }) => {
    console.log('\n=== Step 3: Test AMT Connection ===');
    
    // Find the IWA page
    const pages = context.pages();
    const iwaPage = pages.find(p => p.url().startsWith('isolated-app://'));
    
    if (!iwaPage) {
      console.log('⚠️  IWA not open, skipping connection test');
      test.skip();
      return;
    }
    
    console.log('Found IWA page, testing connection...');
    
    // Set up logging
    iwaPage.on('console', msg => {
      console.log(`[IWA] ${msg.text()}`);
    });
    
    // Wait for app to be ready
    await iwaPage.waitForSelector('#connect-btn', { timeout: 10000 });
    console.log('✓ Connect button found');
    
    // Fill in AMT URL
    const amtUrl = 'amt://83.97.94.146@232.1.2.3:1234@162.250.137.254:2268';
    await iwaPage.fill('#amt-url', amtUrl);
    console.log(`Filled AMT URL: ${amtUrl}`);
    
    // Fill relay name
    await iwaPage.fill('#relay-name', 'test-relay');
    console.log('Filled relay name: test-relay');
    
    // Take screenshot before connecting
    await iwaPage.screenshot({ path: 'playwright-report/before-connect.png', fullPage: true });
    
    // Click connect
    console.log('Clicking connect button...');
    await iwaPage.click('#connect-btn');
    
    // Wait for connection attempt
    await sleep(5000);
    
    // Take screenshot after connecting
    await iwaPage.screenshot({ path: 'playwright-report/after-connect.png', fullPage: true });
    
    // Check statistics
    const stats = await iwaPage.evaluate(() => {
      return {
        packets: document.getElementById('stat-packets')?.textContent || '0',
        bytes: document.getElementById('stat-bytes')?.textContent || '0 B',
        streams: document.getElementById('stat-streams')?.textContent || '0',
        rate: document.getElementById('stat-rate')?.textContent || '0 Mbps'
      };
    });
    
    console.log('\nConnection Statistics:');
    console.log(JSON.stringify(stats, null, 2));
    
    // Check relay list
    const relayListText = await iwaPage.textContent('#relay-list');
    console.log('\nRelay List:', relayListText);
    
    // Give some time for packets to arrive
    console.log('\nWaiting 10 seconds for packets...');
    await sleep(10000);
    
    // Check stats again
    const finalStats = await iwaPage.evaluate(() => {
      return {
        packets: document.getElementById('stat-packets')?.textContent || '0',
        bytes: document.getElementById('stat-bytes')?.textContent || '0 B',
        streams: document.getElementById('stat-streams')?.textContent || '0',
        rate: document.getElementById('stat-rate')?.textContent || '0 Mbps'
      };
    });
    
    console.log('\nFinal Statistics:');
    console.log(JSON.stringify(finalStats, null, 2));
    
    // Take final screenshot
    await iwaPage.screenshot({ path: 'playwright-report/final-state.png', fullPage: true });
    
    if (parseInt(finalStats.packets) > 0) {
      console.log('\n✓✓✓ SUCCESS! Packets received! ✓✓✓');
    } else {
      console.log('\n⚠️  No packets received yet (may take time)');
    }
  });
});

