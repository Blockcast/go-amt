// Automated IWA installation test with improved Chrome flags
import { test, expect } from '@playwright/test';
import { spawn } from 'child_process';
import { promisify } from 'util';
import { exec as execCallback } from 'child_process';
import * as fs from 'fs';

const exec = promisify(execCallback);
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

let httpsServer = null;

test.describe('IWA Automated Installation', () => {
  
  test.beforeAll(async () => {
    // Kill existing servers
    try {
      await exec('pkill -f "python3.*https-server.py" || true');
      await exec('lsof -ti:8445 | xargs kill -9 2>/dev/null || true');
      await sleep(2000);
    } catch (e) {}

    // Start HTTPS server
    console.log('Starting HTTPS server on port 8445...');
    httpsServer = spawn('python3', ['https-server.py'], {
      cwd: process.cwd(),
      stdio: 'pipe'
    });

    httpsServer.stdout.on('data', (data) => console.log(`[Server] ${data}`));
    httpsServer.stderr.on('data', (data) => console.error(`[Server] ${data}`));

    await sleep(3000);
  });

  test.afterAll(async () => {
    if (httpsServer) {
      httpsServer.kill('SIGTERM');
    }
  });

  test('should automatically install and test IWA', async ({ page, context }) => {
    console.log('\n=== Automated IWA Installation Test ===\n');

    // Comprehensive logging
    const allLogs = [];
    const logWithTimestamp = (source, type, message, meta = {}) => {
      const timestamp = new Date().toISOString();
      const logEntry = { timestamp, source, type, message, ...meta };
      allLogs.push(logEntry);
      
      const colors = { error: '\x1b[31m', warning: '\x1b[33m', info: '\x1b[36m', log: '\x1b[37m' };
      const color = colors[type] || '\x1b[37m';
      console.log(`${color}[${timestamp}] [${source}] [${type.toUpperCase()}] ${message}\x1b[0m`);
    };

    page.on('console', msg => {
      const loc = msg.location();
      logWithTimestamp('PAGE', msg.type(), msg.text(), { url: loc.url, line: loc.lineNumber });
    });

    page.on('pageerror', error => {
      logWithTimestamp('PAGE', 'error', error.message, { stack: error.stack });
    });

    // Step 1: Verify HTTPS server
    console.log('\n=== Step 1: Verify HTTPS Server ===');
    
    try {
      const response = await page.goto('https://localhost:8445/manifest.webmanifest', {
        waitUntil: 'networkidle',
        timeout: 10000
      });
      
      expect(response.status()).toBe(200);
      const manifest = await response.json();
      console.log('✓ Manifest loaded successfully');
      console.log(`  Name: ${manifest.name}`);
      console.log(`  Permissions: ${manifest.permissions?.join(', ')}`);
    } catch (error) {
      console.error('✗ Failed to load manifest:', error.message);
      throw error;
    }

    // Step 2: Try programmatic installation first
    console.log('\n=== Step 2: Attempting Programmatic Installation ===');
    
    try {
      await page.goto('https://localhost:8445/', {
        waitUntil: 'networkidle',
        timeout: 10000
      });
      
      // Check if navigator.install is available
      const hasInstallAPI = await page.evaluate(() => {
        return typeof navigator.install === 'function';
      });
      
      if (hasInstallAPI) {
        console.log('✓ navigator.install() API is available!');
        console.log('Attempting programmatic installation...');
        
        const installResult = await page.evaluate(async () => {
          try {
            if (typeof navigator.install === 'function') {
              await navigator.install();
              return { success: true };
            }
            return { success: false, error: 'navigator.install not available' };
          } catch (error) {
            return { success: false, error: error.message };
          }
        });
        
        if (installResult.success) {
          console.log('✓ Programmatic installation successful!');
          await sleep(5000);
        } else {
          console.log(`⚠ Programmatic installation failed: ${installResult.error}`);
        }
      } else {
        console.log('⚠ navigator.install() not available, will use dev mode installation');
      }
    } catch (error) {
      console.log(`⚠ Programmatic installation attempt failed: ${error.message}`);
    }

    // Step 3: Try chrome://web-app-internals installation
    console.log('\n=== Step 3: Chrome Web App Internals Installation ===');
    
    try {
      await page.goto('chrome://web-app-internals', { timeout: 10000 });
      await sleep(2000);
      
      // Take screenshot for debugging
      await page.screenshot({ path: 'test-results/web-app-internals-initial.png', fullPage: true });
      
      // Check if web app system is enabled
      const pageContent = await page.content();
      
      if (pageContent.includes('Web app system not enabled')) {
        console.log('\n⚠️  WEB APP SYSTEM NOT ENABLED FOR PROFILE');
        console.log('This might be due to Chrome flags or profile settings.');
        console.log('Trying alternative approach...\n');
      }
      
      // Look for IWA Dev Mode installation UI
      console.log('Looking for IWA Dev Mode Proxy section...');
      
      // Try to find and interact with the installation form
      const installFormExists = await page.locator('text=/Install.*IWA.*Dev.*Mode/i').count() > 0;
      
      if (installFormExists) {
        console.log('✓ Found IWA Dev Mode installation form');
        
        // Try to find input field
        const inputs = await page.locator('input[type="text"]').all();
        
        if (inputs.length > 0) {
          console.log(`Found ${inputs.length} input field(s)`);
          
          // Fill the first text input with our URL
          await inputs[0].fill('https://localhost:8445');
          console.log('✓ Entered IWA URL');
          
          await sleep(500);
          
          // Look for install button
          const installButtons = await page.locator('button').filter({ hasText: /install/i }).all();
          
          if (installButtons.length > 0) {
            console.log(`Found ${installButtons.length} install button(s)`);
            await installButtons[0].click();
            console.log('✓ Clicked install button');
            
            await sleep(5000);
            await page.screenshot({ path: 'test-results/after-install-click.png', fullPage: true });
          }
        }
      } else {
        console.log('⚠ IWA Dev Mode installation form not found');
      }
      
    } catch (error) {
      console.log(`⚠ Chrome internals interaction failed: ${error.message}`);
    }

    // Step 4: Look for installed IWA
    console.log('\n=== Step 4: Looking for Installed IWA ===');
    
    let iwaPage = null;
    let attempts = 0;
    const maxAttempts = 30;

    while (attempts < maxAttempts && !iwaPage) {
      const pages = context.pages();
      iwaPage = pages.find(p => p.url().startsWith('isolated-app://'));
      
      if (!iwaPage) {
        await sleep(1000);
        attempts++;
        
        if (attempts % 5 === 0) {
          console.log(`Waiting for IWA... (${attempts}s elapsed)`);
          
          // Check all open pages
          const currentPages = context.pages();
          console.log(`  Current pages: ${currentPages.length}`);
          currentPages.forEach((p, i) => {
            console.log(`    ${i + 1}. ${p.url().substring(0, 80)}`);
          });
        }
      }
    }

    if (!iwaPage) {
      console.log('\n⚠️  IWA NOT DETECTED');
      console.log('\nMANUAL INSTALLATION INSTRUCTIONS:');
      console.log('1. In the Chrome window, go to: chrome://web-app-internals');
      console.log('2. Find: "Install IWA via Dev Mode Proxy"');
      console.log('3. Enter URL: https://localhost:8445');
      console.log('4. Click "Install"');
      console.log('\nWaiting 2 more minutes for manual installation...\n');
      
      // Extended wait for manual installation
      attempts = 0;
      while (attempts < 120 && !iwaPage) {
        await sleep(1000);
        attempts++;
        
        const pages = context.pages();
        iwaPage = pages.find(p => p.url().startsWith('isolated-app://'));
        
        if (attempts % 30 === 0) {
          console.log(`Still waiting... (${attempts}s elapsed)`);
        }
      }
    }

    if (iwaPage) {
      console.log('\n✅ IWA DETECTED!');
      console.log(`URL: ${iwaPage.url()}\n`);

      // Set up logging for IWA
      iwaPage.on('console', msg => {
        logWithTimestamp('IWA', msg.type(), msg.text());
      });

      iwaPage.on('pageerror', error => {
        logWithTimestamp('IWA', 'error', error.message);
      });

      // Wait for load
      await iwaPage.waitForLoadState('networkidle', { timeout: 30000 }).catch(() => {});
      await sleep(2000);

      // Take screenshot
      await iwaPage.screenshot({ path: 'test-results/iwa-loaded.png', fullPage: true });

      // Check context
      const contextInfo = await iwaPage.evaluate(() => {
        return {
          protocol: window.location.protocol,
          origin: window.location.origin,
          isSecureContext: window.isSecureContext,
          hasServiceWorker: 'serviceWorker' in navigator,
          hasUDPSocket: typeof UDPSocket !== 'undefined',
          hasTCPSocket: typeof TCPSocket !== 'undefined'
        };
      });

      console.log('\n=== IWA Context Info ===');
      console.log(JSON.stringify(contextInfo, null, 2));

      expect(contextInfo.protocol).toBe('isolated-app:');
      expect(contextInfo.isSecureContext).toBe(true);

      // Step 5: Test Direct Sockets
      console.log('\n=== Step 5: Testing Direct Sockets ===');

      // Register service worker if needed
      const swTest = await iwaPage.evaluate(async () => {
        try {
          if ('serviceWorker' in navigator) {
            const registration = await navigator.serviceWorker.register('./service-worker-minimal.js');
            await navigator.serviceWorker.ready;
            
            const sw = registration.active;
            if (sw) {
              // Check Direct Sockets in SW
              return await new Promise((resolve) => {
                const channel = new MessageChannel();
                const timeout = setTimeout(() => {
                  resolve({ success: false, error: 'Timeout' });
                }, 5000);
                
                channel.port1.onmessage = (e) => {
                  clearTimeout(timeout);
                  resolve({ success: true, data: e.data });
                };
                
                sw.postMessage({ type: 'CHECK_API' }, [channel.port2]);
              });
            }
          }
          return { success: false, error: 'No Service Worker' };
        } catch (error) {
          return { success: false, error: error.message };
        }
      });

      console.log('\nService Worker Check:');
      console.log(JSON.stringify(swTest, null, 2));

      if (swTest.success && swTest.data) {
        if (swTest.data.hasUDP) {
          console.log('\n✅ UDPSocket API AVAILABLE!');
        }
        if (swTest.data.hasTCP) {
          console.log('✅ TCPSocket API AVAILABLE!');
        }
      }

      // Monitor for 30 seconds
      console.log('\n=== Monitoring for 30 seconds ===');
      for (let i = 0; i < 30; i++) {
        await sleep(1000);
      }

      // Save logs
      fs.writeFileSync('test-results/iwa-console-logs.json', JSON.stringify(allLogs, null, 2));
      console.log('\n✅ Logs saved to test-results/iwa-console-logs.json');

    } else {
      console.log('\n✗ IWA was not installed or detected');
      console.log('Please check the screenshots in test-results/');
      
      // Save logs anyway
      fs.writeFileSync('test-results/failed-console-logs.json', JSON.stringify(allLogs, null, 2));
    }
  });
});

