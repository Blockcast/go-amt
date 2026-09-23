// IWA test using persistent browser context
import { test, expect, chromium } from '@playwright/test';
import { spawn } from 'child_process';
import { promisify } from 'util';
import { exec as execCallback } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const exec = promisify(execCallback);
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

let httpsServer = null;

// Persistent profile directory
const userDataDir = path.join(os.tmpdir(), 'chrome-iwa-test-profile');

test.describe('IWA with Persistent Profile', () => {
  
  test.beforeAll(async () => {
    // Kill existing servers
    try {
      await exec('pkill -f "python3.*https-server.py" || true');
      await exec('lsof -ti:8445 | xargs kill -9 2>/dev/null || true');
      await sleep(2000);
    } catch (e) {}

    // Ensure user data directory exists
    if (!fs.existsSync(userDataDir)) {
      fs.mkdirSync(userDataDir, { recursive: true });
      console.log(`Created profile directory: ${userDataDir}`);
    } else {
      console.log(`Using existing profile: ${userDataDir}`);
    }

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
    
    console.log(`\nProfile directory preserved at: ${userDataDir}`);
    console.log('To reset, run: rm -rf ' + userDataDir);
  });

  test('should install and test IWA with persistent profile', async () => {
    console.log('\n=== IWA Installation with Persistent Profile ===\n');
    
    // Find Chrome Canary
    const chromePath = process.env.CHROME_PATH || '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary';
    
    console.log(`Chrome executable: ${chromePath}`);
    console.log(`Profile directory: ${userDataDir}\n`);

    // Launch browser with persistent context
    const context = await chromium.launchPersistentContext(userDataDir, {
      executablePath: chromePath,
      headless: false,
      acceptDownloads: true,
      ignoreHTTPSErrors: true,
      args: [
        // IWA and Direct Sockets features
        '--enable-features=IsolatedWebApps,IsolatedWebAppDevMode,DirectSocketsInServiceWorkers,DirectSocketsInSharedWorkers,MulticastInDirectSockets,WebAppInstallation',
        
        // Experimental features
        '--enable-experimental-web-platform-features',
        
        // SSL
        '--ignore-certificate-errors',
        '--ignore-ssl-errors',
        '--allow-running-insecure-content',
        
        // No dialogs
        '--no-first-run',
        '--no-default-browser-check',
        
        // Enable logging
        '--enable-logging=stderr',
        '--v=1',
      ],
    });

    const page = await context.newPage();

    // Set up comprehensive logging
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

    // Step 1: Verify manifest
    console.log('\n=== Step 1: Verify HTTPS Server ===');
    
    const manifestResponse = await page.goto('https://localhost:8445/manifest.webmanifest', {
      waitUntil: 'networkidle',
      timeout: 10000
    });
    
    expect(manifestResponse.status()).toBe(200);
    const manifest = await manifestResponse.json();
    console.log('✓ Manifest loaded');
    console.log(`  Name: ${manifest.name}`);
    console.log(`  Permissions: ${manifest.permissions?.join(', ')}`);

    // Step 2: Check flags in chrome://version
    console.log('\n=== Step 2: Verify Chrome Flags ===');
    
    await page.goto('chrome://version');
    await sleep(1000);
    
    const versionInfo = await page.evaluate(() => {
      const commandLine = document.querySelector('#command_line')?.textContent || '';
      return {
        hasIsolatedWebApps: commandLine.includes('IsolatedWebApps'),
        hasDevMode: commandLine.includes('IsolatedWebAppDevMode'),
        hasDirectSockets: commandLine.includes('DirectSocketsInServiceWorkers'),
        hasUserDataDir: commandLine.includes('user-data-dir'),
        fullCommandLine: commandLine
      };
    });
    
    console.log('Chrome Flags Check:');
    console.log(`  IsolatedWebApps: ${versionInfo.hasIsolatedWebApps ? '✓' : '✗'}`);
    console.log(`  IsolatedWebAppDevMode: ${versionInfo.hasDevMode ? '✓' : '✗'}`);
    console.log(`  DirectSocketsInServiceWorkers: ${versionInfo.hasDirectSockets ? '✓' : '✗'}`);
    console.log(`  User Data Dir: ${versionInfo.hasUserDataDir ? '✓' : '✗'}`);

    // Step 3: Go to chrome://web-app-internals
    console.log('\n=== Step 3: Chrome Web App Internals ===');
    
    await page.goto('chrome://web-app-internals');
    await sleep(2000);
    
    await page.screenshot({ path: 'test-results/web-app-internals-persistent.png', fullPage: true });
    
    const pageContent = await page.content();
    
    if (pageContent.includes('Web app system not enabled')) {
      console.log('\n⚠️  WEB APP SYSTEM STILL NOT ENABLED');
      console.log('Even with persistent profile and command-line flags.');
      console.log('This may require manual flag enabling in chrome://flags\n');
    } else {
      console.log('✓ Web app system appears to be enabled!');
    }

    // Step 4: Try to find and interact with IWA installation
    console.log('\n=== Step 4: IWA Installation ===');
    
    try {
      // Look for any text inputs
      const inputs = await page.locator('input[type="text"]').all();
      console.log(`Found ${inputs.length} text input(s)`);
      
      if (inputs.length > 0) {
        // Try to fill the first input
        await inputs[0].fill('https://localhost:8445');
        console.log('✓ Entered IWA URL');
        
        await sleep(500);
        
        // Look for install or update button
        const buttons = await page.locator('button').all();
        console.log(`Found ${buttons.length} button(s)`);
        
        for (const button of buttons) {
          const text = await button.textContent();
          console.log(`  Button: "${text}"`);
          
          if (text && text.toLowerCase().includes('install')) {
            await button.click();
            console.log('✓ Clicked install button');
            await sleep(5000);
            break;
          }
        }
        
        await page.screenshot({ path: 'test-results/after-install-persistent.png', fullPage: true });
      }
    } catch (error) {
      console.log(`Installation interaction error: ${error.message}`);
    }

    // Step 5: Look for IWA window
    console.log('\n=== Step 5: Looking for IWA Window ===');
    
    let iwaPage = null;
    let attempts = 0;
    
    while (attempts < 30 && !iwaPage) {
      const pages = context.pages();
      iwaPage = pages.find(p => p.url().startsWith('isolated-app://'));
      
      if (!iwaPage) {
        await sleep(1000);
        attempts++;
        
        if (attempts % 10 === 0) {
          console.log(`Waiting... (${attempts}s)`);
          const currentPages = context.pages();
          console.log(`  Pages open: ${currentPages.length}`);
          currentPages.forEach((p, i) => {
            console.log(`    ${i + 1}. ${p.url().substring(0, 80)}`);
          });
        }
      }
    }

    if (!iwaPage) {
      console.log('\n⚠️  IWA NOT DETECTED');
      console.log('\n📋 MANUAL INSTALLATION REQUIRED:');
      console.log('1. In the Chrome window, navigate to: chrome://web-app-internals');
      console.log('2. Find: "Install IWA via Dev Mode Proxy"');
      console.log('3. Enter URL: https://localhost:8445');
      console.log('4. Click "Install"');
      console.log('\nWaiting 3 minutes for manual installation...\n');
      
      // Wait longer for manual installation
      attempts = 0;
      while (attempts < 180 && !iwaPage) {
        await sleep(1000);
        attempts++;
        
        const pages = context.pages();
        iwaPage = pages.find(p => p.url().startsWith('isolated-app://'));
        
        if (attempts % 30 === 0) {
          console.log(`Still waiting... (${attempts}s)`);
        }
      }
    }

    if (iwaPage) {
      console.log('\n✅ IWA DETECTED!');
      console.log(`URL: ${iwaPage.url()}\n`);

      // Set up IWA logging
      iwaPage.on('console', msg => {
        logWithTimestamp('IWA', msg.type(), msg.text());
      });

      iwaPage.on('pageerror', error => {
        logWithTimestamp('IWA', 'error', error.message);
      });

      await iwaPage.waitForLoadState('networkidle', { timeout: 30000 }).catch(() => {});
      await sleep(2000);

      await iwaPage.screenshot({ path: 'test-results/iwa-loaded-persistent.png', fullPage: true });

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

      console.log('\n=== IWA Context ===');
      console.log(JSON.stringify(contextInfo, null, 2));

      // Test Direct Sockets
      console.log('\n=== Testing Direct Sockets ===');

      const dsTest = await iwaPage.evaluate(async () => {
        try {
          if ('serviceWorker' in navigator) {
            const registration = await navigator.serviceWorker.register('./service-worker-minimal.js');
            await navigator.serviceWorker.ready;
            
            const sw = registration.active;
            if (sw) {
              return await new Promise((resolve) => {
                const channel = new MessageChannel();
                const timeout = setTimeout(() => resolve({ success: false, error: 'Timeout' }), 5000);
                
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

      console.log('\nDirect Sockets Result:');
      console.log(JSON.stringify(dsTest, null, 2));

      if (dsTest.success && dsTest.data?.hasUDP) {
        console.log('\n✅ UDPSocket API AVAILABLE!');
      }

      // Monitor for 30 seconds
      console.log('\n=== Monitoring for 30 seconds ===');
      for (let i = 0; i < 30; i++) {
        await sleep(1000);
      }

      // Save logs
      fs.writeFileSync('test-results/persistent-console-logs.json', JSON.stringify(allLogs, null, 2));
      console.log('\n✅ Logs saved to test-results/persistent-console-logs.json');

    } else {
      console.log('\n✗ IWA was not installed within the timeout period');
    }

    await context.close();
  });
});

