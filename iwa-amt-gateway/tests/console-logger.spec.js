// Simplified test that just captures and displays all console logs
import { test } from '@playwright/test';
import { spawn } from 'child_process';
import { promisify } from 'util';
import { exec as execCallback } from 'child_process';

const exec = promisify(execCallback);
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

let httpsServer = null;

test.describe('IWA Console Logger', () => {
  
  test.beforeAll(async () => {
    // Kill existing servers
    try {
      await exec('pkill -f "python3.*https-server.py" || true');
      await exec('lsof -ti:8445 | xargs kill -9 2>/dev/null || true');
      await sleep(2000);
    } catch (e) {}

    // Start HTTPS server
    console.log('Starting HTTPS server...');
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

  test('should capture all console logs from IWA', async ({ page, context }) => {
    console.log('\n=== Console Logger Started ===\n');

    // Track all logs with timestamps
    const allLogs = [];

    const logWithTimestamp = (source, type, message, meta = {}) => {
      const timestamp = new Date().toISOString();
      const logEntry = {
        timestamp,
        source,
        type,
        message,
        ...meta
      };
      allLogs.push(logEntry);
      
      const color = {
        error: '\x1b[31m',
        warning: '\x1b[33m',
        info: '\x1b[36m',
        log: '\x1b[37m'
      }[type] || '\x1b[37m';
      
      console.log(`${color}[${timestamp}] [${source}] [${type.toUpperCase()}] ${message}\x1b[0m`);
      if (meta.stack) {
        console.log(`  Stack: ${meta.stack}`);
      }
      if (meta.url) {
        console.log(`  URL: ${meta.url}:${meta.lineNumber}`);
      }
    };

    // Set up page logging
    page.on('console', msg => {
      const location = msg.location();
      logWithTimestamp('PAGE', msg.type(), msg.text(), {
        url: location.url,
        lineNumber: location.lineNumber,
        columnNumber: location.columnNumber
      });
    });

    page.on('pageerror', error => {
      logWithTimestamp('PAGE', 'error', error.message, {
        stack: error.stack
      });
    });

    page.on('requestfailed', request => {
      logWithTimestamp('NETWORK', 'error', `Failed: ${request.url()}`, {
        failure: request.failure()?.errorText
      });
    });

    page.on('request', request => {
      if (request.url().includes('localhost:8445')) {
        logWithTimestamp('NETWORK', 'info', `→ ${request.method()} ${request.url()}`);
      }
    });

    page.on('response', response => {
      if (response.url().includes('localhost:8445')) {
        const status = response.status();
        const type = status >= 400 ? 'error' : status >= 300 ? 'warning' : 'info';
        logWithTimestamp('NETWORK', type, `← ${status} ${response.url()}`);
      }
    });

    // Navigate to web app internals for IWA installation
    console.log('\nNavigating to chrome://web-app-internals...\n');
    await page.goto('chrome://web-app-internals');
    await sleep(2000);

    console.log('\n==================================================');
    console.log('MANUAL STEPS REQUIRED:');
    console.log('1. In the browser window that opened:');
    console.log('2. Look for "Install IWA via Dev Mode Proxy"');
    console.log('3. Enter URL: https://localhost:8445');
    console.log('4. Click "Install"');
    console.log('5. Wait for the IWA to open');
    console.log('6. Try connecting to an AMT relay');
    console.log('==================================================\n');

    // Wait for IWA to be installed and opened
    let iwaPage = null;
    let attempts = 0;
    const maxAttempts = 60; // Wait up to 60 seconds

    while (attempts < maxAttempts && !iwaPage) {
      const pages = context.pages();
      iwaPage = pages.find(p => p.url().startsWith('isolated-app://'));
      
      if (!iwaPage) {
        await sleep(1000);
        attempts++;
        
        if (attempts % 10 === 0) {
          console.log(`Waiting for IWA... (${attempts}s elapsed)`);
        }
      }
    }

    if (!iwaPage) {
      console.log('\n⚠️  IWA not detected within 60 seconds');
      console.log('The IWA may need to be manually installed.');
      console.log('\nKeeping browser open for 2 more minutes for manual testing...\n');
      
      // Keep monitoring for another 2 minutes
      for (let i = 0; i < 120; i++) {
        await sleep(1000);
        
        const pages = context.pages();
        iwaPage = pages.find(p => p.url().startsWith('isolated-app://'));
        
        if (iwaPage) {
          console.log('\n✓ IWA detected!\n');
          break;
        }
      }
    }

    if (iwaPage) {
      console.log(`\n✓✓✓ IWA FOUND! ✓✓✓`);
      console.log(`URL: ${iwaPage.url()}\n`);

      // Set up logging for IWA page
      iwaPage.on('console', msg => {
        const location = msg.location();
        logWithTimestamp('IWA', msg.type(), msg.text(), {
          url: location.url,
          lineNumber: location.lineNumber
        });
      });

      iwaPage.on('pageerror', error => {
        logWithTimestamp('IWA', 'error', error.message, {
          stack: error.stack
        });
      });

      iwaPage.on('requestfailed', request => {
        logWithTimestamp('IWA-NETWORK', 'error', `Failed: ${request.url()}`);
      });

      // Wait for page to load
      await iwaPage.waitForLoadState('networkidle', { timeout: 30000 }).catch(() => {});
      await sleep(2000);

      // Check context
      const contextInfo = await iwaPage.evaluate(() => {
        return {
          protocol: window.location.protocol,
          origin: window.location.origin,
          isSecureContext: window.isSecureContext,
          hasServiceWorker: 'serviceWorker' in navigator
        };
      });

      console.log('\n=== IWA Context Info ===');
      console.log(JSON.stringify(contextInfo, null, 2));
      console.log('');

      // Monitor for 3 minutes
      console.log('Monitoring IWA for 3 minutes...');
      console.log('Try connecting to an AMT relay to see logs.\n');

      for (let i = 0; i < 180; i++) {
        await sleep(1000);
        
        if (i % 30 === 0 && i > 0) {
          // Check stats every 30 seconds
          try {
            const stats = await iwaPage.evaluate(() => {
              return {
                packets: document.getElementById('stat-packets')?.textContent || '0',
                bytes: document.getElementById('stat-bytes')?.textContent || '0 B',
                streams: document.getElementById('stat-streams')?.textContent || '0'
              };
            });
            
            console.log(`\n[${i}s] Current Stats: ${JSON.stringify(stats)}\n`);
          } catch (e) {
            // Page might be closed
          }
        }
      }

      console.log('\n=== Monitoring Complete ===');
      
      // Save all logs to file
      const fs = require('fs');
      const logFile = 'playwright-report/console-logs.json';
      fs.writeFileSync(logFile, JSON.stringify(allLogs, null, 2));
      console.log(`\nAll logs saved to: ${logFile}`);
      
      // Print summary
      const errorLogs = allLogs.filter(l => l.type === 'error');
      const warningLogs = allLogs.filter(l => l.type === 'warning');
      
      console.log('\n=== Log Summary ===');
      console.log(`Total logs: ${allLogs.length}`);
      console.log(`Errors: ${errorLogs.length}`);
      console.log(`Warnings: ${warningLogs.length}`);
      
      if (errorLogs.length > 0) {
        console.log('\n=== Errors ===');
        errorLogs.forEach(log => {
          console.log(`[${log.timestamp}] ${log.message}`);
        });
      }

    } else {
      console.log('\n✗ IWA was not opened during the test period.');
      console.log('Please manually install the IWA and run the test again.');
    }
  });
});

