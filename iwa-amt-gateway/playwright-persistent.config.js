// Playwright configuration with persistent context for IWA testing
import { defineConfig, devices } from '@playwright/test';
import * as os from 'os';
import * as path from 'path';

// Use a persistent profile directory
const userDataDir = path.join(os.tmpdir(), 'chrome-iwa-test-profile');

export default defineConfig({
  testDir: './tests',
  timeout: 300000, // 5 minutes
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: [
    ['html', { outputFolder: 'playwright-report' }],
    ['list']
  ],
  
  use: {
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chrome-persistent',
      use: {
        ...devices['Desktop Chrome'],
        channel: 'chrome',
        launchOptions: {
          executablePath: process.env.CHROME_PATH || '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary',
          args: [
            // CRITICAL: User data directory for persistent profile
            `--user-data-dir=${userDataDir}`,
            
            // IWA Features (command-line flags override chrome://flags)
            '--enable-features=IsolatedWebApps',
            '--enable-features=IsolatedWebAppDevMode',
            '--enable-features=WebAppInstallation',
            
            // Direct Sockets
            '--enable-features=DirectSocketsInServiceWorkers',
            '--enable-features=DirectSocketsInSharedWorkers', 
            '--enable-features=MulticastInDirectSockets',
            
            // All experimental features
            '--enable-experimental-web-platform-features',
            
            // Additional helpful features
            '--enable-features=WebAppWindowControlsOverlay',
            '--enable-unrestricted-usb',
            
            // SSL/Security
            '--ignore-certificate-errors',
            '--ignore-ssl-errors',
            '--allow-running-insecure-content',
            '--disable-web-security',
            
            // No first run dialogs
            '--no-first-run',
            '--no-default-browser-check',
            
            // Logging
            '--enable-logging=stderr',
            '--v=1',
          ],
          headless: false,
        },
      },
    },
  ],
});

