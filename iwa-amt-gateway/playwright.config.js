// Playwright configuration for IWA testing
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  timeout: 30000, // 30 seconds per test
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1, // Run tests sequentially
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
      name: 'chrome-canary',
      use: {
        ...devices['Desktop Chrome'],
        channel: 'chrome', // Try stable Chrome first
        launchOptions: {
          executablePath: process.env.CHROME_PATH || undefined,
          args: [
            // IWA and Direct Sockets features
            '--enable-features=IsolatedWebApps,IsolatedWebAppDevMode,DirectSocketsInServiceWorkers,DirectSocketsInSharedWorkers,MulticastInDirectSockets',
            
            // Enable web app system
            '--enable-features=WebAppInstallation',
            
            // Experimental features
            '--enable-experimental-web-platform-features',
            
            // Direct Sockets specific flags
            '--direct-sockets-in-service-workers',
            '--direct-sockets-in-shared-workers',
            '--multicast-in-direct-sockets',
            
            // Allow unsafe WebGPU/WebGL (might be needed)
            '--enable-unsafe-webgpu',
            '--enable-webgl-developer-extensions',
            
            // Disable security for testing
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor',
            
            // SSL/Certificate handling
            '--ignore-certificate-errors',
            '--ignore-ssl-errors',
            '--allow-running-insecure-content',
            
            // No first run
            '--no-first-run',
            '--no-default-browser-check',
            '--disable-extensions',
            
            // Enable logging
            '--enable-logging=stderr',
            '--v=1',
            
            // Enable web apps in this profile
            '--enable-features=WebAppWindowControlsOverlay',
            '--enable-features=WebAppDarkMode',
            
            // Disable GPU if causing issues (can be removed if working)
            // '--disable-gpu',
          ],
          // Use new headless mode via args (don't set headless: true to avoid conflict)
          headless: false,
          
          // Use a persistent context to save installations
          // This helps the web app system work properly
        },
        
        // Additional permissions
        permissions: ['clipboard-read', 'clipboard-write'],
        
        // Allow geolocation, notifications, etc (might help)
        contextOptions: {
          acceptDownloads: true,
        }
      },
    },
  ],
});
