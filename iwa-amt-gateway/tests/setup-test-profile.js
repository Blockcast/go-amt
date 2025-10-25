#!/usr/bin/env node

/**
 * Setup Test Profile for IWA Testing
 * 
 * This script creates a persistent Chrome profile with the IWA pre-installed.
 * This profile is then reused by all Playwright tests to avoid installation issues.
 * 
 * Usage:
 *   node tests/setup-test-profile.js
 * 
 * Or via npm:
 *   npm run test:setup-profile
 */

const { chromium } = require('@playwright/test');
const path = require('path');
const fs = require('fs');
const { getChromePath, getBundleInfo } = require('./test-helpers.cjs');

const PROFILE_DIR = path.join(__dirname, '..', '.test-profile');

async function setupProfile() {
  console.log('\n╔════════════════════════════════════════════════════════╗');
  console.log('║  IWA Test Profile Setup                                ║');
  console.log('╚════════════════════════════════════════════════════════╝\n');

  const { bundlePath, bundleId } = getBundleInfo();
  
  // Verify bundle exists
  if (!fs.existsSync(bundlePath)) {
    console.error('❌ Bundle not found:', bundlePath);
    console.error('   Run: npm run build');
    process.exit(1);
  }

  console.log(`📦 Bundle: ${bundlePath}`);
  console.log(`🆔 Bundle ID: ${bundleId}`);
  console.log(`📁 Profile: ${PROFILE_DIR}\n`);

  // Remove existing profile if it exists
  if (fs.existsSync(PROFILE_DIR)) {
    console.log('🗑️  Removing existing profile...');
    fs.rmSync(PROFILE_DIR, { recursive: true, force: true });
  }

  // Create profile directory
  fs.mkdirSync(PROFILE_DIR, { recursive: true });
  console.log('✓ Profile directory created\n');

  const chromePath = getChromePath();
  console.log(`🌐 Chrome: ${chromePath}\n`);

  console.log('🚀 Launching Chrome with IWA installation...\n');

  try {
    const context = await chromium.launchPersistentContext(PROFILE_DIR, {
      executablePath: chromePath,
      headless: false,
      args: [
        // IWA support
        '--enable-features=IsolatedWebApps',
        '--enable-features=IsolatedWebAppDevMode',
        
        // Direct Sockets support
        '--enable-features=DirectSocketsInServiceWorkers',
        '--enable-features=DirectSockets',
        '--enable-features=MulticastInDirectSockets',
        
        // Install IWA from bundle
        `--install-isolated-web-app-from-file=${bundlePath}`,
        
        // Other useful flags
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding',
        
        // Enable logging
        '--enable-logging=stderr',
        '--v=1',
      ],
      ignoreHTTPSErrors: true
    });

    // Wait for installation to complete
    console.log('⏳ Waiting for IWA installation (10s)...');
    await new Promise(resolve => setTimeout(resolve, 10000));

    // Try to open the IWA to verify it's installed
    const page = await context.newPage();
    const iwaUrl = `isolated-app://${bundleId}/`;
    
    console.log(`\n🔗 Opening IWA: ${iwaUrl}`);
    
    try {
      await page.goto(iwaUrl, { 
        waitUntil: 'domcontentloaded',
        timeout: 30000 
      });
      
      // Wait for service worker
      await page.waitForTimeout(3000);
      
      // Check if service worker is active
      const swActive = await page.evaluate(() => {
        return navigator.serviceWorker.controller !== null;
      });
      
      console.log(`\n✅ IWA loaded successfully!`);
      console.log(`   Service Worker Active: ${swActive ? '✅' : '⚠️'}\n`);
      
      // Keep browser open for a moment to let everything initialize
      console.log('⏳ Letting IWA initialize (5s)...');
      await page.waitForTimeout(5000);
      
    } catch (error) {
      console.error('❌ Failed to open IWA:', error.message);
      console.error('   Installation may have failed\n');
    }

    await context.close();
    
    console.log('\n╔════════════════════════════════════════════════════════╗');
    console.log('║  ✅ Profile Setup Complete!                           ║');
    console.log('╚════════════════════════════════════════════════════════╝\n');
    console.log(`Profile location: ${PROFILE_DIR}`);
    console.log(`\nYou can now run tests with:\n  npm run test\n`);

  } catch (error) {
    console.error('\n❌ Setup failed:', error);
    process.exit(1);
  }
}

// Run setup
setupProfile().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});

