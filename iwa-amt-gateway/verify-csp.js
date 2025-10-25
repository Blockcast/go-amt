// verify-csp.js - Check actual CSP in IWA

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

async function verifyCSP() {
  console.log('╔══════════════════════════════════════════════════════════════════╗');
  console.log('║                    Verify Actual CSP in IWA                      ║');
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

  const page = context.pages()[0] || await context.newPage();
  
  console.log('Opening IWA...');
  await page.goto(appUrl);
  await page.waitForTimeout(3000);

  // Extract CSP from meta tags and HTTP headers
  console.log('\n═══════════════════════════════════════════════════════════════════');
  console.log('  CSP VERIFICATION');
  console.log('═══════════════════════════════════════════════════════════════════\n');

  // Check meta tag CSP
  const metaCSP = await page.evaluate(() => {
    const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    return meta ? meta.getAttribute('content') : null;
  });

  console.log('📄 HTML Meta CSP:');
  if (metaCSP) {
    console.log(`   ${metaCSP}\n`);
    if (metaCSP.includes('http://localhost:*')) {
      console.log('   ✅ Meta CSP includes http://localhost:*');
    } else {
      console.log('   ❌ Meta CSP missing http://localhost:*');
    }
  } else {
    console.log('   ✅ No meta CSP tag (good - using manifest CSP)\n');
  }

  // Check effective CSP via violation test
  console.log('🔒 Effective CSP (testing localhost connection):');
  const testResult = await page.evaluate(() => {
    return new Promise((resolve) => {
      const xhr = new XMLHttpRequest();
      
      // Listen for CSP violations
      document.addEventListener('securitypolicyviolation', (e) => {
        resolve({
          blocked: true,
          violatedDirective: e.violatedDirective,
          blockedURI: e.blockedURI,
          effectiveDirective: e.effectiveDirective,
          originalPolicy: e.originalPolicy
        });
      }, { once: true });

      // Try to connect to localhost
      xhr.open('GET', 'http://localhost:5001/test');
      try {
        xhr.send();
        setTimeout(() => resolve({ blocked: false }), 1000);
      } catch (e) {
        resolve({ blocked: true, error: e.message });
      }
    });
  });

  if (testResult.blocked) {
    console.log('   ❌ localhost connection BLOCKED by CSP');
    if (testResult.originalPolicy) {
      console.log('\n   Full CSP Policy:');
      console.log(`   ${testResult.originalPolicy}`);
      
      const hasLocalhost = testResult.originalPolicy.includes('http://localhost:*');
      console.log(`\n   Contains http://localhost:*? ${hasLocalhost ? '✅ YES' : '❌ NO'}`);
      
      if (!hasLocalhost) {
        console.log('\n   🔍 Connect-src directive:');
        const connectMatch = testResult.originalPolicy.match(/connect-src[^;]+/);
        if (connectMatch) {
          console.log(`   ${connectMatch[0]}`);
        }
      }
    }
  } else {
    console.log('   ✅ localhost connection ALLOWED\n');
  }

  console.log('\n═══════════════════════════════════════════════════════════════════');
  console.log('  Bundle CSP (from .swbn file):');
  console.log('═══════════════════════════════════════════════════════════════════\n');
  
  const { execSync } = require('child_process');
  const bundleCSP = execSync(`strings "${BUNDLE_PATH}" | grep "connect-src" | head -1`, { encoding: 'utf-8' });
  console.log(`   ${bundleCSP.trim()}`);
  
  if (bundleCSP.includes('http://localhost:*')) {
    console.log('   ✅ Bundle CSP includes http://localhost:*\n');
  } else {
    console.log('   ❌ Bundle CSP missing http://localhost:*\n');
  }

  console.log('═══════════════════════════════════════════════════════════════════\n');
  console.log('Press Ctrl+C to exit...');
  
  await page.waitForTimeout(60000);
  await context.close();
}

verifyCSP().catch(console.error);


