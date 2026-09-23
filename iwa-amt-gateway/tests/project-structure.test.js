// project-structure.test.js
// TEST FIRST: Validates project structure and dependencies
// Write this test BEFORE cleaning up the project

const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

test.describe('Project Structure Tests', () => {
  const rootDir = path.join(__dirname, '..', '..');
  const iwaDir = path.join(__dirname, '..');
  
  test('package.json should only have necessary dependencies', async () => {
    const packagePath = path.join(iwaDir, 'package.json');
    expect(fs.existsSync(packagePath)).toBeTruthy();
    
    const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    
    // Should NOT have these unused dependencies
    expect(packageJson.dependencies['hls.js']).toBeUndefined();
    expect(packageJson.dependencies['mux.js']).toBeUndefined();
    
    // SHOULD have these working dependencies
    expect(packageJson.dependencies['mpegts.js']).toBeDefined();
    expect(packageJson.dependencies['playwright']).toBeDefined();
    expect(packageJson.dependencies['serve-handler']).toBeDefined();
    
    // Should have webpack tooling
    expect(packageJson.devDependencies['webpack']).toBeDefined();
    expect(packageJson.devDependencies['webpack-cli']).toBeDefined();
    expect(packageJson.devDependencies['webbundle-webpack-plugin']).toBeDefined();
  });
  
  test('chrome-extension should be archived', async () => {
    const chromeExtDir = path.join(rootDir, 'chrome-extension');
    const archiveReadme = path.join(chromeExtDir, 'README_ARCHIVED.md');
    
    expect(fs.existsSync(chromeExtDir)).toBeTruthy();
    expect(fs.existsSync(archiveReadme)).toBeTruthy();
    
    const archiveContent = fs.readFileSync(archiveReadme, 'utf8');
    expect(archiveContent).toContain('chrome.sockets');
    expect(archiveContent).toContain('Manifest V3');
    expect(archiveContent).toContain('Direct Sockets');
    expect(archiveContent).toContain('IWA');
  });
  
  test('required IWA directories should exist', async () => {
    const outputServersDir = path.join(iwaDir, 'output-servers');
    const testsDir = path.join(iwaDir, 'tests');
    
    expect(fs.existsSync(outputServersDir)).toBeTruthy();
    expect(fs.existsSync(testsDir)).toBeTruthy();
  });
  
  test('constants.js should have all required constants', async () => {
    const constantsPath = path.join(iwaDir, 'constants.js');
    expect(fs.existsSync(constantsPath)).toBeTruthy();
    
    const constantsContent = fs.readFileSync(constantsPath, 'utf8');
    
    // Should have AMT constants
    expect(constantsContent).toContain('AMT_DEFAULT_PORT');
    expect(constantsContent).toContain('AMT_MSG_TYPE');
    expect(constantsContent).toContain('RELAY_STATE');
    
    // Should have output server constants
    expect(constantsContent).toContain('UDP_CONTROL_PORT');
    expect(constantsContent).toContain('TCP_HTTP_PORT');
    expect(constantsContent).toContain('MSG_TYPE');
    expect(constantsContent).toContain('WILDCARD');
  });
  
  test('auto-install infrastructure should be preserved', async () => {
    const autoInstallHtml = path.join(iwaDir, 'auto-install.html');
    const autoInstallJs = path.join(iwaDir, 'auto-install.js');
    const testIwaJs = path.join(iwaDir, 'test-iwa-automated.js');
    const runTestSh = path.join(iwaDir, 'run-automated-install-test.sh');
    
    expect(fs.existsSync(autoInstallHtml)).toBeTruthy();
    expect(fs.existsSync(autoInstallJs)).toBeTruthy();
    expect(fs.existsSync(testIwaJs)).toBeTruthy();
    expect(fs.existsSync(runTestSh)).toBeTruthy();
  });
  
  test('service-worker.js should exist', async () => {
    const serviceWorkerPath = path.join(iwaDir, 'service-worker.js');
    expect(fs.existsSync(serviceWorkerPath)).toBeTruthy();
  });
  
  test('manifest files should exist', async () => {
    const manifestJson = path.join(iwaDir, 'manifest.json');
    const manifestWebmanifest = path.join(iwaDir, 'manifest.webmanifest');
    
    expect(fs.existsSync(manifestJson)).toBeTruthy();
    expect(fs.existsSync(manifestWebmanifest)).toBeTruthy();
  });
  
  test('consumer-app directory should exist', async () => {
    const consumerAppDir = path.join(rootDir, 'consumer-app');
    expect(fs.existsSync(consumerAppDir)).toBeTruthy();
    
    const consumerPackageJson = path.join(consumerAppDir, 'package.json');
    expect(fs.existsSync(consumerPackageJson)).toBeTruthy();
  });
  
  test('output-servers directory should have required structure', async () => {
    const outputServersDir = path.join(iwaDir, 'output-servers');
    
    // Check for README
    const readme = path.join(outputServersDir, 'README.md');
    expect(fs.existsSync(readme)).toBeTruthy();
    
    // These will be created during implementation
    const udpServer = path.join(outputServersDir, 'udp-server.js');
    const tcpServer = path.join(outputServersDir, 'tcp-server.js');
    const websocketServer = path.join(outputServersDir, 'websocket-server.js');
    const webrtcServer = path.join(outputServersDir, 'webrtc-server.js');
    const serverManager = path.join(outputServersDir, 'server-manager.js');
    
    // For now, just check directory exists
    // Files will be created during TDD implementation
  });
  
  test('test directory should have test-helpers.cjs', async () => {
    const testHelpers = path.join(iwaDir, 'tests', 'test-helpers.cjs');
    expect(fs.existsSync(testHelpers)).toBeTruthy();
    
    const helpersContent = fs.readFileSync(testHelpers, 'utf8');
    expect(helpersContent).toContain('installIWA');
    expect(helpersContent).toContain('waitForServiceWorker');
    expect(helpersContent).toContain('checkDirectSocketsAPI');
  });
});

