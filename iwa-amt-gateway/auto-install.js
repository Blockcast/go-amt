// Auto-install IWA using Web App Installation API
'use strict';

const status = document.getElementById('status');

// Create Trusted Types policy for logging
let trustedTypesPolicy = null;
if (window.trustedTypes && trustedTypes.createPolicy) {
    try {
        trustedTypesPolicy = trustedTypes.createPolicy('logger', {
            createHTML: (input) => input
        });
    } catch (e) {
        console.warn('Could not create Trusted Types policy:', e);
    }
}

function log(message, type = 'info') {
    const timestamp = new Date().toLocaleTimeString();
    const className = type;
    const line = `<span class="${className}">[${timestamp}] ${message}</span>\n`;
    
    try {
        if (trustedTypesPolicy) {
            status.innerHTML += trustedTypesPolicy.createHTML(line);
        } else {
            // Fallback: use textContent
            const span = document.createElement('span');
            span.className = className;
            span.textContent = `[${timestamp}] ${message}`;
            status.appendChild(span);
            status.appendChild(document.createTextNode('\n'));
        }
    } catch (e) {
        console.error('Failed to log:', e);
        console.log(message);
    }
}

// Check for installation APIs
document.getElementById('checkApiButton').addEventListener('click', async () => {
    status.textContent = '';
    log('🔍 Checking for installation APIs...', 'info');
    
    // Check navigator.install
    if (navigator.install) {
        log('✅ navigator.install() is available', 'success');
    } else {
        log('❌ navigator.install() NOT available', 'error');
    }
    
    // Check BeforeInstallPromptEvent
    if (window.BeforeInstallPromptEvent) {
        log('✅ BeforeInstallPromptEvent is available', 'success');
    } else {
        log('❌ BeforeInstallPromptEvent NOT available', 'error');
    }
    
    // Check if already installed
    if (navigator.standalone !== undefined) {
        log(`📱 navigator.standalone = ${navigator.standalone}`, 'info');
    }
    
    // Check display mode
    const displayMode = window.matchMedia('(display-mode: standalone)').matches;
    log(`📱 Display mode standalone: ${displayMode}`, 'info');
    
    // Check for related applications
    if (navigator.getInstalledRelatedApps) {
        log('🔍 Checking for installed related apps...', 'info');
        try {
            const relatedApps = await navigator.getInstalledRelatedApps();
            log(`📱 Found ${relatedApps.length} related apps`, 'info');
        } catch (err) {
            log(`❌ getInstalledRelatedApps error: ${err.message}`, 'error');
        }
    } else {
        log('❌ navigator.getInstalledRelatedApps NOT available', 'error');
    }
    
    log('✅ API check complete', 'success');
});

// Try multiple installation methods
document.getElementById('installButton').addEventListener('click', async (event) => {
    status.textContent = '';
    log('🚀 Starting IWA installation...', 'info');
    
    try {
        // Method 1: navigator.install() (experimental)
        // MUST be called synchronously in click handler due to user activation requirement
        if (navigator.install) {
            log('📦 Trying navigator.install()...', 'info');
            const manifestUrl = window.location.origin + '/manifest.webmanifest';
            log(`   Manifest URL: ${manifestUrl}`, 'info');
            
            try {
                // Call install() IMMEDIATELY in the click handler (synchronously)
                // to preserve user activation
                navigator.install(manifestUrl).then(result => {
                    log('✅ Installation via navigator.install() successful!', 'success');
                    log(`   Result: ${JSON.stringify(result)}`, 'success');
                }).catch(err => {
                    log(`⚠️ navigator.install() failed: ${err.message}`, 'error');
                    log(`   Error name: ${err.name}`, 'error');
                    continueWithOtherMethods();
                });
                
                // Return early - we've started the install
                return;
            } catch (err) {
                log(`⚠️ navigator.install() threw: ${err.message}`, 'error');
                log(`   Error name: ${err.name}`, 'error');
            }
        }
        
        continueWithOtherMethods();
    } catch (err) {
        log(`❌ Installation error: ${err.message}`, 'error');
        log(`Stack: ${err.stack}`, 'error');
    }
});

async function continueWithOtherMethods() {
    // Method 2: Try beforeinstallprompt event
    log('📦 Checking for beforeinstallprompt event...', 'info');
    
    if (window.deferredPrompt) {
        log('📦 Showing install prompt...', 'info');
        try {
            const result = await window.deferredPrompt.prompt();
            log(`📱 User response: ${result.outcome}`, 'info');
            
            if (result.outcome === 'accepted') {
                log('✅ Installation accepted!', 'success');
            } else {
                log('⚠️ Installation dismissed', 'error');
            }
            window.deferredPrompt = null;
        } catch (err) {
            log(`❌ Prompt failed: ${err.message}`, 'error');
        }
    } else {
        log('⚠️ No install prompt available', 'error');
        log('ℹ️ App may already be installed or not installable', 'info');
    }
    
    // Method 3: For IWAs specifically, provide manual instructions
    log('', 'info');
    log('📋 Manual IWA Installation:', 'info');
    log('1. Open new tab: chrome://web-app-internals', 'info');
    log('2. Find: "Install IWA via Dev Mode Proxy"', 'info');
    log('3. Enter: https://localhost:8445', 'info');
    log('4. Click: Install', 'info');
}

// Listen for beforeinstallprompt event
window.deferredPrompt = null;
window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    window.deferredPrompt = e;
    log('✅ beforeinstallprompt event captured', 'success');
});

// Auto-trigger on load for Playwright
if (window.location.search.includes('autoinstall=true')) {
    log('🤖 Auto-install mode detected', 'info');
    setTimeout(() => {
        document.getElementById('checkApiButton').click();
        setTimeout(() => {
            document.getElementById('installButton').click();
        }, 1000);
    }, 500);
}

