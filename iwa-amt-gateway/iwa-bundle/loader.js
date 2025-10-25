// Module loader for Trusted Types compatibility
// This replaces the inline script in index.html

if (window.trustedTypes && window.trustedTypes.createPolicy) {
    try {
        // Create the default policy first (needed for service worker and other scripts)
        const defaultPolicy = window.trustedTypes.createPolicy('default', {
            createHTML: (string) => string,
            createScript: (string) => string,
            createScriptURL: (url) => url
        });
        
        // Now create app-module policy
        const appPolicy = window.trustedTypes.createPolicy('app-module', {
            createScriptURL: (url) => url
        });
        
        const script = document.createElement('script');
        script.type = 'module';
        script.src = appPolicy.createScriptURL('app.js');
        document.head.appendChild(script);
    } catch (error) {
        console.warn('Trusted Types policy creation failed:', error);
        // Try without policy (will fail in IWA but fallback for testing)
        const script = document.createElement('script');
        script.type = 'module';
        script.src = 'app.js';
        document.head.appendChild(script);
    }
} else {
    // Fallback for browsers without Trusted Types
    const script = document.createElement('script');
    script.type = 'module';
    script.src = 'app.js';
    document.head.appendChild(script);
}

