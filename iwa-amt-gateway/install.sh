#!/bin/bash
# Manual IWA installation (for development)

set -e

# Detect Chrome binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/detect-chrome.sh"
CHROME_BIN=$(detect_chrome)

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  Manual IWA Installation                                      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

cd "$SCRIPT_DIR"

# Check if bundle exists
if [ ! -f "dist/amt-gateway.swbn" ]; then
    echo "❌ Bundle not found!"
    echo "   Run: npm run build"
    exit 1
fi

# Use persistent profile if available
PROFILE_DIR="$HOME/.chrome-iwa-persistent"
if [ ! -d "$PROFILE_DIR" ]; then
    echo "⚠️  Persistent profile not found!"
    echo "   Direct Sockets may not be available."
    echo "   Run: ./setup.sh (one-time only)"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    PROFILE_DIR="$HOME/.chrome-iwa-dev-temp"
    mkdir -p "$PROFILE_DIR"
fi

# Close existing Chrome
echo "Closing existing Chrome instances..."
if [[ "$OSTYPE" == "darwin"* ]]; then
  pkill -9 "Google Chrome Canary" 2>/dev/null || true
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
  pkill -9 chrome 2>/dev/null || true
fi
sleep 2

# Install and run IWA
echo "Installing IWA..."
echo ""

"$CHROME_BIN" \
  --user-data-dir="$PROFILE_DIR" \
  --enable-features=ExperimentalWebPlatformFeatures,IsolatedWebApps,IsolatedWebAppDevMode,DirectSocketsInServiceWorkers,DirectSocketsInSharedWorkers,MulticastInDirectSockets,WebAppInstallation \
  --enable-experimental-web-platform-features \
  --install-isolated-web-app-from-file="$(pwd)/dist/amt-gateway.swbn" \
  "isolated-app://ajl3qtbxefofp3jbs5cskw2whqpj7etglpj6mruy4oyty3k5wb5jqaacai/" \
  > /tmp/chrome-iwa.log 2>&1 &

CHROME_PID=$!
echo "✓ Chrome launched (PID: $CHROME_PID)"
echo "✓ Profile: $PROFILE_DIR"
echo ""
echo "To inspect:"
echo "  1. Go to: chrome://apps"
echo "  2. Right-click: AMT Gateway"
echo "  3. Click: Inspect"
echo ""
echo "To stop: pkill -9 \"Google Chrome Canary\""
echo ""

