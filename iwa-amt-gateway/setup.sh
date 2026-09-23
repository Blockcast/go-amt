#!/bin/bash
# ONE-TIME SETUP: Enable Direct Sockets in Chrome (run this ONCE)

# Detect Chrome binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/detect-chrome.sh"
CHROME_BIN=$(detect_chrome)

PROFILE_DIR="$HOME/.chrome-iwa-persistent"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  One-Time Setup: Enable Direct Sockets                       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Clean and create profile
rm -rf "$PROFILE_DIR"
mkdir -p "$PROFILE_DIR"

echo "✓ Profile created: $PROFILE_DIR"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  MANUAL STEPS (ONE-TIME ONLY)"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Chrome will open. Enable these 3 flags:"
echo ""
echo "  1. chrome://flags/#direct-sockets-in-service-workers"
echo "     → Set to: Enabled"
echo ""
echo "  2. chrome://flags/#direct-sockets-in-shared-workers"
echo "     → Set to: Enabled"
echo ""
echo "  3. chrome://flags/#multicast-in-direct-sockets"
echo "     → Set to: Enabled"
echo ""
echo "  4. Click 'Relaunch' button"
echo ""
echo "  5. Close Chrome when done"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""
read -p "Press Enter to open Chrome..."

# Launch Chrome
"$CHROME_BIN" \
  --user-data-dir="$PROFILE_DIR" \
  --enable-features=ExperimentalWebPlatformFeatures,IsolatedWebApps,DirectSocketsInServiceWorkers,DirectSocketsInSharedWorkers,MulticastInDirectSockets,WebAppInstallation \
  --enable-experimental-web-platform-features \
  "chrome://flags/#direct-sockets-in-service-workers" &

echo ""
echo "Waiting for you to enable flags and close Chrome..."
wait

echo ""
echo "✓ Setup complete!"
echo ""
echo "Profile saved at: $PROFILE_DIR"
echo "You can now run tests with: ./test.sh"
echo ""

