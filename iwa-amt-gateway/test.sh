#!/bin/bash
# Run automated IWA tests with Playwright

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  IWA Automated Test                                           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

cd "$(dirname "$0")"

# Check if persistent profile exists
PROFILE_DIR="$HOME/.chrome-iwa-persistent"
if [ ! -d "$PROFILE_DIR" ]; then
    echo "❌ Persistent profile not found!"
    echo ""
    echo "Run this first (ONE-TIME ONLY):"
    echo "  ./setup.sh"
    echo ""
    exit 1
fi

# Step 1: Build bundle
echo "[1/3] Building IWA bundle..."
npm run build:bundle-only > /dev/null 2>&1 &
BUILD_PID=$!

while kill -0 $BUILD_PID 2>/dev/null; do
    echo -n "."
    sleep 1
done
wait $BUILD_PID
BUILD_EXIT=$?

if [ $BUILD_EXIT -ne 0 ]; then
    echo " ❌ Build failed!"
    npm run build
    exit 1
fi

echo " ✓ Build complete"
echo ""

# Step 2: Close existing Chrome
echo "[2/3] Closing existing Chrome instances..."
if [[ "$OSTYPE" == "darwin"* ]]; then
  pkill -9 "Google Chrome Canary" 2>/dev/null || true
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
  pkill -9 chrome 2>/dev/null || true
fi
sleep 2
echo "✓ Chrome closed"
echo ""

# Step 3: Run Playwright test
echo "[3/3] Running automated test..."
echo ""
node test-iwa-playback.js

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║  ✅ ALL TESTS PASSED                                          ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
else
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║  ❌ TESTS FAILED - Check output above                         ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
fi

exit $EXIT_CODE

