#!/bin/bash
# Clean up all IWA artifacts, profiles, and processes

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  Clean IWA Environment                                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

cd "$(dirname "$0")"

echo "[1/4] Killing Chrome processes..."
if [[ "$OSTYPE" == "darwin"* ]]; then
  pkill -9 "Google Chrome Canary" 2>/dev/null || true
  pkill -9 "Google Chrome" 2>/dev/null || true
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
  pkill -9 chrome 2>/dev/null || true
fi
echo "✓ Chrome killed"
echo ""

echo "[2/4] Cleaning build artifacts..."
rm -rf dist/
rm -rf node_modules/.cache/
echo "✓ Build artifacts cleaned"
echo ""

echo "[3/4] Cleaning test profiles..."
rm -rf /tmp/chrome-iwa-test-*
echo "✓ Test profiles cleaned"
echo ""

echo "[4/4] Do you want to delete the persistent profile?"
echo "     (This will require re-enabling Direct Sockets flags)"
read -p "     Delete ~/.chrome-iwa-persistent? (y/N) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf ~/.chrome-iwa-persistent
    echo "✓ Persistent profile deleted"
    echo "  Run ./setup.sh to recreate it"
else
    echo "✓ Persistent profile kept"
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  ✅ CLEAN COMPLETE                                            ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

