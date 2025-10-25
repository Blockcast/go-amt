#!/bin/bash
# Install IWA from signed bundle - NO SERVER NEEDED
# This is the most reliable method

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║   INSTALL IWA FROM SIGNED BUNDLE (NO SERVER NEEDED)           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check X11/DISPLAY
if [ -z "$DISPLAY" ]; then
    echo -e "${YELLOW}⚠${NC}  DISPLAY not set. Setting to :0"
    export DISPLAY=:0
else
    echo -e "${GREEN}✓${NC} DISPLAY is set to: $DISPLAY"
fi
echo ""

# Build if bundle doesn't exist
if [ ! -f "dist/amt-gateway.swbn" ]; then
    echo -e "${YELLOW}[1/3]${NC} Building signed bundle..."
    npm run build > /dev/null 2>&1
    echo -e "${GREEN}✓${NC} Bundle built"
else
    echo -e "${GREEN}[1/3]${NC} Signed bundle exists ($(ls -lh dist/amt-gateway.swbn | awk '{print $5}'))"
fi
echo ""

# Kill Chrome
echo -e "${YELLOW}[2/3]${NC} Closing all Chrome instances..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    pkill -9 "Google Chrome Canary" 2>/dev/null || true
    pkill -9 "Google Chrome" 2>/dev/null || true
else
    # Linux
    pkill -9 chrome 2>/dev/null || true
    pkill -9 google-chrome 2>/dev/null || true
fi
sleep 2
echo -e "${GREEN}✓${NC} Chrome closed"
echo ""

# Find Chrome
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS - prefer Canary
    if [ -f "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary" ]; then
        CHROME="/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary"
    elif [ -f "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]; then
        CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    else
        echo -e "${RED}✗${NC} Chrome not found!"
        echo "Install Chrome Canary from: https://www.google.com/chrome/canary/"
        exit 1
    fi
else
    # Linux
    if command -v google-chrome-unstable &> /dev/null; then
        CHROME="google-chrome-unstable"
    elif command -v google-chrome &> /dev/null; then
        CHROME="google-chrome"
    else
        echo -e "${RED}✗${NC} Chrome not found!"
        echo "Install: sudo apt-get install google-chrome-unstable"
        exit 1
    fi
fi

# Install
echo -e "${YELLOW}[3/3]${NC} Installing IWA from signed bundle..."
echo "   Using: $CHROME"
echo "   Bundle: $PWD/dist/amt-gateway.swbn"
echo ""

"$CHROME" \
  --enable-features=IsolatedWebApps,IsolatedWebAppDevMode,DirectSocketsInServiceWorkers,MulticastInDirectSockets \
  --enable-experimental-web-platform-features \
  --install-isolated-web-app-from-file="$PWD/dist/amt-gateway.swbn" \
  --new-window \
  "chrome://apps" &

CHROME_PID=$!

echo -e "${GREEN}✓${NC} Chrome launched (PID: $CHROME_PID)"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "VERIFICATION STEPS:"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "1. Check chrome://apps for 'Blockcast AMT Gateway'"
echo ""
echo "2. Click the app to open it"
echo "   Should open at: isolated-app://..."
echo ""
echo "3. Open DevTools Console (F12) and test:"
echo ""
echo "   # Check Direct Sockets API"
echo "   navigator.serviceWorker.ready.then(reg => {"
echo "     const mc = new MessageChannel();"
echo "     mc.port1.onmessage = e => console.log('✓ API:', e.data);"
echo "     reg.active.postMessage({type:'CHECK_API'}, [mc.port2]);"
echo "   });"
echo ""
echo "   Expected: {success: true, available: true, hasUDP: true}"
echo ""
echo "4. Create a socket:"
echo "   navigator.serviceWorker.ready.then(reg => {"
echo "     const mc = new MessageChannel();"
echo "     mc.port1.onmessage = e => console.log('✓ Socket:', e.data);"
echo "     reg.active.postMessage({type:'CREATE_SOCKET',localPort:0}, [mc.port2]);"
echo "   });"
echo ""
echo "5. Connect to AMT relay:"
echo "   URL: amt://83.97.94.146@232.1.2.3:1234@162.250.137.254:2268"
echo "   Click 'Connect & Join'"
echo ""
echo "═══════════════════════════════════════════════════════════════"


