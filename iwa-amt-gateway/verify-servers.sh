#!/bin/bash

echo "========================================="
echo "  IWA Output Servers Verification"
echo "========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check UDP port
echo "1. Checking UDP port 5000..."
if lsof -i :5000 > /dev/null 2>&1; then
  echo -e "   ${GREEN}✅ Port 5000 is listening${NC}"
  lsof -i :5000 | grep Chrome | head -1
else
  echo -e "   ${RED}❌ Port 5000 is NOT listening${NC}"
  echo "   → Make sure IWA is running with output servers enabled"
fi
echo ""

# Check WebSocket port
echo "2. Checking WebSocket port 5002..."
if lsof -i :5002 > /dev/null 2>&1; then
  echo -e "   ${GREEN}✅ Port 5002 is listening${NC}"
  lsof -i :5002 | grep Chrome | head -1
else
  echo -e "   ${RED}❌ Port 5002 is NOT listening${NC}"
  echo "   → Make sure IWA is running with output servers enabled"
fi
echo ""

# Test UDP server
echo "3. Testing UDP server..."
response=$(timeout 1 bash -c 'echo "{\"action\":\"ping\"}" | nc -u -w 1 localhost 5000 2>/dev/null')
if [ -n "$response" ]; then
  echo -e "   ${GREEN}✅ UDP server is responding${NC}"
  echo "   Response: $response"
elif lsof -i :5000 > /dev/null 2>&1; then
  echo -e "   ${YELLOW}⚠️  Port is listening but no response (this is OK - server may not respond to ping)${NC}"
else
  echo -e "   ${RED}❌ UDP server is NOT responding${NC}"
  echo "   → Check Service Worker console for errors"
fi
echo ""

# Test WebSocket server
echo "4. Testing WebSocket server..."
if command -v websocat > /dev/null 2>&1; then
  ws_response=$(timeout 2 bash -c 'echo "{\"action\":\"ping\"}" | websocat ws://localhost:5002 2>/dev/null')
  if [ -n "$ws_response" ]; then
    echo -e "   ${GREEN}✅ WebSocket server is responding${NC}"
    echo "   Response: $ws_response"
  elif lsof -i :5002 > /dev/null 2>&1; then
    echo -e "   ${YELLOW}⚠️  Port is listening but connection failed${NC}"
    echo "   → May need to check WebSocket handshake in Service Worker console"
  else
    echo -e "   ${RED}❌ WebSocket server is NOT responding${NC}"
  fi
else
  echo -e "   ${YELLOW}⚠️  websocat not installed${NC}"
  echo "   Install with: brew install websocat (macOS) or cargo install websocat"
  echo "   Testing with curl instead..."
  
  # Try curl as fallback
  curl_response=$(curl -s -o /dev/null -w "%{http_code}" -i -N \
    -H "Connection: Upgrade" \
    -H "Upgrade: websocket" \
    -H "Sec-WebSocket-Version: 13" \
    -H "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==" \
    http://localhost:5002 2>/dev/null)
  
  if [ "$curl_response" = "101" ]; then
    echo -e "   ${GREEN}✅ WebSocket server accepts connections (HTTP 101)${NC}"
  else
    echo -e "   ${RED}❌ WebSocket handshake failed (HTTP $curl_response)${NC}"
  fi
fi
echo ""

# Check Chrome processes
echo "5. Checking Chrome/IWA processes..."
chrome_count=$(ps aux | grep -i "chrome" | grep -v grep | wc -l)
if [ $chrome_count -gt 0 ]; then
  echo -e "   ${GREEN}✅ Chrome is running ($chrome_count processes)${NC}"
  
  # Check for IWA-specific process
  iwa_process=$(ps aux | grep -i "isolated-app" | grep -v grep)
  if [ -n "$iwa_process" ]; then
    echo -e "   ${GREEN}✅ IWA process detected${NC}"
  else
    echo -e "   ${YELLOW}⚠️  No IWA-specific process found (may be normal)${NC}"
  fi
else
  echo -e "   ${RED}❌ Chrome is not running${NC}"
  echo "   → Launch IWA first"
fi
echo ""

# Summary
echo "========================================="
echo "  Summary"
echo "========================================="
echo ""

udp_ok=$(lsof -i :5000 > /dev/null 2>&1 && echo "yes" || echo "no")
ws_ok=$(lsof -i :5002 > /dev/null 2>&1 && echo "yes" || echo "no")

if [ "$udp_ok" = "yes" ] && [ "$ws_ok" = "yes" ]; then
  echo -e "${GREEN}✅ Both servers are running!${NC}"
  echo ""
  echo "Next steps:"
  echo "1. Open IWA: isolated-app://ajl3qtbxefofp3jbs5cskw2whqpj7etglpj6mruy4oyty3k5wb5jqaacai"
  echo "2. Check 'Output Servers' panel for 'Hybrid Mode'"
  echo "3. Test with: echo '{\"action\":\"subscribe\",\"source\":\"0.0.0.0\",\"group\":\"232.1.2.3\",\"port\":1234}' | nc -u localhost 5000"
  echo ""
elif [ "$udp_ok" = "yes" ] || [ "$ws_ok" = "yes" ]; then
  echo -e "${YELLOW}⚠️  Partially working${NC}"
  [ "$udp_ok" = "no" ] && echo "   - UDP server (port 5000): NOT running"
  [ "$ws_ok" = "no" ] && echo "   - WebSocket server (port 5002): NOT running"
  echo ""
  echo "Check Service Worker console:"
  echo "1. Right-click IWA window → Inspect"
  echo "2. Application → Service Workers → service-worker.js → Inspect"
  echo "3. Look for server startup errors"
  echo ""
else
  echo -e "${RED}❌ Servers are NOT running${NC}"
  echo ""
  echo "Troubleshooting:"
  echo "1. Make sure IWA is running"
  echo "2. Check Service Worker console for errors:"
  echo "   Right-click IWA → Inspect → Application → Service Workers → Inspect"
  echo "3. Look for: '[SW] ✓ Started 2/2 output servers'"
  echo "4. If not present, check for error messages"
  echo "5. Verify Chrome flags are enabled:"
  echo "   chrome://flags/#enable-direct-sockets-web-api"
  echo ""
fi

echo "========================================="
echo ""
echo "For detailed verification steps, see:"
echo "  → VERIFY_OUTPUT_SERVERS.md"
echo ""

