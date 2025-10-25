#!/bin/bash
# Detect Chrome Canary/Unstable based on OS

detect_chrome() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    CHROME_BIN="/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary"
    if [ ! -f "$CHROME_BIN" ]; then
      echo "❌ Chrome Canary not found at: $CHROME_BIN"
      echo "   Install from: https://www.google.com/chrome/canary/"
      exit 1
    fi
  elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    CHROME_BIN=$(which google-chrome-unstable 2>/dev/null)
    if [ -z "$CHROME_BIN" ]; then
      echo "❌ google-chrome-unstable not found"
      echo "   Install with: sudo apt install google-chrome-unstable"
      exit 1
    fi
  else
    echo "❌ Unsupported OS: $OSTYPE"
    echo "   Supported: macOS (darwin), Linux (linux-gnu)"
    exit 1
  fi
  
  echo "$CHROME_BIN"
}

# Export function for sourcing
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
  # Script is being executed directly
  detect_chrome
fi


