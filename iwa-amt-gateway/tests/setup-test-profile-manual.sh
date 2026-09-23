#!/bin/bash

# Manual Test Profile Setup
# This script helps set up a test profile by using the existing install:auto method

set -e

echo "╔════════════════════════════════════════════════════════╗"
echo "║  IWA Test Profile Setup (Manual Method)               ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_PROFILE_DIR="$PROJECT_DIR/.test-profile"

echo "📁 Test profile location: $TEST_PROFILE_DIR"
echo ""

# Check if profile already exists
if [ -d "$TEST_PROFILE_DIR" ]; then
  echo "⚠️  Test profile already exists"
  read -p "Remove and recreate? (y/N): " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🗑️  Removing existing profile..."
    rm -rf "$TEST_PROFILE_DIR"
  else
    echo "✓ Keeping existing profile"
    exit 0
  fi
fi

echo ""
echo "📋 Setup Steps:"
echo "  1. Run the auto-install script"
echo "  2. Wait for Chrome to open and IWA to load"
echo "  3. Verify the IWA works (you'll see the gateway UI)"
echo "  4. Close Chrome window"
echo "  5. We'll copy the profile for testing"
echo ""
read -p "Ready to start? (y/N): " -n 1 -r
echo

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "❌ Setup cancelled"
  exit 1
fi

echo ""
echo "🚀 Launching IWA installation..."
echo ""

# Run the install:auto script but capture the profile location
cd "$PROJECT_DIR"
npm run install:auto

echo ""
echo "✅ Installation complete!"
echo ""
echo "Now we need to copy the Chrome profile..."
echo ""

# The install:auto script creates a temp profile
# We need to find the most recent Chrome user data directory
TEMP_PROFILE=$(find /var/folders -name "chrome-iwa-test-*" -type d 2>/dev/null | sort -r | head -n 1)

if [ -z "$TEMP_PROFILE" ]; then
  echo "❌ Could not find the installed IWA profile"
  echo "   Please run: npm run install:auto"
  echo "   Then manually copy the profile to: $TEST_PROFILE_DIR"
  exit 1
fi

echo "📂 Found profile: $TEMP_PROFILE"
echo "📋 Copying to test profile..."

cp -R "$TEMP_PROFILE" "$TEST_PROFILE_DIR"

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║  ✅ Test Profile Setup Complete!                      ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "Profile location: $TEST_PROFILE_DIR"
echo ""
echo "You can now run tests with:"
echo "  npm run test"
echo ""




