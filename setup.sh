#!/bin/bash

echo "======================================"
echo "XSS Recon - Setup Wizard"
echo "======================================"
echo ""

if [[ ! "$OSTYPE" == "linux-gnu"* ]] && [[ ! "$OSTYPE" == "linux"* ]]; then
    echo "⚠️  This script is designed for Linux/Kali Linux/WSL"
    echo "Current OS: $OSTYPE"
    exit 1
fi

echo "[1/5] Checking system dependencies..."
MISSING_DEPS=()

for cmd in curl wget git bash; do
    if ! command -v "$cmd" &> /dev/null; then
        MISSING_DEPS+=("$cmd")
    fi
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo "❌ Missing dependencies: ${MISSING_DEPS[*]}"
    echo "Install with: sudo apt-get install ${MISSING_DEPS[*]}"
    exit 1
else
    echo "All basic dependencies installed"
fi

echo ""
echo "[2/5] Checking Go installation..."
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}')
    echo "Go $GO_VERSION found"
else
    echo "❌ Go not installed"
    echo "Install from: https://go.dev/dl/"
    echo "Or run: sudo apt-get install golang-go"
    exit 1
fi

echo ""
echo "[3/5] Checking Python installation..."
if command -v python3 &> /dev/null; then
    PY_VERSION=$(python3 --version | awk '{print $2}')
    echo "Python $PY_VERSION found"
else
    echo "❌ Python 3 not installed"
    echo "Install with: sudo apt-get install python3 python3-pip"
    exit 1
fi

echo ""
echo "[4/5] Checking script permissions..."
if [ ! -x "BlankRecon.sh" ]; then
    echo "Setting executable permissions on BlankRecon.sh..."
    chmod +x BlankRecon.sh
    echo "✅ Permissions updated"
else
    echo "✅ Script already executable"
fi

echo ""
echo "[5/5] Environment check complete!"
echo ""
echo "======================================"
echo "Ready to use! Run with:"
echo "  ./BlankRecon.sh"
echo "======================================"
echo ""
echo "📖 Documentation: README.md"
echo "📝 Log file will be created: recon_<target>/recon.log"
echo ""
