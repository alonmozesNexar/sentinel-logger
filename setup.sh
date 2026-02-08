#!/bin/bash
# Sentinel Logger - Quick Install Script
# Usage: curl -sL <raw-url>/setup.sh | bash
#   or:  bash setup.sh

set -e

REPO_URL="https://github.com/niceforbear/sentinel-logger.git"

echo ""
echo "  ============================================"
echo "  Sentinel Logger - Installer"
echo "  ============================================"
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "  ERROR: Python 3 is required but not installed."
    echo "  Install it from https://www.python.org/downloads/"
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 9 ]); then
    echo "  ERROR: Python 3.9+ is required (found $PY_VERSION)"
    exit 1
fi

echo "  Python $PY_VERSION detected"

# Check pip
if ! python3 -m pip --version &> /dev/null; then
    echo "  ERROR: pip is not installed."
    echo "  Install it with: python3 -m ensurepip --upgrade"
    exit 1
fi

echo "  Installing Sentinel Logger..."
echo ""

python3 -m pip install --upgrade "git+${REPO_URL}" 2>&1 | while read -r line; do
    echo "  $line"
done

echo ""
echo "  ============================================"
echo "  Installation complete!"
echo "  ============================================"
echo ""
echo "  Run:    sentinel-logger"
echo "  Update: pip install --upgrade git+${REPO_URL}"
echo ""

# Ask to launch
read -p "  Launch Sentinel Logger now? [Y/n] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    sentinel-logger
fi
