#!/usr/bin/env bash
# ── ThreatScan — quick local start ─────────────────────────────────────────
# Usage:  bash run.sh
# Requires: Python 3.10+

set -e

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   ThreatScan — Universal Threat Detector ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# 1. Virtual environment
if [ ! -d ".venv" ]; then
  echo "→ Creating virtual environment..."
  python3 -m venv .venv
fi

source .venv/bin/activate

# 2. Dependencies
echo "→ Installing dependencies (first run may take a minute)..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

# 3. .env
if [ ! -f ".env" ]; then
  echo "→ Creating .env from template (add API keys anytime)..."
  cp .env.example .env
fi

# 4. Launch
echo ""
echo "✓ Starting server at http://localhost:8000"
echo "  Press Ctrl+C to stop."
echo ""

export PYTHONPATH="$(pwd)/backend"
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
