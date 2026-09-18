#!/usr/bin/env bash
# Runs automatically when this repo is opened in GitHub Codespaces (or any
# devcontainer-compatible editor). Sets up a working environment with zero
# manual steps: venv, deps, the real Kelmarsh dataset, and runs the unit
# tests so you immediately know the lab is in a working state.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo ""
echo "Fetching the real Kelmarsh dataset (Codespaces has full internet access)..."
make fetch-dataset || echo "Dataset fetch failed -- falling back to the committed 20-row real excerpt, see data/kelmarsh/README.md"

echo ""
echo "Running unit tests as a smoke test:"
python3 -m pytest tests/ -v

echo ""
echo "Setup complete. Try it now:"
echo "  source .venv/bin/activate"
echo "  make lab-up            # start the turbine + HVAC simulators and the tap"
echo "  make demo-discovery    # run a real scan + detection scenario end to end"
echo "  python3 detection/engine.py   # watch alerts live"
