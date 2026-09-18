#!/usr/bin/env bash
# One-command local setup: creates a venv, installs dependencies, fetches
# the real dataset, and runs the tests. Works whether you're on your own
# machine or in GitHub Codespaces (which also runs this automatically via
# .devcontainer/devcontainer.json).
set -euo pipefail
cd "$(dirname "$0")"
exec .devcontainer/setup.sh
