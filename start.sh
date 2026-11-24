#!/usr/bin/env bash
# ==============================================================================
# Trithemius — 1-Click Launcher for macOS & Linux
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

# If venv doesn't exist, run install.sh first
if [ ! -d "$VENV_DIR" ]; then
    echo "[!] Virtual environment not found. Running setup first..."
    bash "$SCRIPT_DIR/install.sh"
fi

# Ensure Ollama daemon is active only if running local Ollama
IS_LOCAL_OLLAMA=true
for arg in "$@"; do
    if [[ "$arg" == "--provider" ]]; then
        IS_LOCAL_OLLAMA=false
    fi
done
if [ -n "$TRITHEMIUS_PROVIDER" ] && [ "$TRITHEMIUS_PROVIDER" != "ollama" ]; then
    IS_LOCAL_OLLAMA=false
fi
if [ -n "$OLLAMA_HOST" ] && [[ "$OLLAMA_HOST" != *"localhost"* ]] && [[ "$OLLAMA_HOST" != *"127.0.0.1"* ]]; then
    IS_LOCAL_OLLAMA=false
fi

if [ "$IS_LOCAL_OLLAMA" = true ] && command -v ollama >/dev/null 2>&1; then
    if ! curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
        echo "[*] Starting local Ollama daemon in background..."
        ollama serve >/dev/null 2>&1 &
        sleep 2
    fi
fi

# Activate venv
source "$VENV_DIR/bin/activate"

# Launch Terminal Workstation
python3 "$SCRIPT_DIR/trithemius.py" "$@"
