#!/usr/bin/env bash
# ==============================================================================
# Trithemius Cicada 3301 Workstation — Interactive Double-Click Launcher
# ==============================================================================
# Double-clicking this file in Finder opens Terminal.app and starts the
# Trithemius interactive REPL without needing to open or navigate directories manually.

# Set Terminal Window Title
printf "\033]0;Trithemius Cicada 3301 Workstation\007"
clear

# Resolve directory of this script or default workspace
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR" || cd "/Users/fabio/Downloads/trithemius-cicada" || exit 1

# Launch the interactive workstation REPL
if [ -x "./venv/bin/python" ]; then
    ./venv/bin/python trithemius.py
else
    python3 trithemius.py
fi
