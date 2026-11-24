#!/usr/bin/env python3
"""
Trithemius — Unified Terminal Cryptanalytic Workstation.
Backward-compatible entrypoint facade.
Named for Johannes Trithemius (1462–1516), father of steganography and cryptography.
"""

import os
import sys

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from workstation.core.workstation import (
    TerminalWorkstation,
    CORPUS_DIR,
    DB_DIR,
    ConsoleRenderer,
)
from workstation.cli.parser import main, build_parser, cli_dispatch

COMMAND_DOCS = ConsoleRenderer.COMMAND_DOCS

if __name__ == "__main__":
    sys.exit(main())
