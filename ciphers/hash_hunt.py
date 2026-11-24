"""
HashHunt — Local 512-bit Hash Hunting Combinatorial Normalization Lattice.
Standard library only: hashlib, os. Zero external dependencies. Zero network calls.

Investigates candidate local text documents against the Page 56 ('An End') 512-bit digest:
36367763ab73783c7af284446c59466b4cd653239a311cb7116d4618dee09a8425893dc7500b464fdaf1672d7bef5e891c6e2274568926a49fb4f45132c2a8b4

Evaluates candidates across an exhaustive local normalization lattice:
1. Algorithms: sha512, sha3_512, blake2b
2. Normalizations:
   - raw bytes as read
   - stripped whitespace
   - normalized LF line feeds
   - normalized CRLF line feeds
   - trailing newline removed
3. Encodings: utf-8, utf-16le, utf-16be, ascii
"""

from __future__ import annotations
import hashlib
import os
from typing import Dict, List, Tuple, Optional, Any

TARGET_512_HASH = (
    "36367763ab73783c7af284446c59466b4cd653239a311cb7116d4618dee09a84"
    "25893dc7500b464fdaf1672d7bef5e891c6e2274568926a49fb4f45132c2a8b4"
).lower()

HASH_ALGORITHMS = ["sha512", "sha3_512", "blake2b"]


def generate_normalization_lattice(text: str) -> List[Tuple[str, bytes]]:
    """
    Generate candidate byte representations of a text string across the normalization lattice.
    Returns list of (normalization_label, byte_payload).
    """
    lattice: List[Tuple[str, bytes]] = []

    # 1. Base string variants
    variants = [
        ("raw", text),
        ("stripped", text.strip()),
        ("lf", text.replace("\r\n", "\n")),
        ("crlf", text.replace("\r\n", "\n").replace("\n", "\r\n")),
        ("no_trailing_newline", text.rstrip("\r\n")),
        ("stripped_lf", text.strip().replace("\r\n", "\n")),
    ]

    # De-duplicate string variants
    seen_strings = set()
    unique_variants = []
    for label, s in variants:
        if s not in seen_strings:
            seen_strings.add(s)
            unique_variants.append((label, s))

    # 2. Encodings
    encodings = ["utf-8", "utf-16le", "utf-16be"]

    for var_label, s in unique_variants:
        for enc in encodings:
            try:
                b = s.encode(enc)
                lattice.append((f"{var_label}_{enc}", b))
            except UnicodeEncodeError:
                pass

    return lattice


def check_candidate_bytes(
    candidate_bytes: bytes,
    target_hex: str = TARGET_512_HASH
) -> Optional[Tuple[str, str]]:
    """
    Check if candidate bytes match target hex under any supported 512-bit algorithm.
    Returns (algo_name, digest_hex) if match found, else None.
    """
    clean_target = target_hex.strip().lower()
    for algo in HASH_ALGORITHMS:
        h = hashlib.new(algo, candidate_bytes).hexdigest().lower()
        if h == clean_target:
            return (algo, h)
    return None


def scan_local_text(
    text: str,
    target_hex: str = TARGET_512_HASH
) -> Optional[Dict[str, Any]]:
    """
    Scan a local text string across the complete normalization lattice.
    Returns match details if found, else None.
    """
    lattice = generate_normalization_lattice(text)
    for label, b in lattice:
        match = check_candidate_bytes(b, target_hex=target_hex)
        if match:
            algo, h = match
            return {
                "matched": True,
                "algorithm": algo,
                "normalization": label,
                "digest": h,
                "byte_length": len(b),
            }
    return None


def scan_local_file(
    filepath: str,
    target_hex: str = TARGET_512_HASH
) -> Dict[str, Any]:
    """
    Exhaustively evaluate a local file across raw bytes and text normalizations.
    """
    if not os.path.exists(filepath):
        return {"error": "File not found", "matched": False}

    try:
        with open(filepath, "rb") as f:
            raw_bytes = f.read()
    except Exception as e:
        return {"error": str(e), "matched": False}

    # Direct raw bytes check
    raw_match = check_candidate_bytes(raw_bytes, target_hex=target_hex)
    if raw_match:
        algo, h = raw_match
        return {
            "filepath": filepath,
            "matched": True,
            "algorithm": algo,
            "normalization": "raw_binary",
            "digest": h,
            "byte_length": len(raw_bytes),
        }

    # If file is text, scan normalization lattice
    try:
        text = raw_bytes.decode("utf-8", errors="ignore")
        text_res = scan_local_text(text, target_hex=target_hex)
        if text_res:
            text_res["filepath"] = filepath
            return text_res
    except Exception:
        pass

    return {
        "filepath": filepath,
        "matched": False,
        "evaluations_count": len(HASH_ALGORITHMS) * (1 + len(generate_normalization_lattice(text if 'text' in locals() else ""))),
    }
