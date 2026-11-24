"""
Normalize Runes — Preprocessing and standardization utility for Liber Primus text.

Prepares raw transcription files for ingestion into the corpus:
- Replaces inconsistent rune transliterations and OCR artifacts
- Standardizes Futhorc punctuation ('᛫' U+16EB, '᛬' U+16EC, '᛭' U+16ED)
- Supports --normalize-three-dot mapping 3-dot punctuation to ᛬ + ᛫ while preserving offsets
- Validates characters against the 29 official Gematria Primus runes
- Calculates page-level statistics (rune count, prime sum, rune offsets)

Usage:
    python3 scripts/normalize_runes.py corpus/raw_page56.txt -o corpus/page56.txt
    python3 scripts/normalize_runes.py corpus/raw_page56.txt --normalize-three-dot
"""

import sys
import os
import argparse
from typing import Tuple, Dict, List, Any

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from ciphers.agrippa import INDEX_BY_RUNE, decode_runes, gematria_prime_sum
except ImportError:
    from agrippa import INDEX_BY_RUNE, decode_runes, gematria_prime_sum

PUNCT_REPLACEMENTS = {
    "•": "᛫",
    "·": "᛫",
    ":": "᛬",
    ";": "᛬",
}

THREE_DOT_CHARS = {"᛭", "⁝", "⋮"}


def normalize_text(text: str, normalize_three_dot: bool = False) -> Tuple[str, Dict[str, Any]]:
    """
    Clean and normalize transcription text.
    If normalize_three_dot is True, maps 3-dot punctuation ('᛭', '⁝', '⋮', '...')
    to Futhorc '᛬' + '᛫' while preserving original character offsets.
    """
    normalized: List[str] = []
    unknown_chars: List[str] = []
    rune_count = 0
    rune_offsets: List[int] = []
    offset_map: List[int] = []  # Maps normalized character index -> original character index

    i = 0
    n = len(text)
    while i < n:
        orig_i = i

        # Check for multi-character 3-dot patterns first if normalize_three_dot is enabled
        if normalize_three_dot and text.startswith("...", i):
            normalized.append("᛬")
            offset_map.append(orig_i)
            normalized.append("᛫")
            offset_map.append(orig_i)
            i += 3
            continue
        elif normalize_three_dot and text.startswith("᛫᛫᛫", i):
            normalized.append("᛬")
            offset_map.append(orig_i)
            normalized.append("᛫")
            offset_map.append(orig_i)
            i += 3
            continue

        ch = text[i]

        if normalize_three_dot and ch in THREE_DOT_CHARS:
            normalized.append("᛬")
            offset_map.append(orig_i)
            normalized.append("᛫")
            offset_map.append(orig_i)
            i += 1
            continue

        # Standard replacements
        if ch in PUNCT_REPLACEMENTS:
            normalized.append(PUNCT_REPLACEMENTS[ch])
            offset_map.append(orig_i)
        elif ch in INDEX_BY_RUNE:
            normalized.append(ch)
            offset_map.append(orig_i)
            rune_offsets.append(orig_i)
            rune_count += 1
        elif ch in ("᛫", "᛬", "᛭", "\n", " ", "\t", "#", "-", "_", "[", "]"):
            normalized.append(ch)
            offset_map.append(orig_i)
        elif ord(ch) < 128:  # Standard ASCII Latin
            normalized.append(ch)
            offset_map.append(orig_i)
        else:
            unknown_chars.append(ch)
            normalized.append(ch)
            offset_map.append(orig_i)

        i += 1

    result_text = "".join(normalized)
    stats = {
        "rune_count": rune_count,
        "gematria_prime_sum": gematria_prime_sum(result_text),
        "unknown_non_ascii_chars": len(unknown_chars),
        "rune_offsets": rune_offsets,
        "offset_map": offset_map,
        "normalize_three_dot": normalize_three_dot,
    }
    return result_text, stats


def main():
    parser = argparse.ArgumentParser(description="Normalize Liber Primus text and runes.")
    parser.add_argument("input_file", help="Path to input text file")
    parser.add_argument("-o", "--output", help="Optional path to output file (default stdout)")
    parser.add_argument(
        "--normalize-three-dot",
        action="store_true",
        help="Normalize 3-dot punctuation (᛭, ⁝, ⋮, ...) to ᛬ + ᛫ while preserving offsets"
    )
    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        print(f"[!] File not found: {args.input_file}")
        sys.exit(1)

    with open(args.input_file, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    cleaned, stats = normalize_text(content, normalize_three_dot=args.normalize_three_dot)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(cleaned)
        print(f"[+] Written normalized text to {args.output}")
    else:
        print(cleaned)

    print(
        f"\n[Statistics: {stats['rune_count']} runes, Gematria Sum: {stats['gematria_prime_sum']}, Three-Dot: {stats['normalize_three_dot']}]",
        file=sys.stderr
    )


if __name__ == "__main__":
    main()
