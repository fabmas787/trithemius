"""
Normalize Runes — Preprocessing and standardization utility for Liber Primus text.

Prepares raw transcription files for ingestion into the corpus:
- Replaces inconsistent rune transliterations and OCR artifacts
- Standardizes Futhorc punctuation ('᛫' U+16EB, '᛬' U+16EC, '᛭' U+16ED)
- Validates characters against the 29 official Gematria Primus runes
- Calculates page-level statistics (rune count, prime sum)

Usage:
    python3 scripts/normalize_runes.py corpus/raw_page56.txt -o corpus/page56.txt
"""

import sys
import os
import argparse
from typing import Tuple, Dict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ciphers"))
from agrippa import INDEX_BY_RUNE, decode_runes, gematria_prime_sum

PUNCT_REPLACEMENTS = {
    "•": "᛫",
    "·": "᛫",
    ":": "᛬",
    ";": "᛬",
}


def normalize_text(text: str) -> Tuple[str, Dict]:
    """Clean and normalize transcription text."""
    normalized = []
    unknown_chars = []
    rune_count = 0

    for ch in text:
        # Check standard punctuation mappings
        if ch in PUNCT_REPLACEMENTS:
            normalized.append(PUNCT_REPLACEMENTS[ch])
        elif ch in INDEX_BY_RUNE:
            normalized.append(ch)
            rune_count += 1
        elif ch in ("᛫", "᛬", "᛭", "\n", " ", "\t", "#", "-", "_", "[", "]"):
            normalized.append(ch)
        elif ord(ch) < 128:  # Standard ASCII Latin
            normalized.append(ch)
        else:
            unknown_chars.append(ch)
            normalized.append(ch)

    result_text = "".join(normalized)
    stats = {
        "rune_count": rune_count,
        "gematria_prime_sum": gematria_prime_sum(result_text),
        "unknown_non_ascii_chars": len(unknown_chars),
    }
    return result_text, stats


def main():
    parser = argparse.ArgumentParser(description="Normalize Liber Primus text and runes.")
    parser.add_argument("input_file", help="Path to input text file")
    parser.add_argument("-o", "--output", help="Optional path to output file (default stdout)")
    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        print(f"[!] File not found: {args.input_file}")
        sys.exit(1)

    with open(args.input_file, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    cleaned, stats = normalize_text(content)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(cleaned)
        print(f"[+] Written normalized text to {args.output}")
    else:
        print(cleaned)

    print(f"\n[Statistics: {stats['rune_count']} runes, Gematria Sum: {stats['gematria_prime_sum']}]", file=sys.stderr)


if __name__ == "__main__":
    main()
