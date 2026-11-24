#!/usr/bin/env python3
"""
Totient Stream — Standalone CLI utility for the Liber Primus Prime Totient Stream Cipher.
Named for Euler's totient function phi(n) and the sacred primes of Cicada 3301.

Mathematical Definition:
    decimal[i] = (decimal[i] - (primes[i + offset] - 1)) mod 29  (decryption)
    decimal[i] = (decimal[i] + (primes[i + offset] - 1)) mod 29  (encryption)
where primes[k] is the k-th prime (2, 3, 5, 7, 11, ...) and phi(p) = p - 1.

Canonical solved page:
    Page 56.jpg / 73.jpg ('An end', chunk 71): offset=0, Fehu skip at index 56.

Usage:
    python3 scripts/totient_stream.py dec corpus/page_71_runes.md --f-skip
    python3 scripts/totient_stream.py dec "ᚪᚾ᛫ᛖᚾᛞ..." --offset 0
    python3 scripts/totient_stream.py enc "AN END WITHIN THE DEEP WEB" --f-skip
"""

import argparse
import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for d in (BASE_DIR, os.path.join(BASE_DIR, "ciphers")):
    if d not in sys.path:
        sys.path.insert(0, d)

from agrippa import INDEX_BY_RUNE, decode_runes, latin_to_rune
from al_kindi import is_plausible_english
from kasiski import (
    generate_prime_totients,
    prime_totient_stream_decode,
    prime_totient_stream_encode,
    rune_index_of_coincidence,
)


def resolve_input(target: str) -> str:
    """Resolve raw string, file path, or corpus reference."""
    if not target or not isinstance(target, str):
        return ""
    stripped = target.strip()
    if os.path.isfile(stripped):
        path = os.path.abspath(stripped)
    elif os.path.isfile(os.path.join(BASE_DIR, "corpus", stripped)):
        path = os.path.join(BASE_DIR, "corpus", stripped)
    else:
        return target

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # If markdown file, extract rune section if present
    import re
    m = re.search(r"## Rune Transcription\n(.*?)(?:\n---|\n## Latin|\Z)", content, re.DOTALL)
    if m:
        return m.group(1).strip()
    lines = [l for l in content.splitlines() if any(c in INDEX_BY_RUNE for c in l)]
    if lines:
        return "\n".join(lines).strip()
    return content.strip()


def main():
    parser = argparse.ArgumentParser(
        description="Liber Primus Prime Totient Stream Cipher (phi(p) = p - 1 mod 29)"
    )
    parser.add_argument("mode", choices=["enc", "dec", "encode", "decode"], help="Cipher mode")
    parser.add_argument("text", type=str, help="Text, ciphertext, filepath, or '-' for stdin")
    parser.add_argument("--offset", type=int, default=0, help="Prime sequence offset (default: 0)")
    parser.add_argument("--f-skip", action="store_true", help="Enable cleartext Fehu keystream pause (skip index 56)")
    parser.add_argument("--skip-indices", type=str, default=None, help="Comma-separated explicit skip indices (e.g. '56')")
    parser.add_argument("--no-separators", action="store_true", help="Do not preserve layout punctuation or separators")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--quiet", "-q", action="store_true", help="Print only decoded Latin text")
    parser.add_argument("-o", "--output", type=str, default=None, help="Write output to file")

    args = parser.parse_args()

    if args.text == "-":
        raw_text = sys.stdin.read()
    else:
        raw_text = resolve_input(args.text)

    is_dec = args.mode in ("dec", "decode")
    preserve = not args.no_separators

    skips = None
    if args.skip_indices:
        skips = set()
        for x in args.skip_indices.split(","):
            try:
                skips.add(int(x.strip()))
            except ValueError:
                pass

    has_runes = any(c in INDEX_BY_RUNE for c in raw_text)
    input_runes = raw_text if has_runes else latin_to_rune(raw_text)

    if is_dec:
        result_runes = prime_totient_stream_decode(
            input_runes,
            offset=args.offset,
            preserve_separators=preserve,
            skip_indices=skips,
            f_skip=args.f_skip,
        )
    else:
        result_runes, detected_skips = prime_totient_stream_encode(
            input_runes,
            offset=args.offset,
            preserve_separators=preserve,
            skip_indices=skips,
            f_skip=args.f_skip,
        )
        if skips is None and args.f_skip:
            skips = detected_skips

    latin_text = decode_runes(result_runes, preserve_punctuation=preserve)
    ioc = rune_index_of_coincidence(result_runes)
    passed, metrics = is_plausible_english(latin_text)

    effective_skips = sorted(skips) if skips else ([56] if args.f_skip else None)

    data = {
        "mode": "DECODE" if is_dec else "ENCODE",
        "offset": args.offset,
        "f_skip": args.f_skip,
        "skip_indices": effective_skips,
        "rune_count": sum(1 for c in input_runes if c in INDEX_BY_RUNE),
        "result_runes": result_runes,
        "latin_text": latin_text,
        "ioc": round(ioc, 4),
        "metrics": metrics,
    }

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            if args.json:
                json.dump(data, f, indent=2)
            else:
                f.write(latin_text + "\n")

    if args.quiet:
        print(latin_text)
        return

    if args.json:
        print(json.dumps(data, indent=2))
        return

    print("\n+--- [PRIME TOTIENT STREAM CIPHER] ---------------------------------------")
    print(f"| Mode:            {data['mode']}")
    print(f"| Prime Offset:    {data['offset']}")
    f_info = "ENABLED" if data["f_skip"] or data["skip_indices"] else "DISABLED"
    if data["skip_indices"]:
        f_info += f" (Positions: {data['skip_indices']})"
    print(f"| Fehu (F) Skip:   {f_info}")
    print(f"| Symbol Count:    {data['rune_count']} runes")
    print(f"| Index of Coinc:  {data['ioc']}")
    print(f"| Gatekeeper:      [{metrics.get('verdict', 'UNKNOWN')}]")
    print("|\n| Result Preview:")
    for line in latin_text.splitlines()[:8]:
        print(f"|   {line}")
    print("+--------------------------------------------------------------------------\n")


if __name__ == "__main__":
    main()
