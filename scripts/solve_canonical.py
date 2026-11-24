#!/usr/bin/env python3
"""
Solve Canonical — Standalone CLI verification and decoding tool for solved Liber Primus pages.
Faithfully reproduces all 9 solved pages according to the Uncovering Cicada wiki:
https://uncovering-cicada.fandom.com/wiki/How_the_solved_pages_of_the_Liber_Primus_were_solved

Pages Supported:
    1. page_00 / 01.jpg:        Atbash in F_29
    2. welcome / 03-04.jpg:      Vigenère DIVINITY with cleartext F-skips
    3. some_wisdom / 05.jpg:     Direct transliteration
    4. koan_1 / 06-09.jpg:       Atbash + Caesar (+3) in F_29
    5. loss_of_divinity / 10-13: Direct transliteration
    6. koan_2 / 14-15.jpg:       Vigenère FIRFUMFERENFE with cleartext F-skips
    7. instruction / 16.jpg:     Direct transliteration
    8. an_end / 56.jpg (73.jpg): Prime Totient Stream Cipher with Fehu skip
    9. parable / 57.jpg:         Direct transliteration

Usage:
    python3 scripts/solve_canonical.py              # Verify all 9 pages
    python3 scripts/solve_canonical.py welcome      # Solve and inspect Welcome
    python3 scripts/solve_canonical.py 56           # Solve Page 56.jpg (An end)
    python3 scripts/solve_canonical.py --json       # Output machine-readable JSON
"""

import argparse
import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for d in (BASE_DIR, os.path.join(BASE_DIR, "ciphers")):
    if d not in sys.path:
        sys.path.insert(0, d)

from solved_pages import (
    SOLVED_PAGES_REGISTRY,
    resolve_solved_page,
    solve_page,
    verify_all_solved_pages,
)


def main():
    parser = argparse.ArgumentParser(
        description="Solve and verify canonical Liber Primus pages from official wiki"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="all",
        help="Page identifier (e.g. 0, welcome, koan1, 56, an_end, all)",
    )
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON format")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print verbose step-by-step telemetry")

    args = parser.parse_args()

    target = args.target.strip().lower()

    if target in ("all", "*", ""):
        report = verify_all_solved_pages(verbose=args.verbose)
        if args.json:
            # Prepare JSON-serializable output
            clean_results = {}
            for k, v in report["results"].items():
                item = dict(v)
                clean_results[k] = item
            out = dict(report)
            out["results"] = clean_results
            print(json.dumps(out, indent=2))
        else:
            print("\n+--- [CANONICAL LIBER PRIMUS SOLVED PAGES VERIFICATION] ------------------")
            print(f"| Total Pages Tested: {report['total']} | Verified: {report['verified']} | Failed: {report['failed']}")
            print("|\n| Status  Page ID            Image           Method")
            for pid, res in report["results"].items():
                status = "[PASS]" if res["verified"] else "[FAIL]"
                print(f"| {status:<6s}  {pid:<18s} {res['original_image']:<15s} {res['method']}")
            print("|\n+--------------------------------------------------------------------------")
            res_str = "ALL 9 PAGES VERIFIED (100% SUCCESS)" if report["all_passed"] else f"{report['verified']}/{report['total']} VERIFIED"
            print(f"| Result: {res_str}")
            print("+--------------------------------------------------------------------------\n")
        sys.exit(0 if report["all_passed"] else 1)

    else:
        try:
            res = solve_page(target)
        except Exception as e:
            print(f"[!] Error solving '{target}': {e}", file=sys.stderr)
            sys.exit(2)

        if args.json:
            print(json.dumps(res, indent=2))
        else:
            status = "[PASS]" if res["verified"] else "[FAIL]"
            print(f"\n+--- [CANONICAL SOLVED PAGE: {res['title'].upper()}] -------------------------")
            print(f"| ID:              {res['id']}")
            print(f"| Original Image:  {res['original_image']}")
            print(f"| Chunks:          {res['chunks']}")
            print(f"| Method:          {res['method']}")
            print(f"| Description:     {res['method_description']}")
            if res.get("key"):
                print(f"| Key:             {res['key']}")
            if res.get("skip_indices"):
                print(f"| Fehu Skip Ptr:   {res['skip_indices']}")
            print(f"| Rune Count:      {res['rune_count']}")
            print(f"| Status:          {status}")
            matched = len(res.get("matched_fragments", []))
            total_frags = matched + len(res.get("missing_fragments", []))
            print(f"| Verification:    {matched}/{total_frags} Canonical Phrases Matched")
            print("|\n| Decrypted Latin Plaintext Preview:")
            lines = res.get("plaintext_latin", "").strip().splitlines()
            for line in lines[:12]:
                print(f"|   {line}")
            if len(lines) > 12:
                print(f"|   ... ({len(lines) - 12} more lines)")
            print("+--------------------------------------------------------------------------\n")

        sys.exit(0 if res["verified"] else 1)


if __name__ == "__main__":
    main()
