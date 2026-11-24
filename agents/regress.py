"""
Regress — regression testing against known-solved Liber Primus pages and ciphers.
Ensures changes to cipher modules, prompts, or algorithms do not break known solutions.

Usage:
    python3 agents/regress.py
"""

import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from ciphers.agrippa import decode_runes, latin_to_rune
    from ciphers.kasiski import (
        vigenere_decode, rune_vigenere_decode, rune_vigenere_encode,
        generate_primes
    )
    from ciphers.al_kindi import is_plausible_english
except ImportError:
    from agrippa import decode_runes, latin_to_rune
    from kasiski import (
        vigenere_decode, rune_vigenere_decode, rune_vigenere_encode,
        generate_primes
    )
    from al_kindi import is_plausible_english

CASES_PATH = os.path.join(os.path.dirname(__file__), "regression_cases.json")


def load_cases() -> list:
    if not os.path.exists(CASES_PATH):
        return []
    with open(CASES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def run_regression():
    cases = load_cases()
    if not cases:
        print(f"No regression cases found at {CASES_PATH}.")
        return

    passed, failed = 0, 0
    print("=== Running Trithemius Cryptographic Regression Suite ===\n")

    for case in cases:
        name = case.get("name", "unnamed case")
        ct = case["ciphertext"]
        expected = case["expected_plaintext"].strip().upper()
        method = case.get("method", "transliteration")
        key = case.get("key")

        actual = ""
        try:
            if method == "transliteration":
                actual = decode_runes(ct)
            elif method == "rune_vigenere":
                dec_runes = rune_vigenere_decode(ct, key)
                actual = decode_runes(dec_runes)
            elif method == "prime_stream":
                # Keystream of primes
                primes = generate_primes(50)
                dec_runes = rune_vigenere_decode(ct, primes)
                actual = decode_runes(dec_runes)
            elif method == "vigenere":
                actual = vigenere_decode(ct, key)
            else:
                actual = decode_runes(ct)
        except Exception as e:
            print(f"[FAIL] {name} — Exception during decryption: {e}")
            failed += 1
            continue

        # Normalization for comparison
        norm_actual = " ".join(actual.split()).upper()
        norm_expected = " ".join(expected.split()).upper()

        is_match = norm_actual == norm_expected
        _, stats = is_plausible_english(norm_actual)

        if is_match:
            print(f"[PASS] {name}")
            print(f"       Decrypted: '{norm_actual}'")
            print(f"       Statistical metric: {stats['verdict']} (Chi2: {stats['chi_squared']}, Ngram: {stats['ngram_score']})\n")
            passed += 1
        else:
            print(f"[FAIL] {name}")
            print(f"       Expected: '{norm_expected}'")
            print(f"       Got:      '{norm_actual}'\n")
            failed += 1

    print(f"Result: {passed} passed, {failed} failed out of {len(cases)} cases.")
    return failed == 0


if __name__ == "__main__":
    success = run_regression()
    sys.exit(0 if success else 1)
