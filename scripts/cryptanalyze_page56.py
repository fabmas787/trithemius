"""
Cryptanalyze Page 56 — Advanced cryptanalysis of authentic 273-rune transcript
against three prioritized non-redundant mathematical key hypotheses:

Hypothesis 1: Offset Euler Totient Keystream
    k_n = phi(p_{n + Delta}) mod 29 = (p_{n + Delta} - 1) mod 29
    - Subtraction (c - k) mod 29, Addition (c + k) mod 29, Beaufort (k - c) mod 29
    - With and without canonical cleartext F-skip rule (when decrypted rune is F / index 0,
      keystream pointer does not advance)
    - Offsets Delta in {0, 56, 57, 73, 273, 14142} and first 500 prime index offsets (0..499).

Hypothesis 2: Pisano Orbit Modular Recurrence in F_29
    S_{n+2} = (a * S_{n+1} + b * S_n) mod 29
    - Standard Fibonacci (0, 1), Lucas (2, 1) and all non-trivial generator pairs
      (S_0, S_1) in F_29^2 with Pisano period pi(29) = 14
    - Forward shift, reverse shift, and Beaufort
    - With and without cleartext F-skip rule.

Hypothesis 3: Syntactic Interrupter & Clause-Reset Polyalphabetic Vigenère
    - 4 clauses delimited by '᛬' (lengths: 13, 71, 114, 75 runes)
    - 68 words delimited by '᛫'
    - Canonical keywords: DIVINITY, FIRFUMFERENFE, SACRED, TOTIENT, CIRCUMFERENCE, PRIMES, TRUTH, PILGRIM
    - Clause-reset, word-reset, and continuous (no-reset)
    - Forward, addition, and Beaufort shifts, with and without F-skip.

Evaluates candidates using:
- Composite runic language model (score_composite_runes)
- Al-Kindi quadgram and n-gram log-likelihood (ngram_score)
- Chi-squared goodness of fit (chi_squared_score, chi2/N)
- English dictionary hit ratio (english_word_ratio)
- Monte Carlo surrogate shuffle test (Z-score, p-value, Sidak p_adj)
- Al-Kindi English and Runic Gatekeeper thresholds

Logs top attempts into vectordb/ledger.sqlite3 (canonical_attempts table).
"""

import argparse
import json
import math
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# Path setup
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(CURRENT_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from ciphers.agrippa import (
        INDEX_BY_RUNE,
        LATIN_BY_RUNE,
        PRIME_BY_RUNE,
        RUNE_BY_INDEX,
        decode_runes,
        generate_primes as _agrippa_generate_primes,
        index_to_rune,
        latin_to_rune,
    )
    from ciphers.al_kindi import (
        chi_squared_score,
        english_word_ratio,
        is_plausible_english,
        is_plausible_runic,
        ngram_score,
    )
    from ciphers.interrupter import canonical_key_shifts
    from ciphers.taxonomy import (
        score_composite_runes,
        surrogate_shuffle_test,
        compute_unigram_ic,
    )
except ImportError:
    from agrippa import (
        INDEX_BY_RUNE,
        LATIN_BY_RUNE,
        PRIME_BY_RUNE,
        RUNE_BY_INDEX,
        decode_runes,
        generate_primes as _agrippa_generate_primes,
        index_to_rune,
        latin_to_rune,
    )
    from al_kindi import (
        chi_squared_score,
        english_word_ratio,
        is_plausible_english,
        is_plausible_runic,
        ngram_score,
    )
    from interrupter import canonical_key_shifts
    from taxonomy import (
        score_composite_runes,
        surrogate_shuffle_test,
        compute_unigram_ic,
    )

try:
    from agents.ledger import log_canonical_attempt, count_attempts
except ImportError:
    log_canonical_attempt = None
    count_attempts = None

M = 29  # F_29


# =============================================================================
# Transcript Loader & Verification
# =============================================================================

def load_page_56_transcript(corpus_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load and validate the authentic 273-rune transcript of Page 56.
    Extracts rune index streams, clauses, and words.
    """
    if corpus_path is None:
        corpus_path = os.path.join(BASE_DIR, "corpus", "page_56_runes.md")

    if not os.path.exists(corpus_path):
        raise FileNotFoundError(f"Transcript file not found: {corpus_path}")

    with open(corpus_path, "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.split("\n")
    trans_lines = []
    in_trans = False
    for line in lines:
        if line.startswith("## Rune Transcription"):
            in_trans = True
            continue
        if in_trans and line.startswith("## "):
            break
        if in_trans:
            trans_lines.append(line)

    trans_text = "\n".join(trans_lines).strip()

    # Extract all runes
    runes_seq = [c for c in trans_text if c in INDEX_BY_RUNE]
    rune_indices = [INDEX_BY_RUNE[c] for c in runes_seq]
    rune_count = len(rune_indices)
    prime_sum = sum(PRIME_BY_RUNE[c] for c in runes_seq)

    # Extract clauses delimited by '᛬'
    raw_clauses = trans_text.split("᛬")
    clauses_indices: List[List[int]] = []
    for c in raw_clauses:
        c_runes = [ch for ch in c if ch in INDEX_BY_RUNE]
        if c_runes:
            clauses_indices.append([INDEX_BY_RUNE[ch] for ch in c_runes])

    # Extract words delimited by '᛫', '᛬', and whitespace
    raw_words = re.split(r"[᛫᛬\s\n]+", trans_text)
    words_indices: List[List[int]] = []
    words_runes: List[str] = []
    for w in raw_words:
        w_runes = [ch for ch in w if ch in INDEX_BY_RUNE]
        if w_runes:
            words_runes.append("".join(w_runes))
            words_indices.append([INDEX_BY_RUNE[ch] for ch in w_runes])

    # Validate against authentic metadata
    if rune_count != 273:
        raise ValueError(f"Expected 273 runes for Page 56, found {rune_count}")
    if prime_sum != 14142:
        raise ValueError(f"Expected prime sum 14142 for Page 56, found {prime_sum}")
    if len(clauses_indices) != 4:
        raise ValueError(f"Expected 4 clauses for Page 56, found {len(clauses_indices)}")

    clause_lengths = [len(c) for c in clauses_indices]
    expected_clause_lengths = [13, 71, 114, 75]
    if clause_lengths != expected_clause_lengths:
        raise ValueError(
            f"Clause lengths {clause_lengths} mismatch expected {expected_clause_lengths}"
        )

    return {
        "trans_text": trans_text,
        "rune_count": rune_count,
        "prime_sum": prime_sum,
        "rune_indices": rune_indices,
        "clauses_indices": clauses_indices,
        "words_indices": words_indices,
        "words_runes": words_runes,
        "clause_lengths": clause_lengths,
        "word_count": len(words_indices),
    }


# =============================================================================
# Prime Sieve & Math Utilities
# =============================================================================

def sieve_primes(n_primes: int) -> List[int]:
    """Generate the first n_primes primes via agrippa.generate_primes."""
    return _agrippa_generate_primes(n_primes)


def reconstruct_formatted_latin(
    dec_indices: List[int],
    trans_text: str,
) -> str:
    """
    Format decrypted indices into Latin text preserving original punctuation
    ('᛫' -> space, '᛬' -> newline).
    """
    out_runes = []
    ptr = 0
    for ch in trans_text:
        if ch in INDEX_BY_RUNE:
            if ptr < len(dec_indices):
                out_runes.append(index_to_rune(dec_indices[ptr]))
                ptr += 1
        elif ch in ("᛫", "᛬", "\n", " "):
            out_runes.append(ch)
    return decode_runes("".join(out_runes))


# =============================================================================
# Candidate Evaluator
# =============================================================================

def evaluate_candidate(
    dec_indices: List[int],
    trans_text: str,
    method: str,
    parameters: dict,
) -> dict:
    """Compute all cryptographic and linguistic metrics for a decryption candidate."""
    comp_score = score_composite_runes(dec_indices)
    dec_runes = "".join(index_to_rune(i) for i in dec_indices)
    latin_formatted = reconstruct_formatted_latin(dec_indices, trans_text)
    latin_clean = "".join(c for c in latin_formatted.upper() if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    chi2 = chi_squared_score(latin_clean)
    n_clean = len(latin_clean)
    chi2_per_sym = round(chi2 / max(1, n_clean), 4)
    ng_score = ngram_score(latin_clean)
    w_ratio = english_word_ratio(latin_formatted)
    plaus_eng, eng_metrics = is_plausible_english(latin_formatted)

    # Fast runic plausibility check:
    # A candidate cannot pass runic model if score < -3.38 (calibrated baseline)
    if comp_score < -3.38:
        plaus_runic = False
    else:
        plaus_runic, _ = is_plausible_runic(dec_runes)

    # Sound Gatekeeper check:
    # In runic cipher cryptanalysis, a candidate passes the gatekeeper if and only if:
    # 1. Its composite runic score meets or exceeds the calibrated bar (comp_score >= -3.38).
    #    Real Liber Primus text scores -1.30 to -3.00; noise scores below -3.70.
    # 2. It either clears the calibrated GF(29) runic model (score >= -3.38, z >= 3.0) or
    #    exhibits authentic English plaintext (word_ratio >= 0.25 and ngram >= 0.15 and chi2/N < 0.75).
    # Any candidate with comp_score < -3.38 is rejected as non-viable noise.
    if comp_score < -3.38:
        passed_gatekeeper = False
    else:
        passed_gatekeeper = bool(
            plaus_runic or (plaus_eng and w_ratio >= 0.25 and ng_score >= 0.15 and chi2_per_sym < 0.75)
        )

    return {
        "method": method,
        "parameters": parameters,
        "score": comp_score,
        "ngram_score": ng_score,
        "chi_squared": chi2,
        "chi_squared_per_symbol": chi2_per_sym,
        "word_ratio": w_ratio,
        "is_plausible_english": plaus_eng,
        "is_plausible_runic": plaus_runic,
        "passed_gatekeeper": passed_gatekeeper,
        "dec_indices": dec_indices,
        "dec_runes": dec_runes,
        "plaintext_latin": latin_formatted,
        "preview": latin_clean[:80],
    }


# =============================================================================
# 1. Offset Euler Totient Keystream
# =============================================================================

def execute_hypothesis_1_euler_totient(
    rune_indices: List[int],
    trans_text: str,
    scan_limit: int = 500,
    specific_offsets: Optional[List[int]] = None,
) -> List[dict]:
    """
    Hypothesis 1:
    k_n = phi(p_{n + Delta}) mod 29 = (p_{n + Delta} - 1) mod 29
    - Operations: subtraction (c - k) mod 29, addition (c + k) mod 29, beaufort (k - c) mod 29
    - F-skip modes:
      * 'none': standard advance
      * 'cleartext_f_skip': when decrypted rune is F (0), key pointer does not advance
      * 'ciphertext_f_skip': when ciphertext rune is F (0), key pointer does not advance
    - Offsets: Delta in {0, 56, 57, 73, 273, 14142} and all 0..scan_limit-1.
    """
    n = len(rune_indices)
    if specific_offsets is None:
        specific_offsets = [0, 56, 57, 73, 273, 14142]

    # Include offsets +/- 1 around specific targets to account for 0 vs 1 indexing
    offsets_set: Set[int] = set()
    for off in specific_offsets:
        for delta in (-1, 0, 1):
            val = off + delta
            if val >= 0:
                offsets_set.add(val)
    for off in range(scan_limit):
        offsets_set.add(off)

    sorted_offsets = sorted(offsets_set)
    max_offset = max(sorted_offsets)

    # Sieve enough primes: max_offset + n + 100
    needed_primes = max_offset + n + 100
    primes = sieve_primes(needed_primes)
    totients_mod29 = [(p - 1) % M for p in primes]

    results: List[dict] = []

    for delta in sorted_offsets:
        if delta + n > len(totients_mod29):
            continue

        # 1. Mode: 'none' (standard unconditional advance)
        for op in ("sub", "add", "beaufort"):
            dec = []
            for i in range(n):
                c = rune_indices[i]
                k = totients_mod29[delta + i]
                if op == "sub":
                    p = (c - k) % M
                elif op == "add":
                    p = (c + k) % M
                else:  # beaufort
                    p = (k - c) % M
                dec.append(p)

            cand = evaluate_candidate(
                dec,
                trans_text,
                method=f"TOTIENT_{op.upper()}_DELTA_{delta}",
                parameters={
                    "hypothesis": 1,
                    "family": "euler_totient",
                    "delta": delta,
                    "operation": op,
                    "f_skip_mode": "none",
                },
            )
            results.append(cand)

        # 2. Mode: 'cleartext_f_skip' (canonical rule: if decrypted rune == 0, key ptr does not advance)
        for op in ("sub", "add", "beaufort"):
            dec = []
            k_ptr = delta
            for i in range(n):
                c = rune_indices[i]
                k = totients_mod29[k_ptr]
                if op == "sub":
                    p = (c - k) % M
                elif op == "add":
                    p = (c + k) % M
                else:
                    p = (k - c) % M
                dec.append(p)
                if p != 0:
                    k_ptr += 1

            cand = evaluate_candidate(
                dec,
                trans_text,
                method=f"TOTIENT_{op.upper()}_DELTA_{delta}_CLEARTEXT_FSKIP",
                parameters={
                    "hypothesis": 1,
                    "family": "euler_totient",
                    "delta": delta,
                    "operation": op,
                    "f_skip_mode": "cleartext_f_skip",
                },
            )
            results.append(cand)

        # 3. Mode: 'ciphertext_f_skip' (fehu pass-through)
        for op in ("sub", "add", "beaufort"):
            dec = []
            k_ptr = delta
            for i in range(n):
                c = rune_indices[i]
                if c == 0:
                    dec.append(0)
                else:
                    k = totients_mod29[k_ptr]
                    if op == "sub":
                        p = (c - k) % M
                    elif op == "add":
                        p = (c + k) % M
                    else:
                        p = (k - c) % M
                    dec.append(p)
                    k_ptr += 1

            cand = evaluate_candidate(
                dec,
                trans_text,
                method=f"TOTIENT_{op.upper()}_DELTA_{delta}_CIPHERTEXT_FSKIP",
                parameters={
                    "hypothesis": 1,
                    "family": "euler_totient",
                    "delta": delta,
                    "operation": op,
                    "f_skip_mode": "ciphertext_f_skip",
                },
            )
            results.append(cand)

    return sorted(results, key=lambda x: -x["score"])


# =============================================================================
# 2. Pisano Orbit Modular Recurrence in F_29
# =============================================================================

def generate_pisano_stream(
    a: int,
    b: int,
    s0: int,
    s1: int,
    length: int,
) -> List[int]:
    """Generate a sequence of specified length under S_{n+2} = (a*S_{n+1} + b*S_n) mod 29."""
    stream = [s0 % M, s1 % M]
    while len(stream) < length:
        nxt = (a * stream[-1] + b * stream[-2]) % M
        stream.append(nxt)
    return stream


def execute_hypothesis_2_pisano_recurrence(
    rune_indices: List[int],
    trans_text: str,
) -> List[dict]:
    """
    Hypothesis 2:
    Keystream: S_{n+2} = (a * S_{n+1} + b * S_n) mod 29
    - Standard Fibonacci (0, 1), Lucas (2, 1) and all non-trivial generator pairs
      (S_0, S_1) in F_29^2 with Pisano period pi(29) = 14
    - Forward shift, reverse shift, and Beaufort
    - With and without cleartext F-skip.
    """
    n = len(rune_indices)
    max_stream_len = n + 100
    results: List[dict] = []

    # Recurrence generators with period 14:
    # 1. Standard (a=1, b=1): All 840 non-trivial pairs (S_0, S_1) in F_29^2 \ {(0,0)}
    # 812 have period 14, 28 have period 7. Testing all 840 covers every possible orbit & phase!
    pairs_to_test: List[Tuple[int, int, str]] = [
        (0, 1, "FIBONACCI_STANDARD"),
        (2, 1, "LUCAS_STANDARD"),
        (1, 1, "FIBONACCI_1_1"),
    ]

    all_non_trivial = []
    for s0 in range(M):
        for s1 in range(M):
            if s0 == 0 and s1 == 0:
                continue
            all_non_trivial.append((s0, s1))

    # Also test all other (a, b) mod 29 where (0, 1) has period 14
    ab_period_14: List[Tuple[int, int]] = []
    for a_cand in range(M):
        for b_cand in range(1, M):
            # check period of (0, 1)
            seq = [0, 1]
            seen = {(0, 1): 0}
            p_len = None
            for step in range(2, 50):
                nxt = (a_cand * seq[-1] + b_cand * seq[-2]) % M
                seq.append(nxt)
                state = (seq[-2], seq[-1])
                if state in seen:
                    p_len = step - 1 - seen[state]
                    break
                seen[state] = step - 1
            if p_len == 14:
                ab_period_14.append((a_cand, b_cand))

    # Test all 840 pairs under a=1, b=1
    for s0, s1 in all_non_trivial:
        stream = generate_pisano_stream(1, 1, s0, s1, max_stream_len)
        label = "PAIR"
        if (s0, s1) == (0, 1):
            label = "FIBONACCI"
        elif (s0, s1) == (2, 1):
            label = "LUCAS"

        # Operations: sub, add, beaufort
        for op in ("sub", "add", "beaufort"):
            # 1. Without F-skip
            dec = []
            for i in range(n):
                c = rune_indices[i]
                k = stream[i]
                if op == "sub":
                    p = (c - k) % M
                elif op == "add":
                    p = (c + k) % M
                else:
                    p = (k - c) % M
                dec.append(p)

            cand = evaluate_candidate(
                dec,
                trans_text,
                method=f"PISANO_{label}_{s0}_{s1}_{op.upper()}",
                parameters={
                    "hypothesis": 2,
                    "family": "pisano_recurrence",
                    "a": 1,
                    "b": 1,
                    "s0": s0,
                    "s1": s1,
                    "operation": op,
                    "f_skip_mode": "none",
                },
            )
            results.append(cand)

            # 2. Cleartext F-skip
            dec = []
            k_ptr = 0
            for i in range(n):
                c = rune_indices[i]
                k = stream[k_ptr]
                if op == "sub":
                    p = (c - k) % M
                elif op == "add":
                    p = (c + k) % M
                else:
                    p = (k - c) % M
                dec.append(p)
                if p != 0:
                    k_ptr += 1

            cand = evaluate_candidate(
                dec,
                trans_text,
                method=f"PISANO_{label}_{s0}_{s1}_{op.upper()}_CLEARTEXT_FSKIP",
                parameters={
                    "hypothesis": 2,
                    "family": "pisano_recurrence",
                    "a": 1,
                    "b": 1,
                    "s0": s0,
                    "s1": s1,
                    "operation": op,
                    "f_skip_mode": "cleartext_f_skip",
                },
            )
            results.append(cand)

    # Test the additional (a, b) recurrences with period 14 for (0, 1) and (2, 1)
    for a_val, b_val in ab_period_14:
        if (a_val, b_val) == (1, 1):
            continue  # already thoroughly swept above
        for s0, s1 in ((0, 1), (2, 1)):
            stream = generate_pisano_stream(a_val, b_val, s0, s1, max_stream_len)
            for op in ("sub", "add"):
                for f_mode in ("none", "cleartext_f_skip"):
                    dec = []
                    k_ptr = 0
                    for i in range(n):
                        c = rune_indices[i]
                        k = stream[k_ptr]
                        if op == "sub":
                            p = (c - k) % M
                        else:
                            p = (c + k) % M
                        dec.append(p)
                        if f_mode == "none" or p != 0:
                            k_ptr += 1
                    cand = evaluate_candidate(
                        dec,
                        trans_text,
                        method=f"PISANO_A{a_val}_B{b_val}_S{s0}_{s1}_{op.upper()}_{f_mode.upper()}",
                        parameters={
                            "hypothesis": 2,
                            "family": "pisano_recurrence",
                            "a": a_val,
                            "b": b_val,
                            "s0": s0,
                            "s1": s1,
                            "operation": op,
                            "f_skip_mode": f_mode,
                        },
                    )
                    results.append(cand)

    return sorted(results, key=lambda x: -x["score"])


# =============================================================================
# 3. Syntactic Interrupter & Clause-Reset Polyalphabetic Vigenère
# =============================================================================

def execute_hypothesis_3_clause_word_vigenere(
    rune_indices: List[int],
    clauses_indices: List[List[int]],
    words_indices: List[List[int]],
    trans_text: str,
    keywords: Optional[List[str]] = None,
) -> List[dict]:
    """
    Hypothesis 3:
    Syntactic Interrupter & Clause-Reset / Word-Reset Vigenère:
    - 4 clauses delimited by '᛬' (13, 71, 114, 75 runes)
    - 68 words delimited by '᛫'
    - Canonical keywords: DIVINITY, FIRFUMFERENFE, SACRED, TOTIENT, CIRCUMFERENCE, PRIMES, TRUTH, PILGRIM
    - Modes: clause-reset, word-reset, continuous (no-reset)
    - Operations: sub (c - k) mod 29, add (c + k) mod 29, beaufort (k - c) mod 29
    - F-skip: none, cleartext F-skip.
    """
    if keywords is None:
        keywords = [
            "DIVINITY",
            "FIRFUMFERENFE",
            "SACRED",
            "TOTIENT",
            "CIRCUMFERENCE",
            "PRIMES",
            "TRUTH",
            "PILGRIM",
        ]

    results: List[dict] = []

    for kw in keywords:
        shifts = canonical_key_shifts(kw)
        L = len(shifts)

        for reset_mode in ("clause_reset", "word_reset", "no_reset"):
            for op in ("sub", "add", "beaufort"):
                for f_mode in ("none", "cleartext_f_skip", "ciphertext_f_skip"):
                    dec_all: List[int] = []

                    if reset_mode == "clause_reset":
                        for clause in clauses_indices:
                            k_ptr = 0
                            for c in clause:
                                if f_mode == "ciphertext_f_skip" and c == 0:
                                    p = 0
                                else:
                                    k = shifts[k_ptr % L]
                                    if op == "sub":
                                        p = (c - k) % M
                                    elif op == "add":
                                        p = (c + k) % M
                                    else:
                                        p = (k - c) % M
                                    if f_mode == "none" or (f_mode == "cleartext_f_skip" and p != 0) or f_mode == "ciphertext_f_skip":
                                        k_ptr += 1
                                dec_all.append(p)

                    elif reset_mode == "word_reset":
                        for word in words_indices:
                            k_ptr = 0
                            for c in word:
                                if f_mode == "ciphertext_f_skip" and c == 0:
                                    p = 0
                                else:
                                    k = shifts[k_ptr % L]
                                    if op == "sub":
                                        p = (c - k) % M
                                    elif op == "add":
                                        p = (c + k) % M
                                    else:
                                        p = (k - c) % M
                                    if f_mode == "none" or (f_mode == "cleartext_f_skip" and p != 0) or f_mode == "ciphertext_f_skip":
                                        k_ptr += 1
                                dec_all.append(p)

                    else:  # no_reset
                        k_ptr = 0
                        for c in rune_indices:
                            if f_mode == "ciphertext_f_skip" and c == 0:
                                p = 0
                            else:
                                k = shifts[k_ptr % L]
                                if op == "sub":
                                    p = (c - k) % M
                                elif op == "add":
                                    p = (c + k) % M
                                else:
                                    p = (k - c) % M
                                if f_mode == "none" or (f_mode == "cleartext_f_skip" and p != 0) or f_mode == "ciphertext_f_skip":
                                    k_ptr += 1
                            dec_all.append(p)

                    f_label = f_mode.upper()
                    method_name = f"VIGENERE_{kw}_{reset_mode.upper()}_{op.upper()}_{f_label}"
                    cand = evaluate_candidate(
                        dec_all,
                        trans_text,
                        method=method_name,
                        parameters={
                            "hypothesis": 3,
                            "family": "syntactic_interrupter",
                            "keyword": kw,
                            "key_shifts": shifts,
                            "period": L,
                            "reset_mode": reset_mode,
                            "operation": op,
                            "f_skip_mode": f_mode,
                            "f_skip": f_mode == "cleartext_f_skip",
                        },
                    )
                    results.append(cand)

    return sorted(results, key=lambda x: -x["score"])


# =============================================================================
# Significance & Surrogate Testing
# =============================================================================

def enrich_with_surrogate_tests(
    candidates: List[dict],
    n_shuffles: int = 50,
) -> None:
    """Run Monte Carlo surrogate shuffle tests for candidates in-place."""
    for cand in candidates:
        indices = cand["dec_indices"]
        score = cand["score"]
        method = cand["method"]
        sig = surrogate_shuffle_test(
            indices,
            score,
            n_shuffles=n_shuffles,
            sequential=False,
            family=cand["parameters"].get("family", method),
        )
        cand["significance"] = {
            "null_mean": sig.mean_null,
            "null_std": sig.std_null,
            "z_score": sig.z_score,
            "p_value": sig.p_value,
            "p_adj": sig.p_adj,
            "is_statistically_significant": sig.is_significant,
        }


# =============================================================================
# Ledger Persistence
# =============================================================================

def log_top_candidates_to_ledger(
    candidates: List[dict],
    page: str = "56",
    top_n: int = 20,
) -> int:
    """Log top candidates to SQLite ledger canonical_attempts table."""
    if log_canonical_attempt is None:
        return 0

    logged_count = 0
    input_digest = f"page56_runes_{len(candidates[0]['dec_indices']) if candidates else 273}"

    for cand in candidates[:top_n]:
        params = cand["parameters"].copy()
        sig = cand.get("significance", {})
        params["z_score"] = sig.get("z_score", 0.0)
        params["p_adj"] = sig.get("p_adj", 1.0)
        params["ngram_score"] = cand.get("ngram_score", 0.0)
        params["chi2_per_symbol"] = cand.get("chi_squared_per_symbol", 0.0)

        passed_flag = bool(cand.get("passed_gatekeeper", False))
        preview = cand.get("preview", "")

        inserted = log_canonical_attempt(
            page=page,
            method=cand["method"],
            parameters=params,
            input_digest=input_digest,
            score=cand["score"],
            passed=passed_flag,
            result_preview=preview,
            method_version=1,
            scorer_version=1,
        )
        if inserted:
            logged_count += 1
        else:
            # Synchronize existing record to ensure passed_gatekeeper reflects true gatekeeper status
            try:
                from agents.ledger import canonical_key as get_ckey, _connect, DB_PATH
                ckey = get_ckey(page, cand["method"], params, input_digest, method_version=1)
                conn = _connect(DB_PATH)
                conn.execute(
                    "UPDATE canonical_attempts SET passed_gatekeeper = ?, score = ? WHERE canonical_key = ?",
                    (1 if passed_flag else 0, float(cand["score"]), ckey)
                )
                conn.commit()
                conn.close()
                logged_count += 1
            except Exception:
                pass

    return logged_count


# =============================================================================
# Main Orchestrator
# =============================================================================

def run_cryptanalysis(
    corpus_path: Optional[str] = None,
    log_db: bool = True,
    top_k: int = 5,
) -> Dict[str, Any]:
    """Execute all three prioritized hypotheses and return comprehensive results."""
    t0 = time.time()
    data = load_page_56_transcript(corpus_path)
    rune_indices = data["rune_indices"]
    clauses_indices = data["clauses_indices"]
    words_indices = data["words_indices"]
    trans_text = data["trans_text"]

    print("Loaded Page 56 transcript:")
    print(f"  Rune count: {data['rune_count']}")
    print(f"  Gematria Prime Sum: {data['prime_sum']}")
    print(f"  Clauses: {len(clauses_indices)} (lengths: {data['clause_lengths']})")
    print(f"  Words: {data['word_count']}")

    # Baseline ciphertext statistics
    raw_score = score_composite_runes(rune_indices)
    raw_latin = reconstruct_formatted_latin(rune_indices, trans_text)
    raw_clean = "".join(c for c in raw_latin.upper() if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    raw_chi2 = chi_squared_score(raw_clean)
    raw_ngram = ngram_score(raw_clean)
    print(f"\nRaw Ciphertext Baseline:")
    print(f"  Composite Runic Score: {raw_score}")
    print(f"  Chi-Squared: {raw_chi2} (per symbol: {raw_chi2/len(raw_clean):.4f})")
    print(f"  N-Gram Score: {raw_ngram}")

    # Hypothesis 1: Offset Euler Totient Keystream
    print("\nExecuting Hypothesis 1: Offset Euler Totient Keystream...")
    t_h1 = time.time()
    h1_results = execute_hypothesis_1_euler_totient(rune_indices, trans_text, scan_limit=500)
    print(f"  Completed H1: {len(h1_results)} candidates in {time.time()-t_h1:.2f}s")
    print(f"  Best H1 score: {h1_results[0]['score']} ({h1_results[0]['method']})")

    # Hypothesis 2: Pisano Orbit Modular Recurrence
    print("\nExecuting Hypothesis 2: Pisano Orbit Modular Recurrence in F_29...")
    t_h2 = time.time()
    h2_results = execute_hypothesis_2_pisano_recurrence(rune_indices, trans_text)
    print(f"  Completed H2: {len(h2_results)} candidates in {time.time()-t_h2:.2f}s")
    print(f"  Best H2 score: {h2_results[0]['score']} ({h2_results[0]['method']})")

    # Hypothesis 3: Syntactic Interrupter & Clause/Word Reset Vigenère
    print("\nExecuting Hypothesis 3: Syntactic Interrupter & Clause/Word Reset Vigenère...")
    t_h3 = time.time()
    h3_results = execute_hypothesis_3_clause_word_vigenere(
        rune_indices, clauses_indices, words_indices, trans_text
    )
    print(f"  Completed H3: {len(h3_results)} candidates in {time.time()-t_h3:.2f}s")
    print(f"  Best H3 score: {h3_results[0]['score']} ({h3_results[0]['method']})")

    # Combine and rank top candidates
    all_candidates = h1_results + h2_results + h3_results
    all_candidates.sort(key=lambda x: -x["score"])
    print(f"\nTotal evaluated candidates across 3 hypotheses: {len(all_candidates)}")

    # Run surrogate shuffle tests on top candidates from each hypothesis + global top
    top_h1 = h1_results[:top_k]
    top_h2 = h2_results[:top_k]
    top_h3 = h3_results[:top_k]
    global_top = all_candidates[: top_k * 3]

    to_enrich = []
    seen_methods = set()
    for c in global_top + top_h1 + top_h2 + top_h3:
        if c["method"] not in seen_methods:
            seen_methods.add(c["method"])
            to_enrich.append(c)

    print(f"\nComputing Monte Carlo surrogate shuffle tests for top {len(to_enrich)} candidates...")
    enrich_with_surrogate_tests(to_enrich, n_shuffles=50)

    # Database logging
    logged_count = 0
    if log_db:
        logged_count = log_top_candidates_to_ledger(to_enrich, page="56", top_n=30)
        print(f"Logged {logged_count} top attempts to SQLite ledger canonical_attempts table.")

    total_time = time.time() - t0
    print(f"\nCompleted Page 56 cryptanalysis in {total_time:.2f}s.")

    return {
        "metadata": data,
        "baseline": {
            "score": raw_score,
            "chi2": raw_chi2,
            "chi2_per_symbol": round(raw_chi2 / len(raw_clean), 4),
            "ngram_score": raw_ngram,
            "clean_latin_length": len(raw_clean),
        },
        "total_evaluated": len(all_candidates),
        "hypothesis_1_count": len(h1_results),
        "hypothesis_2_count": len(h2_results),
        "hypothesis_3_count": len(h3_results),
        "top_h1": top_h1,
        "top_h2": top_h2,
        "top_h3": top_h3,
        "global_top": global_top[:10],
        "logged_to_db": logged_count,
        "elapsed_seconds": round(total_time, 2),
    }


def main():
    parser = argparse.ArgumentParser(description="Cryptanalyze Page 56 authentic transcript.")
    parser.add_argument("--corpus", default=None, help="Path to page_56_runes.md")
    parser.add_argument("--top-k", type=int, default=5, help="Number of top candidates per category")
    parser.add_argument("--no-log", action="store_true", help="Disable SQLite ledger logging")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    results = run_cryptanalysis(
        corpus_path=args.corpus,
        log_db=not args.no_log,
        top_k=args.top_k,
    )

    if args.json:
        # Serializer helper for JSON output
        def _strip_large(obj):
            if isinstance(obj, dict):
                return {k: _strip_large(v) for k, v in obj.items() if k not in ("dec_indices", "dec_runes")}
            if isinstance(obj, list):
                return [_strip_large(x) for x in obj]
            return obj
        print(json.dumps(_strip_large(results), indent=2))


if __name__ == "__main__":
    main()
