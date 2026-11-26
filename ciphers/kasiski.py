"""
Kasiski — Vigenere cipher solver & keystream generator.
Named for Friedrich Kasiski, who first published a general method for
breaking the Vigenere cipher via key-length analysis.

Supports both:
1. Classical English A-Z (mod 26) Vigenere cracking, IoC, Friedman test, chi-squared.
2. Official Liber Primus 29-rune (mod 29) Vigenere encoding, decoding, and keystreams
   (primes, Fibonacci numbers, totients, running keys).

Usage:
    from kasiski import (
        vigenere_decode, vigenere_encode, estimate_key_length, crack_vigenere,
        rune_vigenere_decode, rune_vigenere_encode, rune_index_of_coincidence,
        estimate_rune_key_length, generate_primes, generate_fibonacci, generate_totients
    )
"""

from collections import Counter
import string
import os
import sys
import functools
from typing import List, Union, Tuple, Dict, Optional, Set

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from ciphers.agrippa import (
        INDEX_BY_RUNE, RUNE_BY_INDEX, index_to_rune, rune_to_index,
        latin_to_rune, decode_runes, euler_totient, is_prime,
        generate_primes as _agrippa_generate_primes,
    )
    from ciphers.interrupter import (
        InterrupterConfig, InterruptMode,
        rune_vigenere_decode_dynamic, rune_vigenere_encode_dynamic,
        rune_vigenere_decode_f_skip, rune_vigenere_encode_f_skip,
        verify_f_skip_alignment,
        WELCOME_F_SKIP_POSITIONS, KOAN2_F_SKIP_POSITIONS,
        canonical_key_shifts, divinity_shifts, firfumferenfe_shifts,
        validate_canonical_alphabet
    )
except ImportError:
    from agrippa import (
        INDEX_BY_RUNE, RUNE_BY_INDEX, index_to_rune, rune_to_index,
        latin_to_rune, decode_runes, euler_totient, is_prime,
        generate_primes as _agrippa_generate_primes,
    )
    from interrupter import (
        InterrupterConfig, InterruptMode,
        rune_vigenere_decode_dynamic, rune_vigenere_encode_dynamic,
        rune_vigenere_decode_f_skip, rune_vigenere_encode_f_skip,
        verify_f_skip_alignment,
        WELCOME_F_SKIP_POSITIONS, KOAN2_F_SKIP_POSITIONS,
        canonical_key_shifts, divinity_shifts, firfumferenfe_shifts,
        validate_canonical_alphabet
    )

ALPHABET = string.ascii_uppercase
ALPHABET_SET = set(ALPHABET)
_ORD_A = ord('A')


# --- Classical A-Z (Modulo 26) ---

def clean(text: str) -> str:
    """Keep only uppercase A-Z characters."""
    return "".join(c for c in text.upper() if c in ALPHABET_SET)


def vigenere_decode(ciphertext: str, key: str) -> str:
    """Decode English A-Z Vigenere ciphertext using O(1) integer arithmetic."""
    ciphertext_clean = clean(ciphertext)
    key_clean = clean(key)
    if not key_clean:
        return ciphertext_clean
    k_len = len(key_clean)
    k_shifts = [ord(k) - _ORD_A for k in key_clean]
    out = [chr((ord(c) - _ORD_A - k_shifts[i % k_len]) % 26 + _ORD_A) for i, c in enumerate(ciphertext_clean)]
    return "".join(out)


def vigenere_encode(plaintext: str, key: str) -> str:
    """Encode English A-Z plaintext using O(1) integer arithmetic."""
    plaintext_clean = clean(plaintext)
    key_clean = clean(key)
    if not key_clean:
        return plaintext_clean
    k_len = len(key_clean)
    k_shifts = [ord(k) - _ORD_A for k in key_clean]
    out = [chr((ord(c) - _ORD_A + k_shifts[i % k_len]) % 26 + _ORD_A) for i, c in enumerate(plaintext_clean)]
    return "".join(out)


def index_of_coincidence(text: str) -> float:
    """Compute Index of Coincidence for English A-Z text."""
    text_clean = clean(text)
    n = len(text_clean)
    if n < 2:
        return 0.0
    counts = Counter(text_clean)
    total = sum(c * (c - 1) for c in counts.values())
    return total / (n * (n - 1))


def estimate_key_length(ciphertext: str, max_len: int = 20) -> List[Tuple[int, float]]:
    """Return candidate key lengths ranked by average IoC of columns."""
    ciphertext_clean = clean(ciphertext)
    scores = []
    for key_len in range(1, max_len + 1):
        columns = ["".join(ciphertext_clean[i::key_len]) for i in range(key_len)]
        avg_ioc = sum(index_of_coincidence(col) for col in columns) / key_len
        scores.append((key_len, avg_ioc))
    return sorted(scores, key=lambda x: -x[1])


def crack_caesar_shift(text: str) -> int:
    """Recover Caesar shift for a column using English letter frequency (chi-squared)."""
    english_freq = {
        'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7, 'S': 6.3,
        'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4,
        'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5, 'V': 1.0,
        'K': 0.8, 'J': 0.15, 'X': 0.15, 'Q': 0.1, 'Z': 0.07,
    }
    text_clean = clean(text)
    n = len(text_clean)
    if not n:
        return 0
    counts = Counter(text_clean)
    best_shift, best_score = 0, float("inf")
    for shift in range(26):
        score = sum(
            ((counts.get(ALPHABET[(ALPHABET.index(letter) + shift) % 26], 0) / n * 100 - freq) ** 2) / freq
            for letter, freq in english_freq.items()
        )
        if score < best_score:
            best_score, best_shift = score, shift
    return best_shift


def crack_vigenere(ciphertext: str, key_length: int) -> str:
    """Recover a likely English A-Z key of given length via per-column Caesar analysis."""
    ciphertext_clean = clean(ciphertext)
    key_chars = []
    for i in range(key_length):
        column = ciphertext_clean[i::key_length]
        shift = crack_caesar_shift(column)
        key_chars.append(ALPHABET[shift])
    return "".join(key_chars)


def friedman_test(ciphertext: str) -> float:
    """Friedman's test: estimate key length from observed IoC for English."""
    ic = index_of_coincidence(ciphertext)
    if ic <= 0.0385:
        return float("inf")
    n = len(clean(ciphertext))
    numerator = 0.0267 * n
    denominator = ((0.065 - 0.0385) * ic + 0.0385 * n - 0.0267)
    if denominator <= 0:
        return float("inf")
    return numerator / denominator


def consensus_key_length(ciphertext: str, max_len: int = 20, tolerance: int = 1) -> dict:
    """Cross-check per-column IoC against Friedman's test."""
    ioc_candidates = estimate_key_length(ciphertext, max_len=max_len)
    top_ioc_guess = ioc_candidates[0][0] if ioc_candidates else 1
    friedman_estimate = friedman_test(ciphertext)
    agrees = (
        friedman_estimate != float("inf")
        and abs(friedman_estimate - top_ioc_guess) <= tolerance
    )
    return {
        "ioc_top_guess": top_ioc_guess,
        "ioc_top_3": ioc_candidates[:3],
        "friedman_estimate": round(friedman_estimate, 2) if friedman_estimate != float("inf") else None,
        "methods_agree": agrees,
        "recommended_key_length": top_ioc_guess if agrees else None,
    }


# --- Liber Primus 29-Rune Vigenere (Modulo 29) ---

@functools.lru_cache(maxsize=2048)
def _cached_string_key_to_shifts(key: str) -> Tuple[int, ...]:
    has_runes = any(c in INDEX_BY_RUNE for c in key)
    rune_key = key if has_runes else latin_to_rune(key)
    shifts = [INDEX_BY_RUNE[c] for c in rune_key if c in INDEX_BY_RUNE]
    return tuple(shifts) if shifts else (0,)


def _key_to_shifts(key: Union[str, List[int]]) -> List[int]:
    """
    Convert a key into a list of shift integers (mod 29).
    The key can be:
    - a list/stream of integers (e.g. [2, 3, 5, 7, ...])
    - a string of runes
    - a Latin string (will be mapped to runes first)
    """
    if isinstance(key, (list, tuple)):
        shifts = [int(k) % 29 for k in key]
        return shifts if shifts else [0]
    if isinstance(key, str):
        return list(_cached_string_key_to_shifts(key))
    return [0]


def rune_vigenere_decode(
    ciphertext: str,
    key: Union[str, List[int]],
    preserve_separators: bool = True,
    interrupter_config: Optional[InterrupterConfig] = None,
    f_skip: bool = False,
    skip_indices: Optional[Set[int]] = None,
    **interrupter_kwargs
) -> str:
    r"""
    Decodes runes with a Vigenere key modulo 29.
    $P_i = (C_i - K_i) \pmod{29}$
    Preserves word dividers ('᛫', '᛬', whitespace) if preserve_separators is True.
    Supports dynamic key interrupters via interrupter_config, f_skip, or keyword arguments.
    """
    if f_skip or skip_indices is not None:
        return rune_vigenere_decode_f_skip(
            ciphertext=ciphertext,
            key=key,
            skip_indices=skip_indices,
            preserve_separators=preserve_separators,
        )

    if interrupter_config is not None or interrupter_kwargs:
        cfg = interrupter_config or InterrupterConfig(**interrupter_kwargs)
        return rune_vigenere_decode_dynamic(
            ciphertext=ciphertext,
            key=key,
            config=cfg,
            preserve_separators=preserve_separators
        )

    shifts = _key_to_shifts(key)
    result = []
    shift_idx = 0

    for c in ciphertext:
        if c in INDEX_BY_RUNE:
            c_val = INDEX_BY_RUNE[c]
            k_val = shifts[shift_idx % len(shifts)]
            p_val = (c_val - k_val) % 29
            result.append(index_to_rune(p_val))
            shift_idx += 1
        else:
            if preserve_separators:
                result.append(c)
    return "".join(result)


def rune_vigenere_encode(
    plaintext: str,
    key: Union[str, List[int]],
    preserve_separators: bool = True,
    interrupter_config: Optional[InterrupterConfig] = None,
    f_skip: bool = False,
    **interrupter_kwargs
) -> str:
    r"""
    Encodes runes with a Vigenere key modulo 29.
    $C_i = (P_i + K_i) \pmod{29}$
    Supports dynamic key interrupters via interrupter_config, f_skip, or keyword arguments.
    """
    if f_skip:
        ct, _ = rune_vigenere_encode_f_skip(
            plaintext=plaintext,
            key=key,
            preserve_separators=preserve_separators,
        )
        return ct

    if interrupter_config is not None or interrupter_kwargs:
        cfg = interrupter_config or InterrupterConfig(**interrupter_kwargs)
        return rune_vigenere_encode_dynamic(
            plaintext=plaintext,
            key=key,
            config=cfg,
            preserve_separators=preserve_separators
        )

    shifts = _key_to_shifts(key)
    result = []
    shift_idx = 0

    # Ensure plaintext is runic
    has_runes = any(c in INDEX_BY_RUNE for c in plaintext)
    runes = plaintext if has_runes else latin_to_rune(plaintext)

    for c in runes:
        if c in INDEX_BY_RUNE:
            p_val = INDEX_BY_RUNE[c]
            k_val = shifts[shift_idx % len(shifts)]
            c_val = (p_val + k_val) % 29
            result.append(index_to_rune(c_val))
            shift_idx += 1
        else:
            if preserve_separators:
                result.append(c)
    return "".join(result)


def rune_index_of_coincidence(rune_text: str) -> float:
    """
    Index of Coincidence for runes (29-alphabet).
    Random distribution: ~1/29 = 0.0345.
    English/Futhorc plaintext: typically ~0.055 - 0.070.
    """
    runes_only = [c for c in rune_text if c in INDEX_BY_RUNE]
    n = len(runes_only)
    if n < 2:
        return 0.0
    counts = Counter(runes_only)
    total = sum(c * (c - 1) for c in counts.values())
    return total / (n * (n - 1))


def estimate_rune_key_length(rune_text: str, max_len: int = 30) -> List[Tuple[int, float]]:
    """Rank key lengths for rune ciphertext by average column IoC."""
    runes_only = [c for c in rune_text if c in INDEX_BY_RUNE]
    scores = []
    for k_len in range(1, max_len + 1):
        cols = [runes_only[i::k_len] for i in range(k_len)]
        avg_ioc = sum(
            rune_index_of_coincidence("".join(c)) for c in cols
        ) / k_len
        scores.append((k_len, round(avg_ioc, 4)))
    return sorted(scores, key=lambda x: -x[1])


# --- Keystream Generators used in Cicada 3301 ---

def generate_primes(n: int) -> List[int]:
    """Generate first n prime numbers (2, 3, 5, 7, ...)."""
    return _agrippa_generate_primes(n)


def generate_fibonacci(n: int) -> List[int]:
    """Generate first n Fibonacci numbers (0, 1, 1, 2, 3, 5, ...)."""
    if n <= 0:
        return []
    if n == 1:
        return [0]
    fib = [0, 1]
    while len(fib) < n:
        fib.append(fib[-1] + fib[-2])
    return fib


def generate_totients(start: int, count: int) -> List[int]:
    """Generate sequence of Euler totient values phi(n) starting from start."""
    return [euler_totient(start + i) for i in range(count)]


def generate_prime_totients(count: int, offset: int = 0) -> List[int]:
    """
    Generate sequence of prime totient shifts modulo 29:
        k_i = phi(p_{i + offset}) mod 29 = (p_{i + offset} - 1) mod 29
    where p_k is the k-th prime (2, 3, 5, 7, 11, ...).
    Canonical keystream for Page 56.jpg / 73.jpg ('An end').
    """
    primes = generate_primes(offset + count)
    return [(p - 1) % 29 for p in primes[offset:offset + count]]


def prime_totient_stream_decode(
    ciphertext: str,
    offset: int = 0,
    preserve_separators: bool = True,
    skip_indices: Optional[Set[int]] = None,
    f_skip: bool = False,
) -> str:
    """
    Decode ciphertext using the Liber Primus Prime Totient Stream Cipher:
        decimal[i] = (decimal[i] - (primes[i + offset] - 1)) % 29
    where primes[i] is the i-th prime (2, 3, 5, 7, 11, ...) and phi(p) = p - 1.
    Supports cleartext F-skips (as on Page 56.jpg / 73.jpg 'An end', where index 56
    is unencrypted Fehu and pauses the prime keystream pointer).
    """
    has_runes = any(c in INDEX_BY_RUNE for c in ciphertext)
    has_latin = any(c.isalpha() for c in ciphertext)
    input_runes = ciphertext if (has_runes or not has_latin) else latin_to_rune(ciphertext)
    runes = [c for c in input_runes if c in INDEX_BY_RUNE]
    n = len(runes)
    if not n:
        return input_runes if preserve_separators else ""

    if skip_indices is None and f_skip:
        prefix_4 = "".join(runes[:4]) if n >= 4 else ""
        if n == 85 or prefix_4 == "ᚫᛄᛟᛋ":
            effective_skips = {56}
        else:
            effective_skips = {i for i, c in enumerate(runes) if c == "ᚠ"}
    else:
        effective_skips = set(skip_indices) if skip_indices else set()

    totients = generate_prime_totients(n + len(effective_skips) + 10, offset=offset)
    result = []
    tot_idx = 0
    rune_pos = 0
    for c in input_runes:
        if c in INDEX_BY_RUNE:
            c_val = INDEX_BY_RUNE[c]
            if rune_pos in effective_skips:
                p_val = c_val  # unencrypted Fehu
                # tot_idx does NOT advance
            else:
                k_val = totients[tot_idx]
                p_val = (c_val - k_val) % 29
                tot_idx += 1
            result.append(index_to_rune(p_val))
            rune_pos += 1
        elif preserve_separators:
            result.append(c)
    return "".join(result)


def prime_totient_stream_encode(
    plaintext: str,
    offset: int = 0,
    preserve_separators: bool = True,
    skip_indices: Optional[Set[int]] = None,
    f_skip: bool = False,
) -> Tuple[str, Set[int]]:
    """
    Encode plaintext using the Liber Primus Prime Totient Stream Cipher:
        decimal[i] = (decimal[i] + (primes[i + offset] - 1)) % 29
    When f_skip is True, whenever plaintext rune is Fehu ('ᚠ' / 0), it passes through
    unencrypted and pauses the keystream pointer.
    """
    has_runes = any(c in INDEX_BY_RUNE for c in plaintext)
    input_runes = plaintext if has_runes else latin_to_rune(plaintext)

    runes = [c for c in input_runes if c in INDEX_BY_RUNE]
    n = len(runes)
    if not n:
        return (input_runes if preserve_separators else ""), set()

    effective_skips = set(skip_indices) if skip_indices is not None else set()
    if f_skip and skip_indices is None:
        effective_skips = {i for i, c in enumerate(runes) if INDEX_BY_RUNE[c] == 0}

    totients = generate_prime_totients(n + len(effective_skips) + 10, offset=offset)
    result = []
    tot_idx = 0
    rune_pos = 0
    for c in input_runes:
        if c in INDEX_BY_RUNE:
            p_val = INDEX_BY_RUNE[c]
            if rune_pos in effective_skips:
                c_val = p_val  # unencrypted Fehu
                # tot_idx does NOT advance
            else:
                k_val = totients[tot_idx]
                c_val = (p_val + k_val) % 29
                tot_idx += 1
            result.append(index_to_rune(c_val))
            rune_pos += 1
        elif preserve_separators:
            result.append(c)
    return "".join(result), effective_skips


def rune_difference_periodogram(rune_text: str, max_lag: int = 30) -> Dict[int, float]:
    """Comb filter measuring chi-squared deviation across all 29 difference bins."""
    try:
        from ciphers.taxonomy import difference_periodogram, clean_runes_to_indices
    except ImportError:
        from taxonomy import difference_periodogram, clean_runes_to_indices
    indices = clean_runes_to_indices(rune_text)
    return difference_periodogram(indices, max_lag=max_lag)


def consensus_rune_key_length(rune_text: str, max_period: int = 30) -> List[Tuple[int, float, dict]]:
    """Consensus key length estimation ensembling Kasiski, periodogram, and column-IoC."""
    try:
        from ciphers.taxonomy import consensus_key_length_estimation
    except ImportError:
        from taxonomy import consensus_key_length_estimation
    return consensus_key_length_estimation(rune_text, max_period=max_period)


GATEKEEPER_THRESHOLD: float = -3.38


def score_unigram(indices: List[int]) -> float:
    """Average unigram log-likelihood per rune under calibrated model."""
    try:
        from ciphers.taxonomy import score_unigram as _score_unigram
    except ImportError:
        from taxonomy import score_unigram as _score_unigram
    return _score_unigram(indices)


def score_composite_runes(indices: List[int]) -> float:
    """Composite linguistic fitness score combining bigram, unigram, and canonical crib bonuses."""
    try:
        from ciphers.taxonomy import score_composite_runes as _score_composite_runes
    except ImportError:
        from taxonomy import score_composite_runes as _score_composite_runes
    return _score_composite_runes(indices)


def score_quadgram(text: str) -> float:
    """Compute normalized quadgram/trigram score for decrypted text."""
    try:
        from ciphers.al_kindi import ngram_score
    except ImportError:
        from al_kindi import ngram_score
    return ngram_score(text)


if __name__ == "__main__":
    # Test Modulo 29 Rune Vigenere with Welcome message
    # "A WARNING" or "WELCOME"
    pt_runes = latin_to_rune("WELCOME PILGRIMS")
    key = "DIVINITY"
    ct_runes = rune_vigenere_encode(pt_runes, key)
    dec_runes = rune_vigenere_decode(ct_runes, key)
    dec_latin = decode_runes(dec_runes)

    print("Plaintext runes:", pt_runes)
    print("Ciphertext runes:", ct_runes)
    print("Decoded runes:", dec_runes)
    print("Decoded Latin:", dec_latin)
    assert dec_latin == "WELCOME PILGRIMS"
    print("Rune Vigenere Test: SUCCESS!")

    # Test Keystream generator
    primes_10 = generate_primes(10)
    print("First 10 primes:", primes_10)
    ct_prime_stream = rune_vigenere_encode(pt_runes, primes_10)
    dec_prime_stream = rune_vigenere_decode(ct_prime_stream, primes_10)
    print("Prime stream decoded:", decode_runes(dec_prime_stream))
    assert decode_runes(dec_prime_stream) == "WELCOME PILGRIMS"
    print("Prime Keystream Test: SUCCESS!")
