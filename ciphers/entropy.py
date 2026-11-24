"""
Entropy — Information Theory and Signal Profiling module for Cicada 3301.

Provides:
- Shannon Entropy H(X) calculation (overall and sliding window)
- Miller-Madow bias-corrected entropy H_MM
- Normalized entropy H / log2(|\Sigma|)
- Alphabet cardinality detection (Z29 canonical Futhorc, hex, Latin, binary)
- High-Entropy block detector to isolate ciphertexts/hex/base64/runes from natural language prose
- Feature vector F and dual profiles (BYTE_PROFILE and RUNE_Z29_PROFILE) for statistical routing

Usage:
    from ciphers.entropy import (
        shannon_entropy, miller_madow_entropy, normalized_entropy,
        detect_alphabet_size, sliding_window_entropy, detect_entropy_boundaries,
        extract_signal_features, is_high_entropy
    )
"""

import math
from collections import Counter
import string
from typing import List, Tuple, Dict, Optional, Any

try:
    from ciphers.agrippa import INDEX_BY_RUNE
except ImportError:
    from agrippa import INDEX_BY_RUNE

ALPHABET = string.ascii_uppercase
HEX_CHARS = set(string.hexdigits)

# Canonical 29-rune alphabet of Gematria Primus plus alternate codepoints (e.g. U+16DC for U+16DD, U+16BA for U+16BB)
_RUNE_VARIANTS = {"ᚺ": "ᚻ", "ᛜ": "ᛝ"}
CANONICAL_RUNES_SET = set(INDEX_BY_RUNE.keys()) | set(_RUNE_VARIANTS.keys())
RUNIC_SEPARATORS = {'᛫', '᛬', '᛭', ' '}


def _clean_runic_data(data: str) -> List[str]:
    """Filter out runic separators and normalize alternate codepoints to Z29 canonical runes."""
    result = []
    for c in data:
        if c in RUNIC_SEPARATORS:
            continue
        norm_c = _RUNE_VARIANTS.get(c, c)
        if norm_c in INDEX_BY_RUNE:
            result.append(norm_c)
    return result


def detect_alphabet_size(data: str) -> int:
    """
    Detect the alphabet cardinality |\Sigma| of the given data:
    - 29 for canonical Futhorc runes (Z29)
    - 16 for hexadecimal strings
    - 26 for Latin alphabetic text
    - 256 for raw binary, mixed payloads, or general bytes
    """
    if not data:
        return 256

    non_space = [c for c in data if not c.isspace()]
    if not non_space:
        return 256

    # 1. Runic Futhorc check
    rune_count = sum(1 for c in non_space if c in CANONICAL_RUNES_SET)
    runic_and_sep = sum(1 for c in non_space if c in CANONICAL_RUNES_SET or c in RUNIC_SEPARATORS)
    if rune_count > 0 and (runic_and_sep == len(non_space) or rune_count / len(non_space) > 0.5):
        return 29

    # 2. Pure hex check: all non-space characters in 0-9a-fA-F
    if all(c in HEX_CHARS for c in non_space):
        return 16

    # 3. Latin alphabetic check: letters are ASCII letters
    latin_letters = [c for c in non_space if c.isascii() and c.isalpha()]
    if latin_letters and all(c.isascii() and (c.isalpha() or c in string.punctuation) for c in non_space):
        return 26

    # Default
    return 256


def shannon_entropy(data: str, alphabet_size: Optional[int] = None) -> float:
    """
    Compute Shannon entropy H(X) in bits per character.
    If the data is runic (alphabet_size == 29 or detected as 29),
    runic separators ('᛫', '᛬', '᛭', ' ') are filtered out prior to computation.
    """
    if not data:
        return 0.0

    eff_size = alphabet_size if alphabet_size is not None else detect_alphabet_size(data)
    if eff_size == 29:
        cleaned = _clean_runic_data(data)
        if not cleaned:
            return 0.0
        n = len(cleaned)
        counts = Counter(cleaned)
    else:
        n = len(data)
        counts = Counter(data)

    entropy = 0.0
    for count in counts.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def miller_madow_entropy(data: str, alphabet_size: Optional[int] = None) -> float:
    """
    Compute Miller-Madow bias-corrected entropy in bits per character:
        H_MM = min(log2(|\Sigma|), H_1 + (m - 1) / (2 * L * ln 2))
    where:
        |\Sigma| is the alphabet size (detected or provided)
        L is sample length (excluding separators for runic alphabet)
        m is the number of observed unique symbols in the sample
        H_1 is empirical Shannon entropy
    """
    if not data:
        return 0.0

    eff_size = alphabet_size if alphabet_size is not None else detect_alphabet_size(data)
    if eff_size == 29:
        cleaned = _clean_runic_data(data)
        if not cleaned:
            return 0.0
        L = len(cleaned)
        counts = Counter(cleaned)
    else:
        L = len(data)
        counts = Counter(data)

    m = len(counts)
    if L == 0 or m == 0:
        return 0.0

    h1 = 0.0
    for count in counts.values():
        p = count / L
        if p > 0:
            h1 -= p * math.log2(p)

    bias_correction = (m - 1) / (2.0 * L * math.log(2.0))
    h_mm = h1 + bias_correction

    max_h = math.log2(eff_size) if eff_size > 1 else 1.0
    h_mm = min(max_h, h_mm)

    res = round(h_mm, 4)
    if res > max_h:
        res = max_h
    return res


def normalized_entropy(data: str, alphabet_size: Optional[int] = None) -> float:
    """
    Compute normalized entropy H_norm = H(X) / log2(|\Sigma|) in range [0.0, 1.0].
    """
    if not data:
        return 0.0

    eff_size = alphabet_size if alphabet_size is not None else detect_alphabet_size(data)
    if eff_size <= 1:
        return 0.0

    max_h = math.log2(eff_size)
    h = shannon_entropy(data, alphabet_size=eff_size)
    norm = h / max_h
    return round(min(1.0, max(0.0, norm)), 4)


_MAX_PRECOMPUTED = 65536
_CLOG2C_TABLE = [0.0] * (_MAX_PRECOMPUTED + 1)
for _i in range(1, _MAX_PRECOMPUTED + 1):
    _CLOG2C_TABLE[_i] = _i * math.log2(_i)


def _c_log2_c(c: int) -> float:
    if c <= 0:
        return 0.0
    if c <= _MAX_PRECOMPUTED:
        return _CLOG2C_TABLE[c]
    return c * math.log2(c)


def sliding_window_entropy_naive(text: str, window_size: int = 64, step: int = 16) -> List[Tuple[int, float]]:
    """Reference naive implementation for testing and validation."""
    results = []
    if len(text) < window_size:
        return [(0, shannon_entropy(text))]
    for i in range(0, len(text) - window_size + 1, step):
        window = text[i:i + window_size]
        h = shannon_entropy(window)
        results.append((i, h))
    return results


def sliding_window_entropy(text: str, window_size: int = 64, step: int = 16) -> List[Tuple[int, float]]:
    """
    Calculate Shannon entropy across a sliding window in O(n) time.
    Maintains S = sum(c * log2(c)) incrementally, computing H = log2(w) - S / w.
    Returns list of (start_index, entropy_value).
    """
    n = len(text)
    if n < window_size:
        return [(0, shannon_entropy(text))]
    if window_size <= 0 or step <= 0:
        return []

    log2_w = math.log2(window_size)
    inv_w = 1.0 / window_size

    # Non-overlapping windows
    if step >= window_size:
        results = []
        for i in range(0, n - window_size + 1, step):
            window = text[i:i + window_size]
            counts = Counter(window)
            s_sum = sum(_c_log2_c(c) for c in counts.values())
            h = max(0.0, log2_w - s_sum * inv_w)
            results.append((i, round(h, 4)))
        return results

    # Initialize first window
    counts = Counter(text[:window_size])
    s_sum = sum(_c_log2_c(c) for c in counts.values())
    h = max(0.0, log2_w - s_sum * inv_w)
    results = [(0, round(h, 4))]

    limit = n - window_size + 1
    refresh_interval = 256
    step_count = 0

    for i in range(step, limit, step):
        prev_i = i - step
        # Evict old characters
        for ch in text[prev_i:i]:
            old_c = counts[ch]
            new_c = old_c - 1
            counts[ch] = new_c
            s_sum += _c_log2_c(new_c) - _c_log2_c(old_c)

        # Ingest new characters
        for ch in text[prev_i + window_size:i + window_size]:
            old_c = counts.get(ch, 0)
            new_c = old_c + 1
            counts[ch] = new_c
            s_sum += _c_log2_c(new_c) - _c_log2_c(old_c)

        step_count += 1
        if step_count % refresh_interval == 0:
            s_sum = sum(_c_log2_c(c) for c in counts.values() if c > 0)

        h = max(0.0, log2_w - s_sum * inv_w)
        results.append((i, round(h, 4)))

    return results


def detect_entropy_boundaries(text: str, window_size: int = 64, step: int = 16, threshold_delta: float = 0.6) -> List[int]:
    """
    Identify character indices where entropy significantly shifts (|delta H| > threshold),
    marking boundaries between natural prose and encrypted/encoded payload.
    """
    curve = sliding_window_entropy(text, window_size, step)
    cut_points = []
    for i in range(len(curve) - 1):
        delta = abs(curve[i + 1][1] - curve[i][1])
        if delta >= threshold_delta:
            cut_points.append(curve[i + 1][0])
    return cut_points


def is_high_entropy(text: str, threshold: float = 4.35) -> bool:
    """Check if a string has high entropy indicative of ciphertext or hash."""
    return shannon_entropy(text) >= threshold


def index_of_coincidence(text: str) -> float:
    """Calculate Index of Coincidence (IoC)."""
    filtered = [c.upper() for c in text if c.isalpha()]
    n = len(filtered)
    if n < 2:
        return 0.0
    counts = Counter(filtered)
    total = sum(c * (c - 1) for c in counts.values())
    return round(total / (n * (n - 1)), 4)


def extract_signal_features(text: str) -> Dict[str, Any]:
    """
    Extract statistical feature vector F and alphabet profiles:
    - entropy: Shannon Entropy (legacy key)
    - ioc: Index of Coincidence
    - rune_ratio: fraction of canonical runes
    - hex_ratio: fraction of hexadecimal characters
    - alphabet_size: detected alphabet cardinality
    - miller_madow_entropy: Miller-Madow bias-corrected entropy for detected alphabet
    - normalized_entropy: H / log2(|\Sigma|) in [0.0, 1.0]
    - BYTE_PROFILE: {entropy, miller_madow_entropy, normalized_entropy, alphabet_size=256}
    - RUNE_Z29_PROFILE: {entropy, miller_madow_entropy, normalized_entropy, alphabet_size=29, rune_count}
    - classification: stream/payload type classification
    """
    n = len(text)
    if not n:
        return {
            "entropy": 0.0,
            "ioc": 0.0,
            "rune_ratio": 0.0,
            "hex_ratio": 0.0,
            "classification": "empty",
            "alphabet_size": 256,
            "miller_madow_entropy": 0.0,
            "normalized_entropy": 0.0,
            "BYTE_PROFILE": {
                "entropy": 0.0,
                "miller_madow_entropy": 0.0,
                "normalized_entropy": 0.0,
                "alphabet_size": 256,
            },
            "RUNE_Z29_PROFILE": {
                "entropy": 0.0,
                "miller_madow_entropy": 0.0,
                "normalized_entropy": 0.0,
                "alphabet_size": 29,
                "rune_count": 0,
            },
        }

    # Count runes and hex
    rune_count = sum(1 for c in text if c in CANONICAL_RUNES_SET)
    hex_count = sum(1 for c in text if c in HEX_CHARS and not c.isspace())

    rune_ratio = round(rune_count / n, 4)
    hex_ratio = round(hex_count / n, 4)

    eff_alphabet = detect_alphabet_size(text)

    h = shannon_entropy(text, alphabet_size=eff_alphabet)
    h_mm = miller_madow_entropy(text, alphabet_size=eff_alphabet)
    h_norm = normalized_entropy(text, alphabet_size=eff_alphabet)
    ioc = index_of_coincidence(text)

    # Byte-level profile (|Sigma| = 256)
    byte_profile = {
        "entropy": shannon_entropy(text, alphabet_size=256),
        "miller_madow_entropy": miller_madow_entropy(text, alphabet_size=256),
        "normalized_entropy": normalized_entropy(text, alphabet_size=256),
        "alphabet_size": 256,
    }

    # Runic Z29 profile (|Sigma| = 29)
    runes_cleaned = _clean_runic_data(text)
    runes_only = "".join(runes_cleaned)
    rune_profile = {
        "entropy": shannon_entropy(runes_only, alphabet_size=29) if runes_only else 0.0,
        "miller_madow_entropy": miller_madow_entropy(runes_only, alphabet_size=29) if runes_only else 0.0,
        "normalized_entropy": normalized_entropy(runes_only, alphabet_size=29) if runes_only else 0.0,
        "alphabet_size": 29,
        "rune_count": len(runes_only),
    }

    # Statistical classification
    if rune_ratio > 0.15:
        rune_norm = rune_profile["normalized_entropy"] if rune_profile["rune_count"] > 0 else h_norm
        if rune_norm >= 0.95:
            classification = "high_entropy_runic_stream"
        else:
            classification = "runic_payload"
    elif hex_ratio > 0.85 and n >= 16:
        classification = "hex_or_hash"
    elif ioc < 0.045 and h >= 4.2 and n > 30:
        classification = "polyalphabetic_ciphertext"
    elif ioc >= 0.055:
        classification = "natural_prose"
    else:
        classification = "mixed_signal"

    return {
        "entropy": h,
        "ioc": ioc,
        "rune_ratio": rune_ratio,
        "hex_ratio": hex_ratio,
        "alphabet_size": eff_alphabet,
        "miller_madow_entropy": h_mm,
        "normalized_entropy": h_norm,
        "BYTE_PROFILE": byte_profile,
        "RUNE_Z29_PROFILE": rune_profile,
        "classification": classification,
    }


if __name__ == "__main__":
    sample_prose = "Welcome pilgrims to this great journey. A warning: believe nothing from this book."
    sample_runes = "ᚹᛖᛚᚳᚩᛗᛖ᛫ᛈᛁᛚᚷᚱᛁᛗᛋ᛫ᛏᚩ᛫ᚦᛁᛋ᛫ᚷᚱᛠᛏ᛫ᛄᚩᚢᚱᚾᛖᚣ"
    sample_hex = "4a5f89c2b1e47d039f826194ac52e01b3301a74d"

    print("Prose:", extract_signal_features(sample_prose))
    print("Runes:", extract_signal_features(sample_runes))
    print("Hex:  ", extract_signal_features(sample_hex))
