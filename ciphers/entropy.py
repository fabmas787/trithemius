"""
Entropy — Information Theory and Signal Profiling module for Cicada 3301.

Provides:
- Shannon Entropy H(X) calculation (overall and sliding window)
- High-Entropy block detector to isolate ciphertexts/hex/base64/runes from natural language prose
- Feature vector F = [H, IoC, Kurtosis, Skewness, RuneRatio, HexRatio] for statistical routing

Usage:
    from entropy import (
        shannon_entropy, sliding_window_entropy, detect_entropy_boundaries,
        extract_signal_features, is_high_entropy
    )
"""

import math
from collections import Counter
import string
from typing import List, Tuple, Dict

ALPHABET = string.ascii_uppercase
HEX_CHARS = set(string.hexdigits)


def shannon_entropy(data: str) -> float:
    """
    Compute Shannon entropy H(X) in bits per character.
    Scale: 0.0 (uniform text) up to ~4.7 bits for 26 letters,
    or up to 8.0 bits for full 256-byte binary/hex distribution.
    Natural English text typically scores ~3.8 - 4.3.
    Uniform random ciphertext scores ~4.6+ (for alphabet) or ~7.5+ (for byte/hex).
    """
    if not data:
        return 0.0
    n = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


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


def extract_signal_features(text: str) -> Dict[str, float]:
    """
    Extract statistical feature vector F:
    - H: Shannon Entropy
    - IoC: Index of Coincidence (English ~0.066, random ~0.038)
    - rune_ratio: fraction of Unicode Futhorc runes
    - hex_ratio: fraction of hexadecimal characters
    """
    n = len(text)
    if not n:
        return {"entropy": 0.0, "ioc": 0.0, "rune_ratio": 0.0, "hex_ratio": 0.0, "classification": "empty"}

    h = shannon_entropy(text)
    ioc = index_of_coincidence(text)

    rune_count = sum(1 for c in text if 0x16A0 <= ord(c) <= 0x16FF)
    hex_count = sum(1 for c in text if c in HEX_CHARS and not c.isspace())

    rune_ratio = round(rune_count / n, 4)
    hex_ratio = round(hex_count / n, 4)

    # Statistical classification
    if rune_ratio > 0.15:
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
        "classification": classification
    }


if __name__ == "__main__":
    sample_prose = "Welcome pilgrims to this great journey. A warning: believe nothing from this book."
    sample_runes = "ᚹᛖᛚᚳᚩᛗᛖ᛫ᛈᛁᛚᚷᚱᛁᛗᛋ᛫ᛏᚩ᛫ᚦᛁᛋ᛫ᚷᚱᛠᛏ᛫ᛄᚩᚢᚱᚾᛖᚣ"
    sample_hex = "4a5f89c2b1e47d039f826194ac52e01b3301a74d"

    print("Prose:", extract_signal_features(sample_prose))
    print("Runes:", extract_signal_features(sample_runes))
    print("Hex:  ", extract_signal_features(sample_hex))
