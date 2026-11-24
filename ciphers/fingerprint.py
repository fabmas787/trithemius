"""
Fingerprint — Statistical Fingerprint & Likelihood-Free Forward Simulation for Z29 Ciphertexts.
Standard library only: math, random, collections. Zero external dependencies.

Enables Likelihood-Free Inference (Analysis by Synthesis):
Instead of decrypting and scoring every hypothesis, forward-simulate each cipher family
on known plaintexts and compare summary statistic vectors (doublet rate, Z-score,
IoC*N, consecutive difference distributions) against the empirical manuscript fingerprint.
"""

from __future__ import annotations
import math
import random
from collections import Counter
from typing import Dict, List, Any, Optional, Sequence, Tuple

EMPIRICAL_UNSOLVED_LP = {
    "doublet_rate": 0.00663785,   # 86 doublets / 12,955 transitions = 0.66%
    "doublet_z": -17.4,           # Extreme negative deviation
    "ioc_n": 1.000,               # Flat unigram distribution
    "diff_zero_ratio": 0.1924,    # Severe suppression at Delta = 0
}


def doublet_rate(c: Sequence[int]) -> float:
    """Fraction of consecutive identical symbols: sum(c[i] == c[i+1]) / (len(c) - 1)."""
    if len(c) < 2:
        return 0.0
    return sum(1 for a, b in zip(c, c[1:]) if a == b) / (len(c) - 1)


def doublet_z(c: Sequence[int], n: int = 29) -> float:
    """
    Standard score of observed doublets against null hypothesis of uniform independent symbols.
    Expected mean = (L - 1) / n; variance = (L - 1) * (1/n) * (1 - 1/n).
    """
    pairs = len(c) - 1
    if pairs < 1:
        return 0.0
    p = 1.0 / n
    observed = sum(1 for a, b in zip(c, c[1:]) if a == b)
    expected = pairs * p
    std_dev = math.sqrt(pairs * p * (1.0 - p))
    return (observed - expected) / std_dev


def ioc_n(c: Sequence[int], n: int = 29) -> float:
    """
    Normalized Index of Coincidence scaled by alphabet size n:
    IoC * n = n * sum(f_i * (f_i - 1)) / (L * (L - 1)).
    Flat random text approaches 1.00; natural English text reaches ~1.7 - 2.0.
    """
    L = len(c)
    if L < 2:
        return 0.0
    counts = Counter(c)
    numerator = sum(v * (v - 1) for v in counts.values())
    return (n * numerator) / (L * (L - 1))


def diff_hist(c: Sequence[int], n: int = 29) -> List[int]:
    """Histogram of modular consecutive differences Delta_i = (c_{i+1} - c_i) mod n."""
    if len(c) < 2:
        return [0] * n
    h = Counter((b - a) % n for a, b in zip(c, c[1:]))
    return [h.get(d, 0) for d in range(n)]


def fingerprint(c: Sequence[int], n: int = 29) -> Dict[str, Any]:
    """Extract comprehensive 4D summary statistical fingerprint vector."""
    L = len(c)
    if L < 2:
        return {
            "length": L,
            "ioc_n": 0.0,
            "doublet_rate": 0.0,
            "doublet_z": 0.0,
            "diff_zero_ratio": 0.0,
            "diff_histogram": [0] * n,
        }

    h = diff_hist(c, n)
    pairs = L - 1
    expected_bin_count = pairs / n

    diff_zero_ratio = (h[0] / expected_bin_count) if expected_bin_count > 0 else 0.0

    return {
        "length": L,
        "ioc_n": ioc_n(c, n),
        "doublet_rate": doublet_rate(c),
        "doublet_z": doublet_z(c, n),
        "diff_zero_ratio": diff_zero_ratio,
        "diff_histogram": h,
    }


def simulate(family: str, plaintext: Sequence[int], rng: Optional[random.Random] = None, n: int = 29, **kw) -> List[int]:
    """
    Forward-simulate a cipher family over an integer plaintext sequence [0..n-1].
    Supported families:
    - 'vigenere': Periodic key of specified 'period'
    - 'otp': Uniform unconstrained one-time pad
    - 'otp_norepeat': One-time pad with strict no-consecutive-duplicate ciphertext rule
    - 'chain_mod29': c_i = (c_{i-1} + k_i) mod n with non-zero increments k_i in 1..n-1
    """
    if rng is None:
        rng = random.Random()

    fam = family.lower()

    if fam == "vigenere":
        m = kw.get("period", 8)
        k = [rng.randrange(n) for _ in range(m)]
        return [(x + k[i % m]) % n for i, x in enumerate(plaintext)]

    if fam == "otp":
        return [(x + rng.randrange(n)) % n for x in plaintext]

    if fam == "otp_norepeat":
        out = []
        prev = None
        for x in plaintext:
            while True:
                c = (x + rng.randrange(n)) % n
                if c != prev:
                    break
            out.append(c)
            prev = c
        return out

    if fam == "chain_mod29":
        # Chain cipher where difference is non-zero
        out = []
        prev = rng.randrange(n)
        out.append(prev)
        for _ in plaintext[1:]:
            step = rng.randrange(1, n)  # 1 to n-1 (no step 0)
            c = (prev + step) % n
            out.append(c)
            prev = c
        return out

    raise ValueError(f"Unknown cipher family: {family}")


def compare_fingerprints(fp1: Dict[str, Any], fp2: Dict[str, Any] = EMPIRICAL_UNSOLVED_LP) -> float:
    """
    Compute Euclidean distance between summary statistical features:
    Weights: IoC*N (1.0), Doublet Rate (10.0), Diff-0 Ratio (1.0).
    """
    d_ioc = fp1.get("ioc_n", 1.0) - fp2.get("ioc_n", 1.0)
    d_dbl = (fp1.get("doublet_rate", 0.0) - fp2.get("doublet_rate", 0.0)) * 10.0
    d_diff0 = fp1.get("diff_zero_ratio", 1.0) - fp2.get("diff_zero_ratio", 1.0)
    return math.sqrt(d_ioc**2 + d_dbl**2 + d_diff0**2)
