"""
Unicity — Identifiability Budget and Shannon Unicity Distance for Z29 Ciphertexts.
Standard library only: math. Zero external dependencies.

Calculates the information-theoretic identifiability limits of candidate ciphers:
- Language redundancy D = log2(n) - H_L
- Unicity distance U = H(K) / D
- Maximum resolvable periodic key length m_max = N * D / log2(n)
"""

from __future__ import annotations
import math
from typing import Dict, Any, Optional


def redundancy(language_entropy_bits: float, n: int = 29) -> float:
    """Compute per-symbol redundancy D = log2(n) - H_L in bits per symbol."""
    return math.log2(n) - language_entropy_bits


def unicity_distance(key_entropy_bits: float, language_entropy_bits: float, n: int = 29) -> float:
    """
    Shannon unicity distance: minimum ciphertext length required to uniquely determine the key.
    U = H(K) / D.
    """
    d = redundancy(language_entropy_bits, n=n)
    if d <= 0:
        return float("inf")
    return key_entropy_bits / d


def max_periodic_key_length(n_symbols: int, language_entropy_bits: float, n: int = 29) -> float:
    """
    Longest uniformly random periodic key (m symbols, entropy m * log2(n))
    resolvable from an observed ciphertext of n_symbols.
    m_max = n_symbols * D / log2(n).
    """
    d = redundancy(language_entropy_bits, n=n)
    if d <= 0:
        return 0.0
    return (n_symbols * d) / math.log2(n)


def max_unconstrained_periodic_key_length(
    n_symbols: int,
    min_runes_per_col: int = 16,
    hard_cap: int = 16,
) -> int:
    """
    Maximum periodic key length resolvable by unconstrained per-column/bigram solvers,
    requiring at least min_runes_per_col symbols per column and capped by hard_cap.
    """
    if n_symbols <= 0:
        return 1
    return min(hard_cap, max(1, n_symbols // max(1, min_runes_per_col)))


def identifiability_report(
    n_symbols: int,
    assumed_entropies: Optional[Dict[str, float]] = None,
    n: int = 29
) -> Dict[str, Any]:
    """
    Generate an identifiability budget report for an observed ciphertext of length n_symbols.
    Default entropy scenarios for English mapped to Z29:
    - Conservative (low redundancy, high entropy): 3.3 bits/symbol
    - Moderate (empirical bigram): 2.5 bits/symbol
    - Ideal (long-range English Shannon): 1.5 bits/symbol
    """
    if assumed_entropies is None:
        assumed_entropies = {
            "conservative_3_3": 3.3,
            "moderate_2_5": 2.5,
            "ideal_1_5": 1.5,
        }

    alphabet_entropy = math.log2(n)
    scenarios = {}

    for label, h_l in assumed_entropies.items():
        red = redundancy(h_l, n=n)
        max_m = max_periodic_key_length(n_symbols, h_l, n=n)
        scenarios[label] = {
            "assumed_entropy_bits": h_l,
            "redundancy_bits": red,
            "max_resolvable_periodic_key_len": round(max_m, 1),
        }

    return {
        "n_symbols": n_symbols,
        "alphabet_size": n,
        "max_symbol_entropy_bits": alphabet_entropy,
        "max_unconstrained_periodic_key_len": max_unconstrained_periodic_key_length(n_symbols),
        "scenarios": scenarios,
    }
