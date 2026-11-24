"""
SPRT — Wald's Sequential Probability Ratio Test for Z29 Bigram Language Models.
Standard library only: math. Zero external dependencies.

Enables optimal sample-efficient screening:
H0: Flat uniform symbol distribution (noise)
H1: Calibrated language-like bigram distribution

Terminates candidate evaluation as soon as cumulative log-likelihood ratio crosses
Wald's decision boundaries:
    upper = ln((1 - beta) / alpha)
    lower = ln(beta / (1 - alpha))
"""

from __future__ import annotations
import math
from typing import List, Sequence, Tuple


def bigram_llr_table(train: Sequence[int], k: float = 0.5, n: int = 29) -> List[List[float]]:
    """
    Build a 29x29 log-likelihood ratio table:
    llr[a][b] = ln(P_lang(b|a)) - ln(1/n) using add-k Laplace smoothing.
    train: Sequence of symbol indices in 0..n-1.
    """
    counts = [[k] * n for _ in range(n)]
    for a, b in zip(train, train[1:]):
        if 0 <= a < n and 0 <= b < n:
            counts[a][b] += 1.0

    lu = math.log(1.0 / n)
    table: List[List[float]] = []
    for a in range(n):
        row_sum = sum(counts[a])
        row = [math.log(counts[a][b] / row_sum) - lu for b in range(n)]
        table.append(row)
    return table


def sprt(
    seq: Sequence[int],
    llr: List[List[float]],
    alpha: float = 0.01,
    beta: float = 0.01
) -> Tuple[str, int]:
    """
    Execute Wald's Sequential Probability Ratio Test over symbol sequence.
    Returns (decision, symbols_used).
    decision in {'accept', 'reject', 'undecided'}.
    alpha = P(accept | H0) (false alarm probability)
    beta = P(reject | H1) (miss probability)
    """
    if len(seq) < 2:
        return "undecided", len(seq)

    upper = math.log((1.0 - beta) / alpha)
    lower = math.log(beta / (1.0 - alpha))
    s = 0.0
    n = len(llr)

    for i in range(1, len(seq)):
        a = seq[i - 1]
        b = seq[i]
        if 0 <= a < n and 0 <= b < n:
            s += llr[a][b]
        if s >= upper:
            return "accept", i + 1
        if s <= lower:
            return "reject", i + 1

    return "undecided", len(seq)
