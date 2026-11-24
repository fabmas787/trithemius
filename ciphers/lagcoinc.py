"""
LagCoinc — Exact Coincidence Spectrum at Every Lag via 29 Indicator-Channel FFTs.
Vectorized O(29 * N * log N) computation of coincidence counts:
kappa(d) = sum_{i=0}^{L-1-d} I(c[i] == c[i+d]) for all lags d in 1..L-1.

Supports optional NumPy acceleration with pure-Python fallback.
"""

from __future__ import annotations
import math
from typing import List, Sequence

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None
    HAS_NUMPY = False


def coincidence_by_lag_numpy(c: Sequence[int], n: int = 29) -> List[int]:
    """Compute coincidences across all lags using 29 indicator channels with NumPy FFT."""
    arr = np.asarray(c, dtype=int)
    L = len(arr)
    if L < 2:
        return []
    # Optimal FFT size: next power of 2 >= 2 * L
    size = 1 << (2 * L).bit_length()
    acc = np.zeros(size, dtype=float)

    for s in range(n):
        channel = (arr == s).astype(float)
        f = np.fft.rfft(channel, size)
        acc += np.fft.irfft(f * np.conj(f), size)

    # acc[0] is lag 0 (length L); index 1..L-1 correspond to lags 1..L-1
    res = np.rint(acc[1:L]).astype(int).tolist()
    return res


def coincidence_by_lag_pure(c: Sequence[int], n: int = 29) -> List[int]:
    """
    Pure Python direct computation of coincidences at all lags.
    O(L^2) fallback for environments without NumPy.
    """
    L = len(c)
    if L < 2:
        return []
    res = [0] * (L - 1)
    for d in range(1, L):
        count = 0
        for i in range(L - d):
            if c[i] == c[i + d]:
                count += 1
        res[d - 1] = count
    return res


def coincidence_by_lag(c: Sequence[int], n: int = 29) -> List[int]:
    """
    Compute coincidence counts kappa(d) across all lags d in [1, len(c)-1].
    Uses NumPy FFT if available, else pure-Python fallback.
    """
    if HAS_NUMPY:
        return coincidence_by_lag_numpy(c, n=n)
    return coincidence_by_lag_pure(c, n=n)
