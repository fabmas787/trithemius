"""
LagCoinc — Exact Coincidence Spectrum at Every Lag via 29 Indicator-Channel FFTs.
Vectorized O(29 * N * log N) computation of coincidence counts:
kappa(d) = sum_{i=0}^{L-1-d} I(c[i] == c[i+d]) for all lags d in 1..L-1.

Supports optional NumPy acceleration with pure-Python fallback.
"""

from __future__ import annotations
from collections import Counter
import math
from typing import List, Optional, Sequence, Tuple

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None
    HAS_NUMPY = False

_DIRECT_MAX_LAG = 128


def coincidence_by_lag_numpy(
    c: Sequence[int], n: int = 29, max_lag: Optional[int] = None
) -> List[int]:
    """Compute coincidences across lags 1..limit using adaptive direct NumPy or batched 2D FFT."""
    arr = np.asarray(c, dtype=int)
    L = len(arr)
    limit = (L - 1) if max_lag is None else min(int(max_lag), L - 1)
    if limit <= 0:
        return []

    if limit <= _DIRECT_MAX_LAG or L <= 256:
        return [int(np.count_nonzero(arr[:-d] == arr[d:])) for d in range(1, limit + 1)]

    # Minimal power-of-2 size >= 2 * L - 1 to avoid circular aliasing
    size = 1 << (2 * L - 2).bit_length()
    uniq = np.unique(arr)
    batch_size = max(1, 2_000_000 // size)
    acc_freq = np.zeros(size // 2 + 1, dtype=np.float64)

    for start in range(0, len(uniq), batch_size):
        chunk = uniq[start : start + batch_size]
        indicators = (arr[None, :] == chunk[:, None]).astype(np.float64)
        f = np.fft.rfft(indicators, n=size, axis=1)
        acc_freq += np.sum(f.real * f.real + f.imag * f.imag, axis=0)

    acc = np.fft.irfft(acc_freq, n=size)
    return np.rint(acc[1 : limit + 1]).astype(int).tolist()


def coincidence_by_lag_pure(
    c: Sequence[int], n: int = 29, max_lag: Optional[int] = None
) -> List[int]:
    """
    Pure Python direct computation of coincidences at lags 1..limit.
    O(L * limit) fallback for environments without NumPy.
    """
    L = len(c)
    limit = (L - 1) if max_lag is None else min(int(max_lag), L - 1)
    if limit <= 0:
        return []
    res = [0] * limit
    for d in range(1, limit + 1):
        count = 0
        for i in range(L - d):
            if c[i] == c[i + d]:
                count += 1
        res[d - 1] = count
    return res


def coincidence_by_lag(
    c: Sequence[int], n: int = 29, max_lag: Optional[int] = None
) -> List[int]:
    """
    Compute coincidence counts kappa(d) across lags d in [1, limit].
    Uses adaptive NumPy (direct or batched FFT) if available, else pure-Python fallback.
    """
    if HAS_NUMPY:
        return coincidence_by_lag_numpy(c, n=n, max_lag=max_lag)
    return coincidence_by_lag_pure(c, n=n, max_lag=max_lag)


def _columnar_stats(indices: Sequence[int], period: int) -> Tuple[List[float], int]:
    """Compute per-column IoCs (for n_r >= 2) and total within-column pairs."""
    if period <= 0 or len(indices) < 2:
        return [], 0

    col_iocs: List[float] = []
    n_pairs = 0
    for r in range(period):
        col = indices[r::period]
        n_r = len(col)
        if n_r < 2:
            continue
        counts = Counter(col)
        coincidences = sum(f * (f - 1) for f in counts.values())
        col_iocs.append(coincidences / (n_r * (n_r - 1)))
        n_pairs += n_r * (n_r - 1) // 2
    return col_iocs, n_pairs


def mean_columnar_ioc(indices: Sequence[int], period: int, n: int = 29) -> float:
    """
    Compute unweighted mean Index of Coincidence across period columns:
    (1 / valid_cols) * sum_{r=0}^{p-1} [ sum_x f_{r,x} * (f_{r,x} - 1) / (n_r * (n_r - 1)) ].
    Columns with n_r < 2 are skipped; returns 0.0 if none remain.
    """
    col_iocs, _ = _columnar_stats(indices, period)
    if not col_iocs:
        return 0.0
    return sum(col_iocs) / len(col_iocs)


def passes_sinkov_columnar_ioc_gate(
    indices: Sequence[int],
    period: int,
    expected_ioc: float = 0.066,
    sigma_threshold: float = 2.0,
    min_per_col: int = 12,
    n: int = 29,
) -> Tuple[bool, float, float]:
    """
    Sinkov columnar Index-of-Coincidence pre-gate for unconstrained periodic search.
    Returns (passed, mean_ioc, threshold); never prunes period <= 1 or N/p < min_per_col.
    """
    col_iocs, n_pairs = _columnar_stats(indices, period)
    mean_ioc = (sum(col_iocs) / len(col_iocs)) if col_iocs else 0.0
    if period <= 1 or (len(indices) / period) < min_per_col:
        return (True, mean_ioc, 0.0)

    se = math.sqrt(max(0.0, expected_ioc * (1.0 - expected_ioc)) / max(1, n_pairs))
    threshold = expected_ioc - sigma_threshold * se
    return (mean_ioc >= threshold, round(mean_ioc, 5), round(threshold, 5))
