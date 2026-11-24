"""
Difference — Difference-Domain Constraint Solving & Extended Number-Theoretic Sequences.
Standard library only: math, hashlib. Zero external dependencies.

Features:
1. Difference-Domain Representation: Delta_i = (c_i - c_{i-1}) mod 29.
2. Keystream Constraint Satisfaction (CSP): The zero-hole constraint (Delta c_i != 0)
   prunes candidate keystream steps that would produce consecutive duplicate ciphertext.
3. Extended Sacred Number-Theoretic Sequences:
   - Mobius function mu(n)
   - Liouville function lambda(n)
   - Carmichael function lambda_carm(n)
   - Divisor functions sigma(n), d(n), omega(n), Omega(n)
4. Sequence deduplication via SHA-256 fingerprint of first 64 terms.
"""

from __future__ import annotations
import math
import hashlib
from typing import List, Sequence, Tuple, Dict, Any, Optional, Union

N = 29


def to_differences(c: Sequence[int], n: int = N) -> List[int]:
    """Convert symbol sequence to consecutive forward differences Delta_i = (c_{i+1} - c_i) mod n."""
    if len(c) < 2:
        return []
    return [(b - a) % n for a, b in zip(c, c[1:])]


def from_differences(diffs: Sequence[int], initial_symbol: int, n: int = N) -> List[int]:
    """Reconstruct symbol sequence from differences and initial symbol."""
    out = [initial_symbol % n]
    curr = initial_symbol % n
    for d in diffs:
        curr = (curr + d) % n
        out.append(curr)
    return out


def is_keystream_delta_valid(cipher: Sequence[int], key: Sequence[int], n: int = N) -> bool:
    """
    Check if a candidate key satisfies the empirical zero-hole constraint.
    For unsolved Liber Primus, (c_{i+1} - c_i) mod 29 is virtually never 0 (only 86 doublets in 12,956 symbols).
    If a generated candidate ciphertext from this key produces an impossible doublet rate (> 1.5%), reject.
    """
    if len(cipher) < 2:
        return True
    diffs = to_differences(cipher, n=n)
    zero_count = sum(1 for d in diffs if d == 0)
    rate = zero_count / len(diffs)
    # The unsolved pages have doublet rate ~0.66%, uniform random is ~3.45%
    return rate <= 0.015


def difference_ioc(
    runes: Union[str, Sequence[int]],
    lag: int = 1,
    modulus: int = N
) -> float:
    """
    Calculate the Index of Coincidence (IoC) of the difference sequence at given lag:
    Delta_i = (c_{i+lag} - c_i) mod modulus.

    Accepts either:
    - A runic text string (characters mapped via INDEX_BY_RUNE)
    - A sequence of integer symbol values in Z_modulus
    """
    if lag <= 0:
        return 0.0

    symbols: List[int] = []
    if isinstance(runes, str):
        try:
            from ciphers.agrippa import INDEX_BY_RUNE
        except ImportError:
            from agrippa import INDEX_BY_RUNE
        symbols = [INDEX_BY_RUNE[c] for c in runes if c in INDEX_BY_RUNE]
    else:
        symbols = [int(x) % modulus for x in runes]

    n_sym = len(symbols)
    if n_sym <= lag:
        return 0.0

    diffs = [(symbols[i + lag] - symbols[i]) % modulus for i in range(n_sym - lag)]
    n_diff = len(diffs)
    if n_diff < 2:
        return 0.0

    counts: Dict[int, int] = {}
    for d in diffs:
        counts[d] = counts.get(d, 0) + 1

    total = sum(c * (c - 1) for c in counts.values())
    return total / (n_diff * (n_diff - 1))


def _word_pattern(word: Sequence[Any]) -> Tuple[int, ...]:
    """Compute the canonical isomorphism pattern of a word based on first occurrence IDs."""
    seen: Dict[Any, int] = {}
    pattern: List[int] = []
    for item in word:
        if item not in seen:
            seen[item] = len(seen)
        pattern.append(seen[item])
    return tuple(pattern)


def pattern_ioc(words: Union[str, Sequence[Union[str, Sequence[Any]]]]) -> float:
    """
    Calculate the Index of Coincidence over word letter-patterns (isomorphism signatures).
    Measures non-uniformity of word structures across words. Words with identical internal
    repetition structures (e.g. 'THAT' -> (0, 1, 2, 0), 'SEEK' -> (0, 1, 1, 2)) share patterns.

    Accepts:
    - A sequence of word strings or symbol sequences
    - A single text string (tokenized by whitespace and runic/standard punctuation)
    """
    word_list: List[Sequence[Any]] = []
    if isinstance(words, str):
        import re
        tokens = re.split(r'[\s᛫᛬᛭.,;:!?\-/&%§$]+', words)
        word_list = [t for t in tokens if t]
    else:
        word_list = [w for w in words if len(w) > 0]

    n_words = len(word_list)
    if n_words < 2:
        return 0.0

    pattern_counts: Dict[Tuple[int, ...], int] = {}
    for w in word_list:
        pat = _word_pattern(w)
        pattern_counts[pat] = pattern_counts.get(pat, 0) + 1

    total = sum(c * (c - 1) for c in pattern_counts.values())
    return total / (n_words * (n_words - 1))


# =============================================================================
# Sacred Number-Theoretic Sequences
# =============================================================================

def prime_factors_mult(n: int) -> List[int]:
    """Return prime factors of n with multiplicity."""
    if n <= 1:
        return []
    factors = []
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.append(d)
            n //= d
        d += 1
    if n > 1:
        factors.append(n)
    return factors


def mobius(n: int) -> int:
    """
    Mobius function mu(n):
    mu(1) = 1
    mu(n) = 0 if n has a squared prime factor
    mu(n) = (-1)^k if n is product of k distinct prime factors
    """
    if n < 1:
        return 0
    if n == 1:
        return 1
    factors = prime_factors_mult(n)
    # Check for square factor
    if len(factors) != len(set(factors)):
        return 0
    return -1 if (len(factors) % 2 == 1) else 1


def liouville(n: int) -> int:
    """
    Liouville function lambda(n) = (-1)^Omega(n),
    where Omega(n) is the total number of prime factors with multiplicity.
    """
    if n < 1:
        return 0
    if n == 1:
        return 1
    omega = len(prime_factors_mult(n))
    return -1 if (omega % 2 == 1) else 1


def carmichael_lambda(n: int) -> int:
    """
    Carmichael function lambda(n): the smallest m such that a^m = 1 mod n for all gcd(a, n) = 1.
    """
    if n <= 0:
        return 0
    if n in (1, 2):
        return 1
    if n == 4:
        return 2

    # Factor n into prime powers
    factors = prime_factors_mult(n)
    prime_powers: Dict[int, int] = {}
    for p in factors:
        prime_powers[p] = prime_powers.get(p, 0) + 1

    def lambda_prime_power(p: int, k: int) -> int:
        if p == 2:
            if k == 1:
                return 1
            if k == 2:
                return 2
            return 2 ** (k - 2)
        # For odd prime p: lambda(p^k) = phi(p^k) = p^(k-1) * (p - 1)
        return (p ** (k - 1)) * (p - 1)

    lams = [lambda_prime_power(p, k) for p, k in prime_powers.items()]

    def lcm(a: int, b: int) -> int:
        return (a * b) // math.gcd(a, b)

    res = lams[0]
    for val in lams[1:]:
        res = lcm(res, val)
    return res


def sum_divisors(n: int) -> int:
    """Sum of all positive divisors sigma(n)."""
    if n <= 0:
        return 0
    s = 0
    for i in range(1, int(math.isqrt(n)) + 1):
        if n % i == 0:
            s += i
            if i * i != n:
                s += n // i
    return s


def count_divisors(n: int) -> int:
    """Count of positive divisors d(n)."""
    if n <= 0:
        return 0
    c = 0
    for i in range(1, int(math.isqrt(n)) + 1):
        if n % i == 0:
            c += 1
            if i * i != n:
                c += 1
    return c


def omega_distinct(n: int) -> int:
    """Number of distinct prime factors omega(n)."""
    return len(set(prime_factors_mult(n)))


def omega_total(n: int) -> int:
    """Total number of prime factors with multiplicity Omega(n)."""
    return len(prime_factors_mult(n))


def generate_sequence(name: str, length: int, start: int = 1, mod: Optional[int] = N) -> List[int]:
    """
    Generate an arithmetic sequence of specified length.
    Supported names:
    - 'mobius': mu(n) mod 29 (maps -1 to 28)
    - 'liouville': lambda(n) mod 29 (maps -1 to 28)
    - 'carmichael': lambda_carm(n) mod 29
    - 'sigma': sum of divisors sigma(n) mod 29
    - 'divisors_count': d(n) mod 29
    - 'omega_distinct': omega(n) mod 29
    - 'omega_total': Omega(n) mod 29
    """
    seq: List[int] = []
    funcs = {
        "mobius": mobius,
        "liouville": liouville,
        "carmichael": carmichael_lambda,
        "sigma": sum_divisors,
        "divisors_count": count_divisors,
        "omega_distinct": omega_distinct,
        "omega_total": omega_total,
    }
    fn = funcs.get(name.lower())
    if fn is None:
        raise ValueError(f"Unknown sequence: {name}")

    for idx in range(start, start + length):
        val = fn(idx)
        if mod is not None:
            val = val % mod
        seq.append(val)
    return seq


def sequence_fingerprint(seq: Sequence[int], n_terms: int = 64) -> str:
    """Compute SHA-256 fingerprint over first n_terms for sequence deduplication."""
    sub = seq[:n_terms]
    raw = ",".join(str(x) for x in sub)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
