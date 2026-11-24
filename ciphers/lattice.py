"""
Lattice Reduction, Coppersmith Small Roots, and Lattice-Based Cryptanalysis.

Provides pure-Python standard-library implementations of:
1. Exact Gram-Schmidt orthogonalization and Lenstra-Lenstra-Lovasz (LLL) basis reduction
   (with Lovasz parameter delta=0.99, supporting dimensions up to 40+).
2. Univariate Coppersmith small roots over modular polynomials via Howgrave-Graham shifts.
3. Knapsack / Subset-Sum solver using the Lagarias-Odlyzko (LO) / CJLOSS lattice formulation,
   specifically optimized for Cicada 3301 Gematria Primus prime weights.
4. Integer relations finder (PSLQ analogue) via lattice reduction.
"""

from fractions import Fraction
import math
from typing import List, Tuple, Optional, Union, Dict, Any

# First 29 Gematria Primus prime weights
GEMATRIA_PRIMUS_PRIMES: List[int] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109
]

# Futhorc runes corresponding to indices 0..28
FUTHORC_RUNES: List[str] = [
    "ᚠ", "ᚢ", "ᚦ", "ᚩ", "ᚱ", "ᚳ", "ᚷ", "ᚹ", "ᚻ", "ᚾ", "ᛁ", "ᛄ", "ᛇ", "ᛈ", "ᛉ",
    "ᛋ", "ᛏ", "ᛒ", "ᛖ", "ᛗ", "ᛚ", "ᛝ", "ᛟ", "ᛞ", "ᚪ", "ᚫ", "ᚣ", "ᛡ", "ᛠ"
]


# =============================================================================
# 1. Gram-Schmidt Orthogonalization & LLL Basis Reduction
# =============================================================================

def gram_schmidt(
    basis: List[List[Union[int, float, Fraction]]],
    exact: bool = True
) -> Tuple[List[List[Fraction]], List[List[Fraction]]]:
    """
    Computes exact Gram-Schmidt orthogonalization of an input basis B.
    B* = [b_0*, b_1*, ..., b_{n-1}*]
    mu_{i, j} = <b_i, b_j*> / ||b_j*||^2

    Args:
        basis: List of basis vectors (each a list of ints, floats, or Fractions).
        exact: If True, uses exact fractions.Fraction arithmetic.

    Returns:
        (b_star, mu): Orthogonalized vectors and Gram-Schmidt projection coefficients.
    """
    if not basis:
        return [], []

    n = len(basis)
    m = len(basis[0])
    b_star: List[List[Fraction]] = []
    mu: List[List[Fraction]] = [[Fraction(0) for _ in range(n)] for _ in range(n)]
    b_norms: List[Fraction] = [Fraction(0)] * n

    for i in range(n):
        v = [Fraction(x) for x in basis[i]]
        for j in range(i):
            if b_norms[j] != 0:
                dot = sum(Fraction(basis[i][c]) * b_star[j][c] for c in range(m))
                mu_ij = dot / b_norms[j]
            else:
                mu_ij = Fraction(0)
            mu[i][j] = mu_ij
            for c in range(m):
                v[c] -= mu_ij * b_star[j][c]
        b_star.append(v)
        b_norms[i] = sum(x * x for x in v)
        mu[i][i] = Fraction(1)

    return b_star, mu


def lll_reduction(
    basis: List[List[Union[int, float]]],
    delta: Union[float, Fraction] = 0.99
) -> List[List[int]]:
    """
    Lenstra-Lenstra-Lovasz (LLL) lattice basis reduction.
    Transforms the input lattice basis into an LLL-reduced basis satisfying:
    1. Size condition: |mu_{i, j}| <= 1/2 for all j < i.
    2. Lovasz condition: ||b_k*||^2 >= (delta - mu_{k, k-1}^2) * ||b_{k-1}*||^2.

    Supports dimension up to 40+ with fast local Gram-Schmidt updates.

    Args:
        basis: Matrix of linearly independent rows representing lattice basis.
        delta: Lovasz reduction parameter (0.25 < delta <= 1.0, default 0.99).

    Returns:
        List of reduced basis vectors with integer coordinates.
    """
    if not basis:
        return []

    n = len(basis)
    m = len(basis[0])
    b = [[int(x) for x in row] for row in basis]

    delta_f = Fraction(delta).limit_denominator(10000)

    # Initial Gram-Schmidt initialization
    b_star: List[List[Fraction]] = []
    mu: List[List[Fraction]] = [[Fraction(0) for _ in range(n)] for _ in range(n)]
    b_norm: List[Fraction] = [Fraction(0)] * n

    for i in range(n):
        v = [Fraction(x) for x in b[i]]
        for j in range(i):
            if b_norm[j] != 0:
                dot = sum(Fraction(b[i][c]) * b_star[j][c] for c in range(m))
                mu[i][j] = dot / b_norm[j]
            else:
                mu[i][j] = Fraction(0)
            for c in range(m):
                v[c] -= mu[i][j] * b_star[j][c]
        b_star.append(v)
        b_norm[i] = sum(x * x for x in v)
        mu[i][i] = Fraction(1)

    k = 1
    while k < n:
        # Size reduction of b[k] against b[j] for j = k-1 down to 0
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = round(mu[k][j])
                for c in range(m):
                    b[k][c] -= q * b[j][c]
                for l in range(j):
                    mu[k][l] -= q * mu[j][l]
                mu[k][j] -= q

        # Lovasz condition check
        lovasz_rhs = (delta_f - mu[k][k - 1] ** 2) * b_norm[k - 1]
        if b_norm[k] >= lovasz_rhs:
            k += 1
        else:
            # Swap b[k] and b[k - 1]
            b[k], b[k - 1] = b[k - 1], b[k]

            # Fast local update of Gram-Schmidt vectors and coefficients
            nu = mu[k][k - 1]
            b_norm_new = b_norm[k] + nu * nu * b_norm[k - 1]

            if b_norm_new == 0:
                mu_prime = Fraction(0)
            else:
                mu_prime = nu * b_norm[k - 1] / b_norm_new

            b_star_k_minus_1 = [b_star[k][c] + nu * b_star[k - 1][c] for c in range(m)]
            b_star_k = [b_star[k - 1][c] - mu_prime * b_star_k_minus_1[c] for c in range(m)]

            b_star[k - 1] = b_star_k_minus_1
            b_star[k] = b_star_k

            if b_norm_new == 0:
                b_norm[k] = Fraction(0)
                b_norm[k - 1] = Fraction(0)
            else:
                b_norm[k] = b_norm[k - 1] * b_norm[k] / b_norm_new
                b_norm[k - 1] = b_norm_new

            for j in range(k - 1):
                mu[k - 1][j], mu[k][j] = mu[k][j], mu[k - 1][j]
            mu[k][k - 1] = mu_prime

            for i in range(k + 1, n):
                t = mu[i][k - 1]
                mu[i][k - 1] = mu_prime * t + (Fraction(1) - nu * mu_prime) * mu[i][k]
                mu[i][k] = t - nu * mu[i][k]

            k = max(k - 1, 1)

    return b


# Convenience alias
lll = lll_reduction


# =============================================================================
# 2. Polynomial Arithmetic & Root Isolation Helpers
# =============================================================================

def poly_eval(poly: List[int], x: Union[int, Fraction, float]) -> Union[int, Fraction, float]:
    """Evaluate univariate polynomial p(x) = sum(poly[i] * x^i) using Horner's method."""
    res = poly[-1] if poly else 0
    for c in reversed(poly[:-1]):
        res = res * x + c
    return res


def poly_mul(p: List[int], q: List[int]) -> List[int]:
    """Multiply two univariate polynomials with coefficients ordered by ascending degree."""
    if not p or not q:
        return [0]
    res = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        if a == 0:
            continue
        for j, b in enumerate(q):
            res[i + j] += a * b
    return res


def poly_pow(p: List[int], exp: int) -> List[int]:
    """Exponentiate a polynomial to a non-negative integer power using binary ladder."""
    if exp == 0:
        return [1]
    res = [1]
    base = list(p)
    while exp > 0:
        if exp % 2 == 1:
            res = poly_mul(res, base)
        base = poly_mul(base, base)
        exp //= 2
    return res


def poly_deriv(p: List[int]) -> List[int]:
    """Compute formal derivative of polynomial p(x)."""
    if len(p) <= 1:
        return [0]
    return [i * c for i, c in enumerate(p)][1:]


def _find_real_roots_recursive(p: List[int], lo: float, hi: float) -> List[float]:
    """
    Finds real roots of polynomial p(x) in [lo, hi] by recursively partitioning
    monotonic intervals via roots of derivative p'(x).
    """
    while len(p) > 1 and p[-1] == 0:
        p = p[:-1]
    if len(p) <= 1:
        return []
    if len(p) == 2:
        r = -p[0] / p[1]
        return [r] if lo <= r <= hi else []

    dp = poly_deriv(p)
    extrema = _find_real_roots_recursive(dp, lo, hi)
    crit = [lo] + [x for x in extrema if lo < x < hi] + [hi]
    crit.sort()

    roots: List[float] = []
    for i in range(len(crit) - 1):
        x1, x2 = crit[i], crit[i + 1]
        if x2 - x1 < 1e-12:
            continue
        y1, y2 = poly_eval(p, x1), poly_eval(p, x2)
        if abs(y1) < 1e-12:
            roots.append(x1)
            continue
        if y1 * y2 <= 0:
            a, b = x1, x2
            for _ in range(60):
                mid = (a + b) / 2.0
                if poly_eval(p, mid) * y1 <= 0:
                    b = mid
                else:
                    a = mid
            roots.append((a + b) / 2.0)

    return sorted(list(set(roots)))


def find_integer_roots(poly: List[int], bound: int) -> List[int]:
    """
    Finds all integer roots of p(x) = 0 within [-bound, bound].
    Removes common integer content (content/GCD) and uses root isolation.
    """
    while len(poly) > 1 and poly[-1] == 0:
        poly = poly[:-1]
    if not poly or (len(poly) == 1 and poly[0] != 0):
        return []

    # Divide out integer GCD
    g = 0
    for c in poly:
        g = math.gcd(g, c)
    if g > 1:
        poly = [c // g for c in poly]

    roots: List[int] = []

    # Check root at 0
    if poly[0] == 0:
        roots.append(0)
        while len(poly) > 1 and poly[0] == 0:
            poly = poly[1:]
        if len(poly) <= 1:
            return roots

    # Check small bounds directly
    if bound <= 200:
        for x in range(-bound, bound + 1):
            if x not in roots and poly_eval(poly, x) == 0:
                roots.append(x)
        return sorted(roots)

    # Use derivative root isolation
    real_cands = _find_real_roots_recursive(poly, -float(bound), float(bound))
    for r in real_cands:
        ir = round(r)
        if abs(ir) <= bound and ir not in roots:
            if poly_eval(poly, ir) == 0:
                roots.append(ir)

    # Check rational root candidates if constant term is small
    c0 = abs(poly[0])
    if c0 > 0 and c0 <= 100000:
        divs = set()
        for d in range(1, math.isqrt(c0) + 1):
            if c0 % d == 0:
                divs.add(d)
                divs.add(c0 // d)
        for d in divs:
            for cand in (d, -d):
                if abs(cand) <= bound and cand not in roots:
                    if poly_eval(poly, cand) == 0:
                        roots.append(cand)

    return sorted(roots)


# =============================================================================
# 3. Coppersmith Small Roots via Howgrave-Graham Shifts
# =============================================================================

def coppersmith_small_roots(
    poly: List[int],
    modulus: int,
    beta: float = 1.0,
    root_bound: Optional[int] = None,
    max_degree: Optional[int] = None
) -> List[int]:
    """
    Univariate Coppersmith small roots algorithm via Howgrave-Graham shifts.
    Finds integer roots |x_0| <= root_bound of f(x) == 0 (mod b), where b >= N^beta is a divisor of N.
    By default beta=1.0 (roots modulo N).

    Args:
        poly: Coefficients of f(x) in ascending degree [a_0, a_1, ..., a_d].
        modulus: The RSA / composite modulus N.
        beta: Parameter beta in (0, 1.0] specifying factor bound N^beta (default: 1.0).
        root_bound: Upper bound X on root magnitude |x_0|. If None, set to floor(N^(beta^2 / d - epsilon)).
        max_degree: Optional cap on lattice dimension / shift parameter m.

    Returns:
        Sorted list of integer roots x_0 satisfying f(x_0) == 0 mod N (or mod b) and |x_0| <= root_bound.
    """
    # Clean leading zeroes
    p = list(poly)
    while len(p) > 1 and p[-1] == 0:
        p.pop()

    d = len(p) - 1
    if d <= 0:
        return []

    # Make monic modulo N if leading coefficient invertible
    a_d = p[-1] % modulus
    g = math.gcd(a_d, modulus)
    if g == 1:
        inv_ad = pow(a_d, -1, modulus)
        f = [(c * inv_ad) % modulus for c in p]
        f[-1] = 1
    else:
        # If leading coefficient shares a factor with N
        f = [c % modulus for c in p]

    # Theoretical root bound X
    if root_bound is None:
        # Standard Coppersmith bound: X < N^(beta^2 / d)
        exponent = (beta * beta) / d
        root_bound = int(modulus ** exponent) if exponent < 1 else modulus

    X = max(1, root_bound)

    # Shift parameter m: default 2 or 3 for small degree
    m = max(1, min(max_degree if max_degree else 3, int(math.ceil(1.0 / (d * 0.15)))))

    # Howgrave-Graham shift polynomials:
    # g_{i, j}(x) = x^j * N^(m - i) * f(x)^i for i = 0..m-1, j = 0..d-1
    # and g_{m, j}(x) = x^j * f(x)^m for j = 0..t-1 (t = max(1, d))
    shift_polys: List[List[int]] = []
    for i in range(m + 1):
        f_pow_i = poly_pow(f, i)
        max_j = d if i < m else 1
        for j in range(max_j):
            coeff_scale = modulus ** (m - i)
            # x^j * coeff_scale * f_pow_i(x)
            shifted = [0] * j + [c * coeff_scale for c in f_pow_i]
            shift_polys.append(shifted)

    dim = max(len(sp) for sp in shift_polys)
    # Build lattice matrix: row i has coefficients of shift_polys[i](x * X)
    matrix: List[List[int]] = []
    for sp in shift_polys:
        row = [0] * dim
        for idx, c in enumerate(sp):
            row[idx] = c * (X ** idx)
        matrix.append(row)

    # Run LLL basis reduction
    reduced = lll_reduction(matrix, delta=0.99)

    # Shortest non-zero vector in reduced basis
    valid_roots = set()
    for row in reduced:
        if all(x == 0 for x in row):
            continue
        # Unscale coefficients: h_k = row[k] / X^k
        h = [row[k] // (X ** k) for k in range(dim)]
        cands = find_integer_roots(h, X)
        for r in cands:
            # Check modulo condition
            val = poly_eval(p, r)
            if beta == 1.0:
                if val % modulus == 0:
                    valid_roots.add(r)
            else:
                divisor_cand = math.gcd(val, modulus)
                if divisor_cand >= modulus ** beta:
                    valid_roots.add(r)
        if valid_roots:
            break

    return sorted(list(valid_roots))


# =============================================================================
# 4. Knapsack / Subset-Sum (Lagarias-Odlyzko / CJLOSS)
# =============================================================================

def solve_knapsack_subset_sum(
    weights: List[int],
    target: int
) -> Optional[List[int]]:
    """
    Solves the subset-sum / knapsack problem using the CJLOSS lattice reduction formulation:
    Given weights w = [w_1, ..., w_n] and target S, finds e in {0, 1}^n such that
    sum(e_i * w_i) == target.

    Lattice basis of dimension n + 1:
        Row i (0 <= i < n): [0, ..., 2, ..., 0, N * w_i]
        Row n:             [1, ..., 1, ..., 1, N * target]
    where N > 1/2 * sqrt(n) is an integer multiplier.

    Args:
        weights: List of positive integer weights (e.g. Gematria Primus primes).
        target: Target sum.

    Returns:
        List of selected weights that sum to target, or None if no solution found.
    """
    if target == 0:
        return []

    # Quick check for exact single elements or negative/overflow target
    if target in weights:
        return [target]

    total_weight = sum(weights)
    if target < 0 or target > total_weight:
        return None

    n = len(weights)
    N = max(100, 2 * int(math.ceil(math.sqrt(n))) + 10)

    # Construct CJLOSS basis matrix
    matrix: List[List[int]] = []
    for i in range(n):
        row = [0] * (n + 1)
        row[i] = 2
        row[-1] = N * weights[i]
        matrix.append(row)

    last_row = [1] * n + [N * target]
    matrix.append(last_row)

    reduced = lll_reduction(matrix, delta=0.99)

    for row in reduced:
        if row[-1] == 0:
            coords = row[:n]
            if all(abs(c) == 1 for c in coords):
                # Candidate 1: e_i = (c_i + 1) // 2
                cand1 = [(c + 1) // 2 for c in coords]
                if sum(w * e for w, e in zip(weights, cand1)) == target:
                    return [w for w, e in zip(weights, cand1) if e == 1]

                # Candidate 2: e_i = (-c_i + 1) // 2
                cand2 = [(-c + 1) // 2 for c in coords]
                if sum(w * e for w, e in zip(weights, cand2)) == target:
                    return [w for w, e in zip(weights, cand2) if e == 1]

    # Deterministic fallback for small n (<= 24) or dense instances
    if n <= 24:
        def _backtrack(idx: int, cur_sum: int, path: List[int]) -> Optional[List[int]]:
            if cur_sum == target:
                return path
            if idx >= n or cur_sum > target:
                return None
            with_idx = _backtrack(idx + 1, cur_sum + weights[idx], path + [weights[idx]])
            if with_idx is not None:
                return with_idx
            return _backtrack(idx + 1, cur_sum, path)

        return _backtrack(0, 0, [])

    return None


def solve_gematria_subset_sum(target: int) -> Optional[List[str]]:
    """
    Finds a combination of Gematria Primus Futhorc runes whose prime values
    sum exactly to target.

    Returns:
        List of Futhorc runes summing to target, or None if no combination exists.
    """
    prime_to_rune = {p: r for p, r in zip(GEMATRIA_PRIMUS_PRIMES, FUTHORC_RUNES)}
    selected_primes = solve_knapsack_subset_sum(GEMATRIA_PRIMUS_PRIMES, target)
    if selected_primes is None:
        return None
    return [prime_to_rune[p] for p in selected_primes]


# =============================================================================
# 5. Integer Relations Finder (PSLQ Analogue via LLL)
# =============================================================================

def find_integer_relations(
    values: List[float],
    scale: int = 10**6,
    tolerance: float = 1e-4
) -> Optional[List[int]]:
    """
    Finds non-trivial integer relations m = [m_1, ..., m_n] such that
    sum(m_i * x_i) == 0 (within tolerance), with small Euclidean norm ||m||.

    Constructs an n x (n+1) lattice:
        Row i: [0, ..., 1, ..., 0, round(scale * values[i])]
    and reduces with LLL.

    Args:
        values: List of real values x_1, ..., x_n.
        scale: Integer magnification factor for real values (default: 10^6).
        tolerance: Allowed residual error for relation check.

    Returns:
        Integer vector [m_1, ..., m_n], or None if no non-trivial relation found.
    """
    n = len(values)
    if n < 2:
        return None

    # Scaled integer values
    scaled_vals = [round(v * scale) for v in values]

    matrix: List[List[int]] = []
    for i in range(n):
        row = [0] * (n + 1)
        row[i] = 1
        row[-1] = scaled_vals[i]
        matrix.append(row)

    reduced = lll_reduction(matrix, delta=0.99)

    for row in reduced:
        coeffs = row[:n]
        if all(c == 0 for c in coeffs):
            continue

        dot_product = sum(c * v for c, v in zip(coeffs, values))
        if abs(dot_product) <= tolerance:
            # Canonicalize sign: make first non-zero coefficient positive
            first_nz = next(c for c in coeffs if c != 0)
            if first_nz < 0:
                coeffs = [-c for c in coeffs]
            return coeffs

    return None
