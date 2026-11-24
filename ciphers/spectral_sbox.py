"""
Spectral, Differential & Nonlinear S-Box Analysis over F_29.
Standard library only: math, cmath, typing. Zero external dependencies.

Implements S-box generators over F_29 and comprehensive cryptographic diagnostics:
- Generators: Affine Inversion, Mobius Maps on P^1(F_29), Power Maps, and Double-Affine Composition.
- Diagnostics: Difference Distribution Table (DDT) & Differential Uniformity for Z_29 and bitwise XOR,
  Fast Walsh-Hadamard Transform (FWHT), Linear Approximation Table (LAT), Nonlinearity (NL),
  Strict Avalanche Criterion (SAC), Algebraic Degree (AD), DFT bias over Z_29, and
  Linear Hull Potential via correlation matrix powers C^r.
"""

from __future__ import annotations

import cmath
import math
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

DEFAULT_MODULUS = 29


# =====================================================================
# S-Box Generators over F_29
# =====================================================================

def affine_inversion_sbox(a: int = 1, b: int = 0, modulus: int = DEFAULT_MODULUS) -> List[int]:
    """
    Generate an S-box via affine inversion over F_p:
        S(x) = (a * x^-1 + b) mod p, with 0^-1 := 0.
    Requires gcd(a, p) == 1.
    """
    a_mod = a % modulus
    if a_mod == 0:
        raise ValueError("Linear coefficient 'a' cannot be 0 mod modulus")
    b_mod = b % modulus

    sbox = [0] * modulus
    for x in range(modulus):
        if x == 0:
            x_inv = 0
        else:
            x_inv = pow(x, modulus - 2, modulus)
        sbox[x] = (a_mod * x_inv + b_mod) % modulus
    return sbox


def mobius_sbox(a: int, b: int, c: int, d: int, modulus: int = DEFAULT_MODULUS) -> List[int]:
    """
    Generate an S-box via Mobius transformation on P^1(F_p) mapped to a bijection on F_p:
        S(x) = (a * x + b) * (c * x + d)^-1 mod p.
    Boundary condition on pole:
        When cx + d == 0 mod p, S(x) := (a * c^-1) mod p.
    Requires non-singular determinant: (ad - bc) mod p != 0.
    """
    det = (a * d - b * c) % modulus
    if det == 0:
        raise ValueError(f"Mobius transformation is singular: ad - bc == 0 mod {modulus}")

    c_mod = c % modulus
    if c_mod == 0:
        # cx + d == d != 0 for all x
        d_inv = pow(d % modulus, modulus - 2, modulus)
        return [((a * x + b) * d_inv) % modulus for x in range(modulus)]

    c_inv = pow(c_mod, modulus - 2, modulus)
    pole_value = (a * c_inv) % modulus

    sbox = [0] * modulus
    for x in range(modulus):
        denom = (c * x + d) % modulus
        if denom == 0:
            sbox[x] = pole_value
        else:
            denom_inv = pow(denom, modulus - 2, modulus)
            sbox[x] = ((a * x + b) * denom_inv) % modulus
    return sbox


def power_map_sbox(k: int, modulus: int = DEFAULT_MODULUS) -> List[int]:
    """
    Generate an S-box via power map over F_p:
        S(x) = x^k mod p, with 0^k := 0.
    Permutation condition requires gcd(k, p - 1) == 1.
    """
    order = modulus - 1
    if math.gcd(k, order) != 1:
        raise ValueError(f"Exponent k={k} is not coprime to {modulus}-1={order}; map is not a permutation")

    sbox = [0] * modulus
    for x in range(modulus):
        if x == 0:
            sbox[x] = 0
        else:
            sbox[x] = pow(x, k, modulus)
    return sbox


def double_affine_sbox(
    sbox: Sequence[int],
    a1: int = 1,
    b1: int = 0,
    a2: int = 1,
    b2: int = 0,
    modulus: int = DEFAULT_MODULUS,
) -> List[int]:
    """
    Compose an S-box with input and output affine transformations:
        S'(x) = A2(S(A1(x))) = (a2 * S((a1 * x + b1) mod p) + b2) mod p.
    Requires gcd(a1, p) == 1 and gcd(a2, p) == 1.
    """
    if a1 % modulus == 0 or a2 % modulus == 0:
        raise ValueError("Affine multipliers a1 and a2 must be coprime to modulus")

    res = [0] * modulus
    for x in range(modulus):
        in_x = (a1 * x + b1) % modulus
        out_s = sbox[in_x]
        res[x] = (a2 * out_s + b2) % modulus
    return res


# =====================================================================
# Cryptographic Diagnostics
# =====================================================================

def difference_distribution_table(
    sbox: Sequence[int],
    mode: str = "z29",
    modulus: int = DEFAULT_MODULUS,
    embed_power_of_2: bool = True,
) -> List[List[int]]:
    """
    Compute Difference Distribution Table (DDT).
    Modes:
      - 'z29': Additive differences over Z_p: S((x + din) % p) - S(x) == dout (mod p).
      - 'xor': Bitwise XOR differences: S(x ^ din) ^ S(x) == dout.
               When embed_power_of_2 is True, pads S with identity to 2^ceil(log2(N)) (32 for 29).
    """
    mode_lower = mode.lower()
    if mode_lower in ("z29", "zp", "additive", "mod"):
        p = modulus
        ddt = [[0] * p for _ in range(p)]
        for din in range(p):
            for x in range(p):
                dout = (sbox[(x + din) % p] - sbox[x]) % p
                ddt[din][dout] += 1
        return ddt

    elif mode_lower in ("xor", "bitwise"):
        n_orig = len(sbox)
        if embed_power_of_2:
            n_bits = math.ceil(math.log2(max(n_orig, 2)))
            dim = 1 << n_bits
            # Identity extension for out-of-range elements
            s_ext = list(sbox) + list(range(n_orig, dim))
        else:
            dim = n_orig
            s_ext = list(sbox)

        ddt = [[0] * dim for _ in range(dim)]
        for din in range(dim):
            for x in range(dim):
                x_prime = x ^ din
                if x_prime < len(s_ext):
                    dout = s_ext[x_prime] ^ s_ext[x]
                    if dout < dim:
                        ddt[din][dout] += 1
        return ddt

    else:
        raise ValueError(f"Unknown DDT mode '{mode}'. Choose 'z29' or 'xor'.")


compute_ddt = difference_distribution_table


def differential_uniformity(ddt_matrix: Sequence[Sequence[int]]) -> int:
    """
    Compute differential uniformity delta:
        delta = max_{din != 0, dout} DDT[din][dout]
    """
    max_val = 0
    num_rows = len(ddt_matrix)
    for din in range(1, num_rows):
        row = ddt_matrix[din]
        for dout_val in row:
            if dout_val > max_val:
                max_val = dout_val
    return max_val


compute_differential_uniformity = differential_uniformity


def fast_walsh_hadamard_transform(f: Sequence[Union[int, float]]) -> List[Union[int, float]]:
    """
    Compute Fast Walsh-Hadamard Transform (FWHT) of sequence f via butterfly network.
    Length of f is padded with 0 to the next power of 2 if necessary.
    """
    n = len(f)
    if n == 0:
        return []

    # Round up to next power of 2
    power = 1 << (n - 1).bit_length()
    res: List[Union[int, float]] = list(f) + [0] * (power - n)

    h = 1
    while h < power:
        for i in range(0, power, h * 2):
            for j in range(i, i + h):
                u = res[j]
                v = res[j + h]
                res[j] = u + v
                res[j + h] = u - v
        h *= 2
    return res


fwht = fast_walsh_hadamard_transform


def linear_approximation_table(
    sbox: Sequence[int],
    mode: str = "binary",
) -> List[List[int]]:
    """
    Compute Linear Approximation Table (LAT) using FWHT.
    For 5-bit representation (dim=32), embeds S-box with identity padding.
    LAT[a][b] = #{x : a . x == b . S(x)} - 2^{n-1}.
    LAT[a][b] = W_{b . S}(a) // 2.
    """
    n_orig = len(sbox)
    n_bits = math.ceil(math.log2(max(n_orig, 2)))
    dim = 1 << n_bits
    s_ext = list(sbox) + list(range(n_orig, dim))

    lat: List[List[int]] = [[0] * dim for _ in range(dim)]

    for b in range(dim):
        # Component function g_b(x) = parity(b & S(x))
        # Vector v[x] = (-1)^(b . S(x)) : +1 if 0, -1 if 1
        v = [1 if (bin(b & s_ext[x]).count("1") % 2 == 0) else -1 for x in range(dim)]
        w = fast_walsh_hadamard_transform(v)
        for a in range(dim):
            lat[a][b] = int(w[a]) // 2

    return lat


compute_lat = linear_approximation_table
lat = linear_approximation_table


def nonlinearity(sbox: Sequence[int]) -> int:
    """
    Compute the nonlinearity of the S-box:
        NL(S) = 2^{n-1} - max_{a, b != 0} |LAT[a][b]|
    """
    lat_table = linear_approximation_table(sbox)
    dim = len(lat_table)
    half_dim = dim // 2

    max_lat = 0
    for a in range(dim):
        for b in range(1, dim):
            val = abs(lat_table[a][b])
            if val > max_lat:
                max_lat = val

    return half_dim - max_lat


compute_nonlinearity = nonlinearity


def strict_avalanche_criterion(sbox: Sequence[int]) -> Dict[str, Any]:
    """
    Compute Strict Avalanche Criterion (SAC) matrix and deviation metrics.
    For each input bit i and output bit j:
        SAC[i][j] = P(S_j(x ^ e_i) != S_j(x)).
    An ideal S-box has SAC[i][j] == 0.5 for all i, j.
    """
    n_orig = len(sbox)
    n_bits = math.ceil(math.log2(max(n_orig, 2)))
    dim = 1 << n_bits
    s_ext = list(sbox) + list(range(n_orig, dim))

    sac_matrix = [[0.0] * n_bits for _ in range(n_bits)]
    total_dev = 0.0
    max_dev = 0.0

    for i in range(n_bits):
        e_i = 1 << i
        for j in range(n_bits):
            flips = 0
            for x in range(dim):
                bit_before = (s_ext[x] >> j) & 1
                bit_after = (s_ext[x ^ e_i] >> j) & 1
                if bit_before != bit_after:
                    flips += 1
            prob = flips / float(dim)
            sac_matrix[i][j] = prob
            dev = abs(prob - 0.5)
            total_dev += dev
            if dev > max_dev:
                max_dev = dev

    mean_dev = total_dev / (n_bits * n_bits)
    return {
        "matrix": sac_matrix,
        "max_deviation": max_dev,
        "mean_deviation": mean_dev,
        "num_bits": n_bits,
        "satisfies_strict_sac": max_dev == 0.0,
    }


compute_sac = strict_avalanche_criterion


def algebraic_degree(sbox: Sequence[int]) -> int:
    """
    Compute overall Algebraic Degree (AD) of the S-box:
        AD(S) = max_j deg(S_j),
    where S_j are the coordinate Boolean functions.
    """
    degs = algebraic_degrees(sbox)
    return max(degs) if degs else 0


compute_algebraic_degree = algebraic_degree


def algebraic_degrees(sbox: Sequence[int]) -> List[int]:
    """
    Compute algebraic degree of each coordinate function S_j(x).
    Uses Fast Reed-Muller / Mobius transform over GF(2).
    """
    n_orig = len(sbox)
    n_bits = math.ceil(math.log2(max(n_orig, 2)))
    dim = 1 << n_bits
    s_ext = list(sbox) + list(range(n_orig, dim))

    degrees: List[int] = []
    for j in range(n_bits):
        tt = [(s_ext[x] >> j) & 1 for x in range(dim)]
        # Fast Mobius inversion over GF(2)
        anf = list(tt)
        h = 1
        while h < dim:
            for i in range(0, dim, h * 2):
                for k in range(i, i + h):
                    anf[k + h] ^= anf[k]
            h *= 2

        deg = 0
        for u, coeff in enumerate(anf):
            if coeff != 0:
                wt = bin(u).count("1")
                if wt > deg:
                    deg = wt
        degrees.append(deg)

    return degrees


def dft_bias_z29(sbox: Sequence[int], modulus: int = DEFAULT_MODULUS) -> Dict[str, Any]:
    """
    Compute Discrete Fourier Transform (DFT) bias metrics over Z_p (default p=29):
    1. 1D DFT: F[k] = sum_{x=0}^{p-1} S(x) * exp(-2*pi*i*k*x / p).
       Measures AC harmonic spectral bias.
    2. 2D Walsh-Fourier Character Sums: W[a][b] = sum_{x=0}^{p-1} exp(2*pi*i*(a*x + b*S(x)) / p).
       Measures maximum nonlinear/spectral character bias over Z_p.
    """
    p = modulus
    # 1D DFT
    dft_1d: List[complex] = []
    for k in range(p):
        val = sum(sbox[x % len(sbox)] * cmath.exp(-2j * math.pi * k * x / p) for x in range(p))
        dft_1d.append(val)

    max_bias_1d = max((abs(dft_1d[k]) for k in range(1, p)), default=0.0)

    # 2D Character sums W[a][b]
    max_bias_2d = 0.0
    best_pair = (0, 0)
    for a in range(p):
        for b in range(1, p):
            val = abs(sum(cmath.exp(2j * math.pi * (a * x + b * sbox[x % len(sbox)]) / p) for x in range(p)))
            if val > max_bias_2d:
                max_bias_2d = val
                best_pair = (a, b)

    normalized_bias_2d = max_bias_2d / float(p)
    theoretical_bent_bound = math.sqrt(p)

    return {
        "max_bias_1d": max_bias_1d,
        "max_bias_2d": max_bias_2d,
        "normalized_bias_2d": normalized_bias_2d,
        "best_spectral_pair": best_pair,
        "theoretical_bent_bound": theoretical_bent_bound,
        "dft_1d": dft_1d,
    }


compute_dft_bias_z29 = dft_bias_z29


class LinearHullPotentialResult(list):
    """
    Result container for linear hull potentials.
    Inherits from list so it can be indexed directly as result[in_mask][out_mask],
    while also exposing attributes potential_matrix, correlation_matrix, max_potential.
    """

    def __init__(
        self,
        potential_matrix: List[List[float]],
        correlation_matrix: List[List[float]],
        rounds: int,
        max_potential: float,
        best_pair: Tuple[int, int],
    ):
        super().__init__(potential_matrix)
        self.potential_matrix = potential_matrix
        self.correlation_matrix = correlation_matrix
        self.rounds = rounds
        self.max_potential = max_potential
        self.best_pair = best_pair


def compute_linear_hull_potential(
    lat_matrix: Sequence[Sequence[Union[int, float]]],
    rounds: int,
    input_mask: Optional[int] = None,
    output_mask: Optional[int] = None,
) -> Any:
    """
    Compute linear hull potential via correlation matrix powers C^r.
    Given LAT matrix, normalizes to correlation matrix C where C[a][b] = 2 * LAT[a][b] / dim.
    Then computes C^r via binary exponentiation.
    Hull potential ALH(a, b) = (C^r[a][b])^2.

    If input_mask and output_mask are given, returns float ALH[input_mask][output_mask].
    Otherwise returns LinearHullPotentialResult matrix.
    """
    dim = len(lat_matrix)
    if dim == 0:
        return 0.0 if (input_mask is not None and output_mask is not None) else []

    # Normalization factor
    c00 = float(lat_matrix[0][0])
    if c00 > 1.0:
        norm = c00
    else:
        norm = 1.0

    C = [[float(lat_matrix[i][j]) / norm for j in range(dim)] for i in range(dim)]

    # Matrix power C^r via binary exponentiation
    def matmul(A: List[List[float]], B: List[List[float]]) -> List[List[float]]:
        return [[sum(A[i][k] * B[k][j] for k in range(dim)) for j in range(dim)] for i in range(dim)]

    res = [[1.0 if i == j else 0.0 for j in range(dim)] for i in range(dim)]
    base = [row[:] for row in C]
    p = rounds
    while p > 0:
        if p % 2 == 1:
            res = matmul(res, base)
        base = matmul(base, base)
        p //= 2

    # Linear hull potential: square of correlation
    potentials = [[res[i][j] ** 2 for j in range(dim)] for i in range(dim)]

    if input_mask is not None and output_mask is not None:
        return potentials[input_mask][output_mask]

    # Find maximum non-trivial potential (ignoring 0 -> 0)
    max_pot = 0.0
    best_pair = (0, 0)
    for i in range(dim):
        for j in range(dim):
            if i == 0 and j == 0:
                continue
            if potentials[i][j] > max_pot:
                max_pot = potentials[i][j]
                best_pair = (i, j)

    return LinearHullPotentialResult(
        potential_matrix=potentials,
        correlation_matrix=res,
        rounds=rounds,
        max_potential=max_pot,
        best_pair=best_pair,
    )
