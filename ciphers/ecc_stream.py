"""
ECC Stream — Elliptic Curve Keystream Generator for Liber Primus Cryptanalysis.

Implements pure-Python short Weierstrass elliptic curve arithmetic over prime fields F_p (p >= 5):
    y^2 = x^3 + a*x + b (mod p)

Features:
1. Short Weierstrass curve validation, discriminant computation Delta = -16*(4a^3 + 27b^2) mod p,
   and non-singularity verification (4a^3 + 27b^2 != 0 mod p).
2. Group law operations: affine point addition, doubling, negation, identity (point at infinity O),
   and scalar multiplication (double-and-add).
3. Hasse theorem order bounds (|#E(F_p) - (p + 1)| <= 2*sqrt(p)) and naive point counting for small fields.
4. Deterministic keystream generation: extraction of x(kP) mod 29 and y(kP) mod 29 streams across
   F_29 and Cicada primes (p = 3301, 1033, 761).
5. Streaming encryption / decryption helpers in Futhorc rune space mod 29.
"""

from __future__ import annotations
import math
from typing import List, Optional, Tuple, Union, Dict, Any


def check_non_singular(a: int, b: int, p: int) -> bool:
    """Return True if the curve y^2 = x^3 + ax + b (mod p) is non-singular."""
    return (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p != 0


def curve_discriminant(a: int, b: int, p: int) -> int:
    """
    Compute Weierstrass discriminant Delta = -16 * (4*a^3 + 27*b^2) mod p.
    """
    disc = (-16 * (4 * pow(a, 3, p) + 27 * pow(b, 2, p))) % p
    return disc


def hasse_bounds(p: int) -> Tuple[int, int]:
    """
    Compute Hasse interval [p + 1 - 2*sqrt(p), p + 1 + 2*sqrt(p)] for curve order #E(F_p).
    """
    bound = int(math.floor(2.0 * math.sqrt(p)))
    return (p + 1 - bound, p + 1 + bound)


def check_hasse_bound(order: int, p: int) -> bool:
    """
    Verify whether integer order satisfies Hasse's theorem: (order - (p + 1))^2 <= 4*p.
    """
    diff = order - (p + 1)
    return (diff * diff) <= (4 * p)


def mod_sqrt(n: int, p: int) -> Optional[int]:
    """
    Compute modular square root r such that r^2 = n mod p using Tonelli-Shanks.
    Returns None if n is a quadratic non-residue mod p.
    """
    n = n % p
    if n == 0:
        return 0
    if p == 2:
        return n
    # Euler criterion
    if pow(n, (p - 1) // 2, p) != 1:
        return None

    # Fast path for p = 3 mod 4
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    # Tonelli-Shanks algorithm for p = 1 mod 4
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    # Find quadratic non-residue z
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)

    while True:
        if t == 0:
            return 0
        if t == 1:
            return r

        # Find least i such that t^(2^i) = 1 mod p
        i = 0
        temp = t
        while temp != 1 and i < m:
            temp = pow(temp, 2, p)
            i += 1

        if i == m:
            return None

        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = (t * c) % p
        r = (r * b) % p


Point = Optional[Tuple[int, int]]


class EllipticCurve:
    """
    Short Weierstrass Elliptic Curve over prime field F_p:
        y^2 = x^3 + a*x + b (mod p)
    where p >= 5 is prime, and 4a^3 + 27b^2 != 0 (mod p).
    Points are represented as (x, y) tuples, with None denoting the point at infinity O.
    """

    def __init__(self, a: int, b: int, p: int, check_singularity: bool = True):
        if p < 5:
            raise ValueError(f"Prime p must be >= 5 for short Weierstrass form, got {p}")
        self.a = a % p
        self.b = b % p
        self.p = p

        if check_singularity and not check_non_singular(self.a, self.b, self.p):
            raise ValueError(f"Curve y^2 = x^3 + {self.a}x + {self.b} mod {self.p} is singular (Delta = 0 mod p)")

    @property
    def discriminant(self) -> int:
        """Return the discriminant Delta = -16*(4a^3 + 27b^2) mod p."""
        return curve_discriminant(self.a, self.b, self.p)

    def is_on_curve(self, pt: Point) -> bool:
        """Check if point pt is on this curve."""
        if pt is None:
            return True
        x, y = pt
        if not (0 <= x < self.p and 0 <= y < self.p):
            return False
        lhs = pow(y, 2, self.p)
        rhs = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
        return lhs == rhs

    def point_neg(self, pt: Point) -> Point:
        """Return group inverse -P."""
        if pt is None:
            return None
        x, y = pt
        return (x, (-y) % self.p)

    def point_add(self, p1: Point, p2: Point) -> Point:
        """Group addition P1 + P2 on the elliptic curve."""
        if p1 is None:
            return p2
        if p2 is None:
            return p1

        x1, y1 = p1
        x2, y2 = p2
        p = self.p

        if x1 == x2:
            if (y1 + y2) % p == 0:
                return None  # P + (-P) = O
            # Point doubling P1 == P2
            num = (3 * pow(x1, 2, p) + self.a) % p
            den = (2 * y1) % p
            slope = (num * pow(den, -1, p)) % p
        else:
            num = (y2 - y1) % p
            den = (x2 - x1) % p
            slope = (num * pow(den, -1, p)) % p

        x3 = (pow(slope, 2, p) - x1 - x2) % p
        y3 = (slope * (x1 - x3) - y1) % p
        return (x3, y3)

    def point_double(self, pt: Point) -> Point:
        """Double point pt (convenience alias for point_add(pt, pt))."""
        return self.point_add(pt, pt)

    def scalar_mul(self, k: int, pt: Point) -> Point:
        """Scalar multiplication k * P using double-and-add."""
        if pt is None or k == 0:
            return None
        if k < 0:
            return self.scalar_mul(-k, self.point_neg(pt))

        result: Point = None
        current = pt

        while k > 0:
            if k & 1:
                result = self.point_add(result, current)
            current = self.point_add(current, current)
            k >>= 1

        return result

    def count_points_naive(self) -> int:
        """
        Count #E(F_p) points on small curves by checking Legendre symbols.
        Returns total count including the point at infinity O.
        Guarantees Hasse bound check.
        """
        count = 1  # Point at infinity O
        p = self.p
        half_p = (p - 1) // 2

        for x in range(p):
            rhs = (pow(x, 3, p) + self.a * x + self.b) % p
            if rhs == 0:
                count += 1
            elif pow(rhs, half_p, p) == 1:
                count += 2

        if not check_hasse_bound(count, p):
            raise AssertionError(f"Count {count} violates Hasse bound for p={p}")
        return count

    def find_points(self, limit: int = 10) -> List[Tuple[int, int]]:
        """Find up to `limit` affine points on the curve."""
        pts: List[Tuple[int, int]] = []
        p = self.p
        for x in range(p):
            rhs = (pow(x, 3, p) + self.a * x + self.b) % p
            y = mod_sqrt(rhs, p)
            if y is not None:
                pts.append((x, y))
                if len(pts) >= limit:
                    break
                if y != 0 and (p - y) % p != y:
                    pts.append((x, (p - y) % p))
                    if len(pts) >= limit:
                        break
        return pts

    def __repr__(self) -> str:
        return f"EllipticCurve(y^2 = x^3 + {self.a}x + {self.b} mod {self.p})"


# =============================================================================
# Keystream Extraction & Streaming Ciphers
# =============================================================================

CICADA_PRIMES = (3301, 1033, 761, 29)


def get_canonical_cicada_curve(p: int = 3301, a: int = 1, b: int = 1) -> Tuple[EllipticCurve, Tuple[int, int]]:
    """
    Instantiate standard test curve y^2 = x^3 + ax + b mod p with point (0, 1).
    For a=1, b=1, (0, 1) is guaranteed on the curve for all Cicada primes since 0+0+1 = 1^2.
    """
    curve = EllipticCurve(a, b, p)
    # Check if (0, 1) is on curve
    if curve.is_on_curve((0, 1 % p)):
        base_point = (0, 1 % p)
    else:
        pts = curve.find_points(limit=1)
        if not pts:
            raise ValueError(f"No affine points found for curve {curve}")
        base_point = pts[0]
    return curve, base_point


def generate_ecc_keystream(
    curve: EllipticCurve,
    base_point: Tuple[int, int],
    length: int,
    coord: str = "x",
    k_start: int = 1,
    k_step: int = 1,
    mod: int = 29,
    infinity_val: int = 0,
) -> List[int]:
    """
    Generate a keystream of `length` symbols modulo `mod` (default 29)
    from scalar multiples of base_point on curve:
        k = k_start + i * k_step
        P_k = k * base_point
    and extracting x(P_k) mod 29 or y(P_k) mod 29.
    If P_k is the point at infinity O, emits infinity_val mod mod.
    """
    if length <= 0:
        return []

    keystream: List[int] = []
    # Fast incremental orbit when k_step == 1
    if k_step == 1:
        current = curve.scalar_mul(k_start, base_point)
        for _ in range(length):
            if current is None:
                keystream.append(infinity_val % mod)
            else:
                x, y = current
                if coord == "x":
                    keystream.append(x % mod)
                elif coord == "y":
                    keystream.append(y % mod)
                elif coord == "xy":
                    keystream.append((x + y) % mod)
                else:
                    raise ValueError(f"Unknown coord extraction mode: {coord}")
            current = curve.point_add(current, base_point)
    else:
        for i in range(length):
            k = k_start + i * k_step
            pt = curve.scalar_mul(k, base_point)
            if pt is None:
                keystream.append(infinity_val % mod)
            else:
                x, y = pt
                if coord == "x":
                    keystream.append(x % mod)
                elif coord == "y":
                    keystream.append(y % mod)
                elif coord == "xy":
                    keystream.append((x + y) % mod)
                else:
                    raise ValueError(f"Unknown coord extraction mode: {coord}")

    return keystream


def extract_x_stream(
    curve: EllipticCurve,
    base_point: Tuple[int, int],
    length: int,
    mod: int = 29,
    k_start: int = 1,
    k_step: int = 1,
) -> List[int]:
    """Convenience wrapper to extract x(kP) mod `mod`."""
    return generate_ecc_keystream(curve, base_point, length, coord="x", k_start=k_start, k_step=k_step, mod=mod)


def extract_y_stream(
    curve: EllipticCurve,
    base_point: Tuple[int, int],
    length: int,
    mod: int = 29,
    k_start: int = 1,
    k_step: int = 1,
) -> List[int]:
    """Convenience wrapper to extract y(kP) mod `mod`."""
    return generate_ecc_keystream(curve, base_point, length, coord="y", k_start=k_start, k_step=k_step, mod=mod)


def ecc_stream_encrypt(
    plaintext_indices: List[int],
    curve: EllipticCurve,
    base_point: Tuple[int, int],
    coord: str = "x",
    k_start: int = 1,
    mod: int = 29,
) -> List[int]:
    """
    Encrypt plaintext indices mod 29 with an ECC keystream:
        c_i = (p_i + k_i) mod 29
    """
    stream = generate_ecc_keystream(curve, base_point, len(plaintext_indices), coord=coord, k_start=k_start, mod=mod)
    return [(p + k) % mod for p, k in zip(plaintext_indices, stream)]


def ecc_stream_decrypt(
    ciphertext_indices: List[int],
    curve: EllipticCurve,
    base_point: Tuple[int, int],
    coord: str = "x",
    k_start: int = 1,
    mod: int = 29,
) -> List[int]:
    """
    Decrypt ciphertext indices mod 29 with an ECC keystream:
        p_i = (c_i - k_i) mod 29
    """
    stream = generate_ecc_keystream(curve, base_point, len(ciphertext_indices), coord=coord, k_start=k_start, mod=mod)
    return [(c - k) % mod for c, k in zip(ciphertext_indices, stream)]
