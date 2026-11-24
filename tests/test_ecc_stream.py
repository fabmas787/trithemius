"""
Unit tests for ciphers/ecc_stream.py — Elliptic Curve Keystream Generator.
"""

import unittest
from ciphers.ecc_stream import (
    EllipticCurve,
    check_non_singular,
    curve_discriminant,
    hasse_bounds,
    check_hasse_bound,
    mod_sqrt,
    generate_ecc_keystream,
    extract_x_stream,
    extract_y_stream,
    ecc_stream_encrypt,
    ecc_stream_decrypt,
    get_canonical_cicada_curve,
    CICADA_PRIMES,
)


class TestECCStream(unittest.TestCase):
    """Test suite for pure-Python short Weierstrass elliptic curve arithmetic."""

    def test_singularity_detection(self):
        """Singular curves with Delta = 0 mod p must be rejected."""
        # y^2 = x^3 (cusp): a=0, b=0 -> 4a^3 + 27b^2 = 0
        self.assertFalse(check_non_singular(0, 0, 29))
        with self.assertRaises(ValueError):
            EllipticCurve(0, 0, 29)

        # y^2 = x^3 - 3x + 2 mod 29 (node): 4*(-27) + 27*4 = -108 + 108 = 0
        self.assertFalse(check_non_singular(-3, 2, 29))
        with self.assertRaises(ValueError):
            EllipticCurve(-3, 2, 29)

        # Non-singular curve
        self.assertTrue(check_non_singular(1, 1, 29))
        curve = EllipticCurve(1, 1, 29)
        self.assertEqual(curve.a, 1)
        self.assertEqual(curve.b, 1)
        self.assertEqual(curve.p, 29)
        self.assertNotEqual(curve.discriminant, 0)

    def test_group_axioms(self):
        """Verify abelian group axioms: identity, inverse, doubling, associativity."""
        curve = EllipticCurve(1, 1, 29)
        pts = curve.find_points(limit=10)
        self.assertTrue(len(pts) >= 3, "Should find at least 3 points on curve")

        P = pts[0]
        Q = pts[1]
        R = pts[2]

        # 1. Identity O (None)
        self.assertEqual(curve.point_add(P, None), P)
        self.assertEqual(curve.point_add(None, P), P)

        # 2. Inverse P + (-P) = O
        neg_P = curve.point_neg(P)
        self.assertTrue(curve.is_on_curve(neg_P))
        self.assertIsNone(curve.point_add(P, neg_P))

        # 3. Doubling
        two_P = curve.point_double(P)
        self.assertEqual(two_P, curve.point_add(P, P))
        if two_P is not None:
            self.assertTrue(curve.is_on_curve(two_P))

        # 4. Associativity (P + Q) + R == P + (Q + R)
        lhs = curve.point_add(curve.point_add(P, Q), R)
        rhs = curve.point_add(P, curve.point_add(Q, R))
        self.assertEqual(lhs, rhs)

    def test_scalar_multiplication(self):
        """Verify scalar multiplication properties."""
        curve = EllipticCurve(1, 1, 29)
        P = (0, 1)  # (0, 1) is on y^2 = x^3 + x + 1 mod 29
        self.assertTrue(curve.is_on_curve(P))

        # 0 * P = O
        self.assertIsNone(curve.scalar_mul(0, P))

        # 1 * P = P
        self.assertEqual(curve.scalar_mul(1, P), P)

        # 2 * P = P + P
        self.assertEqual(curve.scalar_mul(2, P), curve.point_add(P, P))

        # 3 * P = 2P + P
        self.assertEqual(curve.scalar_mul(3, P), curve.point_add(curve.scalar_mul(2, P), P))

        # Negative scalar: -1 * P = -P
        self.assertEqual(curve.scalar_mul(-1, P), curve.point_neg(P))
        self.assertEqual(curve.scalar_mul(-3, P), curve.point_neg(curve.scalar_mul(3, P)))

    def test_hasse_bound_and_point_counting(self):
        """Verify Hasse bounds for F_29 and count points on small curves."""
        # For p=29: 2*sqrt(29) ~ 2 * 5.385 = 10.77 -> floor(10.77) = 10
        # Hasse interval: [29 + 1 - 10, 29 + 1 + 10] = [20, 40]
        low, high = hasse_bounds(29)
        self.assertEqual(low, 20)
        self.assertEqual(high, 40)

        curve1 = EllipticCurve(1, 1, 29)
        order1 = curve1.count_points_naive()
        self.assertTrue(low <= order1 <= high)
        self.assertTrue(check_hasse_bound(order1, 29))

        curve2 = EllipticCurve(4, 20, 29)
        order2 = curve2.count_points_naive()
        self.assertTrue(low <= order2 <= high)
        self.assertTrue(check_hasse_bound(order2, 29))

        # Violating bound check
        self.assertFalse(check_hasse_bound(15, 29))
        self.assertFalse(check_hasse_bound(45, 29))

    def test_mod_sqrt(self):
        """Verify modular square root for both p = 3 mod 4 and p = 1 mod 4."""
        # p = 3 mod 4: p = 29 is not 3 mod 4 (29 = 1 mod 4), p = 31 is 3 mod 4
        # Test p = 31 (3 mod 4)
        for val in range(1, 31):
            sq = (val * val) % 31
            r = mod_sqrt(sq, 31)
            self.assertIsNotNone(r)
            self.assertEqual((r * r) % 31, sq)

        # Test p = 29 (1 mod 4)
        for val in range(1, 29):
            sq = (val * val) % 29
            r = mod_sqrt(sq, 29)
            self.assertIsNotNone(r)
            self.assertEqual((r * r) % 29, sq)

    def test_cicada_prime_curves(self):
        """Curves over Cicada primes (3301, 1033, 761, 29) must generate valid points."""
        for p in CICADA_PRIMES:
            curve, base_pt = get_canonical_cicada_curve(p=p, a=1, b=1)
            self.assertTrue(curve.is_on_curve(base_pt), f"Base point {base_pt} must be on curve mod {p}")
            self.assertTrue(check_non_singular(1, 1, p))

            # Multiply base point by scalars
            P2 = curve.scalar_mul(2, base_pt)
            self.assertTrue(curve.is_on_curve(P2))
            P5 = curve.scalar_mul(5, base_pt)
            self.assertTrue(curve.is_on_curve(P5))

    def test_keystream_extraction(self):
        """Keystream extraction x(kP) mod 29 and y(kP) mod 29."""
        curve, base_pt = get_canonical_cicada_curve(p=3301, a=1, b=1)

        # Extract 20 symbols
        x_stream = extract_x_stream(curve, base_pt, 20, mod=29)
        y_stream = extract_y_stream(curve, base_pt, 20, mod=29)

        self.assertEqual(len(x_stream), 20)
        self.assertEqual(len(y_stream), 20)

        # All symbols must be in GF(29) range [0, 28]
        for v in x_stream + y_stream:
            self.assertTrue(0 <= v < 29)

        # Verify incremental orbit matches scalar_mul
        for i in range(20):
            pt = curve.scalar_mul(1 + i, base_pt)
            if pt is not None:
                self.assertEqual(x_stream[i], pt[0] % 29)
                self.assertEqual(y_stream[i], pt[1] % 29)

    def test_encryption_decryption_roundtrip(self):
        """Stream encryption and decryption must perfectly roundtrip in F_29."""
        curve, base_pt = get_canonical_cicada_curve(p=1033, a=1, b=1)
        plaintext = [0, 4, 18, 22, 28, 14, 5, 1, 9, 12, 17]

        # Encrypt with x-coord stream
        ciphertext = ecc_stream_encrypt(plaintext, curve, base_pt, coord="x", k_start=1)
        self.assertEqual(len(ciphertext), len(plaintext))
        self.assertNotEqual(ciphertext, plaintext)

        # Decrypt
        recovered = ecc_stream_decrypt(ciphertext, curve, base_pt, coord="x", k_start=1)
        self.assertEqual(recovered, plaintext)

        # Encrypt with y-coord stream
        ciphertext_y = ecc_stream_encrypt(plaintext, curve, base_pt, coord="y", k_start=5)
        recovered_y = ecc_stream_decrypt(ciphertext_y, curve, base_pt, coord="y", k_start=5)
        self.assertEqual(recovered_y, plaintext)


if __name__ == "__main__":
    unittest.main()
