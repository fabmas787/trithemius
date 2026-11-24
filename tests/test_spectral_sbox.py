"""
Unit tests for ciphers/spectral_sbox.py.
Covers S-box generators over F_29 and cryptographic diagnostics.
"""

import math
import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ciphers.spectral_sbox import (
    DEFAULT_MODULUS,
    affine_inversion_sbox,
    mobius_sbox,
    power_map_sbox,
    double_affine_sbox,
    difference_distribution_table,
    differential_uniformity,
    fast_walsh_hadamard_transform,
    linear_approximation_table,
    nonlinearity,
    strict_avalanche_criterion,
    algebraic_degree,
    algebraic_degrees,
    dft_bias_z29,
    compute_linear_hull_potential,
    LinearHullPotentialResult,
)


class TestSpectralSBoxGenerators(unittest.TestCase):
    def test_affine_inversion_permutation(self):
        # Default inversion: S(x) = x^-1 mod 29, 0^-1 = 0
        sbox = affine_inversion_sbox(1, 0, 29)
        self.assertEqual(len(sbox), 29)
        self.assertEqual(len(set(sbox)), 29)
        self.assertEqual(sbox[0], 0)
        self.assertEqual(sbox[1], 1)
        # 2 * 15 = 30 = 1 mod 29
        self.assertEqual(sbox[2], 15)

        # Affine inversion with a=3, b=7
        sbox_aff = affine_inversion_sbox(3, 7, 29)
        self.assertEqual(len(set(sbox_aff)), 29)
        self.assertEqual(sbox_aff[0], 7)
        self.assertEqual(sbox_aff[1], (3 * 1 + 7) % 29)
        self.assertEqual(sbox_aff[2], (3 * 15 + 7) % 29)

        # a = 0 must raise ValueError
        with self.assertRaises(ValueError):
            affine_inversion_sbox(0, 5, 29)

    def test_mobius_sbox_permutation(self):
        # Non-singular Mobius map: (2x + 3)/(5x + 7) mod 29
        det = (2 * 7 - 3 * 5) % 29
        self.assertNotEqual(det, 0)

        sbox = mobius_sbox(2, 3, 5, 7, 29)
        self.assertEqual(len(sbox), 29)
        self.assertEqual(len(set(sbox)), 29)

        # Verify pole handling: 5x + 7 = 0 mod 29 -> 5x = 22 -> x = 22 * 5^-1 = 22 * 6 = 132 = 16 mod 29
        # At pole x=16: S(16) should be a * c^-1 = 2 * 5^-1 = 2 * 6 = 12 mod 29
        self.assertEqual(sbox[16], 12)

        # Singular Mobius map: 2*14 - 4*7 = 28 - 28 = 0 mod 29
        with self.assertRaises(ValueError):
            mobius_sbox(2, 4, 7, 14, 29)

        # c = 0 mod 29 (affine case)
        sbox_aff = mobius_sbox(3, 5, 0, 2, 29)
        self.assertEqual(len(set(sbox_aff)), 29)
        # S(x) = (3x + 5) * 2^-1 = (3x + 5) * 15 mod 29
        for x in range(29):
            self.assertEqual(sbox_aff[x], ((3 * x + 5) * 15) % 29)

    def test_power_map_sbox(self):
        # k=3 is coprime to 28 (order of F_29*)
        self.assertEqual(math.gcd(3, 28), 1)
        sbox_3 = power_map_sbox(3, 29)
        self.assertEqual(len(set(sbox_3)), 29)
        self.assertEqual(sbox_3[0], 0)
        self.assertEqual(sbox_3[1], 1)
        self.assertEqual(sbox_3[2], 8)
        self.assertEqual(sbox_3[3], 27)

        # k=2 is not coprime to 28 (gcd=2) -> must raise ValueError
        with self.assertRaises(ValueError):
            power_map_sbox(2, 29)

        # k=27 is coprime to 28 (inversion map x^27 = x^-1 mod 29)
        sbox_inv = power_map_sbox(27, 29)
        sbox_aff_inv = affine_inversion_sbox(1, 0, 29)
        self.assertEqual(sbox_inv, sbox_aff_inv)

    def test_double_affine_sbox(self):
        base_sbox = affine_inversion_sbox(1, 0, 29)
        # Double affine: A2(S(A1(x)))
        sbox_comp = double_affine_sbox(base_sbox, a1=3, b1=5, a2=7, b2=11, modulus=29)
        self.assertEqual(len(set(sbox_comp)), 29)
        for x in range(29):
            in_x = (3 * x + 5) % 29
            expected = (7 * base_sbox[in_x] + 11) % 29
            self.assertEqual(sbox_comp[x], expected)

        # Singular linear factor raises ValueError
        with self.assertRaises(ValueError):
            double_affine_sbox(base_sbox, a1=0, b1=1, modulus=29)
        with self.assertRaises(ValueError):
            double_affine_sbox(base_sbox, a2=0, b2=1, modulus=29)


class TestCryptographicDiagnostics(unittest.TestCase):
    def setUp(self):
        self.inv_sbox = affine_inversion_sbox(1, 0, 29)

    def test_ddt_z29_and_differential_uniformity(self):
        ddt = difference_distribution_table(self.inv_sbox, mode="z29", modulus=29)
        self.assertEqual(len(ddt), 29)
        self.assertEqual(len(ddt[0]), 29)

        # Trivial difference: din = 0 -> dout = 0 for all 29 inputs
        self.assertEqual(ddt[0][0], 29)
        for dout in range(1, 29):
            self.assertEqual(ddt[0][dout], 0)

        # Each row sum must equal modulus (29)
        for din in range(29):
            self.assertEqual(sum(ddt[din]), 29)

        # Inversion map over F_29 has differential uniformity delta = 2
        du = differential_uniformity(ddt)
        self.assertEqual(du, 2)

    def test_ddt_xor_mode(self):
        ddt = difference_distribution_table(self.inv_sbox, mode="xor", embed_power_of_2=True)
        self.assertEqual(len(ddt), 32)
        self.assertEqual(len(ddt[0]), 32)

        # Trivial difference: din = 0 -> dout = 0 for all 32 inputs
        self.assertEqual(ddt[0][0], 32)
        for din in range(32):
            self.assertEqual(sum(ddt[din]), 32)

        du = differential_uniformity(ddt)
        self.assertGreater(du, 0)
        self.assertLessEqual(du, 32)

    def test_fast_walsh_hadamard_transform(self):
        # Test 1: Basis impulse [1, 0, 0, 0] -> Walsh transform is all 1s
        v = [1, 0, 0, 0]
        w = fast_walsh_hadamard_transform(v)
        self.assertEqual(w, [1, 1, 1, 1])

        # Test 2: Involutive property FWHT(FWHT(v)) == 2^n * v
        v_test = [3, -1, 4, 2, -5, 7, 0, 1]
        w1 = fast_walsh_hadamard_transform(v_test)
        w2 = fast_walsh_hadamard_transform(w1)
        self.assertEqual(w2, [len(v_test) * x for x in v_test])

        # Test 3: Parseval's identity sum(v^2) * 2^n == sum(w^2)
        energy_v = sum(x**2 for x in v_test)
        energy_w = sum(x**2 for x in w1)
        self.assertEqual(energy_w, len(v_test) * energy_v)

    def test_linear_approximation_table_and_nonlinearity(self):
        lat = linear_approximation_table(self.inv_sbox)
        self.assertEqual(len(lat), 32)
        self.assertEqual(len(lat[0]), 32)

        # LAT[0][0] = 16 (since all 32 inputs satisfy 0.x == 0.S(x) -> 32 - 16 = 16)
        self.assertEqual(lat[0][0], 16)

        # Verify direct count equivalence for random coordinate masks
        # LAT[a][b] = #{x : a.x == b.S(x)} - 16
        s_ext = list(self.inv_sbox) + [29, 30, 31]
        for a, b in [(1, 2), (5, 7), (13, 19), (3, 0)]:
            count = sum(
                1
                for x in range(32)
                if (bin(a & x).count("1") % 2) == (bin(b & s_ext[x]).count("1") % 2)
            )
            self.assertEqual(lat[a][b], count - 16)

        # Nonlinearity NL(S) = 16 - max_{a, b!=0} |LAT[a][b]|
        nl = nonlinearity(self.inv_sbox)
        self.assertGreater(nl, 0)
        self.assertLessEqual(nl, 16)

    def test_strict_avalanche_criterion(self):
        sac_res = strict_avalanche_criterion(self.inv_sbox)
        self.assertIn("matrix", sac_res)
        self.assertIn("max_deviation", sac_res)
        self.assertIn("mean_deviation", sac_res)
        self.assertEqual(sac_res["num_bits"], 5)

        mat = sac_res["matrix"]
        self.assertEqual(len(mat), 5)
        self.assertEqual(len(mat[0]), 5)

        # Probabilities must be in [0, 1]
        for i in range(5):
            for j in range(5):
                self.assertGreaterEqual(mat[i][j], 0.0)
                self.assertLessEqual(mat[i][j], 1.0)

    def test_algebraic_degree(self):
        ad = algebraic_degree(self.inv_sbox)
        degs = algebraic_degrees(self.inv_sbox)
        self.assertEqual(len(degs), 5)
        self.assertEqual(ad, max(degs))
        # Non-linear inversion S-box has degree 4 on 5 bits
        self.assertEqual(ad, 4)

        # Identity S-box should have degree 1
        id_sbox = list(range(29))
        self.assertEqual(algebraic_degree(id_sbox), 1)

    def test_dft_bias_z29(self):
        dft_res = dft_bias_z29(self.inv_sbox, modulus=29)
        self.assertIn("max_bias_1d", dft_res)
        self.assertIn("max_bias_2d", dft_res)
        self.assertIn("normalized_bias_2d", dft_res)
        self.assertIn("theoretical_bent_bound", dft_res)

        self.assertGreater(dft_res["max_bias_1d"], 0.0)
        self.assertGreater(dft_res["max_bias_2d"], 0.0)
        self.assertAlmostEqual(dft_res["theoretical_bent_bound"], math.sqrt(29), places=5)
        self.assertLess(dft_res["normalized_bias_2d"], 1.0)

    def test_compute_linear_hull_potential(self):
        lat = linear_approximation_table(self.inv_sbox)

        # Test single pair evaluation
        pot_single = compute_linear_hull_potential(lat, rounds=2, input_mask=1, output_mask=1)
        self.assertIsInstance(pot_single, float)
        self.assertGreaterEqual(pot_single, 0.0)
        self.assertLessEqual(pot_single, 1.0)

        # Test full matrix evaluation
        hull_res = compute_linear_hull_potential(lat, rounds=3)
        self.assertIsInstance(hull_res, LinearHullPotentialResult)
        self.assertEqual(len(hull_res), 32)
        self.assertEqual(len(hull_res[0]), 32)
        self.assertEqual(hull_res.rounds, 3)
        self.assertGreaterEqual(hull_res.max_potential, 0.0)
        self.assertLessEqual(hull_res.max_potential, 1.0)

        # Identity S-box linear hull potential should be 1.0 for mask a -> a
        id_sbox = list(range(29))
        id_lat = linear_approximation_table(id_sbox)
        id_hull = compute_linear_hull_potential(id_lat, rounds=5, input_mask=3, output_mask=3)
        self.assertAlmostEqual(id_hull, 1.0, places=5)


if __name__ == "__main__":
    unittest.main()
