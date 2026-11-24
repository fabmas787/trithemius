"""
Unit tests for ciphers/fingerprint.py likelihood-free forward simulation module.
"""

import unittest
import random
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ciphers.fingerprint import (
    doublet_rate,
    doublet_z,
    ioc_n,
    diff_hist,
    fingerprint,
    simulate,
    compare_fingerprints,
    EMPIRICAL_UNSOLVED_LP,
)


class TestFingerprint(unittest.TestCase):
    def test_doublet_rate_and_z_score(self):
        # Sequence with 0 doublets
        seq_nodoublets = [0, 1, 2, 3, 4, 5, 6, 7]
        self.assertEqual(doublet_rate(seq_nodoublets), 0.0)
        self.assertLess(doublet_z(seq_nodoublets, 29), 0.0)

        # Sequence with all doublets
        seq_alldoublets = [5, 5, 5, 5, 5]
        self.assertEqual(doublet_rate(seq_alldoublets), 1.0)
        self.assertGreater(doublet_z(seq_alldoublets, 29), 0.0)

    def test_ioc_n_uniform_vs_skewed(self):
        # Flat distribution
        flat = list(range(29)) * 10
        self.assertAlmostEqual(ioc_n(flat, 29), 0.903, places=2)

        # Skewed distribution (English-like)
        skewed = [0] * 50 + [1] * 20 + [2] * 10 + list(range(3, 29))
        self.assertGreater(ioc_n(skewed, 29), 1.5)

    def test_forward_simulation_families(self):
        rng = random.Random(42)
        plaintext = [rng.randrange(29) for _ in range(2000)]

        # otp_norepeat must have exactly 0 doublets
        c_norepeat = simulate("otp_norepeat", plaintext, rng=random.Random(42), n=29)
        self.assertEqual(doublet_rate(c_norepeat), 0.0)
        fp_norepeat = fingerprint(c_norepeat, n=29)
        self.assertEqual(fp_norepeat["diff_zero_ratio"], 0.0)

        # chain_mod29 must have diff_zero_ratio == 0
        c_chain = simulate("chain_mod29", plaintext, rng=random.Random(42), n=29)
        fp_chain = fingerprint(c_chain, n=29)
        self.assertEqual(fp_chain["diff_zero_ratio"], 0.0)

        # normal otp should have doublet_rate near 1/29 ≈ 0.0345
        c_otp = simulate("otp", plaintext, rng=random.Random(42), n=29)
        fp_otp = fingerprint(c_otp, n=29)
        self.assertAlmostEqual(fp_otp["doublet_rate"], 1.0 / 29, delta=0.015)

    def test_empirical_comparison(self):
        # Distance to itself should be 0.0
        d = compare_fingerprints(EMPIRICAL_UNSOLVED_LP, EMPIRICAL_UNSOLVED_LP)
        self.assertEqual(d, 0.0)


if __name__ == "__main__":
    unittest.main()
