"""
Unit tests for ciphers/lagcoinc.py exact lag coincidence spectrum module.
"""

import unittest
import random
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ciphers.agrippa import INDEX_BY_RUNE, latin_to_rune
from ciphers.lagcoinc import (
    coincidence_by_lag,
    coincidence_by_lag_pure,
    coincidence_by_lag_numpy,
    HAS_NUMPY,
    mean_columnar_ioc,
    passes_sinkov_columnar_ioc_gate,
)
from ciphers.taxonomy import lag_coincidence_spectrum


class TestLagCoincidence(unittest.TestCase):
    def test_pure_vs_numpy_equivalence(self):
        rng = random.Random(42)
        seq = [rng.randrange(29) for _ in range(120)]

        pure_res = coincidence_by_lag_pure(seq, n=29)
        self.assertEqual(len(pure_res), len(seq) - 1)

        if HAS_NUMPY:
            numpy_res = coincidence_by_lag_numpy(seq, n=29)
            self.assertEqual(pure_res, numpy_res)

        general_res = coincidence_by_lag(seq, n=29)
        self.assertEqual(general_res, pure_res)

    def test_known_periodic_sequence(self):
        # Sequence with period 3: [0, 1, 2, 0, 1, 2, 0, 1, 2]
        seq = [0, 1, 2] * 10  # length 30
        res = coincidence_by_lag(seq, n=29)
        # Lag 3 (index 2 in 0-indexed list) should have maximum coincidence = 27
        self.assertEqual(res[2], 27)
        # Lag 6 (index 5) should have coincidence = 24
        self.assertEqual(res[5], 24)
        # Lag 1 (index 0) should have coincidence = 0
        self.assertEqual(res[0], 0)

    def test_tiny_input(self):
        self.assertEqual(coincidence_by_lag([]), [])
        self.assertEqual(coincidence_by_lag([5]), [])
        self.assertEqual(coincidence_by_lag([5, 5]), [1])
        self.assertEqual(coincidence_by_lag([5, 6]), [0])

    def test_mean_columnar_ioc_exact_and_edge_cases(self):
        self.assertEqual(mean_columnar_ioc([], period=3), 0.0)
        self.assertEqual(mean_columnar_ioc([1, 2, 3], period=0), 0.0)
        self.assertEqual(mean_columnar_ioc([0, 1, 2], period=3), 0.0)
        self.assertAlmostEqual(mean_columnar_ioc([0, 1, 2] * 10, period=3), 1.0)
        # Col 0: [0, 0] -> 1.0; Cols 1, 2 have length 1 and are skipped
        self.assertAlmostEqual(mean_columnar_ioc([0, 1, 2, 0], period=3), 1.0)
        # Col 0: [0, 0, 0] -> 1.0; Col 1: [1, 2, 1] -> 1/3; mean -> 2/3
        self.assertAlmostEqual(mean_columnar_ioc([0, 1, 0, 2, 0, 1], period=2), 2.0 / 3.0)

    def test_sinkov_gate_true_periodic_english_passes(self):
        prose = (
            "WELCOME PILGRIM TO THE GREAT JOURNEY TOWARD THE END OF ALL THINGS "
            "IT IS NOT AN EASY TRIP BUT FOR THOSE WHO FIND THEIR WAY HERE IT IS A NECESSARY ONE "
            "ALONG THE WAY YOU WILL FIND AN END TO ALL STRUGGLE AND SUFFERING"
        )
        runes = latin_to_rune(prose)
        pt = [INDEX_BY_RUNE[r] for r in runes if r in INDEX_BY_RUNE]
        key = [3, 14, 15, 9, 2, 6, 5]  # period 7
        ct = [(val + key[i % len(key)]) % 29 for i, val in enumerate(pt)]
        self.assertGreaterEqual(len(ct) / len(key), 12)

        passed, mean_ioc, threshold = passes_sinkov_columnar_ioc_gate(ct, period=len(key))
        self.assertTrue(passed)
        self.assertGreater(threshold, 0.0)
        self.assertGreaterEqual(mean_ioc, threshold)

    def test_sinkov_gate_uniform_random_pruned_and_short_preserved(self):
        rng = random.Random(42)
        seq = [rng.randrange(29) for _ in range(240)]

        # n/p = 20 >= 12 -> uniform random must be pruned
        passed, mean_ioc, threshold = passes_sinkov_columnar_ioc_gate(seq, period=12)
        self.assertFalse(passed)
        self.assertGreater(threshold, mean_ioc)

        # Short column budget n/p < 12 -> must not be pruned, threshold == 0.0
        short_seq = seq[:100]  # 100 / 10 = 10 < 12
        passed_short, mean_short, thr_short = passes_sinkov_columnar_ioc_gate(short_seq, period=10)
        self.assertTrue(passed_short)
        self.assertEqual(thr_short, 0.0)
        self.assertAlmostEqual(mean_short, mean_columnar_ioc(short_seq, period=10), places=5)

        # Period <= 1 -> must not be pruned, threshold == 0.0
        passed_p1, mean_p1, thr_p1 = passes_sinkov_columnar_ioc_gate(seq, period=1)
        self.assertTrue(passed_p1)
        self.assertEqual(thr_p1, 0.0)
        self.assertAlmostEqual(mean_p1, mean_columnar_ioc(seq, period=1), places=5)

    def test_differential_numpy_vs_pure_across_lengths_and_max_lag(self):
        rng = random.Random(1337)
        lengths = [0, 1, 2, 3, 4, 5, 16, 256, 257, 512, 1000]
        for L in lengths:
            seq = [rng.randrange(29) for _ in range(L)]
            for max_lag in (None, 30, 0, -1):
                pure_res = coincidence_by_lag_pure(seq, max_lag=max_lag)
                general_res = coincidence_by_lag(seq, max_lag=max_lag)
                self.assertEqual(general_res, pure_res, f"L={L}, max_lag={max_lag}")
                if HAS_NUMPY:
                    numpy_res = coincidence_by_lag_numpy(seq, max_lag=max_lag)
                    self.assertEqual(numpy_res, pure_res, f"L={L}, max_lag={max_lag}")

    def test_differential_non_z29_sequences(self):
        rng = random.Random(2025)
        cases = {
            "negatives_and_large": [rng.randint(-500, 500) for _ in range(320)],
            "values_gt_28": [rng.randint(29, 200) for _ in range(300)],
            "all_equal": [777] * 300,
            "all_distinct": list(range(-150, 150)),
        }
        for name, seq in cases.items():
            for max_lag in (None, 30, 150):
                pure_res = coincidence_by_lag_pure(seq, max_lag=max_lag)
                self.assertEqual(coincidence_by_lag(seq, max_lag=max_lag), pure_res, name)
                if HAS_NUMPY:
                    self.assertEqual(
                        coincidence_by_lag_numpy(seq, max_lag=max_lag), pure_res, name
                    )

    def test_taxonomy_lag_coincidence_spectrum_parity(self):
        rng = random.Random(99)
        seqs = [
            [],
            [4],
            [rng.randrange(29) for _ in range(15)],
            [rng.randrange(29) for _ in range(300)],
            [rng.randint(-50, 120) for _ in range(350)],
        ]
        for seq in seqs:
            for max_lag in (32, 10, 0):
                pure_res = coincidence_by_lag_pure(seq, max_lag=max_lag)
                expected = {d: pure_res[d - 1] for d in range(1, len(pure_res) + 1)}
                actual = lag_coincidence_spectrum(seq, max_lag=max_lag)
                self.assertEqual(actual, expected, f"L={len(seq)}, max_lag={max_lag}")


if __name__ == "__main__":
    unittest.main()
