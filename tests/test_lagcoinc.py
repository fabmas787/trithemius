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
CIPHERS_DIR = os.path.join(BASE_DIR, "ciphers")
if CIPHERS_DIR not in sys.path:
    sys.path.insert(0, CIPHERS_DIR)

from lagcoinc import coincidence_by_lag, coincidence_by_lag_pure, coincidence_by_lag_numpy, HAS_NUMPY


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


if __name__ == "__main__":
    unittest.main()
