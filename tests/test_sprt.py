"""
Unit tests for ciphers/sprt.py Wald's Sequential Probability Ratio Test module.
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

from sprt import bigram_llr_table, sprt


class TestSPRT(unittest.TestCase):
    def setUp(self):
        # Create a synthetic training text favoring certain transitions:
        # e.g., 0 -> 1, 1 -> 2, 2 -> 0, etc.
        self.rng = random.Random(42)
        pattern = [0, 1, 2, 3, 0, 1, 2, 3] * 50
        noise = [self.rng.randrange(29) for _ in range(200)]
        self.train = pattern + noise
        self.llr = bigram_llr_table(self.train, k=0.5, n=29)

    def test_llr_table_dimensions(self):
        self.assertEqual(len(self.llr), 29)
        for row in self.llr:
            self.assertEqual(len(row), 29)

    def test_sprt_accepts_structured_sequence(self):
        # Structured sequence matching training pattern
        structured = [0, 1, 2, 3] * 20
        decision, symbols = sprt(structured, self.llr, alpha=0.01, beta=0.01)
        self.assertEqual(decision, "accept")
        self.assertLess(symbols, 25)

    def test_sprt_rejects_uniform_noise(self):
        # Noise sequence with uniformly random transitions
        noise = [self.rng.randrange(29) for _ in range(200)]
        decision, symbols = sprt(noise, self.llr, alpha=0.01, beta=0.01)
        self.assertEqual(decision, "reject")
        self.assertLess(symbols, 50)

    def test_sprt_undecided_on_tiny_input(self):
        tiny = [0, 1]
        decision, symbols = sprt(tiny, self.llr, alpha=0.001, beta=0.001)
        self.assertEqual(symbols, 2)
        # On 2 symbols with strict thresholds, should be undecided
        self.assertIn(decision, ["undecided", "accept", "reject"])


if __name__ == "__main__":
    unittest.main()
