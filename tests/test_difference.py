"""
Unit tests for ciphers/difference.py difference domain and sacred number sequences.
"""

import unittest
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
CIPHERS_DIR = os.path.join(BASE_DIR, "ciphers")
if CIPHERS_DIR not in sys.path:
    sys.path.insert(0, CIPHERS_DIR)

from difference import (
    to_differences,
    from_differences,
    is_keystream_delta_valid,
    mobius,
    liouville,
    carmichael_lambda,
    sum_divisors,
    count_divisors,
    generate_sequence,
    sequence_fingerprint,
)


class TestDifference(unittest.TestCase):
    def test_difference_roundtrip(self):
        orig = [0, 5, 12, 12, 28, 3]
        diffs = to_differences(orig, n=29)
        self.assertEqual(len(diffs), len(orig) - 1)
        recon = from_differences(diffs, orig[0], n=29)
        self.assertEqual(recon, orig)

    def test_delta_validity(self):
        # High doublet rate should be invalid for unsolved manuscript
        high_doublets = [5, 5, 5, 5, 6, 7]
        self.assertFalse(is_keystream_delta_valid(high_doublets, []))

        # Clean sequence with no doublets
        no_doublets = list(range(29))
        self.assertTrue(is_keystream_delta_valid(no_doublets, []))

    def test_mobius_values(self):
        # mu(1) = 1, mu(2) = -1, mu(3) = -1, mu(4) = 0 (2^2), mu(5) = -1, mu(6) = 1 (2*3)
        self.assertEqual(mobius(1), 1)
        self.assertEqual(mobius(2), -1)
        self.assertEqual(mobius(3), -1)
        self.assertEqual(mobius(4), 0)
        self.assertEqual(mobius(5), -1)
        self.assertEqual(mobius(6), 1)

    def test_liouville_values(self):
        # lambda(1) = 1, lambda(2) = -1, lambda(4) = 1 (2^2), lambda(8) = -1 (2^3)
        self.assertEqual(liouville(1), 1)
        self.assertEqual(liouville(2), -1)
        self.assertEqual(liouville(4), 1)
        self.assertEqual(liouville(8), -1)

    def test_carmichael_values(self):
        # lambda(1)=1, lambda(2)=1, lambda(3)=2, lambda(4)=2, lambda(5)=4, lambda(8)=2 (2^(3-2)=2)
        self.assertEqual(carmichael_lambda(1), 1)
        self.assertEqual(carmichael_lambda(2), 1)
        self.assertEqual(carmichael_lambda(3), 2)
        self.assertEqual(carmichael_lambda(4), 2)
        self.assertEqual(carmichael_lambda(5), 4)
        self.assertEqual(carmichael_lambda(8), 2)

    def test_sequence_fingerprint_deduplication(self):
        seq1 = generate_sequence("mobius", 100)
        seq2 = generate_sequence("mobius", 100)
        seq3 = generate_sequence("liouville", 100)

        fp1 = sequence_fingerprint(seq1)
        fp2 = sequence_fingerprint(seq2)
        fp3 = sequence_fingerprint(seq3)

        self.assertEqual(fp1, fp2)
        self.assertNotEqual(fp1, fp3)


if __name__ == "__main__":
    unittest.main()
