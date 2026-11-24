"""
Unit tests for ciphers/unicity.py unicity distance and identifiability module.
"""

import unittest
import math
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ciphers.unicity import (
    redundancy,
    unicity_distance,
    max_periodic_key_length,
    identifiability_report,
)


class TestUnicity(unittest.TestCase):
    def test_redundancy_calculation(self):
        # log2(29) ≈ 4.85798
        # If language entropy is 2.5, D ≈ 2.35798
        d = redundancy(2.5, n=29)
        self.assertAlmostEqual(d, math.log2(29) - 2.5, places=5)

    def test_unicity_distance(self):
        # Key entropy = 10 bits, redundancy = 2.0 bits/symbol -> U = 5 symbols
        u = unicity_distance(10.0, math.log2(29) - 2.0, n=29)
        self.assertAlmostEqual(u, 5.0, places=4)

    def test_max_periodic_key_length_values(self):
        # Entire manuscript: N = 12,956 runes
        # For H_L = 1.5, max_m should be ~8956
        m_full = max_periodic_key_length(12956, 1.5, n=29)
        self.assertTrue(8900 < m_full < 9000)

        # Single page: N = 236 runes
        # For H_L = 3.3, max_m should be ~76
        m_page = max_periodic_key_length(236, 3.3, n=29)
        self.assertTrue(70 < m_page < 80)

    def test_identifiability_report_structure(self):
        rep = identifiability_report(236, n=29)
        self.assertEqual(rep["n_symbols"], 236)
        self.assertIn("scenarios", rep)
        self.assertIn("conservative_3_3", rep["scenarios"])
        self.assertIn("max_resolvable_periodic_key_len", rep["scenarios"]["conservative_3_3"])


if __name__ == "__main__":
    unittest.main()
