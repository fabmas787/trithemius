"""
Unit tests for WS-F: Empirical Heuristics.
Verifies difference_ioc(runes, lag=1, modulus=29), pattern_ioc(words),
and normalize_runes --normalize-three-dot mapping with offset preservation.
"""

import os
import sys
import random
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ciphers.difference import difference_ioc, pattern_ioc
from ciphers.agrippa import INDEX_BY_RUNE, RUNE_BY_INDEX
from scripts.normalize_runes import normalize_text


class TestLiberPlaygroundHeuristics(unittest.TestCase):

    # =========================================================================
    # ciphers/difference.py: difference_ioc Tests
    # =========================================================================

    def test_difference_ioc_constant_progression(self):
        """Constant arithmetic differences produce identical differences (IoC = 1.0)."""
        # Linear sequence: c_{i+1} - c_i = 3 mod 29 constant
        seq = [(i * 3) % 29 for i in range(100)]
        ioc = difference_ioc(seq, lag=1, modulus=29)
        self.assertEqual(ioc, 1.0)

        # lag=2 difference is also constant (6 mod 29)
        ioc_lag2 = difference_ioc(seq, lag=2, modulus=29)
        self.assertEqual(ioc_lag2, 1.0)

    def test_difference_ioc_uniform_random_baseline(self):
        """Uniformly distributed random differences yield IoC ~ 1/29 ≈ 0.0345."""
        rng = random.Random(3301)
        uniform_seq = [rng.randint(0, 28) for _ in range(5000)]
        ioc = difference_ioc(uniform_seq, lag=1, modulus=29)
        self.assertAlmostEqual(ioc, 1.0 / 29.0, delta=0.01)

    def test_difference_ioc_periodic_keystream_peak(self):
        """A periodic Vigenère keystream produces an elevated difference IoC at lag = period."""
        rng = random.Random(3301)
        plaintext = [rng.randint(0, 28) for _ in range(600)]
        key = [5, 12, 19, 7]  # Period 4
        cipher = [(p + key[i % 4]) % 29 for i, p in enumerate(plaintext)]

        # Lag matching period (4) shows distinct difference coincidence
        ioc_period = difference_ioc(cipher, lag=4, modulus=29)
        ioc_non_period = difference_ioc(cipher, lag=3, modulus=29)
        self.assertGreater(ioc_period, ioc_non_period)

    def test_difference_ioc_with_rune_string_input(self):
        """Verify difference_ioc correctly parses and processes a UTF-8 runic string."""
        sample_runes = "".join(RUNE_BY_INDEX[i % 29] for i in range(120))
        ioc = difference_ioc(sample_runes, lag=1, modulus=29)
        self.assertEqual(ioc, 1.0)

    def test_difference_ioc_edge_cases(self):
        """Verify boundary and invalid inputs return 0.0 gracefully."""
        self.assertEqual(difference_ioc([], lag=1), 0.0)
        self.assertEqual(difference_ioc([5], lag=1), 0.0)
        self.assertEqual(difference_ioc([5, 6], lag=2), 0.0)
        self.assertEqual(difference_ioc([1, 2, 3], lag=0), 0.0)
        self.assertEqual(difference_ioc([1, 2, 3], lag=-1), 0.0)

    # =========================================================================
    # ciphers/difference.py: pattern_ioc Tests
    # =========================================================================

    def test_pattern_ioc_identical_patterns(self):
        """A corpus of words sharing the same internal repeat pattern has IoC = 1.0."""
        # Pattern (0, 1, 1, 2)
        words_isomorphic = ["LOOK", "SEEK", "BOOK", "TOOK", "DEED"]
        # Wait, DEED is (0, 1, 1, 0), so let's use only words with identical pattern (0, 1, 1, 2):
        words_identical_pattern = ["LOOK", "SEEK", "BOOK", "TOOK", "FEEL"]
        ioc = pattern_ioc(words_identical_pattern)
        self.assertEqual(ioc, 1.0)

    def test_pattern_ioc_distinct_patterns(self):
        """A collection of words with all pairwise distinct patterns has IoC = 0.0."""
        words_distinct = [
            "A",        # (0,)
            "AT",       # (0, 1)
            "THE",      # (0, 1, 2)
            "THAT",     # (0, 1, 2, 0)
            "SEEK",     # (0, 1, 1, 2)
            "BANANA",   # (0, 1, 2, 1, 2, 1)
        ]
        ioc = pattern_ioc(words_distinct)
        self.assertEqual(ioc, 0.0)

    def test_pattern_ioc_mixed_formula(self):
        """Verify pattern IoC matches sum(c * (c - 1)) / (N * (N - 1))."""
        # 3 words with pattern (0, 1) -> count 3
        # 2 words with pattern (0, 1, 1, 2) -> count 2
        # Total N = 5
        words = ["IN", "AT", "ON", "SEEK", "LOOK"]
        # Matching pairs: 3*2 + 2*1 = 6 + 2 = 8
        # Total pairs: 5*4 = 20
        # Expected IoC = 8 / 20 = 0.40
        ioc = pattern_ioc(words)
        self.assertAlmostEqual(ioc, 0.40, places=6)

    def test_pattern_ioc_delimited_string_input(self):
        """Verify pattern_ioc tokenizes words separated by runic interpuncts, colons, and spaces."""
        text = "ᛋᚩᛗᛖ᛫ᚹᛁᛋᛞᚩᛗ᛬ᚦᛖ᛫ᛈᚱᛁᛗᛖᛋ"
        ioc = pattern_ioc(text)
        self.assertIsInstance(ioc, float)
        self.assertGreaterEqual(ioc, 0.0)
        self.assertLessEqual(ioc, 1.0)

    def test_pattern_ioc_edge_cases(self):
        """Verify edge cases (< 2 words, empty words) return 0.0."""
        self.assertEqual(pattern_ioc([]), 0.0)
        self.assertEqual(pattern_ioc(["SOLO"]), 0.0)
        self.assertEqual(pattern_ioc("   "), 0.0)

    # =========================================================================
    # scripts/normalize_runes.py: --normalize-three-dot Tests
    # =========================================================================

    def test_normalize_three_dot_mapping(self):
        """Verify 3-dot punctuation (᛭, ⁝, ⋮, ...) maps to ᛬ + ᛫ when enabled."""
        raw_text = "ᛋᚩᛗᛖ᛭ᚹᛁᛋᛞᚩᛗ⁝ᚦᛖ⋮ᛈᚱᛁᛗᛖᛋ...ᛋᚪᚳᚱᛖᛞ"
        normalized, stats = normalize_text(raw_text, normalize_three_dot=True)

        # All 3-dot characters must be replaced by ᛬᛫ (\u16EC\u16EB)
        self.assertNotIn("᛭", normalized)
        self.assertNotIn("⁝", normalized)
        self.assertNotIn("⋮", normalized)
        self.assertNotIn("...", normalized)
        self.assertIn("᛬᛫", normalized)

        # Count occurrences of ᛬᛫
        self.assertEqual(normalized.count("᛬᛫"), 4)

    def test_normalize_three_dot_preserves_offsets(self):
        """Verify that normalize_three_dot preserves the exact original character offsets of runes."""
        raw_text = "ᛋᚩᛗᛖ᛭ᚹᛁᛋ"
        # Index breakdown in raw_text:
        # 0: ᛋ, 1: ᚩ, 2: ᛗ, 3: ᛖ
        # 4: ᛭ (3-dot symbol)
        # 5: ᚹ, 6: ᛁ, 7: ᛋ
        expected_rune_offsets = [0, 1, 2, 3, 5, 6, 7]

        normalized, stats = normalize_text(raw_text, normalize_three_dot=True)
        self.assertEqual(normalized, "ᛋᚩᛗᛖ᛬᛫ᚹᛁᛋ")
        self.assertEqual(stats["rune_offsets"], expected_rune_offsets)
        self.assertEqual(stats["rune_count"], 7)

        # Verify offset_map links each normalized index back to the source index
        offset_map = stats["offset_map"]
        # '᛬' and '᛫' at normalized indices 4 and 5 both point to source index 4 (the '᛭')
        self.assertEqual(offset_map[4], 4)
        self.assertEqual(offset_map[5], 4)
        # 'ᚹ' at normalized index 6 points to source index 5
        self.assertEqual(offset_map[6], 5)

    def test_normalize_three_dot_backward_compatibility(self):
        """When normalize_three_dot=False (default), ᛭ is preserved as standard Futhorc punctuation."""
        raw_text = "ᛋᚩᛗᛖ᛭ᚹᛁᛋ"
        normalized, stats = normalize_text(raw_text, normalize_three_dot=False)
        self.assertEqual(normalized, "ᛋᚩᛗᛖ᛭ᚹᛁᛋ")
        self.assertFalse(stats["normalize_three_dot"])


if __name__ == "__main__":
    unittest.main()
