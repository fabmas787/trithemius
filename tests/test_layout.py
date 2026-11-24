"""
Unit tests for Layout Side-Channel Mutual Information Analysis (ciphers/layout.py).
Verifies:
1. Multiplexed stream parsing (symbols, word lengths, line lengths, separators, Fehu positions).
2. Boundary and edge cases (empty input, non-runic strings, single runes, delimited transcripts).
3. Discrete mutual information and Miller-Madow bias correction against theoretical formulas.
4. Besag-Clifford sequential Monte Carlo permutation null test (early-stopping on null, detection on planted signal).
5. Ground-truth calibration run across all 4 solved Liber Primus pages (Pages 0, 56, 57, 73).
6. Persistent hypothesis ledger recording under family 'layout-carrier'.
"""

import math
import os
import random
import tempfile
import unittest

from ciphers.agrippa import INDEX_BY_RUNE, latin_to_rune
from ciphers.layout import (
    LayoutStream,
    MIResult,
    extract_layout_stream,
    compute_discrete_mutual_information,
    estimate_mutual_information,
    analyze_all_features,
    calibrate_solved_pages,
)
from agents.ledger import count_attempts


class TestLayoutStreamExtraction(unittest.TestCase):
    def test_extract_layout_stream_synthetic(self):
        """Verify parsing of word lengths, line lengths, separators, and Fehu tracking."""
        # Line 1: Word 1 (3 runes) + '᛫', Word 2 (Fehu + 1 rune = 2 runes) + '᛬'
        # Line 2: Word 3 (4 runes) + '᛭'
        # Fehu is ᚠ (index 0)
        text = (
            "ᚱᚢᚦ᛫ᚠᚩ᛬\n"
            "ᚳᚷᚹᚻ᛭"
        )
        stream = extract_layout_stream(text)
        self.assertEqual(len(stream), 3 + 2 + 4)
        self.assertEqual(len(stream.words), 3)
        self.assertEqual(len(stream.lines), 2)

        # Word lengths aligned per symbol
        expected_word_lens = [3, 3, 3, 2, 2, 4, 4, 4, 4]
        self.assertEqual(stream.word_lengths, expected_word_lens)

        # Line lengths aligned per symbol
        expected_line_lens = [5, 5, 5, 5, 5, 4, 4, 4, 4]
        self.assertEqual(stream.line_lengths, expected_line_lens)

        # Separator tracking
        self.assertEqual(stream.separators[0], "᛫")
        self.assertEqual(stream.separators[2], "᛫")
        self.assertEqual(stream.separators[3], "᛬")
        self.assertEqual(stream.separators[5], "᛭")

        # Fehu flag tracking: symbol at index 3 is ᚠ
        self.assertEqual(stream.fehu_flags[3], 1)
        self.assertEqual(stream.fehu_flags[0], 0)
        self.assertEqual(stream.fehu_flags[5], 0)

        # Fehu distance tracking
        self.assertEqual(stream.fehu_distances[3], 0)
        self.assertEqual(stream.fehu_distances[4], 1)
        self.assertEqual(stream.fehu_distances[5], 2)

    def test_extract_layout_stream_delimited_fallbacks(self):
        """Verify fallback delimiters (- for ᛫, . for ᛬) are normalized correctly."""
        delimited_text = "ᚱᚢᚦ-ᚳᚷ.\n"
        stream = extract_layout_stream(delimited_text)
        self.assertEqual(len(stream), 5)
        self.assertEqual(stream.word_lengths, [3, 3, 3, 2, 2])
        self.assertEqual(stream.separators[0], "᛫")
        self.assertEqual(stream.separators[3], "᛬")

    def test_extract_layout_stream_empty_and_no_runes(self):
        """Edge cases: empty string or non-runic string return valid empty stream."""
        s1 = extract_layout_stream("")
        self.assertEqual(len(s1), 0)
        self.assertEqual(s1.word_lengths, [])

        s2 = extract_layout_stream("JUST LATIN TEXT WITHOUT RUNES 12345")
        self.assertEqual(len(s2), 0)
        self.assertEqual(s2.symbols, [])

    def test_extract_layout_corpus_page_lookup(self):
        """Corpus page lookup loads real file and extracts runes."""
        stream = extract_layout_stream(56)
        self.assertGreater(len(stream), 0)
        self.assertIn("word_lengths", [f for f in dir(stream) if not f.startswith("_")])
        self.assertEqual(len(stream.word_lengths), len(stream.symbols))


class TestMutualInformationEstimation(unittest.TestCase):
    def test_mutual_information_identical_streams(self):
        """I(X; X) equals empirical Shannon entropy H(X)."""
        X = [0, 1, 0, 1, 0, 1, 0, 1] * 10
        raw, mm, bias, kx, ky = compute_discrete_mutual_information(X, X)
        # For equal binary symbols, H(X) = 1.0 bit
        self.assertAlmostEqual(raw, 1.0, places=4)
        self.assertEqual(kx, 2)
        self.assertEqual(ky, 2)
        expected_bias = ((2 - 1) * (2 - 1)) / (2.0 * len(X) * math.log(2))
        self.assertAlmostEqual(bias, expected_bias, places=5)
        self.assertAlmostEqual(mm, 1.0 - expected_bias, places=4)

    def test_miller_madow_bias_formula(self):
        """Verify asymptotic bias correction formula: (kx-1)*(ky-1) / (2*N*ln2)."""
        N = 200
        # 3 categories for X, 4 categories for Y
        X = [i % 3 for i in range(N)]
        Y = [i % 4 for i in range(N)]
        _, _, bias, kx, ky = compute_discrete_mutual_information(X, Y)
        self.assertEqual(kx, 3)
        self.assertEqual(ky, 4)
        theoretical_bias = ((3 - 1) * (4 - 1)) / (2.0 * N * math.log(2.0))
        self.assertAlmostEqual(bias, theoretical_bias, places=6)

    def test_sequential_mc_early_stopping_on_null(self):
        """Independent layout and keystream exit early under sequential test."""
        rng = random.Random(42)
        N = 150
        X = [rng.randint(2, 8) for _ in range(N)]
        Y = [rng.randint(0, 28) for _ in range(N)]

        res = estimate_mutual_information(X, Y, feature_name="word_lengths", seed=42, h=10, n_max=1000)
        self.assertEqual(res.exceedances, 10)
        # Must exit after ~10-25 trials (far below 1000)
        self.assertLess(res.trials, 30)
        self.assertFalse(res.is_significant)
        self.assertEqual(res.outcome, "Outcome A: Clean Negative")

    def test_planted_side_channel_detection(self):
        """Planted side channel where keystream shift correlates with word length is detected."""
        rng = random.Random(1337)
        N = 300
        # Word lengths in {2, 3, 4, 5, 6}
        word_lens = [rng.randint(2, 6) for _ in range(N)]
        # Keystream shift strongly linked to word length
        keystream = [(wl * 5 + rng.choice([0, 0, 1])) % 29 for wl in word_lens]

        res = estimate_mutual_information(
            word_lens,
            keystream,
            feature_name="word_lengths",
            seed=1337,
            h=10,
            n_max=500,
        )
        self.assertGreater(res.mi_mm, 0.4)
        self.assertTrue(res.is_significant)
        self.assertEqual(res.outcome, "Outcome B: Significant Carrier")
        self.assertLess(res.p_value, 0.01)
        self.assertEqual(res.trials, 500)


class TestSolvedPagesCalibration(unittest.TestCase):
    def test_calibrate_all_solved_pages(self):
        """Calibration across pages 0, 56, 57, 73 produces clean negative (Outcome A) and logs to ledger."""
        with tempfile.NamedTemporaryFile(suffix=".sqlite3") as tmp_db:
            db_path = tmp_db.name
            init_attempts = count_attempts("layout-carrier", db_path=db_path)
            self.assertEqual(init_attempts, 0)

            calib = calibrate_solved_pages(db_path=db_path, seed=42, log_to_ledger=True)
            self.assertEqual(calib["status"], "completed")
            self.assertEqual(calib["family"], "layout-carrier")
            self.assertFalse(calib["any_significant"])
            self.assertIn("Outcome A", calib["overall_outcome"])

            # 4 solved pages * 5 features = 20 evaluations
            self.assertEqual(calib["total_evaluations"], 20)
            self.assertEqual(len(calib["pages"]), 4)

            # Check ledger persistence
            logged_attempts = count_attempts("layout-carrier", db_path=db_path)
            self.assertGreater(logged_attempts, 0)

            # Verify reproducibility with fixed seed
            calib2 = calibrate_solved_pages(db_path=db_path, seed=42, log_to_ledger=False)
            for p1, p2 in zip(calib["pages"], calib2["pages"]):
                for feat in p1["features"]:
                    self.assertEqual(p1["features"][feat]["mi_mm"], p2["features"][feat]["mi_mm"])
                    self.assertEqual(p1["features"][feat]["p_value"], p2["features"][feat]["p_value"])

    def test_space_and_tab_separated_word_segmentation(self):
        """Verify that space-separated and tab-separated rune words segment properly."""
        raw_text = "ᚹᛁᛋᛞᚩᛗ ᚦᛖ \t ᛈᛁᛚᚷᚱᛁᛗᛋ"
        stream = extract_layout_stream(raw_text)
        self.assertEqual(len(stream.words), 3)
        self.assertEqual([w["runes"] for w in stream.words], ["ᚹᛁᛋᛞᚩᛗ", "ᚦᛖ", "ᛈᛁᛚᚷᚱᛁᛗᛋ"])
        self.assertEqual(stream.word_lengths[:6], [6] * 6)
        self.assertEqual(stream.word_lengths[6:8], [2] * 2)
        self.assertEqual(stream.word_lengths[8:], [8] * 8)

    def test_prefer_solved_manuscript_toggle(self):
        """Verify that prefer_solved toggle selects solved summary or raw manuscript transcript."""
        s_solved = extract_layout_stream(56, prefer_solved=True)
        s_raw = extract_layout_stream(56, prefer_solved=False)
        self.assertEqual(len(s_solved), 91)
        self.assertEqual(len(s_raw), 273)


if __name__ == "__main__":
    unittest.main()
