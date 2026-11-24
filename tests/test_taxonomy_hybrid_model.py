import random
import unittest
from ciphers.taxonomy import (
    RUNIC_BIGRAM_LOGP,
    score_composite_runes,
    surrogate_shuffle_test,
    clean_runes_to_indices,
    triage_cipher,
)
from ciphers.agrippa import latin_to_rune
from ciphers.interrupter import analyze_f_skip_periodicity


class TestTaxonomyHybridModel(unittest.TestCase):
    def test_hybrid_bigram_matrix_coverage_and_cache(self):
        m = 29
        floor_count = sum(
            1 for r in range(m) for c in range(m)
            if RUNIC_BIGRAM_LOGP[r][c] < -6.5
        )
        self.assertLess(floor_count, 400, "Bigram matrix remains too sparse!")

    def test_surrogate_test_prng_isolation(self):
        # Global random state must not be modified by surrogate_shuffle_test
        state_before = random.getstate()
        sample = clean_runes_to_indices(latin_to_rune("A WARNING BELIEVE NOTHING FROM THIS BOOK"))
        score = score_composite_runes(sample)
        res = surrogate_shuffle_test(sample, score, n_shuffles=50, n_trials=10)
        state_after = random.getstate()
        self.assertEqual(state_before, state_after, "Global random state was polluted!")
        self.assertIsNotNone(res.p_adj)

    def test_f_skip_periodicity_and_doubles_diagnostic(self):
        # Diagnostic check for consecutive double runes & local Fehu intervals
        sample_text = "ᚠᚪᚱᛖᚹᛖᛚᛚ᛫ᚠᛁᚱᚠᚢᛗᚠᛖᚱᛖᚾᚠᛖ᛫ᚠ"
        diag = analyze_f_skip_periodicity(sample_text)
        self.assertIn("consecutive_doubles_rate", diag)
        self.assertIn("uniform_doubles_rate", diag)
        self.assertAlmostEqual(diag["uniform_doubles_rate"], 1.0 / 29.0, places=4)
        self.assertIn("fehu_intervals", diag)

        # Check integration in triage_cipher
        triage = triage_cipher(sample_text)
        self.assertIn("consecutive_doubles_rate", triage)
        self.assertIn("fehu_intervals", triage)


if __name__ == "__main__":
    unittest.main()
