"""
Tests for Phase 2 (Statistical Rigor) and Phase 3 (Exact Bigram Solver):
1. Brute-force equivalence for m=2 and m=3
2. Exact score >= hill-climbing score
3. Page 56 DIVINITY recovery
4. Sequential MC early-stopping on null vs full resolution on signal
5. Look-elsewhere Sidak correction and ledger count_attempts
6. Lag-coincidence spectrum correctness
"""

import os
import sys
import math
import random
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "ciphers"))

import taxonomy
from agrippa import latin_to_rune
from kasiski import rune_vigenere_encode, rune_vigenere_decode
import agents.ledger as ledger


class TestExactBigramSolver(unittest.TestCase):
    def test_brute_force_equivalence_m2(self):
        """Verify that solve_periodic_bigram_exact matches exhaustive 29^2 argmax."""
        # Random ciphertext of length 40
        rng = random.Random(42)
        ct_indices = [rng.randint(0, 28) for _ in range(40)]

        exact_key, exact_score = taxonomy.solve_periodic_bigram_exact(ct_indices, m=2, include_unigrams=True)

        # Brute force over all 841 pairs
        best_bf_key = None
        best_bf_score = -1e9
        w_b = 0.6 / 39
        w_u = 0.4 / 40
        L2 = taxonomy.RUNIC_BIGRAM_LOGP
        L1 = taxonomy.RUNIC_UNIGRAM_LOGP

        for k0 in range(29):
            for k1 in range(29):
                key = [k0, k1]
                dec = [(ct_indices[i] - key[i % 2]) % 29 for i in range(40)]
                score = w_b * sum(L2[dec[i]][dec[i + 1]] for i in range(39)) + w_u * sum(L1[dec[i]] for i in range(40))
                if score > best_bf_score:
                    best_bf_score = score
                    best_bf_key = key

        self.assertEqual(exact_key, best_bf_key)
        self.assertAlmostEqual(exact_score, round(best_bf_score, 4), places=4)

    def test_brute_force_equivalence_m3(self):
        """Verify that solve_periodic_bigram_exact matches exhaustive 29^3 argmax."""
        rng = random.Random(1337)
        ct_indices = [rng.randint(0, 28) for _ in range(35)]

        exact_key, exact_score = taxonomy.solve_periodic_bigram_exact(ct_indices, m=3, include_unigrams=True)

        best_bf_key = None
        best_bf_score = -1e9
        w_b = 0.6 / 34
        w_u = 0.4 / 35
        L2 = taxonomy.RUNIC_BIGRAM_LOGP
        L1 = taxonomy.RUNIC_UNIGRAM_LOGP

        for k0 in range(29):
            for k1 in range(29):
                for k2 in range(29):
                    key = [k0, k1, k2]
                    dec = [(ct_indices[i] - key[i % 3]) % 29 for i in range(35)]
                    score = w_b * sum(L2[dec[i]][dec[i + 1]] for i in range(34)) + w_u * sum(L1[dec[i]] for i in range(35))
                    if score > best_bf_score:
                        best_bf_score = score
                        best_bf_key = key

        self.assertEqual(exact_key, best_bf_key)
        self.assertAlmostEqual(exact_score, round(best_bf_score, 4), places=4)

    def test_exact_beats_or_equals_hill_climbing(self):
        """Property test: exact bigram score is mathematically >= hill climbing score."""
        rng = random.Random(999)
        sample_pt = "WELCOME PILGRIMS TO THE SACRED PATH OF PRIMES AND KNOWLEDGE"
        runes = latin_to_rune(sample_pt)
        ct_runes = rune_vigenere_encode(runes, "DIVINITY")
        indices = taxonomy.clean_runes_to_indices(ct_runes)

        for period in [4, 6, 8]:
            exact_key, exact_score = taxonomy.solve_periodic_bigram_exact(indices, period)
            hc_key, hc_score = taxonomy.hill_climbing_coupled(indices, period, restarts=2)

            # Compute objective score under the bigram+unigram model
            w_b = 0.6 / (len(indices) - 1)
            w_u = 0.4 / len(indices)
            L2 = taxonomy.RUNIC_BIGRAM_LOGP
            L1 = taxonomy.RUNIC_UNIGRAM_LOGP

            def eval_model(k):
                d = [(indices[i] - k[i % period]) % 29 for i in range(len(indices))]
                return w_b * sum(L2[d[i]][d[i + 1]] for i in range(len(indices) - 1)) + w_u * sum(L1[d[i]] for i in range(len(indices)))

            exact_obj = eval_model(exact_key)
            hc_obj = eval_model(hc_key)

            # Exact solver must be >= hill climbing (within float tolerance)
            self.assertGreaterEqual(exact_obj + 1e-9, hc_obj, f"Hill climbing beat exact at m={period}!")

    def test_divinity_recovery_on_page_56(self):
        """Page 56 plaintext encrypted with DIVINITY is recovered by exact solver."""
        sample_pt = (
            "SOME WISDOM THE PRIMES ARE SACRED THE TOTIENT FUNCTION IS SACRED "
            "ALL THINGS SHOULD BE PARED TO THEIR SIMPLEST STATE"
        )
        runes = latin_to_rune(sample_pt)
        ct_runes = rune_vigenere_encode(runes, "DIVINITY")
        indices = taxonomy.clean_runes_to_indices(ct_runes)

        exact_key, score = taxonomy.solve_periodic_bigram_exact(indices, m=8)
        expected_shifts = taxonomy.canonical_key_shifts("DIVINITY")
        self.assertEqual(exact_key, expected_shifts)


class TestStatisticalRigor(unittest.TestCase):
    def test_sequential_mc_early_stop_on_null(self):
        """Clear null hypothesis exits early (trials << 1000)."""
        rng = random.Random(42)
        # Observed statistic is near median (score = -3.85)
        stat_obs = -3.85

        def null_gen():
            # Generates normal noise around -3.85
            return rng.gauss(-3.85, 0.15)

        p_hat, exceedances, trials = taxonomy.sequential_mc_pvalue(
            stat_obs, null_gen, h=10, n_max=1000
        )
        self.assertEqual(exceedances, 10)
        # Should stop after around 15-30 trials
        self.assertLess(trials, 40)
        self.assertGreaterEqual(trials, 10)

    def test_sequential_mc_detects_real_signal(self):
        """Real candidate with high statistic runs to fine-grained resolution."""
        rng = random.Random(42)
        stat_obs = -2.50  # Far out in upper tail

        def null_gen():
            return rng.gauss(-3.85, 0.15)

        p_hat, exceedances, trials = taxonomy.sequential_mc_pvalue(
            stat_obs, null_gen, h=10, n_max=1000
        )
        # Exceedances should be 0 because null never reaches -2.50
        self.assertEqual(exceedances, 0)
        self.assertEqual(trials, 1000)
        self.assertLess(p_hat, 0.002)

    def test_surrogate_test_result_rich_tuple_and_sidak(self):
        """surrogate_shuffle_test returns 4-tuple compatible with legacy unpacking and provides p_adj."""
        indices = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] * 5
        res = taxonomy.surrogate_shuffle_test(indices, candidate_score=-3.0, n_shuffles=20, sequential=False)

        # Legacy 4-tuple unpacking
        mu, std, z, sig = res
        self.assertEqual(len(res), 4)
        self.assertIsInstance(mu, float)
        self.assertIsInstance(z, float)

        # Rich attributes
        self.assertTrue(hasattr(res, "p_value"))
        self.assertTrue(hasattr(res, "p_adj"))
        self.assertTrue(hasattr(res, "trials"))
        self.assertGreaterEqual(res.p_adj, res.p_value)

    def test_lag_coincidence_spectrum_correctness(self):
        """Verify lag coincidence spectrum matches direct count."""
        indices = [3, 7, 12, 3, 5, 7, 12, 19, 3, 7]
        spectrum = taxonomy.lag_coincidence_spectrum(indices, max_lag=6)
        for d in range(1, 7):
            expected = sum(1 for i in range(len(indices) - d) if indices[i] == indices[i + d])
            self.assertEqual(spectrum[d], expected)

    def test_solve_interrupter_bigram_exact(self):
        """Verify exact MAP recovery under dynamic key interrupter schedule."""
        from interrupter import InterrupterConfig, rune_vigenere_encode_dynamic
        sample_pt = "SOME WISDOM THE PRIMES ARE SACRED THE TOTIENT FUNCTION IS SACRED ALL THINGS SHOULD BE PARED"
        runes = latin_to_rune(sample_pt)
        key = "DIVINITY"
        cfg = InterrupterConfig.from_rune_positions(runes, {"ᚠ"}, pause_key=True, pass_through=True)
        ct = rune_vigenere_encode_dynamic(runes, key, config=cfg)
        indices = taxonomy.clean_runes_to_indices(ct)

        recovered_key, score = taxonomy.solve_interrupter_bigram_exact(indices, m=8, config=cfg)
        expected_shifts = taxonomy.canonical_key_shifts(key)
        self.assertEqual(recovered_key, expected_shifts)

    def test_period_estimators_consume_lag_spectrum(self):
        """Verify that difference_periodogram, column_ioc_scan, and kasiski consume lag spectrum consistently."""
        sample_pt = "SOME WISDOM THE PRIMES ARE SACRED THE TOTIENT FUNCTION IS SACRED ALL THINGS SHOULD BE PARED TO THEIR SIMPLEST STATE"
        runes = latin_to_rune(sample_pt)
        indices = taxonomy.clean_runes_to_indices(runes)

        spectrum = taxonomy.lag_coincidence_spectrum(indices, max_lag=16)

        # Difference periodogram
        diff_with = taxonomy.difference_periodogram(indices, max_lag=16, lag_spectrum=spectrum)
        diff_without = taxonomy.difference_periodogram(indices, max_lag=16, lag_spectrum=None)
        self.assertEqual(diff_with, diff_without)

        # Column IoC scan
        col_with = taxonomy.column_ioc_scan(indices, max_period=8, lag_spectrum=spectrum)
        col_without = taxonomy.column_ioc_scan(indices, max_period=8, lag_spectrum=None)
        for m in range(1, 9):
            if m in col_with and m in col_without:
                self.assertAlmostEqual(col_with[m], col_without[m], delta=0.002)

        # Kasiski weighted GCD
        kas_with = taxonomy.kasiski_weighted_gcd(indices, max_period=8, lag_spectrum=spectrum)
        kas_without = taxonomy.kasiski_weighted_gcd(indices, max_period=8, lag_spectrum=None)
        self.assertIsInstance(kas_with, dict)
        self.assertIsInstance(kas_without, dict)


if __name__ == "__main__":
    unittest.main()
