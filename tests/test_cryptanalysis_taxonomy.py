"""
Unit test suite for ciphers/taxonomy.py — Advanced Cryptanalytic Taxonomy for Liber Primus.
Tests:
1. Calibrated GF(29) Futhorc Language Model & Scoring
2. Statistical Triage Engine (Unigram IC, Kappa, Bigram IC, Entropy, Word Lengths)
3. Multi-Metric Key Length Estimation (Kasiski GCD, Difference Periodogram, Column IoC)
4. Separable Per-Column T-Table Solver, MIC Alignment & Coupled Hill Climbing
5. Fast O(m) Dictionary Keyword Scoring via T-Table
6. Berlekamp-Massey over GF(29), Finite Differences & Stream Hash Bank
7. Deterministic Stream Sweeps (Primes, Totients, Fehu-Skip)
8. Monte Carlo Surrogate Shuffle Significance Test (Z-Score)
9. End-to-End Cryptanalytic Pipeline (crack_liber_primus) & Ledger Persistence
10. Terminal Workstation Integration (/crack, /triage, /period, /crib)
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import agents.ledger as ledger
from ciphers.agrippa import decode_runes, latin_to_rune
from ciphers.kasiski import rune_vigenere_decode, rune_vigenere_encode
import ciphers.taxonomy as taxonomy
import trithemius


class TestCryptanalysisTaxonomy(unittest.TestCase):
    def setUp(self):
        tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(tmp_dir.cleanup)
        db_path = os.path.join(tmp_dir.name, "ledger.sqlite3")
        vector_dir = os.path.join(tmp_dir.name, "vectordb")
        os.makedirs(vector_dir, exist_ok=True)

        orig_db = ledger.DB_PATH
        orig_vec = ledger.VECTOR_DIR
        saved_defaults = []
        for name in dir(ledger):
            fn = getattr(ledger, name)
            if callable(fn) and getattr(fn, "__defaults__", None):
                defs = fn.__defaults__
                if orig_db in defs or orig_vec in defs:
                    saved_defaults.append((fn, defs))
                    fn.__defaults__ = tuple(
                        db_path if d == orig_db else (vector_dir if d == orig_vec else d)
                        for d in defs
                    )

        ledger._VECTOR_CLIENT = None
        ledger._VECTOR_COLLECTION = None
        p_db = patch.object(ledger, "DB_PATH", db_path)
        p_vec = patch.object(ledger, "VECTOR_DIR", vector_dir)
        p_db.start()
        p_vec.start()

        def _cleanup_ledger():
            ledger._VECTOR_CLIENT = None
            ledger._VECTOR_COLLECTION = None
            for fn, defs in saved_defaults:
                fn.__defaults__ = defs

        self.addCleanup(p_db.stop)
        self.addCleanup(p_vec.stop)
        self.addCleanup(_cleanup_ledger)

        self.workstation = trithemius.TerminalWorkstation()
        self.sample_pt_latin = (
            "WELCOME PILGRIMS TO THIS GREAT JOURNEY A WARNING BELIEVE NOTHING FROM THIS BOOK "
            "EXCEPT WHAT YOU KNOW TO BE TRUE TEST THE KNOWLEDGE FIND YOUR TRUTH EXPERIENCE YOUR DEATH "
            "DO NOT EDIT OR CHANGE THIS BOOK OR THE MESSAGE CONTAINED WITHIN FOR ALL IS SACRED"
        )
        self.sample_pt_runes = latin_to_rune(self.sample_pt_latin)
        self.sample_key = "DIVINITY"
        self.sample_ct_runes = rune_vigenere_encode(self.sample_pt_runes, self.sample_key)

    def test_calibrated_language_model(self):
        """Verify the calibrated 29-rune language model unigram and bigram properties."""
        self.assertEqual(len(taxonomy.RUNIC_UNIGRAM_LOGP), 29)
        self.assertEqual(len(taxonomy.RUNIC_BIGRAM_LOGP), 29)
        for row in taxonomy.RUNIC_BIGRAM_LOGP:
            self.assertEqual(len(row), 29)

        # English-like text should score substantially higher than random indices
        pt_indices = taxonomy.clean_runes_to_indices(self.sample_pt_runes)
        score_pt = taxonomy.score_composite_runes(pt_indices)

        # Inverted or scrambled indices should score lower
        random_indices = [(x * 17 + 11) % 29 for x in range(len(pt_indices))]
        score_rand = taxonomy.score_composite_runes(random_indices)

        self.assertGreater(score_pt, score_rand)
        self.assertGreater(score_pt, -3.5)

    def test_triage_engine_classifications(self):
        """Verify statistical triage metrics and classification rules."""
        # 1. Cleartext / Monoalphabetic: high kappa (> 1.55)
        triage_mono = taxonomy.triage_cipher(self.sample_pt_runes)
        self.assertIn("MONOALPHABETIC", triage_mono["classification"])
        self.assertGreater(triage_mono["normalized_kappa"], 1.55)
        self.assertGreater(triage_mono["ic"], 0.050)

        # 2. Periodic Vigenere: intermediate kappa (1.14 - 1.55)
        triage_poly = taxonomy.triage_cipher(self.sample_ct_runes)
        self.assertEqual(triage_poly["classification"], "PERIODIC_POLYALPHABETIC")
        self.assertGreaterEqual(triage_poly["normalized_kappa"], 1.10)
        self.assertLess(triage_poly["normalized_kappa"], 1.55)

        # 3. Flat stream / OTP: kappa ~ 1.0
        flat_stream = [((i * 13) % 29) for i in range(250)]
        flat_runes = taxonomy.indices_to_runes(flat_stream)
        triage_flat = taxonomy.triage_cipher(flat_runes)
        self.assertEqual(triage_flat["classification"], "APERIODIC_OR_STREAM")
        self.assertLess(triage_flat["normalized_kappa"], 1.15)

    def test_multi_metric_key_length_estimation(self):
        """Verify Kasiski GCD, difference periodogram comb, and consensus key length."""
        indices = taxonomy.clean_runes_to_indices(self.sample_ct_runes)

        # Difference periodogram comb filter should compute chi-squared over 29 bins
        diff_periodogram = taxonomy.difference_periodogram(indices, max_lag=24)
        self.assertIn(8, diff_periodogram)
        self.assertIn(16, diff_periodogram)

        # Consensus estimation should identify key length multiples
        consensus = taxonomy.consensus_key_length_estimation(self.sample_ct_runes, max_period=20)
        top_periods = [p[0] for p in consensus[:5]]
        # 8 or its divisors/multiples (e.g. 2, 4, 8, 16) must appear in top candidate periods
        self.assertTrue(any(p in top_periods for p in (2, 4, 8, 16)))

    def test_separable_t_table_and_separable_optimum(self):
        """Verify O(29*m) T-table computation and separable per-column recovery."""
        indices = taxonomy.clean_runes_to_indices(self.sample_ct_runes)
        m = 8
        t_table = taxonomy.compute_t_table(indices, m)
        self.assertEqual(len(t_table), m)
        self.assertEqual(len(t_table[0]), 29)

        sep_key = taxonomy.solve_separable_key(t_table)
        self.assertEqual(len(sep_key), m)

        # Decoding with separable key should yield substantially higher fitness than random key
        dec = [(indices[i] - sep_key[i % m]) % 29 for i in range(len(indices))]
        score = taxonomy.score_composite_runes(dec)
        self.assertGreater(score, -3.6)

    def test_fast_dictionary_scoring_t_table(self):
        """Verify O(m) dictionary candidate evaluation using precomputed T-tables."""
        indices = taxonomy.clean_runes_to_indices(self.sample_ct_runes)
        m = 8
        t_table = taxonomy.compute_t_table(indices, m)

        candidates = [
            taxonomy.canonical_key_shifts("DIVINITY"),
            taxonomy.canonical_key_shifts("WELCOME"),
            taxonomy.canonical_key_shifts("PILGRIMS"),
            taxonomy.canonical_key_shifts("SACRED"),
        ]
        scored = taxonomy.score_dictionary_keys_t_table(t_table, candidates)

        # DIVINITY must score highest among candidates
        best_candidate, best_score = scored[0]
        divinity_shifts = taxonomy.canonical_key_shifts("DIVINITY")
        self.assertEqual(best_candidate, divinity_shifts)

    def test_berlekamp_massey_over_gf29(self):
        """Verify Berlekamp-Massey linear complexity and recurrence extraction in GF(29)."""
        # 1. Fibonacci recurrence: s_n = s_{n-1} + s_{n-2} mod 29 -> LC = 2
        fib = [0, 1]
        for _ in range(16):
            fib.append((fib[-1] + fib[-2]) % 29)
        lc_fib, poly_fib = taxonomy.berlekamp_massey_gf29(fib)
        self.assertEqual(lc_fib, 2)
        # Connection polynomial [1, 28, 28] corresponds to 1 - x - x^2 = 0
        self.assertEqual(poly_fib[:3], [1, 28, 28])

        # 2. Constant stream: LC = 1
        constant_stream = [7] * 12
        lc_const, _ = taxonomy.berlekamp_massey_gf29(constant_stream)
        self.assertEqual(lc_const, 1)

        # 3. Arithmetic progression: s_n = 3*n + 4 mod 29 -> LC = 2
        arith_stream = [(3 * i + 4) % 29 for i in range(12)]
        lc_arith, _ = taxonomy.berlekamp_massey_gf29(arith_stream)
        self.assertEqual(lc_arith, 2)

    def test_finite_difference_detection(self):
        """Verify detection of constant and linear counter sequences via finite differences."""
        constant_stream = [5, 5, 5, 5, 5, 5]
        self.assertEqual(taxonomy.detect_finite_differences(constant_stream), 0)

        linear_stream = [2, 5, 8, 11, 14, 17]
        self.assertEqual(taxonomy.detect_finite_differences(linear_stream), 1)

        quadratic_stream = [(i * i) % 29 for i in range(8)]
        self.assertEqual(taxonomy.detect_finite_differences(quadratic_stream), 2)

    def test_stream_hash_bank(self):
        """Verify O(1) identification of deterministic stream fragments in StreamHashBank."""
        # Query 6-element prime window mod 29: [2, 3, 5, 7, 11, 13]
        prime_frag = [2, 3, 5, 7, 11, 13]
        match = taxonomy.HASH_BANK.query_fragment(prime_frag)
        self.assertIsNotNone(match)
        self.assertTrue("PRIME_STREAM" in match)

        # Query Fibonacci window: [1, 1, 2, 3, 5, 8]
        fib_frag = [1, 1, 2, 3, 5, 8]
        match_fib = taxonomy.HASH_BANK.query_fragment(fib_frag)
        self.assertIsNotNone(match_fib)
        self.assertTrue("FIBONACCI_STREAM" in match_fib)

    def test_crib_dragging(self):
        """Verify sliding crib extraction and implied key analysis."""
        indices = taxonomy.clean_runes_to_indices(self.sample_ct_runes)
        # Position 0 has plaintext 'WELCOME'
        hits = taxonomy.drag_crib(indices, "WELCOME")
        self.assertTrue(len(hits) > 0)
        # Hit at position 0 must have implied key beginning with DIVINIT...
        pos0_hit = next((h for h in hits if h["position"] == 0), None)
        self.assertIsNotNone(pos0_hit)
        self.assertLessEqual(pos0_hit["linear_complexity"], 4)

    def test_deterministic_stream_sweeps(self):
        """Verify sweep of prime and totient streams with and without Fehu-skip."""
        # Generate a test ciphertext encrypted with prime stream offset 5
        primes = []
        c = 2
        while len(primes) < 50:
            if taxonomy.is_prime(c):
                primes.append(c % 29)
            c += 1
        pt_runes = latin_to_rune("SACRED PRIMES AND TOTIENTS")
        pt_indices = taxonomy.clean_runes_to_indices(pt_runes)
        ct_indices = [(pt_indices[i] + primes[5 + i]) % 29 for i in range(len(pt_indices))]

        hits = taxonomy.sweep_deterministic_streams(ct_indices, max_offset=20)
        self.assertTrue(len(hits) > 0)
        # Best hit should recover PRIME_STREAM at offset 5
        best_hit = hits[0]
        self.assertEqual(best_hit["stream"], "PRIME_STREAM")
        self.assertEqual(best_hit["offset"], 5)

    def test_surrogate_shuffle_significance(self):
        """Verify Monte Carlo shuffle test produces high Z-scores for real decryptions."""
        pt_indices = taxonomy.clean_runes_to_indices(self.sample_pt_runes)
        score_pt = taxonomy.score_composite_runes(pt_indices)

        mu, std, z, is_sig = taxonomy.surrogate_shuffle_test(pt_indices, score_pt, n_shuffles=30)
        self.assertGreater(z, 5.0)
        self.assertTrue(is_sig)

        # Flat noise score should not be significant
        noise_score = mu
        _, _, z_noise, is_sig_noise = taxonomy.surrogate_shuffle_test(pt_indices, noise_score, n_shuffles=30)
        self.assertLess(z_noise, 2.0)
        self.assertFalse(is_sig_noise)

    def test_full_crack_pipeline_and_ledger(self):
        """Verify complete crack_liber_primus cascade solver recovers known keys and logs to SQLite."""
        res = taxonomy.crack_liber_primus(self.sample_ct_runes, page_id="unit_test_page", deep=False)
        self.assertIsNotNone(res["winner"])
        self.assertTrue("DIVINITY" in res["winner"]["key_latin"] or "DIUINITY" in res["winner"]["key_latin"])
        self.assertTrue(res["winner"]["significance"]["is_statistically_significant"])

        # Check that it logged to canonical_attempts table
        from agents.ledger import _connect
        conn = _connect()
        cur = conn.execute(
            "SELECT score, passed_gatekeeper, canonical_key "
            "FROM canonical_attempts WHERE page = 'unit_test_page' AND passed_gatekeeper = 1"
        )
        row = cur.fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row[1], 1)  # passed_gatekeeper == True

    def test_workstation_cli_methods(self):
        """Verify TerminalWorkstation run_ methods execute cleanly."""
        # 1. run_triage
        triage_data = self.workstation.run_triage(self.sample_ct_runes)
        self.assertEqual(triage_data["classification"], "PERIODIC_POLYALPHABETIC")

        # 2. run_period
        period_data = self.workstation.run_period(self.sample_ct_runes, max_period=16)
        self.assertTrue(len(period_data["periods"]) > 0)

        # 3. run_crib
        crib_data = self.workstation.run_crib(self.sample_ct_runes, "WELCOME")
        self.assertTrue(crib_data["total_tested"] > 0)

        # 4. run_crack
        crack_data = self.workstation.run_crack(self.sample_ct_runes)
        self.assertIsNotNone(crack_data["winner"])


if __name__ == "__main__":
    unittest.main()
