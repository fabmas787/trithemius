"""
Unit tests for Page 56 cryptanalysis module (scripts/cryptanalyze_page56.py).
Verifies transcript loading, prime sieve, Pisano recurrence generator,
clause/word reset Vigenère decoders, and scoring integration.
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "ciphers"))
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))

from scripts.cryptanalyze_page56 import (
    load_page_56_transcript,
    sieve_primes,
    generate_pisano_stream,
    execute_hypothesis_1_euler_totient,
    execute_hypothesis_2_pisano_recurrence,
    execute_hypothesis_3_clause_word_vigenere,
    evaluate_candidate,
)
from ciphers.agrippa import INDEX_BY_RUNE, PRIME_BY_RUNE


class TestCryptanalyzePage56(unittest.TestCase):
    """Test suite for Page 56 mathematical hypothesis cryptanalysis."""

    def test_transcript_loading_and_integrity(self):
        """Verify that Page 56 authentic transcript loads with exact canonical counts."""
        data = load_page_56_transcript()
        self.assertEqual(data["rune_count"], 273)
        self.assertEqual(data["prime_sum"], 14142)
        self.assertEqual(len(data["clauses_indices"]), 4)
        self.assertEqual(data["clause_lengths"], [13, 71, 114, 75])
        self.assertEqual(data["word_count"], 68)
        self.assertEqual(sum(len(c) for c in data["clauses_indices"]), 273)
        self.assertEqual(sum(len(w) for w in data["words_indices"]), 273)

    def test_prime_sieve_and_totients(self):
        """Verify prime generator and Euler totient properties."""
        primes = sieve_primes(20)
        expected_first_10 = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
        self.assertEqual(primes[:10], expected_first_10)

        # Totients mod 29 for primes p: (p - 1) mod 29
        # For p=2: 1 mod 29
        # For p=29: 28 mod 29
        # For p=31: 30 mod 29 = 1 mod 29
        totients = [(p - 1) % 29 for p in primes]
        self.assertEqual(totients[0], 1)
        self.assertEqual(totients[9], 28)
        self.assertEqual(totients[10], 1)  # 31 - 1 = 30 = 1 mod 29

    def test_pisano_recurrence_period_14(self):
        """Verify that Fibonacci mod 29 has Pisano period 14."""
        stream = generate_pisano_stream(1, 1, 0, 1, 30)
        # Sequence: 0, 1, 1, 2, 3, 5, 8, 13, 21, 5, 26, 2, 28, 1, 0, 1 ...
        self.assertEqual(stream[0], 0)
        self.assertEqual(stream[1], 1)
        self.assertEqual(stream[14], 0)
        self.assertEqual(stream[15], 1)

    def test_candidate_evaluator(self):
        """Verify candidate evaluator returns expected metrics schema and correctly rejects raw ciphertext."""
        data = load_page_56_transcript()
        cand = evaluate_candidate(
            data["rune_indices"],
            data["trans_text"],
            method="TEST_RAW_CIPHERTEXT",
            parameters={"test": True},
        )
        self.assertIn("score", cand)
        self.assertIn("ngram_score", cand)
        self.assertIn("chi_squared", cand)
        self.assertIn("word_ratio", cand)
        self.assertIn("passed_gatekeeper", cand)
        self.assertFalse(cand["is_plausible_runic"])
        self.assertFalse(cand["passed_gatekeeper"])

    def test_gatekeeper_rejects_spurious_multigraph_noise(self):
        """Verify that pseudo-random runic noise with accidental Latin trigrams is rejected."""
        data = load_page_56_transcript()
        # Candidate with random multigraphs should not pass gatekeeper
        cand = evaluate_candidate(
            data["rune_indices"][:50],
            data["trans_text"][:50],
            method="TEST_NOISE",
            parameters={},
        )
        self.assertFalse(cand["passed_gatekeeper"])

    def test_gatekeeper_accepts_authentic_text(self):
        """Verify that genuine solved Liber Primus text clears the gatekeeper."""
        from ciphers.taxonomy import clean_runes_to_indices
        from ciphers.agrippa import latin_to_rune
        authentic_sample = latin_to_rune("WELCOME PILGRIM ON THE SACRED PATH OF KNOWLEDGE AND TRUTH")
        indices = clean_runes_to_indices(authentic_sample)
        cand = evaluate_candidate(
            indices,
            authentic_sample,
            method="TEST_AUTHENTIC",
            parameters={},
        )
        self.assertTrue(cand["passed_gatekeeper"])

    def test_hypothesis_1_execution_sample(self):
        """Verify Hypothesis 1 runs on sample offsets."""
        data = load_page_56_transcript()
        h1_res = execute_hypothesis_1_euler_totient(
            data["rune_indices"][:30],
            data["trans_text"],
            scan_limit=5,
            specific_offsets=[0, 56],
        )
        self.assertGreater(len(h1_res), 0)
        for cand in h1_res:
            self.assertEqual(cand["parameters"]["hypothesis"], 1)
            self.assertFalse(cand["passed_gatekeeper"])

    def test_hypothesis_2_execution_sample(self):
        """Verify Hypothesis 2 runs on sample pairs."""
        data = load_page_56_transcript()
        # Test full recurrence execution on slice
        h2_res = execute_hypothesis_2_pisano_recurrence(
            data["rune_indices"][:30],
            data["trans_text"],
        )
        self.assertGreater(len(h2_res), 100)
        for cand in h2_res:
            self.assertFalse(cand["passed_gatekeeper"])

    def test_hypothesis_3_execution_sample(self):
        """Verify Hypothesis 3 runs across clause and word reset modes and all F-skip modes."""
        data = load_page_56_transcript()
        h3_res = execute_hypothesis_3_clause_word_vigenere(
            data["rune_indices"],
            data["clauses_indices"],
            data["words_indices"],
            data["trans_text"],
            keywords=["DIVINITY", "SACRED"],
        )
        # 2 keywords * 3 reset modes * 3 operations * 3 f_skip modes = 54 candidates
        self.assertEqual(len(h3_res), 54)
        reset_modes = {c["parameters"]["reset_mode"] for c in h3_res}
        self.assertEqual(reset_modes, {"clause_reset", "word_reset", "no_reset"})
        f_skip_modes = {c["parameters"]["f_skip_mode"] for c in h3_res}
        self.assertEqual(f_skip_modes, {"none", "cleartext_f_skip", "ciphertext_f_skip"})
        for cand in h3_res:
            self.assertFalse(cand["passed_gatekeeper"])


if __name__ == "__main__":
    unittest.main()
