"""
Unit tests for the Deterministic Router (scripts/router.py).
Covers:
1. Pure deterministic query classification (English and Italian)
2. Hybrid query classification with ground truth precomputation
3. Fallthrough to RAG
4. Operand bounds safeguards (<= 10^12) and text length bounds
5. Page 0 ("Welcome" page) handling
6. Corpus directory traversal safeguards
7. Feature flag TRITHEMIUS_ROUTER=off
"""

import os
import sys
import unittest
from unittest.mock import patch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import scripts.router as router


class TestRouterClassification(unittest.TestCase):
    def test_prime_check_english(self):
        res = router.classify_query("is 3301 prime?")
        self.assertEqual(res["mode"], "deterministic")
        self.assertEqual(res["action"], "prime_check")
        self.assertEqual(res["params"]["number"], 3301)

    def test_prime_check_italian(self):
        res = router.classify_query("è 3301 primo")
        self.assertEqual(res["mode"], "deterministic")
        self.assertEqual(res["action"], "prime_check")
        self.assertEqual(res["params"]["number"], 3301)

    def test_prime_factors_english(self):
        res = router.classify_query("factors of 60")
        self.assertEqual(res["mode"], "deterministic")
        self.assertEqual(res["action"], "prime_factors")
        self.assertEqual(res["params"]["number"], 60)

    def test_prime_factors_italian(self):
        res = router.classify_query("fattori primi di 60")
        self.assertEqual(res["mode"], "deterministic")
        self.assertEqual(res["action"], "prime_factors")
        self.assertEqual(res["params"]["number"], 60)

    def test_euler_totient_english(self):
        res = router.classify_query("phi(3301)")
        self.assertEqual(res["mode"], "deterministic")
        self.assertEqual(res["action"], "euler_totient")
        self.assertEqual(res["params"]["number"], 3301)

    def test_euler_totient_italian(self):
        res = router.classify_query("totiente di 3301")
        self.assertEqual(res["mode"], "deterministic")
        self.assertEqual(res["action"], "euler_totient")
        self.assertEqual(res["params"]["number"], 3301)

    def test_gematria_lookup(self):
        res = router.classify_query("gematria of WELCOME")
        self.assertEqual(res["mode"], "deterministic")
        self.assertEqual(res["action"], "gematria")
        self.assertEqual(res["params"]["text"], "WELCOME")

    def test_vigenere_lookup(self):
        res = router.classify_query("decrypt ᚹᛖᛚ with key DIVINITY")
        self.assertEqual(res["mode"], "deterministic")
        self.assertEqual(res["action"], "vigenere")
        self.assertEqual(res["params"]["mode"], "decode")
        self.assertEqual(res["params"]["key"], "DIVINITY")

    def test_page_raw_text(self):
        res = router.classify_query("show page 0")
        self.assertEqual(res["mode"], "deterministic")
        self.assertEqual(res["action"], "page_text")
        self.assertEqual(res["params"]["page"], "0")

    def test_status_query(self):
        res = router.classify_query("status")
        self.assertEqual(res["mode"], "deterministic")
        self.assertEqual(res["action"], "status")

    def test_hybrid_explanatory_page(self):
        res = router.classify_query("Why is the prime sum of page 56 significant?")
        self.assertEqual(res["mode"], "hybrid")
        self.assertIsNotNone(res["ground_truth"])
        self.assertEqual(res["ground_truth"]["page"], "56")
        self.assertGreater(res["ground_truth"]["prime_sum"], 0)

    def test_hybrid_explanatory_math(self):
        res = router.classify_query("Explain why 3301 is a prime number in Cicada lore")
        self.assertEqual(res["mode"], "hybrid")
        self.assertIsNotNone(res["ground_truth"])
        self.assertTrue(res["ground_truth"]["is_prime"])

    def test_fallthrough_rag(self):
        res = router.classify_query("What is the philosophy behind Cicada 3301?")
        self.assertEqual(res["mode"], "rag")
        self.assertIsNone(res["action"])

    def test_atbash_classification(self):
        res = router.classify_query("atbash of ᚹᛖᛚᚳᚩᛗᛖ")
        self.assertEqual(res["mode"], "deterministic")
        self.assertEqual(res["action"], "atbash")
        self.assertEqual(res["params"]["text"], "ᚹᛖᛚᚳᚩᛗᛖ")

    def test_transliterate_classification(self):
        res = router.classify_query("decode runes ᚦᚩᚱᚳ")
        self.assertEqual(res["mode"], "deterministic")
        self.assertEqual(res["action"], "transliterate")
        self.assertEqual(res["params"]["text"], "ᚦᚩᚱᚳ")

    def test_entropy_classification(self):
        res = router.classify_query("entropy of ᚠᚢᚦᚩᚱᚳ")
        self.assertEqual(res["mode"], "deterministic")
        self.assertEqual(res["action"], "entropy")

    def test_ioc_classification(self):
        res = router.classify_query("ioc of WELCOMEPILGRIM")
        self.assertEqual(res["mode"], "deterministic")
        self.assertEqual(res["action"], "ioc")

    def test_hybrid_named_page(self):
        res = router.classify_query("Explain what happens in loss of innocence")
        self.assertEqual(res["mode"], "hybrid")
        self.assertIsNotNone(res["ground_truth"])
        self.assertEqual(res["ground_truth"]["page"], "56")


class TestRouterExecution(unittest.TestCase):
    def test_execute_prime_check(self):
        route = {"action": "prime_check", "params": {"number": 3301}}
        out = router.execute_deterministic(route)
        self.assertIn("0 LLM tokens", out)
        self.assertIn("3301 is a PRIME number", out)

    def test_execute_composite_check(self):
        route = {"action": "prime_check", "params": {"number": 60}}
        out = router.execute_deterministic(route)
        self.assertIn("COMPOSITE", out)
        self.assertIn("[2, 2, 3, 5]", out)

    def test_execute_totient(self):
        route = {"action": "euler_totient", "params": {"number": 3301}}
        out = router.execute_deterministic(route)
        self.assertIn("phi(3301) = 3300", out)

    def test_execute_page_0(self):
        route = {"action": "page_text", "params": {"page": "0"}}
        out = router.execute_deterministic(route)
        self.assertIn("WELCOME PILGRIMS", out)

    def test_execute_atbash(self):
        route = {"action": "atbash", "params": {"text": "ᚹᛖᛚᚳᚩᛗᛖ"}}
        out = router.execute_deterministic(route)
        self.assertIn("Atbash Runes", out)
        self.assertIn("Atbash Latin", out)

    def test_execute_transliterate(self):
        route = {"action": "transliterate", "params": {"text": "ᚹᛖᛚᚳᚩᛗᛖ"}}
        out = router.execute_deterministic(route)
        self.assertIn("Decoded Latin:   WELCOME", out)

    def test_execute_entropy(self):
        route = {"action": "entropy", "params": {"text": "ABCDEFGH"}}
        out = router.execute_deterministic(route)
        self.assertIn("Shannon Entropy", out)

    def test_execute_ioc(self):
        route = {"action": "ioc", "params": {"text": "WELCOMEPILGRIM"}}
        out = router.execute_deterministic(route)
        self.assertIn("Index of Coinc", out)

    def test_operand_bound_safeguard(self):
        route = {"action": "prime_check", "params": {"number": 10**13}}
        out = router.execute_deterministic(route)
        self.assertIn("Operand exceeds deterministic calculation bound of 10^12", out)

    def test_text_len_safeguard(self):
        route = {"action": "gematria", "params": {"text": "A" * 15000}}
        out = router.execute_deterministic(route)
        self.assertIn("Input length exceeds maximum bound of 10,000 characters", out)


class TestRouterFeatureFlag(unittest.TestCase):
    def test_router_off_flag(self):
        with patch.dict(os.environ, {"TRITHEMIUS_ROUTER": "off"}):
            res = router.classify_query("is 3301 prime")
            self.assertEqual(res["mode"], "rag")


if __name__ == "__main__":
    unittest.main()
