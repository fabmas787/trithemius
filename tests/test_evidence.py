"""
Unit tests for agents/evidence.py epistemic evidence register module.
"""

import unittest
import tempfile
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agents.evidence import (
    evidence_status,
    posterior_after_negative,
    init_evidence_schema,
    record_detector_power,
    get_detector_power,
)


class TestEvidence(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_ledger.sqlite3")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_evidence_status_thresholds(self):
        # Positive outcome always yields 'candidate'
        self.assertEqual(evidence_status("positive", 0.5), "candidate")
        self.assertEqual(evidence_status("positive", 0.99), "candidate")

        # Negative with high power yields 'excluded'
        self.assertEqual(evidence_status("negative", 0.95), "excluded")
        self.assertEqual(evidence_status("negative", 0.90), "excluded")

        # Negative with weak power yields 'inconclusive'
        self.assertEqual(evidence_status("negative", 0.89), "inconclusive")
        self.assertEqual(evidence_status("negative", 0.40), "inconclusive")

    def test_bayesian_posterior_updating(self):
        # Prior 0.10, detector power 0.95
        # Odds = 0.1 / 0.9 = 1/9
        # Post odds = (1/9) * (1 - 0.95) = 0.05 / 9 = 0.005555...
        # Post = 0.005555 / 1.005555 ≈ 0.005525 (0.55%)
        post = posterior_after_negative(0.10, 0.95)
        self.assertAlmostEqual(post, 0.005525, places=4)

        # Prior 0.10, detector power 0.40
        # Post odds = (1/9) * 0.6 = 0.6/9 = 0.06666...
        # Post ≈ 0.0625 (6.25%)
        post_weak = posterior_after_negative(0.10, 0.40)
        self.assertAlmostEqual(post_weak, 0.0625, places=3)

    def test_database_persistence_and_retrieval(self):
        init_evidence_schema(self.db_path)
        record_detector_power("babbage_v1", "vigenere", 236, 0.98, 100, db_path=self.db_path)

        power = get_detector_power("babbage_v1", "vigenere", 236, db_path=self.db_path)
        self.assertIsNotNone(power)
        self.assertAlmostEqual(power, 0.98)

        missing = get_detector_power("nonexistent", "vigenere", 236, db_path=self.db_path)
        self.assertIsNone(missing)


if __name__ == "__main__":
    unittest.main()
