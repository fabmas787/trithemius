"""
Unit tests for Apple Silicon Metal GPU and Apple Neural Engine (ANE) Acceleration.
Verifies device detection, compute kernels, batch scoring equivalence, compound phrase sweeps,
and neural semantic scoring.
"""

import unittest
try:
    import numpy as np
except ImportError:
    np = None

from ciphers.metal_accel import (
    is_metal_available,
    get_metal_device_info,
    metal_score_keys_batch,
    metal_sweep_2words,
    metal_sweep_3words,
    metal_surrogate_shuffles,
    benchmark_metal_throughput,
)
from ciphers.ane_engine import (
    is_ane_available,
    get_ane_device_info,
    compute_ane_embeddings,
    score_candidate_naturalness_neural,
)
from ciphers.taxonomy import crack_liber_primus


class TestMetalAcceleration(unittest.TestCase):

    def test_metal_device_detection(self):
        """Verify Metal GPU device detection and metadata retrieval."""
        info = get_metal_device_info()
        self.assertIsInstance(info, dict)
        self.assertIn("available", info)
        if info["available"]:
            self.assertIn("Apple", info["device_name"])
            self.assertGreater(info["max_buffer_bytes"], 0)
            self.assertTrue(info.get("unified_memory", False))

    def test_metal_score_keys_batch(self):
        """Verify Metal batch key scoring and equivalence with mathematical definition."""
        if not is_metal_available():
            self.skipTest("Metal GPU not available on this platform/configuration")
        period = 7
        t_table = [[float((i * 3 + j * 5) % 29) for j in range(29)] for i in range(period)]
        keys = [
            [0, 1, 2, 3, 4, 5, 6],
            [6, 5, 4, 3, 2, 1, 0],
            [10, 10, 10, 10, 10, 10, 10],
            [1, 2, 3],  # shorter key tiled
        ]

        # Reference CPU expected calculation
        expected_scores = []
        for k in keys:
            k_len = len(k)
            total = sum(t_table[i][k[i % k_len] % 29] for i in range(period))
            expected_scores.append(round(total / period, 4))

        scores = metal_score_keys_batch(t_table, keys, period)
        self.assertEqual(len(scores), len(keys))
        for s, exp in zip(scores, expected_scores):
            self.assertAlmostEqual(s, exp, places=3)

    def test_metal_sweep_2words(self):
        """Verify parallel 2-word compound sweep and threshold hit retrieval."""
        if not is_metal_available():
            self.skipTest("Metal GPU not available on this platform/configuration")
        period = 5
        t_table = [[float((i + j) % 29) for j in range(29)] for i in range(period)]
        words = [
            ("ALPHA", [1, 2, 3]),
            ("BETA", [4, 5, 6]),
            ("GAMMA", [7, 8, 9, 10]),
        ]
        hits = metal_sweep_2words(t_table, words, period, threshold=0.0, max_hits=20)
        self.assertIsInstance(hits, list)
        self.assertGreater(len(hits), 0)
        # All hits should be tuples of (w1, w2, score)
        for h in hits:
            self.assertEqual(len(h), 3)
            self.assertIsInstance(h[0], str)
            self.assertIsInstance(h[1], str)
            self.assertIsInstance(h[2], float)
            self.assertGreaterEqual(h[2], 0.0)

        # Hits should be sorted descending by score
        scores = [h[2] for h in hits]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_metal_sweep_3words(self):
        """Verify parallel 3-word compound sweep."""
        if not is_metal_available():
            self.skipTest("Metal GPU not available on this platform/configuration")
        period = 4
        t_table = [[float((i * 2 + j) % 29) for j in range(29)] for i in range(period)]
        words = [
            ("ONE", [1, 2]),
            ("TWO", [3, 4]),
            ("THREE", [5, 6]),
        ]
        hits = metal_sweep_3words(t_table, words, period, threshold=0.0, max_hits=30)
        self.assertIsInstance(hits, list)
        self.assertGreater(len(hits), 0)
        for h in hits:
            self.assertEqual(len(h), 4)
            self.assertIsInstance(h[0], str)
            self.assertIsInstance(h[1], str)
            self.assertIsInstance(h[2], str)
            self.assertIsInstance(h[3], float)

    def test_metal_surrogate_shuffles(self):
        """Verify parallel Monte Carlo surrogate shuffles."""
        if not is_metal_available():
            self.skipTest("Metal GPU not available on this platform/configuration")
        ciphertext = [1, 5, 10, 15, 20, 25, 2, 8, 14, 21, 27]
        unigram_logp = [-2.5 for _ in range(29)]
        period = 4
        num_trials = 200
        shuffles = metal_surrogate_shuffles(ciphertext, unigram_logp, period, num_trials=num_trials, base_seed=42)
        self.assertEqual(len(shuffles), num_trials)
        # With constant log-probability of -2.5, every shuffle score must evaluate to -2.5
        for s in shuffles:
            self.assertAlmostEqual(s, -2.5, places=3)

    def test_metal_benchmark(self):
        """Verify benchmark throughput utility execution."""
        bm = benchmark_metal_throughput(num_words=100, period=5)
        if is_metal_available():
            self.assertIn("combinations_tested", bm)
            self.assertEqual(bm["combinations_tested"], 10000)
            self.assertGreater(bm["combinations_per_second"], 0.0)


class TestNeuralEngineAcceleration(unittest.TestCase):

    def test_ane_device_detection(self):
        """Verify ANE device detection and execution provider options."""
        info = get_ane_device_info()
        self.assertIsInstance(info, dict)
        self.assertIn("available", info)
        self.assertIn("hardware", info)

    def test_ane_scoring_discrimination(self):
        """Verify that neural semantic scoring prefers coherent English plaintexts over noise."""
        if not is_ane_available():
            self.skipTest("Apple Neural Engine / CoreML not available on this platform")
        natural_texts = [
            "WELCOME PILGRIMS ON THE SACRED PATH OF PRIMES AND DIVINE WISDOM",
            "A WARNING BELIEVE NOTHING FROM THIS BOOK EXCEPT WHAT YOU KNOW TO BE TRUE",
        ]
        random_texts = [
            "XZQJ VBKL PWMR CTNM LKJH QWERT ZXC VBN MASD",
            "QQQQ ZZZZ XXXX JJJJ KKKK PPPP WWWW YYYY",
        ]
        nat_scores = score_candidate_naturalness_neural(natural_texts)
        rand_scores = score_candidate_naturalness_neural(random_texts)

        self.assertEqual(len(nat_scores), 2)
        self.assertEqual(len(rand_scores), 2)
        # Natural Cicada / English text must score substantially higher than random noise
        self.assertGreater(max(nat_scores), max(rand_scores))

    def test_ane_embeddings_normalized(self):
        """Verify computed ANE embeddings have unit L2 norm."""
        if not is_ane_available():
            self.skipTest("Apple Neural Engine / CoreML not available on this platform")
        texts = ["TEST VECTOR FOR APPLE SILICON ANE", "ANOTHER CANONICAL SENTENCE"]
        embs = compute_ane_embeddings(texts)
        if is_ane_available() and len(embs) > 0:
            self.assertEqual(embs.shape, (2, 384))
            for i in range(2):
                norm = np.linalg.norm(embs[i])
                self.assertAlmostEqual(norm, 1.0, places=3)


class TestSolverHardwareIntegration(unittest.TestCase):

    def test_crack_liber_primus_hardware_telemetry(self):
        """Verify crack_liber_primus returns hardware metadata and runs compound sweeps."""
        runes = "ᚹᛖᛚᚳᚩᛗᛖ᛫ᛈᛁᛚᚷᚱᛁᛗᛋ᛫ᛏᚩ᛫ᚦᛁᛋ᛫ᚷᚱᛖᚪᛏ᛫ᛡᚩᚢᚱᚾᛖᚣ"
        res = crack_liber_primus(runes, deep=False, compound=True)
        self.assertIn("hardware", res)
        self.assertIn("metal_gpu", res["hardware"])
        self.assertIn("neural_engine", res["hardware"])
        self.assertIsInstance(res["top_candidates"], list)
        self.assertGreater(len(res["top_candidates"]), 0)


if __name__ == "__main__":
    unittest.main()
