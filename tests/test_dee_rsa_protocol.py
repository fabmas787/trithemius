"""
Unit tests for WS-A: DEE-RSA Experimental Protocol & Reproducibility Manifest.
Verifies benchmark trials (n>=100 default, underpowered flag for n<100), nanosecond timing,
tracemalloc peak memory, 95% confidence intervals, accelerated vs reference baselines,
raw CSV and summary JSON exports, 10-point reproducibility manifest, and 8-point validity checklist.
"""

import os
import sys
import math
import json
import csv
import tempfile
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from scripts.benchmark import (
    time_callable,
    run_baseline_comparison,
    run_benchmark,
    export_raw_trials_csv,
    export_summary_json,
    pure_python_reference_key_scoring,
    accelerated_key_scoring,
)
from agents.evidence import (
    emit_reproducibility_manifest,
    validate_evidence_claim,
    MANIFEST_POINTS,
    VALIDITY_CHECKLIST_POINTS,
)


class TestDeeRsaProtocol(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    # =========================================================================
    # scripts/benchmark.py Tests
    # =========================================================================

    def test_benchmark_default_trials_and_underpowered_flag(self):
        """Verify default n>=100 trials has underpowered=False, while n<100 has underpowered=True."""
        def dummy_op():
            return sum(i * i for i in range(50))

        # 1. Default trials (100)
        res_default = time_callable(dummy_op)
        self.assertGreaterEqual(res_default["trials"], 100)
        self.assertFalse(res_default["underpowered"])

        # 2. Underpowered trials (override n < 100)
        res_underpowered = time_callable(dummy_op, trials=25)
        self.assertEqual(res_underpowered["trials"], 25)
        self.assertTrue(res_underpowered["underpowered"])

        # 3. Sufficient trials (override n >= 100)
        res_powered = time_callable(dummy_op, trials=120)
        self.assertEqual(res_powered["trials"], 120)
        self.assertFalse(res_powered["underpowered"])

    def test_benchmark_latency_statistics_and_confidence_interval(self):
        """Verify nanosecond precision, sample stdev, and 95% confidence interval formula."""
        def quick_calc():
            x = 0
            for i in range(100):
                x += i
            return x

        n = 100
        res = time_callable(quick_calc, trials=n)
        mean_ms = res["mean_ms"]
        stdev_ms = res["sample_stdev_ms"]
        ci_95 = res["ci_95"]
        ci_margin = res["ci_margin_ms"]

        self.assertGreater(res["mean_ns"], 0)
        self.assertGreater(mean_ms, 0)
        self.assertIsInstance(ci_95, tuple)
        self.assertEqual(len(ci_95), 2)

        # Expected formula: mean +/- 1.96 * (stdev / sqrt(n))
        expected_margin = 1.96 * stdev_ms / math.sqrt(n)
        self.assertAlmostEqual(ci_margin, expected_margin, places=6)
        self.assertAlmostEqual(ci_95[0], mean_ms - expected_margin, places=6)
        self.assertAlmostEqual(ci_95[1], mean_ms + expected_margin, places=6)

    def test_benchmark_tracemalloc_peak_memory(self):
        """Verify peak memory tracking via tracemalloc."""
        def memory_alloc_op():
            # Allocate a small transient list
            data = [i for i in range(1000)]
            return sum(data)

        res = time_callable(memory_alloc_op, trials=10)
        self.assertIn("peak_memory_bytes", res)
        self.assertGreater(res["peak_memory_bytes"], 0)

    def test_mandatory_accelerated_vs_pure_python_baseline(self):
        """Verify mandatory baseline comparison between accelerated and pure-Python reference."""
        baseline = run_baseline_comparison(trials=100)

        self.assertIn("pure_python_reference", baseline)
        self.assertIn("accelerated", baseline)
        self.assertIn("speedup", baseline)
        self.assertIn("accelerator_type", baseline)
        self.assertEqual(baseline["trials"], 100)
        self.assertFalse(baseline["underpowered"])

        ref_metrics = baseline["pure_python_reference"]
        acc_metrics = baseline["accelerated"]

        self.assertGreater(ref_metrics["mean_ms"], 0)
        self.assertGreater(acc_metrics["mean_ms"], 0)
        self.assertGreater(baseline["speedup"], 0)

    def test_export_raw_trials_csv_and_summary_json(self):
        """Verify export of per-trial raw CSV and summary JSON."""
        csv_path = os.path.join(self.temp_dir.name, "raw_trials.csv")
        json_path = os.path.join(self.temp_dir.name, "summary.json")

        sample_raw = [
            {"component": "test_kernel", "trial": i, "duration_ns": 10000 + i * 100, "duration_ms": (10000 + i * 100) / 1e6}
            for i in range(100)
        ]
        sample_results = {
            "test_kernel": {"mean_ms": 0.015, "trials": 100, "underpowered": False},
            "trials": 100,
            "underpowered": False,
        }

        # Export CSV
        out_csv = export_raw_trials_csv(sample_raw, csv_path)
        self.assertTrue(os.path.exists(out_csv))
        with open(out_csv, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            self.assertEqual(header, ["component", "trial", "duration_ns", "duration_ms"])
            rows = list(reader)
            self.assertEqual(len(rows), 100)

        # Export JSON
        out_json = export_summary_json(sample_results, json_path)
        self.assertTrue(os.path.exists(out_json))
        with open(out_json, "r", encoding="utf-8") as f:
            loaded = json.load(f)
            self.assertEqual(loaded["trials"], 100)
            self.assertFalse(loaded["underpowered"])
            self.assertIn("test_kernel", loaded)

    # =========================================================================
    # agents/evidence.py Tests
    # =========================================================================

    def test_10_point_reproducibility_manifest(self):
        """Verify generation of complete 10-point DEE-RSA reproducibility manifest."""
        manifest = emit_reproducibility_manifest()

        self.assertEqual(len(MANIFEST_POINTS), 10)
        for point in MANIFEST_POINTS:
            self.assertIn(point, manifest, f"Missing required manifest point: {point}")
            self.assertIsNotNone(manifest[point], f"Manifest point {point} is None")

        # Check expected structure of key fields
        self.assertIn("platform", manifest["hardware_specs"])
        self.assertIn("system", manifest["os_environment"])
        self.assertIsInstance(manifest["python_version"], str)
        self.assertIn("standard_library_only", manifest["dependency_lock"])
        self.assertIsInstance(manifest["git_commit"], str)
        self.assertIn("algorithm", manifest["solver_parameters"])
        self.assertTrue(manifest["seeding_policy"]["deterministic"])
        self.assertIn("corpus", manifest["dataset_provenance"])
        self.assertIsInstance(manifest["raw_data_artifacts"], list)
        self.assertIn("T", manifest["timestamp_utc"])

    def test_8_point_validity_checklist_success(self):
        """Verify that a compliant empirical claim passes all 8 validity checklist points."""
        manifest = emit_reproducibility_manifest()
        claim = {
            "manifest": manifest,
            "outcome": "positive",
            "detector_power": 0.95,
            "trials": 100,
            "p_value": 0.005,
            "seeding_policy": {"seed": 3301, "deterministic": True},
            "surrogate_tested": True,
            "baseline_comparison": {"pure_python": 1.2, "speedup": 2.1},
            "raw_data_artifacts": ["vectordb/trial_data.csv"],
        }

        res = validate_evidence_claim(claim)
        self.assertEqual(res["total"], 8)
        self.assertEqual(res["passed"], 8)
        self.assertTrue(res["valid"])
        self.assertTrue(res["is_valid"])

        for point in VALIDITY_CHECKLIST_POINTS:
            self.assertTrue(res["checklist"][point], f"Expected point {point} to pass")
            self.assertTrue(res[point], f"Direct key {point} should be True")

    def test_8_point_validity_checklist_failures(self):
        """Verify that underpowered, low-power, or incomplete claims fail the validity checklist."""
        manifest = emit_reproducibility_manifest()

        # 1. Underpowered claim (trials < 100)
        claim_underpowered = {
            "manifest": manifest,
            "detector_power": 0.95,
            "trials": 50,
            "p_value": 0.01,
            "surrogate_tested": True,
            "baseline_comparison": {"ref": 1.0},
            "raw_data_artifacts": ["data.csv"],
        }
        res_up = validate_evidence_claim(claim_underpowered)
        self.assertFalse(res_up["valid"])
        self.assertFalse(res_up["sample_size_adequate"])

        # 2. Low statistical power on negative/excluded claim
        claim_low_power = {
            "manifest": manifest,
            "outcome": "negative",
            "status": "excluded",
            "detector_power": 0.60,  # Below 0.90 threshold
            "trials": 100,
            "p_value": 0.01,
            "surrogate_tested": True,
            "baseline_comparison": {"ref": 1.0},
            "raw_data_artifacts": ["data.csv"],
        }
        res_lp = validate_evidence_claim(claim_low_power)
        self.assertFalse(res_lp["valid"])
        self.assertFalse(res_lp["statistical_power"])

        # 3. Missing manifest
        claim_no_manifest = {
            "detector_power": 0.95,
            "trials": 100,
            "p_value": 0.01,
            "surrogate_tested": True,
            "baseline_comparison": {"ref": 1.0},
            "raw_data_artifacts": ["data.csv"],
        }
        res_nm = validate_evidence_claim(claim_no_manifest)
        self.assertFalse(res_nm["valid"])
        self.assertFalse(res_nm["reproducibility_manifest"])


if __name__ == "__main__":
    unittest.main()
