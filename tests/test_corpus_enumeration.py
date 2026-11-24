"""
Unit tests for unified corpus enumeration and performance harness safety.
Validates:
- Unified corpus document discovery across root and nested subdirectories
- Strict exclusion of private/hidden directories (_duplicates, dotfiles)
- Filtering by permitted extensions (.txt, .md, .json, .csv)
- Garbage collection restoration in benchmark.time_callable upon exceptions
- Dispersion and tail percentile metrics (p95, mean) in benchmark reporting
- Diagnostic normalization in golden master subprocess runner
"""

import os
import gc
import sys
import tempfile
import unittest
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from scripts.bodleian import iter_corpus_documents, compute_corpus_digest, clear_digest_memo
from scripts.benchmark import time_callable
from tests.golden.record import normalize


class TestCorpusEnumeration(unittest.TestCase):
    """Test suite for corpus document enumeration and recursive indexing."""

    def setUp(self) -> None:
        clear_digest_memo()

    def test_iter_corpus_documents_recursive_and_filtering(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            # Valid root files
            (root / "page_00.txt").write_text("welcome", encoding="utf-8")
            (root / "page_56.md").write_text("primes", encoding="utf-8")
            (root / "data.json").write_text("{}", encoding="utf-8")
            (root / "table.csv").write_text("a,b", encoding="utf-8")

            # Nested valid subfolder
            ref_dir = root / "reference_texts"
            ref_dir.mkdir(parents=True, exist_ok=True)
            (ref_dir / "blake.txt").write_text("infinity", encoding="utf-8")
            (ref_dir / "hermes.md").write_text("emerald", encoding="utf-8")

            # Ignored: forbidden extension
            (root / "model.onnx").write_bytes(b"\x00\x01\x02")
            (root / "cache.pyc").write_bytes(b"\x00")

            # Ignored: hidden file / directory
            (root / ".hidden.txt").write_text("secret", encoding="utf-8")
            hidden_dir = root / ".git"
            hidden_dir.mkdir(parents=True, exist_ok=True)
            (hidden_dir / "config.txt").write_text("git config", encoding="utf-8")

            # Ignored: underscore / duplicates directory
            dup_dir = root / "_duplicates"
            dup_dir.mkdir(parents=True, exist_ok=True)
            (dup_dir / "page_00_copy.txt").write_text("welcome copy", encoding="utf-8")

            docs = iter_corpus_documents(root)
            rel_paths = [rel for rel, _ in docs]

            expected_paths = [
                "data.json",
                "page_00.txt",
                "page_56.md",
                "reference_texts/blake.txt",
                "reference_texts/hermes.md",
                "table.csv",
            ]
            self.assertEqual(rel_paths, expected_paths)

    def test_digest_sensitivity_to_nested_documents(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "doc1.txt").write_text("original", encoding="utf-8")
            sub = root / "reference_texts"
            sub.mkdir(parents=True, exist_ok=True)
            (sub / "ref1.txt").write_text("subtext original", encoding="utf-8")

            clear_digest_memo()
            d1 = compute_corpus_digest(root)

            # Modifying subtext must alter digest
            (sub / "ref1.txt").write_text("subtext modified", encoding="utf-8")
            clear_digest_memo()
            d2 = compute_corpus_digest(root)
            self.assertNotEqual(d1, d2)


class TestBenchmarkSafety(unittest.TestCase):
    """Test suite ensuring benchmark timing harness safety and metric completeness."""

    def test_gc_state_restored_on_exception(self) -> None:
        def raising_callable() -> None:
            raise RuntimeError("Synthetic benchmark fault")

        initial_gc_state = gc.isenabled()
        with self.assertRaises(RuntimeError):
            time_callable(raising_callable, iterations=5, warmup=1)

        self.assertEqual(gc.isenabled(), initial_gc_state)

    def test_benchmark_metrics_structure(self) -> None:
        def harmless_work() -> int:
            return sum(x * x for x in range(50))

        metrics = time_callable(harmless_work, iterations=15, warmup=2)
        for key in ("p50_ms", "p95_ms", "min_ms", "max_ms", "mean_ms", "iterations"):
            self.assertIn(key, metrics)
        self.assertGreaterEqual(metrics["p95_ms"], metrics["p50_ms"])
        self.assertGreaterEqual(metrics["max_ms"], metrics["p95_ms"])
        self.assertGreaterEqual(metrics["p50_ms"], metrics["min_ms"])
        self.assertEqual(metrics["iterations"], 15)


class TestGoldenMasterNormalization(unittest.TestCase):
    """Test suite verifying environmental diagnostic suppression in golden master recordings."""

    def test_onnx_and_runtime_telemetry_stripped(self) -> None:
        noisy_output = (
            "rc=0\n"
            "--stdout--\n"
            "Valid output line\n"
            "--stderr--\n"
            "[W:onnxruntime:Default, session_state.cc:1169 VerifyEachNodeIsAssignedToAnEp] Some node warning\n"
            "CoreMLExecutionProvider failed to create compiler cache: Permission denied\n"
        )
        cleaned = normalize(noisy_output)
        self.assertNotIn("[W:onnxruntime:", cleaned)
        self.assertNotIn("CoreMLExecutionProvider", cleaned)
        self.assertIn("Valid output line", cleaned)


if __name__ == "__main__":
    unittest.main()
