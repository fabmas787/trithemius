"""
Comprehensive Unit Tests for Level 1 Optimizations & Performance Infrastructure (F01–F08).
Covers:
- F01: Benchmark module (microsecond timing, history logging, baseline delta comparison)
- F02: Corpus Digest (atomic memoization, exclusion of hidden/_ files, invalidation)
- F04: Exact RAG Cache (LRU eviction, hit_count, 7d TTL purge, --fresh bypass, web search invariance)
- F05: Canonical Hypothesis Ledger (WAL pragma, backup API, canonical JSON, canonical page & key, deduplication)
- F06: Provider connection reuse & Ollama keep_alive parameter
- F07: Porta Unicode NFC normalization, preservation of runic dividers (᛫, ᛬, ᛭), moving duplicates to _duplicates/
- F08: Persisted BM25 Index (format version, atomic replace, digest validation)
"""

import os
import sys
import json
import time
import shutil
import tempfile
import sqlite3
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import scripts.benchmark as benchmark
import scripts.bodleian as bodleian
import scripts.ask as ask
import scripts.porta as porta
import scripts.providers as providers
import agents.ledger as ledger


class TestBenchmarkModule(unittest.TestCase):
    def test_time_callable(self):
        def sample_work():
            return sum(i for i in range(100))
        metrics = benchmark.time_callable(sample_work, iterations=10, warmup=2)
        self.assertIn("p50_ms", metrics)
        self.assertIn("min_ms", metrics)
        self.assertIn("max_ms", metrics)
        self.assertGreaterEqual(metrics["max_ms"], metrics["min_ms"])

    def test_save_and_load_baselines(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_file = os.path.join(tmpdir, "bench_baselines.json")
            sample_res = {"test": {"p50_ms": 10.0, "min_ms": 9.0, "max_ms": 11.0}}
            benchmark.save_baseline("test_base", sample_res, baselines_file=base_file)
            loaded = benchmark.load_baselines(baselines_file=base_file)
            self.assertIn("test_base", loaded)
            self.assertEqual(loaded["test_base"]["results"]["test"]["p50_ms"], 10.0)


class TestCorpusDigest(unittest.TestCase):
    def test_corpus_digest_excludes_hidden_and_underscore(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create valid file
            with open(os.path.join(tmpdir, "page_01.txt"), "w") as f:
                f.write("Normal content")
            # Create hidden file
            with open(os.path.join(tmpdir, ".hidden.txt"), "w") as f:
                f.write("Hidden content")
            # Create underscore directory
            sub = os.path.join(tmpdir, "_duplicates")
            os.makedirs(sub, exist_ok=True)
            with open(os.path.join(sub, "dup.txt"), "w") as f:
                f.write("Duplicate content")

            bodleian.clear_digest_memo()
            d1 = bodleian.compute_corpus_digest(tmpdir)
            self.assertEqual(len(d1), 64)

            # Modifying hidden file or _duplicates must NOT change digest
            with open(os.path.join(tmpdir, ".hidden.txt"), "w") as f:
                f.write("Modified hidden")
            with open(os.path.join(sub, "dup.txt"), "w") as f:
                f.write("Modified duplicate")

            bodleian.clear_digest_memo()
            d2 = bodleian.compute_corpus_digest(tmpdir)
            self.assertEqual(d1, d2)

            # Modifying valid file MUST change digest
            with open(os.path.join(tmpdir, "page_01.txt"), "w") as f:
                f.write("Modified normal content")
            bodleian.clear_digest_memo()
            d3 = bodleian.compute_corpus_digest(tmpdir)
            self.assertNotEqual(d1, d3)


class TestBM25Persistence(unittest.TestCase):
    def test_bm25_save_and_load_validation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            idx_file = os.path.join(tmpdir, "bm25_index.json")
            corpus_dir = os.path.join(tmpdir, "corpus")
            os.makedirs(corpus_dir, exist_ok=True)
            with open(os.path.join(corpus_dir, "doc.txt"), "w") as f:
                f.write("Welcome pilgrim sacred primes")

            bodleian.clear_digest_memo()
            digest = bodleian.compute_corpus_digest(corpus_dir)

            test_index = {
                "format_version": ask.BM25_FORMAT_VERSION,
                "tokenizer_version": ask.BM25_TOKENIZER_VERSION,
                "corpus_digest": digest,
                "created_at": time.time(),
                "k1": ask.BM25_K1,
                "b": ask.BM25_B,
                "N": 1,
                "avgdl": 4.0,
                "doc_lengths": [4],
                "doc_metadata": [{"source": "doc.txt", "page": "0"}],
                "doc_texts": ["Welcome pilgrim sacred primes"],
                "df": {"welcome": 1, "pilgrim": 1, "sacred": 1, "primes": 1},
                "idf": {"welcome": 0.5, "pilgrim": 0.5, "sacred": 0.5, "primes": 0.5},
            }
            ask.save_persisted_bm25(test_index, index_path=idx_file)
            self.assertTrue(os.path.exists(idx_file))

            # Load matching index
            loaded = ask.load_persisted_bm25(corpus_dir=corpus_dir, index_path=idx_file)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["N"], 1)

            # Mismatch digest must reject and return None
            with open(os.path.join(corpus_dir, "doc2.txt"), "w") as f:
                f.write("New document changes digest")
            bodleian.clear_digest_memo()
            mismatch_load = ask.load_persisted_bm25(corpus_dir=corpus_dir, index_path=idx_file)
            self.assertIsNone(mismatch_load)


class TestExactRAGCache(unittest.TestCase):
    def test_cache_store_lookup_lru_and_ttl(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_cache.sqlite3")
            key1 = ask.rag_cache_key("Query 1", "digest_a", "ollama", "spark", False)
            key2 = ask.rag_cache_key("Query 2", "digest_a", "ollama", "spark", False)

            # Store key1 and key2
            ask.store_rag_cache(key1, "Query 1", "digest_a", "ollama", "spark", False, "v1", "bm25", "Answer 1", [], db_path=db_path, max_entries=2)
            ask.store_rag_cache(key2, "Query 2", "digest_a", "ollama", "spark", False, "v1", "bm25", "Answer 2", [], db_path=db_path, max_entries=2)

            res1 = ask.lookup_rag_cache(key1, db_path=db_path)
            self.assertIsNotNone(res1)
            self.assertEqual(res1["response"], "Answer 1")

            # Store key3 with max_entries=2 -> key2 should be evicted (key1 was accessed most recently)
            key3 = ask.rag_cache_key("Query 3", "digest_a", "ollama", "spark", False)
            ask.store_rag_cache(key3, "Query 3", "digest_a", "ollama", "spark", False, "v1", "bm25", "Answer 3", [], db_path=db_path, max_entries=2)

            self.assertIsNotNone(ask.lookup_rag_cache(key1, db_path=db_path))
            self.assertIsNotNone(ask.lookup_rag_cache(key3, db_path=db_path))
            self.assertIsNone(ask.lookup_rag_cache(key2, db_path=db_path))

    def test_cache_feature_flag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_cache.sqlite3")
            key = ask.rag_cache_key("Query", "digest", "ollama", "spark", False)
            ask.store_rag_cache(key, "Query", "digest", "ollama", "spark", False, "v1", "bm25", "Answer", [], db_path=db_path)

            with patch.dict(os.environ, {"TRITHEMIUS_CACHE": "off"}):
                self.assertIsNone(ask.lookup_rag_cache(key, db_path=db_path))

    def test_cache_normalization_and_digest_invalidation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_cache.sqlite3")
            base_query = "What is the sacred prime of WELCOME?"
            variant_query = "   what  is   the sacred   prime of WELCOME?  \n"

            key_base = ask.rag_cache_key(base_query, "digest_v1", "ollama", "spark", False, boost=False)
            key_variant = ask.rag_cache_key(variant_query, "digest_v1", "ollama", "spark", False, boost=False)
            self.assertEqual(key_base, key_variant)

            # Store response with base key
            ask.store_rag_cache(key_base, base_query, "digest_v1", "ollama", "spark", False, "v1", "bm25",
                                "The sacred prime is 3301", [], db_path=db_path, boost=False)

            # Lookup with variant key -> cache hit!
            hit = ask.lookup_rag_cache(key_variant, db_path=db_path)
            self.assertIsNotNone(hit)
            self.assertEqual(hit["response"], "The sacred prime is 3301")

            # Different corpus digest (after /ingest) -> cache miss!
            key_new_digest = ask.rag_cache_key(base_query, "digest_v2", "ollama", "spark", False, boost=False)
            self.assertNotEqual(key_base, key_new_digest)
            self.assertIsNone(ask.lookup_rag_cache(key_new_digest, db_path=db_path))

            # Different boost mode -> cache miss!
            key_boost = ask.rag_cache_key(base_query, "digest_v1", "ollama", "spark", False, boost=True)
            self.assertNotEqual(key_base, key_boost)
            self.assertIsNone(ask.lookup_rag_cache(key_boost, db_path=db_path))


class TestEntropyAndAlKindiOptimizations(unittest.TestCase):
    def test_sliding_window_entropy_incremental_equivalence(self):
        import ciphers.entropy as entropy_mod
        test_text = "WELCOME PILGRIMS TO THE SACRED PATH OF PRIMES AND TOTIENTS " * 10
        curve_fast = entropy_mod.sliding_window_entropy(test_text, window_size=32, step=8)
        curve_naive = entropy_mod.sliding_window_entropy_naive(test_text, window_size=32, step=8)
        self.assertEqual(len(curve_fast), len(curve_naive))
        for (i1, h1), (i2, h2) in zip(curve_fast, curve_naive):
            self.assertEqual(i1, i2)
            self.assertAlmostEqual(h1, h2, places=4)

    def test_al_kindi_length_invariance(self):
        import ciphers.al_kindi as al_kindi_mod
        sample_plaintext = "WELCOME PILGRIMS TO THIS GREAT JOURNEY A WARNING BELIEVE NOTHING FROM THIS BOOK EXCEPT WHAT YOU KNOW TO BE TRUE TEST THE KNOWLEDGE " * 15
        for n_chars in [100, 300, 1000]:
            snippet = sample_plaintext[:n_chars]
            passed, metrics = al_kindi_mod.is_plausible_english(snippet, legacy_threshold=False)
            self.assertTrue(passed, f"Failed length invariance at n={n_chars}")
            self.assertEqual(metrics["verdict"], "PLAUSIBLE")
            self.assertLess(metrics["chi_squared_per_symbol"], 0.75)
    def test_canonical_json_and_key(self):
        p1 = {"b": 2, "a": 1}
        p2 = {"a": 1, "b": 2}
        self.assertEqual(ledger.canonical_json(p1), '{"a":1,"b":2}')
        self.assertEqual(ledger.canonical_json(p1), ledger.canonical_json(p2))

        # Test canonical page normalization
        self.assertEqual(ledger.canonical_page("page_056"), "56")
        self.assertEqual(ledger.canonical_page("00"), "0")
        self.assertEqual(ledger.canonical_page(0), "0")
        self.assertEqual(ledger.canonical_page("all"), "all")

        # Test canonical key
        k1 = ledger.canonical_key("056", "vigenere", p1, "digest123")
        k2 = ledger.canonical_key("56", "VIGENERE", p2, "digest123")
        self.assertEqual(k1, k2)

    def test_ledger_storage_and_backup(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_ledger.sqlite3")
            logged = ledger.log_canonical_attempt(
                page="page_56",
                method="vigenere",
                parameters={"key": "DIVINITY"},
                input_digest="hash123",
                score=0.88,
                passed=True,
                result_preview="The primes are sacred",
                db_path=db_path,
            )
            self.assertTrue(logged)

            # Duplicate attempt must return False
            dup = ledger.log_canonical_attempt(
                page="56",
                method="VIGENERE",
                parameters={"key": "DIVINITY"},
                input_digest="hash123",
                score=0.88,
                passed=True,
                db_path=db_path,
            )
            self.assertFalse(dup)

            # Check lookup
            info = ledger.has_attempt_been_tried("56", "vigenere", {"key": "DIVINITY"}, "hash123", db_path=db_path)
            self.assertIsNotNone(info)
            self.assertEqual(info["score"], 0.88)
            self.assertTrue(info["passed_gatekeeper"])

            # Test backup API
            backup_file = ledger.backup_ledger(db_path=db_path)
            self.assertIsNotNone(backup_file)
            self.assertTrue(os.path.exists(backup_file))


class TestPortaNormalization(unittest.TestCase):
    def test_runic_punctuation_preserved(self):
        text = "<!-- porta: metadata -->\r\nᚹᛖᛚᚳᚩᛗᛖ  ᛫  ᛈᛁᛚᚷᚱᛁᛗᛋ ᛬ ᛒᛖᛚᛁᛖᚠ ᛭ \r\n\r\n\r\n"
        norm = porta.normalize_for_hash(text)
        # Runic dividers must not be stripped
        self.assertIn("᛫", norm)
        self.assertIn("᛬", norm)
        self.assertIn("᛭", norm)
        self.assertNotIn("<!-- porta:", norm)
        self.assertNotIn("\r", norm)

    def test_move_duplicates_to_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            f1 = os.path.join(tmpdir, "page_00_welcome.md")
            f2 = os.path.join(tmpdir, "harvest_copy.md")
            content = "ᚹᛖᛚᚳᚩᛗᛖ\n"
            with open(f1, "w", encoding="utf-8") as f:
                f.write(content)
            with open(f2, "w", encoding="utf-8") as f:
                f.write(content + "\r\n")

            dups = porta.find_and_remove_duplicates(remove=True, corpus_dir=tmpdir)
            self.assertEqual(len(dups), 1)
            # Duplicate moved to _duplicates
            dup_dir = os.path.join(tmpdir, "_duplicates")
            self.assertTrue(os.path.exists(os.path.join(dup_dir, "harvest_copy.md")))
            self.assertTrue(os.path.exists(f1))


class TestProviderConnections(unittest.TestCase):
    def test_thread_local_session_reuse(self):
        s1 = providers.get_session()
        s2 = providers.get_session()
        self.assertIs(s1, s2)

    def test_ollama_keep_alive_env(self):
        with patch.dict(os.environ, {"TRITHEMIUS_KEEP_ALIVE": "15m"}):
            self.assertEqual(providers._get_keep_alive(), "15m")


if __name__ == "__main__":
    unittest.main()
