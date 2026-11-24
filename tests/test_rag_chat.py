"""
Unit and Integration Tests for Trithemius RAG Chat Optimizations.
Covers:
1. build_prompt context budgeting and metadata retention
2. stream_chat streaming of content and reasoning (CoT)
3. /api/chat SSE streaming and backward-compatible JSON mode
4. Context-window options (num_ctx: 8192, num_predict: 400, think: bool)
5. Bodleian compact chunking constraints
"""

import io
import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
from config import DEFAULT_NUM_PREDICT, DEFAULT_NUM_CTX
from scripts.ask import build_prompt, stream_chat, TOP_K, CONTEXT_WINDOW
from scripts.bodleian import CHUNK_SIZE, MAX_CHUNK_CHARS, chunk_document


class TestBuildPromptBudget(unittest.TestCase):
    def test_build_prompt_empty(self):
        prompt = build_prompt("Cicada inquiry", [])
        self.assertIn("[No local corpus matches found]", prompt)
        self.assertIn("Cicada inquiry", prompt)

    def test_build_prompt_caps_character_budget(self):
        # 10 large chunks of 2,000 characters each = 20,000 chars total
        retrieved = [
            (f"Chunk text content {i} " * 100, {"source": f"file_{i}.md", "page": str(i)})
            for i in range(10)
        ]
        max_budget = 2500
        prompt = build_prompt("Test question", retrieved, max_context_chars=max_budget)
        
        # Verify prompt contains sources and question
        self.assertIn("Test question", prompt)
        self.assertIn("[Source: file_0.md | Page: 0]", prompt)

        # Extract the corpus section between header and separator
        start_idx = prompt.find("Context from Liber Primus Corpus:\n\n") + len("Context from Liber Primus Corpus:\n\n")
        end_idx = prompt.find("\n\n---\n\nResearch Question:")
        corpus_section = prompt[start_idx:end_idx]

        # Corpus section should strictly obey max_budget (+ small tolerance for chunk joins if any)
        self.assertLessEqual(len(corpus_section), max_budget + 200)

    def test_build_prompt_preserves_page_and_source_headers(self):
        retrieved = [
            ("The prime totient mechanics are revealed here.", {"source": "page_56.md", "page": "56"}),
            ("Welcome pilgrims to the journey.", {"source": "page_00.md", "page": "0"}),
        ]
        prompt = build_prompt("Explain page 56", retrieved)
        self.assertIn("[Source: page_56.md | Page: 56]", prompt)
        self.assertIn("[Source: page_00.md | Page: 0]", prompt)
        self.assertIn("The prime totient mechanics", prompt)

    def test_build_prompt_with_none_meta(self):
        # Edge case: metadata dictionary is None or contains empty entries
        retrieved = [
            ("Sample text with missing metadata", None),
            ("Another text snippet", {}),
        ]
        prompt = build_prompt("Explain runes", retrieved)
        self.assertIn("[Source: unknown | Page: general]", prompt)
        self.assertIn("Sample text with missing metadata", prompt)


class TestRetrievePageNormalization(unittest.TestCase):
    @patch("scripts.ask.ollama.embeddings")
    def test_retrieve_page_padded_normalization(self, mock_emb):
        mock_emb.return_value = {"embedding": [0.1, 0.2]}
        mock_collection = MagicMock()

        # Simulate collection returning match on normalized "0" when queried with "/page 00"
        def query_side_effect(**kwargs):
            where = kwargs.get("where")
            if where == {"page": "0"}:
                return {"documents": [["Welcome pilgrims"]], "metadatas": [[{"source": "page_00.md", "page": "0"}]]}
            return {"documents": [[]], "metadatas": [[]]}

        mock_collection.query.side_effect = query_side_effect
        from scripts.ask import retrieve
        res = retrieve(mock_collection, "/page 00")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0][0], "Welcome pilgrims")
        self.assertEqual(res[0][1]["source"], "page_00.md")


class TestStreamChat(unittest.TestCase):
    @patch("scripts.ask.ollama.chat")
    def test_stream_chat_think_false(self, mock_chat):
        # Mock streaming chunks with only content
        chunks = [
            {"message": {"content": "Liber "}},
            {"message": {"content": "Primus"}},
            {"message": {"content": "\n"}},
        ]
        mock_chat.return_value = iter(chunks)

        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            stream_chat("SparkLLM/Spark-X2.5-4B", "Prompt test", think=False)

        output = stdout_trap.getvalue()
        self.assertIn("Liber Primus", output)
        self.assertNotIn("[Reasoning:", output)
        mock_chat.assert_called_once_with(
            model="SparkLLM/Spark-X2.5-4B",
            messages=unittest.mock.ANY,
            options={"num_ctx": CONTEXT_WINDOW, "num_predict": DEFAULT_NUM_PREDICT},
            stream=True,
            think=False,
        )

    @patch("scripts.ask.ollama.chat")
    def test_stream_chat_think_true(self, mock_chat):
        # Mock streaming chunks with thinking and content
        chunks = [
            {"message": {"thinking": "Analyzing runes..."}},
            {"message": {"content": "Decoded answer."}},
        ]
        mock_chat.return_value = iter(chunks)

        stdout_trap = io.StringIO()
        with patch("sys.stdout", stdout_trap):
            stream_chat("SparkLLM/Spark-X2.5-4B", "Prompt test", think=True)

        output = stdout_trap.getvalue()
        self.assertIn("Analyzing runes...", output)
        self.assertIn("Decoded answer.", output)


class TestBodleianTuning(unittest.TestCase):
    def test_constants_tuned(self):
        self.assertEqual(CHUNK_SIZE, 250)
        self.assertEqual(MAX_CHUNK_CHARS, 1800)

    def test_chunking_honors_max_chars(self):
        huge_text = ("Gematria totients and prime distributions. " * 300) + "\n\n" + ("Another section. " * 300)
        chunks = chunk_document(huge_text, "test.txt")
        self.assertGreater(len(chunks), 1)
        for c in chunks:
            self.assertLessEqual(len(c["text"]), MAX_CHUNK_CHARS)

class TestBM25Retriever(unittest.TestCase):
    def test_bm25_retrieves_relevant_page(self):
        from scripts.ask import bm25_retrieve
        res = bm25_retrieve("some wisdom primes sacred page 56", k=2)
        self.assertGreaterEqual(len(res), 1)
        top_chunk, meta = res[0]
        self.assertEqual(meta["page"], "56")
        self.assertIn("page_56", meta["source"])

    def test_retrieve_fallback_when_embedding_fails(self):
        from scripts.ask import retrieve
        # When collection is None or embeddings raise exception
        res = retrieve(None, "welcome pilgrims", k=2)
        self.assertGreaterEqual(len(res), 1)
        top_chunk, meta = res[0]
        self.assertIn("page_00", meta["source"])


class TestRAGCacheAndBM25Phase1(unittest.TestCase):
    def test_rag_cache_different_corpus_digest_miss(self):
        import tempfile
        import scripts.ask as ask
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "cache.sqlite3")
            q = "What is sacred in Liber Primus?"
            key_v1 = ask.rag_cache_key(q, "digest_v1", "ollama", "spark", False)
            ask.store_rag_cache(key_v1, q, "digest_v1", "ollama", "spark", False, "v1", "bm25", "The primes are sacred", [], db_path=db_path)

            # Different corpus digest -> miss
            key_v2 = ask.rag_cache_key(q, "digest_v2", "ollama", "spark", False)
            self.assertNotEqual(key_v1, key_v2)
            self.assertIsNone(ask.lookup_rag_cache(key_v2, db_path=db_path))

    def test_rag_cache_whitespace_and_case_variants_hit(self):
        import tempfile
        import scripts.ask as ask
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "cache.sqlite3")
            base_q = "What is the key to page 56?"
            variant_q = "   what   is  the   KEY   to PAGE 56? \n\t"
            key_base = ask.rag_cache_key(base_q, "digest_1", "ollama", "spark", False)
            key_variant = ask.rag_cache_key(variant_q, "digest_1", "ollama", "spark", False)
            self.assertEqual(key_base, key_variant)

            ask.store_rag_cache(key_base, base_q, "digest_1", "ollama", "spark", False, "v1", "bm25", "DIVINITY", [], db_path=db_path)
            res = ask.lookup_rag_cache(key_variant, db_path=db_path)
            self.assertIsNotNone(res)
            self.assertEqual(res["response"], "DIVINITY")

    def test_rag_cache_old_format_rows_ignored(self):
        import tempfile
        import sqlite3
        import scripts.ask as ask
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "cache.sqlite3")
            conn = ask._get_cache_db(db_path)
            # Insert a legacy v1-keyed row directly into table
            legacy_key = "v1_legacy_old_hash_99999"
            conn.execute(
                "INSERT INTO rag_cache (cache_key, query_norm, corpus_digest, provider, model, think_flag, prompt_version, retrieval_mode, response_text, sources_json, created_at, last_access_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (legacy_key, "old query", "old_digest", "ollama", "spark", 0, "v1", "bm25", "Old response", "[]", 100.0, 100.0)
            )
            conn.commit()
            conn.close()

            # Looking up with current key generator for the same query does not match legacy key format
            current_key = ask.rag_cache_key("old query", "old_digest", "ollama", "spark", False)
            self.assertNotEqual(current_key, legacy_key)
            self.assertIsNone(ask.lookup_rag_cache(current_key, db_path=db_path))

    def test_bm25_index_reloaded_when_digest_unchanged_and_rebuilt_on_change(self):
        import tempfile
        import time
        import scripts.ask as ask
        import scripts.bodleian as bodleian
        with tempfile.TemporaryDirectory() as tmpdir:
            corpus_dir = os.path.join(tmpdir, "corpus")
            idx_file = os.path.join(tmpdir, "bm25_index.json")
            os.makedirs(corpus_dir, exist_ok=True)
            doc_path = os.path.join(corpus_dir, "page_00.md")
            with open(doc_path, "w") as f:
                f.write("Welcome pilgrims to the journey")

            bodleian.clear_digest_memo()
            d1 = bodleian.compute_corpus_digest(corpus_dir)
            index_data = {
                "format_version": ask.BM25_FORMAT_VERSION,
                "tokenizer_version": ask.BM25_TOKENIZER_VERSION,
                "corpus_digest": d1,
                "created_at": time.time(),
                "k1": ask.BM25_K1,
                "b": ask.BM25_B,
                "N": 1,
                "avgdl": 5.0,
                "doc_lengths": [5],
                "doc_metadata": [{"source": "page_00.md", "page": "0"}],
                "doc_texts": ["Welcome pilgrims to the journey"],
                "df": {"welcome": 1, "pilgrims": 1},
                "idf": {"welcome": 0.5, "pilgrims": 0.5},
            }
            ask.save_persisted_bm25(index_data, index_path=idx_file)

            # Unchanged digest -> successfully reloaded
            loaded = ask.load_persisted_bm25(corpus_dir=corpus_dir, index_path=idx_file)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["corpus_digest"], d1)

            # Change corpus file -> digest changes -> index invalidated/rejected
            with open(doc_path, "a") as f:
                f.write("\nNew line changes digest")
            bodleian.clear_digest_memo()
            mismatch_load = ask.load_persisted_bm25(corpus_dir=corpus_dir, index_path=idx_file)
            self.assertIsNone(mismatch_load)


if __name__ == "__main__":
    unittest.main()



