import unittest
import math
import shutil
import tempfile
import os
from unittest.mock import patch
import agents.ledger as ledger
from agents.ledger import (
    deterministic_embed,
    record_attempt,
    record_attempts_batch,
    get_tested_words,
    is_word_tested,
    filter_untested_words,
    query_similar_attempts,
    get_attempts_stats,
    canonical_page,
)
from ciphers.lexicon import get_rotated_vocabulary, get_master_dictionary
from ciphers.taxonomy import crack_liber_primus
from trithemius import TerminalWorkstation


class TestVectorAttemptsTracking(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="trithemius_test_vec_")
        self.addCleanup(lambda: shutil.rmtree(self.test_dir, ignore_errors=True))
        db_path = os.path.join(self.test_dir, "ledger.sqlite3")
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
                        db_path if d == orig_db else (self.test_dir if d == orig_vec else d)
                        for d in defs
                    )
        ledger._VECTOR_CLIENT = None
        ledger._VECTOR_COLLECTION = None
        p_db = patch.object(ledger, "DB_PATH", db_path)
        p_vec = patch.object(ledger, "VECTOR_DIR", self.test_dir)
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

    def tearDown(self):
        pass

    def test_deterministic_embed_geometry(self):
        v1 = deterministic_embed("DIVINITY", dim=768)
        self.assertEqual(len(v1), 768)
        norm = math.sqrt(sum(x * x for x in v1))
        self.assertAlmostEqual(norm, 1.0, places=4)

        # Reproducibility
        v1_again = deterministic_embed("DIVINITY", dim=768)
        self.assertEqual(v1, v1_again)

        # Morphological proximity
        v2 = deterministic_embed("DIVINE", dim=768)
        v3 = deterministic_embed("ANARCHY", dim=768)
        cos_12 = sum(a * b for a, b in zip(v1, v2))
        cos_13 = sum(a * b for a, b in zip(v1, v3))
        self.assertGreater(cos_12, cos_13)

    def test_record_and_get_tested_words(self):
        page = "test_page_99"
        self.assertFalse(is_word_tested("MAGIC", page=page, db_dir=self.test_dir))

        # Record attempt
        ok = record_attempt(
            page=page,
            word="MAGIC",
            method="CRIB_DRAG",
            score=-4.1,
            db_dir=self.test_dir,
        )
        self.assertTrue(ok)
        self.assertTrue(is_word_tested("MAGIC", page=page, db_dir=self.test_dir))
        self.assertFalse(is_word_tested("MAGIC", page="other_page", db_dir=self.test_dir))

        tested = get_tested_words(page=page, db_dir=self.test_dir)
        self.assertIn("MAGIC", tested)

    def test_record_attempts_batch(self):
        page = "test_page_batch"
        batch = [
            {"page": page, "word": "SOLVE", "method": "CRIB_DRAG", "score": -3.0},
            {"page": page, "word": "REASON", "method": "CRIB_DRAG", "score": -3.5},
            {"page": page, "word": "WISDOM", "method": "CRIB_DRAG", "score": -2.8},
        ]
        cnt = record_attempts_batch(batch, db_dir=self.test_dir)
        self.assertEqual(cnt, 3)

        tested = get_tested_words(page=page, db_dir=self.test_dir)
        self.assertEqual(tested, {"SOLVE", "REASON", "WISDOM"})

        # filter_untested_words
        candidates = ["SOLVE", "REASON", "NOVEL_WORD", "ANOTHER_NEW"]
        untested = filter_untested_words(candidates, page=page, db_dir=self.test_dir)
        self.assertEqual(untested, ["NOVEL_WORD", "ANOTHER_NEW"])

    def test_query_similar_attempts(self):
        page = "test_sim_page"
        record_attempt(page=page, word="DIVINITY", method="CRIB", score=-3.8, db_dir=self.test_dir)
        record_attempt(page=page, word="ANARCHY", method="CRIB", score=-4.5, db_dir=self.test_dir)

        hits = query_similar_attempts("DIVINE", n_results=2, page=page, db_dir=self.test_dir)
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["word"], "DIVINITY")

    def test_get_rotated_vocabulary_excludes_tested_words(self):
        page = "test_filter_page"
        initial_words = get_rotated_vocabulary(page_id=page, limit=10, filter_tested=False)
        self.assertEqual(len(initial_words), 10)

        # Record the first 5 words as tested
        batch = [{"page": page, "word": w, "method": "CRIB_DRAG"} for w in initial_words[:5]]
        record_attempts_batch(batch)

        # Now get vocabulary with filter_tested=True
        filtered_words = get_rotated_vocabulary(page_id=page, limit=10, filter_tested=True)
        for w in initial_words[:5]:
            self.assertNotIn(w.upper(), [fw.upper() for fw in filtered_words])

    def test_consecutive_cracks_explore_disjoint_words(self):
        sample_runes = "ᚠᚢᚦᚩᚱᚳᚷᚹᚻᚾᛁᛄᛇᛈᛉᛋᛏᛒᛖᛗᛚᛝᛟᛞᚪᚫᚣᛡᛠ"
        page = "test_consecutive_p42"

        # First crack
        res1 = crack_liber_primus(sample_runes, page_id=page, crib_limit=5)
        self.assertGreater(res1.get("recorded_attempts_count", 0), 0)

        tested1 = get_tested_words(page=page)
        self.assertGreaterEqual(len(tested1), 5)

        # Second crack on the same page
        res2 = crack_liber_primus(sample_runes, page_id=page, crib_limit=5)
        self.assertGreater(res2.get("recorded_attempts_count", 0), 0)

        tested2 = get_tested_words(page=page)
        self.assertGreaterEqual(len(tested2), len(tested1) + 5)

    def test_workstation_ledger_command(self):
        ws = TerminalWorkstation()
        res = ws.run_ledger(target="56")
        self.assertIn("stats", res)
        self.assertIn("tested_words_count", res["stats"])


if __name__ == "__main__":
    unittest.main()
