import os
import tempfile
import unittest
from unittest.mock import patch

import agents.ledger as ledger
from ciphers.lexicon import (
    generate_cyclic_rotations,
    generate_all_key_variants,
    get_rotated_vocabulary,
    get_master_dictionary,
    SACRED_CANONICAL_WORDS,
)
from ciphers.taxonomy import crack_liber_primus
from trithemius import TerminalWorkstation


class TestLexiconRotationAndRandomization(unittest.TestCase):
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
    def test_generate_cyclic_rotations(self):
        # For an 8-letter word like DIVINITY
        shifts = [3, 8, 21, 8, 13, 8, 19, 24]  # arbitrary shifts length 8
        rots = generate_cyclic_rotations(shifts, "TESTWORD", base_label="FORWARD")
        self.assertEqual(len(rots), 7)
        for r, rot in enumerate(rots, 1):
            self.assertEqual(rot["label"], f"FORWARD_ROT_{r}")
            self.assertEqual(rot["word"], f"TESTWORD_ROT{r}")
            self.assertEqual(rot["rotation_offset"], r)
            self.assertEqual(len(rot["shifts"]), 8)
            expected_shifts = shifts[r:] + shifts[:r]
            self.assertEqual(rot["shifts"], expected_shifts)

    def test_single_letter_rotations_empty(self):
        rots = generate_cyclic_rotations([5], "A", base_label="FORWARD")
        self.assertEqual(rots, [])

    def test_generate_all_key_variants_with_rotations(self):
        unrotated = generate_all_key_variants("DIVINITY", include_rotations=False)
        rotated = generate_all_key_variants("DIVINITY", include_rotations=True)
        self.assertGreater(len(rotated), len(unrotated))
        labels = [v["label"] for v in rotated]
        self.assertTrue(any("ROT" in l for l in labels))

    def test_get_rotated_vocabulary_page_determinism(self):
        vocab_p00 = get_rotated_vocabulary(page_id="page_00", limit=20)
        vocab_p56 = get_rotated_vocabulary(page_id="page_56", limit=20)
        self.assertEqual(len(vocab_p00), 20)
        self.assertEqual(len(vocab_p56), 20)
        # Different pages should rotate to different dictionary offsets
        self.assertNotEqual(vocab_p00, vocab_p56)

        # Same page must be 100% deterministic
        vocab_p00_again = get_rotated_vocabulary(page_id="page_00", limit=20)
        self.assertEqual(vocab_p00, vocab_p00_again)

    def test_get_rotated_vocabulary_randomization(self):
        # Fixed seed should be deterministic
        sample1 = get_rotated_vocabulary(limit=15, randomize=True, seed=42)
        sample2 = get_rotated_vocabulary(limit=15, randomize=True, seed=42)
        self.assertEqual(sample1, sample2)
        self.assertEqual(len(sample1), 15)

        # Different seed should produce a different sample
        sample3 = get_rotated_vocabulary(limit=15, randomize=True, seed=999)
        self.assertNotEqual(sample1, sample3)

    def test_crack_liber_primus_with_rotations_and_randomize(self):
        # A short runic ciphertext
        sample_runes = "ᚠᚢᚦᚩᚱᚳᚷᚹᚻᚾᛁᛄᛇᛈᛉᛋᛏᛒᛖᛗᛚᛝᛟᛞᚪᚫᚣᛡᛠ"
        res = crack_liber_primus(
            sample_runes,
            page_id="test_page",
            deep=False,
            top_k=3,
            randomize=True,
            include_rotations=True,
            crib_limit=10,
            seed=123,
        )
        self.assertIn("top_candidates", res)
        self.assertIn("triage", res)
        self.assertIn("crib_drag_hits", res)

    def test_workstation_run_crack_arguments(self):
        ws = TerminalWorkstation()
        sample_runes = "ᚠᚢᚦᚩᚱᚳᚷᚹᚻᚾᛁᛄᛇᛈᛉᛋᛏᛒᛖᛗᛚᛝᛟᛞᚪᚫᚣᛡᛠ"
        res = ws.run_crack(
            sample_runes,
            deep=False,
            top_k=2,
            randomize=True,
            include_rotations=True,
            crib_limit=5,
            seed=77,
        )
        self.assertEqual(res["target_input"], sample_runes)
        self.assertIn("top_candidates", res)


if __name__ == "__main__":
    unittest.main()
