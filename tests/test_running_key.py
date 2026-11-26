"""
Unit tests for GF(29) Futhorc Running-Key Engine, Canonical Reference Corpus,
and Master Philosophical Phrase Harvester.
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import agents.ledger as ledger

from ciphers.running_key import (
    text_to_rune_indices,
    running_key_encrypt,
    running_key_decrypt,
    scan_keystream,
    scan_reference_file,
    scan_reference_directory,
    log_running_key_attempt_to_ledger,
    GATEKEEPER_THRESHOLD,
    REFERENCE_DIR,
)
from ciphers.lexicon import (
    load_reference_text_vocabulary,
    generate_philosophical_phrases,
    get_master_dictionary,
    FastLexiconIndex,
)
from ciphers.agrippa import latin_to_rune, INDEX_BY_RUNE, decode_runes, index_to_rune


class TestRunningKeyEngine(unittest.TestCase):
    """Test suite for GF(29) running-key mathematical transformations and keystream conversions."""

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

    def test_text_to_rune_indices(self):
        """Converts Latin and Futhorc text to GF(29) rune indices [0..28]."""
        # 1. Standard Latin text
        indices = text_to_rune_indices("WELCOME PILGRIM")
        self.assertTrue(len(indices) > 0)
        for idx in indices:
            self.assertIsInstance(idx, int)
            self.assertTrue(0 <= idx < 29)

        # 2. Pure Futhorc runes
        runes = "ᚹᛖᛚᚳᚩᛗᛖ"
        rune_indices = text_to_rune_indices(runes)
        self.assertEqual(len(rune_indices), len(runes))
        for r, i in zip(runes, rune_indices):
            self.assertEqual(INDEX_BY_RUNE[r], i)

        # 3. Digraphs (TH -> ᚦ [2], ING -> ᛝ [21], EA -> ᛠ [28])
        th_indices = text_to_rune_indices("TH")
        self.assertEqual(th_indices, [INDEX_BY_RUNE["ᚦ"]])
        ing_indices = text_to_rune_indices("ING")
        self.assertEqual(ing_indices, [INDEX_BY_RUNE["ᛝ"]])

        # 4. Empty and non-alpha input
        self.assertEqual(text_to_rune_indices(""), [])
        self.assertEqual(text_to_rune_indices("12345!@#$"), [])

    def test_roundtrip_sub_add_beaufort_without_f_skip(self):
        """Verify exact mathematical inverse roundtrips for sub, add, and beaufort without f_skip."""
        pt_indices = text_to_rune_indices("WELCOME PILGRIM TO THE SACRED CIRCUMFERENCE")
        keystream = text_to_rune_indices("FOR ALL THAT LIVES IS HOLY AND THE DOORS OF PERCEPTION WERE CLEANSED")
        self.assertGreater(len(keystream), len(pt_indices))

        for mode in ["sub", "add", "beaufort"]:
            for offset in [0, 5, 12]:
                cipher = running_key_encrypt(pt_indices, keystream, mode=mode, f_skip=False, offset=offset)
                self.assertEqual(len(cipher), len(pt_indices))

                dec_indices, dec_str = running_key_decrypt(cipher, keystream, mode=mode, f_skip=False, offset=offset)
                self.assertEqual(dec_indices, pt_indices, f"Failed roundtrip for mode={mode}, offset={offset}")
                self.assertIn("WELCOME", str(dec_str))

    def test_roundtrip_with_f_skip(self):
        """Verify roundtrip with Fehu-skip (plaintext index 0 pauses keystream pointer)."""
        # Fehu is 'F' (index 0). Ensure plaintext has multiple Fehu runes.
        pt_indices = text_to_rune_indices("FOR ALL THAT LIVES IS HOLY AND FREE FROM FEAR")
        self.assertIn(0, pt_indices, "Plaintext must contain Fehu (0) to test f_skip")

        keystream = text_to_rune_indices("NOTHING IS AT LAST SACRED BUT THE INTEGRITY OF YOUR OWN MIND TRUST THYSELF")
        self.assertGreater(len(keystream), len(pt_indices))

        for mode in ["sub", "add", "beaufort"]:
            for offset in [0, 7]:
                cipher = running_key_encrypt(pt_indices, keystream, mode=mode, f_skip=True, offset=offset)
                self.assertEqual(len(cipher), len(pt_indices))

                dec_indices, dec_str = running_key_decrypt(cipher, keystream, mode=mode, f_skip=True, offset=offset)
                self.assertEqual(dec_indices, pt_indices, f"Failed f_skip roundtrip for mode={mode}, offset={offset}")

    def test_sliding_scan_detection_planted_key(self):
        """Verify sliding window scan recovers planted running key and offset accurately."""
        pt_indices = text_to_rune_indices("THE SACRED PRIMES AND TOTIENTS REVEAL TRUTH AND WISDOM")
        reference_text = (
            "IN THE BEGINNING THERE WAS THE VOID AND FROM THE VOID AROSE THE DIVINE CONSCIOUSNESS "
            "THERE IS A SPHERICAL EXPANSION IN ALL DIRECTIONS THE SOUL IS THE CIRCUMFERENCE AND CENTER "
            "WHICH HOLDS THE COSMOS TOGETHER AND SHINES AS A LIGHT IN THE DARKNESS OF THE UNIVERSE"
        )
        full_keystream = text_to_rune_indices(reference_text)
        planted_offset = 25
        self.assertGreater(len(full_keystream), planted_offset + len(pt_indices))

        # Encrypt with sub mode at planted_offset
        cipher = running_key_encrypt(pt_indices, full_keystream, mode="sub", f_skip=False, offset=planted_offset)

        # Scan full keystream
        results = scan_keystream(cipher, full_keystream, mode="sub", f_skip=False, step=1, top_k=3)
        self.assertTrue(len(results) > 0)

        top_match = results[0]
        self.assertEqual(top_match["offset"], planted_offset)
        self.assertEqual(top_match["plain_indices"], pt_indices)
        self.assertGreater(top_match["score"], -3.0)
        self.assertTrue(top_match["passed"])

    def test_scan_reference_file(self):
        """Verify scanning against a physical reference file."""
        ref_file = os.path.join(REFERENCE_DIR, "hermes_emerald_tablet.txt")
        self.assertTrue(os.path.exists(ref_file))

        pt_indices = text_to_rune_indices("THAT WHICH IS BELOW CORRESPONDS TO THAT WHICH IS ABOVE")
        with open(ref_file, "r", encoding="utf-8") as f:
            ref_stream = text_to_rune_indices(f.read())

        offset = 15
        cipher = running_key_encrypt(pt_indices, ref_stream, mode="sub", offset=offset)

        matches = scan_reference_file(cipher, ref_file, modes=["sub"], f_skips=[False], step=1, top_k=3)
        self.assertTrue(len(matches) > 0)
        top = matches[0]
        self.assertEqual(top["offset"], offset)
        self.assertEqual(top["plain_indices"], pt_indices)
        self.assertEqual(top["source_file"], "hermes_emerald_tablet.txt")

    def test_ledger_logging(self):
        """Verify running-key attempts log to canonical_attempts without double-counting."""
        self.assertEqual(ledger.count_attempts(page="test_page"), 0)
        success = log_running_key_attempt_to_ledger(
            page="test_page",
            source_text="test_reference.txt",
            mode="sub",
            f_skip=False,
            offset=0,
            score=-2.85,
            plaintext="WELCOME PILGRIM",
            passed=True,
        )
        self.assertTrue(success)
        self.assertEqual(ledger.count_attempts(page="test_page"), 1)
        self.assertTrue(ledger.has_been_tried("test_page", "running_key"))

        # Duplicate attempt must not inflate count_attempts()
        dup = log_running_key_attempt_to_ledger(
            page="test_page",
            source_text="test_reference.txt",
            mode="sub",
            f_skip=False,
            offset=0,
            score=-2.85,
            plaintext="WELCOME PILGRIM",
            passed=True,
        )
        self.assertFalse(dup)
        self.assertEqual(ledger.count_attempts(page="test_page"), 1)

    def test_edge_cases_and_error_handling(self):
        """Verify boundary values, empty inputs, and error handling paths."""
        # Empty inputs
        self.assertEqual(text_to_rune_indices(""), [])
        self.assertEqual(text_to_rune_indices(None), [])
        self.assertEqual(running_key_encrypt([], [1, 2, 3]), [])
        dec_idx, dec_s = running_key_decrypt([], [1, 2, 3])
        self.assertEqual(dec_idx, [])
        self.assertEqual(dec_s, "")

        # Empty keystream raises ValueError
        with self.assertRaises(ValueError):
            running_key_decrypt([1, 2], [])
        with self.assertRaises(ValueError):
            running_key_encrypt([1, 2], [])

        # Invalid mode raises ValueError
        with self.assertRaises(ValueError):
            running_key_decrypt([1, 2], [3, 4], mode="invalid")
        with self.assertRaises(ValueError):
            running_key_encrypt([1, 2], [3, 4], mode="invalid")

        # Keystream shorter than cipher indices returns empty scan
        self.assertEqual(scan_keystream([1, 2, 3], [1, 2]), [])

        # Non-existent reference file raises FileNotFoundError
        with self.assertRaises(FileNotFoundError):
            scan_reference_file([1, 2], "/nonexistent/path/file.txt")

        # Non-existent directory returns empty
        self.assertEqual(scan_reference_directory([1, 2], "/nonexistent/directory"), [])
        self.assertEqual(load_reference_text_vocabulary("/nonexistent/directory"), [])


class TestPhilosophicalCorpusAndLexicon(unittest.TestCase):
    """Test suite for canonical reference texts, vocabulary harvesting, and philosophical phrases."""

    REQUIRED_CANONICAL_TEXTS = [
        "blake_marriage_heaven_hell.txt",
        "blake_auguries_of_innocence.txt",
        "emerson_self_reliance.txt",
        "emerson_over_soul.txt",
        "nietzsche_zarathustra_excerpts.txt",
        "hermes_emerald_tablet.txt",
        "crowley_liber_al_vel_legis.txt",
        "gibson_agrippa.txt",
        "gospel_of_thomas_excerpts.txt",
        "gibran_the_prophet_excerpts.txt",
        "jung_seven_sermons.txt",
    ]

    def test_all_reference_texts_exist_and_non_empty(self):
        """Verify all 11 canonical reference texts exist and yield substantial keystreams."""
        self.assertTrue(os.path.exists(REFERENCE_DIR), f"Reference dir not found: {REFERENCE_DIR}")

        for fname in self.REQUIRED_CANONICAL_TEXTS:
            fpath = os.path.join(REFERENCE_DIR, fname)
            self.assertTrue(os.path.exists(fpath), f"Missing canonical reference text: {fname}")

            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertGreater(len(content), 500, f"Text {fname} is too short ({len(content)} chars)")
            stream = text_to_rune_indices(content)
            self.assertGreater(len(stream), 200, f"Text {fname} yielded fewer than 200 keystream runes")

    def test_load_reference_text_vocabulary(self):
        """Verify vocabulary extraction from reference texts."""
        vocab = load_reference_text_vocabulary()
        self.assertGreater(len(vocab), 1000)

        # Check key terms from the 11 authors
        for expected in ["HEAVEN", "PERCEPTION", "PLEROMA", "ABRAXAS", "ZARATHUSTRA", "OVERSOUL", "CIRCUMFERENCE"]:
            self.assertIn(expected, vocab, f"Expected philosophical word '{expected}' missing from vocabulary")

    def test_generate_philosophical_phrases(self):
        """Verify generation of curated multi-word aphorisms."""
        phrases = generate_philosophical_phrases()
        self.assertGreater(len(phrases), 80)

        expected_phrases = [
            "FORALLTHATLIVESISHOLY",
            "EVERYMANANDWOMANISASTAR",
            "DOORSOFPERCEPTION",
            "ASABOVESOBELOW",
            "TRUSTTHYSELF",
            "THEPRIMESARESACRED",
            "COMMANDYOUROWNSELF",
            "NOTHINGISLASTSACRED",
            "KNOWTHYSELF",
            "THREEMETAMORPHOSES",
            "GRAINOFSAND",
            "SOVEREIGNSOURCE",
            "ANAMNESIS",
            "CIRCUMFERENCEANDCENTER",
            "INTEGRITYOFYOUROWNMIND",
        ]
        for ep in expected_phrases:
            self.assertIn(ep, phrases, f"Missing required philosophical phrase: {ep}")

    def test_get_master_dictionary_integration(self):
        """Verify combined master dictionary includes references and phrases seamlessly."""
        master = get_master_dictionary(include_corpus=True, include_references=True)
        self.assertGreater(len(master), 5000)

        # Check presence of phrases and words
        self.assertIn("FORALLTHATLIVESISHOLY", master)
        self.assertIn("PLEROMA", master)
        self.assertIn("WELCOME", master)

        # Verify FastLexiconIndex indexes the phrases
        index = FastLexiconIndex(master)
        # Check prefix and word lookup for a known phrase
        holy_rune = "".join(c for c in latin_to_rune("FORALLTHATLIVESISHOLY") if c in INDEX_BY_RUNE)
        self.assertTrue(index.is_word(holy_rune))
        self.assertTrue(index.is_prefix(holy_rune[:6]))

    def test_decoded_string_hash_and_membership(self):
        """Verify DecodedString uses symmetric Latin str equality/hashing and preserves .runes."""
        from ciphers.running_key import DecodedString
        s = DecodedString("WELCOME", "ᚹᛖᛚᚳᚩᛗᛖ")
        self.assertEqual(s.runes, "ᚹᛖᛚᚳᚩᛗᛖ")
        self.assertEqual(s, "WELCOME")
        self.assertEqual("WELCOME", s)
        self.assertNotEqual(s, s.runes)
        self.assertNotEqual(s.runes, s)
        self.assertFalse(s == s.runes)
        self.assertFalse(s.runes == s)
        self.assertEqual(hash(s), hash("WELCOME"))
        self.assertEqual(len({s, "WELCOME"}), 1)
        s_set = {s}
        self.assertIn("WELCOME", s_set)
        self.assertIn(s, s_set)
        s_dict = {s: 1}
        self.assertEqual(s_dict["WELCOME"], 1)
        self.assertEqual({"WELCOME": 42}[s], 42)

    def test_text_to_rune_indices_mixed_input(self):
        """Verify text containing both Latin and runes preserves all runes and Latin words."""
        # Mixed: Latin word + rune
        mixed_indices = text_to_rune_indices("WELCOME ᚠ")
        # Should include WELCOME runes plus Fehu (0)
        self.assertIn(0, mixed_indices)
        self.assertEqual(mixed_indices[-1], 0)
        self.assertGreater(len(mixed_indices), 1)

    def test_sliding_scan_step_parameter(self):
        """Verify sliding window scan respects step size parameter."""
        cipher = text_to_rune_indices("WELCOME")
        key = text_to_rune_indices("THE SACRED PRIMES AND TOTIENTS REVEAL WISDOM")
        res_step1 = scan_keystream(cipher, key, step=1, top_k=100)
        res_step3 = scan_keystream(cipher, key, step=3, top_k=100)
        self.assertGreater(len(res_step1), len(res_step3))
        for item in res_step3:
            self.assertEqual(item["offset"] % 3, 0)

    def test_load_reference_text_vocabulary_custom_bounds(self):
        """Verify load_reference_text_vocabulary respects custom min_len and max_len."""
        vocab_short = load_reference_text_vocabulary(min_len=4, max_len=6)
        self.assertTrue(all(4 <= len(w) <= 6 for w in vocab_short))
        self.assertGreater(len(vocab_short), 100)

    def test_terminal_workstation_running_key_integration(self):
        """Verify workstation runners execute running-key, scan, and lexicon actions."""
        from trithemius import TerminalWorkstation
        ws = TerminalWorkstation(model_key="spark")

        # 1. run_running_key
        ref_file = os.path.join(REFERENCE_DIR, "hermes_emerald_tablet.txt")
        res_rk = ws.run_running_key("56", ref_file, mode="sub")
        self.assertNotIn("error", res_rk)
        self.assertEqual(res_rk["page"], "56")
        self.assertIn("plain_latin", res_rk)

        # 2. run_running_key_scan with step
        res_scan = ws.run_running_key_scan("56", step=100, top_k=2)
        self.assertNotIn("error", res_scan)
        self.assertGreaterEqual(len(res_scan["candidates"]), 1)

        # 3. run_lexicon
        res_lex = ws.run_lexicon(action="phrases", limit=10)
        self.assertEqual(len(res_lex["items"]), 10)
        self.assertGreater(res_lex["total"], 80)

    def test_ciphers_standalone_subprocess_import(self):
        """Verify ciphers.lexicon and ciphers.running_key can be imported in clean subprocess."""
        import subprocess
        cmd = [sys.executable, "-c", "import ciphers.lexicon, ciphers.running_key; print('OK')"]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.join(os.path.dirname(__file__), ".."))
        self.assertEqual(proc.returncode, 0, f"Subprocess import failed: {proc.stderr}")
        self.assertIn("OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
