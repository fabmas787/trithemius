"""
Unit tests for corpus preprocessing scripts:
- scripts/split_master_transcript.py
- scripts/normalize_runes.py
"""

import io
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import scripts.normalize_runes as normalize_runes
import scripts.split_master_transcript as split_master


class TestSplitMasterTranscript(unittest.TestCase):
    def test_parse_delimiters_defaults_and_overrides(self):
        header = (
            "Delimiter Legend:\n"
            "Word: |\n"
            "Paragraph: ~\n"
            "Page: #\n"
        )
        delims = split_master.parse_delimiters(header)
        self.assertEqual(delims["Word"], "|")
        self.assertEqual(delims["Paragraph"], "~")
        self.assertEqual(delims["Page"], "#")
        self.assertEqual(delims["Clause"], ".")
        self.assertEqual(delims["Chapter"], "§")

    def test_format_chunk_runes_and_transliterate(self):
        raw_chunk = "ᚹᛖᛚ-ᚳᚩᛗᛖ.\n&\n$\n§\nLATIN/LINE"
        formatted = split_master.format_chunk_runes(raw_chunk)
        lines = formatted.splitlines()
        self.assertEqual(lines[0], "ᚹᛖᛚ᛫ᚳᚩᛗᛖ᛬")
        self.assertEqual(lines[1], "")
        self.assertEqual(lines[2], "---")
        self.assertEqual(lines[3], "§")
        self.assertEqual(lines[4], "LATIN")
        self.assertEqual(lines[5], "LINE")

        latin = split_master.transliterate_chunk(formatted)
        self.assertIn("WEL", latin)
        self.assertIn("COME", latin)
        self.assertIn("---", latin)
        self.assertIn("§", latin)

    def test_process_master_file_dry_run_and_write_isolated(self):
        header = "\n".join([f"Header line {i}" for i in range(9)] + ["Page: %"])
        body = "ᚹᛖᛚ-ᚳᚩᛗᛖ.\n%\n§\n%\nᛈᛁᛚᚷᚱᛁᛗᛋ/\n"
        content = header + "\n" + body

        with tempfile.TemporaryDirectory() as tmpdir:
            master_path = os.path.join(tmpdir, "master.txt")
            corpus_dir = os.path.join(tmpdir, "corpus")
            os.makedirs(corpus_dir, exist_ok=True)
            with open(master_path, "w", encoding="utf-8") as f:
                f.write(content)

            with patch.object(split_master, "MASTER_FILE", master_path), \
                 patch.object(split_master, "CORPUS_DIR", corpus_dir):
                dry_stats = split_master.process_master_file(dry_run=True)
                self.assertEqual(dry_stats["total_chunks"], 3)
                self.assertEqual(dry_stats["created_files"], 0)
                self.assertEqual(dry_stats["total_runes"], 15)
                self.assertEqual(os.listdir(corpus_dir), [])

                write_stats = split_master.process_master_file(dry_run=False)
                self.assertEqual(write_stats["created_files"], 3)
                self.assertEqual(write_stats["total_runes"], 15)

                p0 = os.path.join(corpus_dir, "page_00_runes.md")
                p1 = os.path.join(corpus_dir, "page_01_runes.md")
                p2 = os.path.join(corpus_dir, "page_02_runes.md")
                self.assertTrue(os.path.exists(p0))
                self.assertTrue(os.path.exists(p1))
                self.assertTrue(os.path.exists(p2))

                with open(p0, "r", encoding="utf-8") as f:
                    p0_text = f.read()
                self.assertIn("<!-- cicada:page=00 -->", p0_text)
                self.assertIn("<!-- cicada:rune_count=7 -->", p0_text)
                self.assertIn("ᚹᛖᛚ᛫ᚳᚩᛗᛖ᛬", p0_text)
                self.assertIn("## Latin Transliteration", p0_text)

                with open(p1, "r", encoding="utf-8") as f:
                    p1_text = f.read()
                self.assertIn("Chapter Delimiter Seal", p1_text)

    def test_process_master_file_missing_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = os.path.join(tmpdir, "missing_master.txt")
            with patch.object(split_master, "MASTER_FILE", missing):
                with self.assertRaises(FileNotFoundError):
                    split_master.process_master_file(dry_run=True)


class TestNormalizeRunes(unittest.TestCase):
    def test_normalize_text_punctuation_and_stats(self):
        raw = "ᚹᛖᛚ•ᚳᚩᛗᛖ: ᛈᛁᛚᚷᚱᛁᛗᛋ; Ω"
        cleaned, stats = normalize_runes.normalize_text(raw)
        self.assertEqual(cleaned, "ᚹᛖᛚ᛫ᚳᚩᛗᛖ᛬ ᛈᛁᛚᚷᚱᛁᛗᛋ᛬ Ω")
        self.assertEqual(stats["rune_count"], 15)
        self.assertGreater(stats["gematria_prime_sum"], 0)
        self.assertEqual(stats["unknown_non_ascii_chars"], 1)

    def test_normalize_text_preserves_ascii_and_standard_separators(self):
        raw = "# Header\n[note] ᚠ-ᚢ_ᚦ᛫᛭᛬"
        cleaned, stats = normalize_runes.normalize_text(raw)
        self.assertEqual(cleaned, raw)
        self.assertEqual(stats["rune_count"], 3)
        self.assertEqual(stats["unknown_non_ascii_chars"], 0)

    def test_main_writes_output_file_and_handles_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            in_path = os.path.join(tmpdir, "in.txt")
            out_path = os.path.join(tmpdir, "out.txt")
            with open(in_path, "w", encoding="utf-8") as f:
                f.write("ᚹᛖᛚ·ᚳᚩᛗᛖ:")

            stdout_trap = io.StringIO()
            stderr_trap = io.StringIO()
            with patch.object(sys, "argv", ["normalize_runes.py", in_path, "-o", out_path]), \
                 patch("sys.stdout", stdout_trap), \
                 patch("sys.stderr", stderr_trap):
                normalize_runes.main()

            with open(out_path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "ᚹᛖᛚ᛫ᚳᚩᛗᛖ᛬")
            self.assertIn("Statistics: 7 runes", stderr_trap.getvalue())

            missing = os.path.join(tmpdir, "nope.txt")
            with patch.object(sys, "argv", ["normalize_runes.py", missing]), \
                 patch("sys.stdout", io.StringIO()), \
                 self.assertRaises(SystemExit) as ctx:
                normalize_runes.main()
            self.assertEqual(ctx.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
