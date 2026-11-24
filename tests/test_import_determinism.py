import subprocess
import sys
import unittest
from pathlib import Path


class TestImportDeterminism(unittest.TestCase):
    def test_trithemius_does_not_inject_subdirs_into_sys_path(self):
        import trithemius
        base_dir = str(Path(__file__).resolve().parent.parent)
        for sub in ("ciphers", "scripts", "agents"):
            sub_path = str(Path(base_dir) / sub)
            self.assertNotIn(sub_path, sys.path, f"Pollution detected: {sub_path} in sys.path")

    def test_clean_absolute_imports(self):
        from ciphers.entropy import shannon_entropy
        from ciphers.agrippa import decode_runes
        from ciphers.kasiski import rune_vigenere_decode
        from scripts.bodleian import iter_corpus_documents
        from agents.ledger import has_been_tried
        self.assertTrue(callable(shannon_entropy))
        self.assertTrue(callable(decode_runes))
        self.assertTrue(callable(rune_vigenere_decode))
        self.assertTrue(callable(iter_corpus_documents))
        self.assertTrue(callable(has_been_tried))

    def test_cli_execution_from_external_working_directory(self):
        base_dir = Path(__file__).resolve().parent.parent
        proc = subprocess.run(
            [sys.executable, str(base_dir / "trithemius.py"), "status", "--json"],
            cwd="/tmp",
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, f"CLI failed from /tmp: {proc.stderr}")
