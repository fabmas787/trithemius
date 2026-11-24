import os
import unittest
import pathlib
from tests.golden.record import CASES, REPL_SCRIPT, run_cli, run_repl, REF_DIR


class TestGoldenMaster(unittest.TestCase):
    """Test suite ensuring byte-level consistency against recorded golden master outputs."""

    def test_cli_cases_against_golden_master(self):
        for name, argv in CASES.items():
            with self.subTest(case=name):
                ref_file = REF_DIR / f"{name}.txt"
                self.assertTrue(ref_file.exists(), f"Reference file {ref_file} not found")
                expected = ref_file.read_text(encoding="utf-8")
                actual = run_cli(argv)
                self.assertEqual(
                    actual,
                    expected,
                    f"Output divergence detected in golden master case '{name}'"
                )

    def test_repl_session_against_golden_master(self):
        ref_file = REF_DIR / "repl_session.txt"
        self.assertTrue(ref_file.exists(), f"Reference file {ref_file} not found")
        expected = ref_file.read_text(encoding="utf-8")
        actual = run_repl(REPL_SCRIPT)
        self.assertEqual(
            actual,
            expected,
            "Output divergence detected in REPL golden master session"
        )


if __name__ == "__main__":
    unittest.main()
