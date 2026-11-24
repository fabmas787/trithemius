"""
Tests for Workstation Typed Results and Interchangeable Renderers (Phase 7).
"""

import io
import json
import unittest
from unittest.mock import patch

from workstation.core.results import (
    TypedResult,
    GematriaResult,
    AtbashResult,
    VigenereResult,
    TotientStreamResult,
    SolveResult,
    CrackResult,
    HardwareResult,
    LedgerResult,
    TriageResult,
    PeriodResult,
    CribResult,
    RunningKeyResult,
    RunningKeyScanResult,
    LexiconResult,
    OpsecResult,
    StatusResult,
)
from workstation.core.workstation import TerminalWorkstation
from workstation.ui.formatters import ConsoleRenderer
from workstation.ui.json_renderer import JsonRenderer
from workstation.cli.parser import main, build_parser


class TestTypedResults(unittest.TestCase):
    """Verify behavior, typing, and backward compatibility of typed result objects."""

    def test_typed_result_dict_and_attribute_access(self):
        res = GematriaResult(
            text="WELCOME",
            runes="ᚹᛖᛚᚳᚩᛗᛖ",
            prime_sum=188,
            is_prime=False,
            prime_factors=[2, 2, 47],
            totient=92,
            word_sums=[188],
            direct_latin="WELCOME",
        )
        # Dictionary-style access (legacy tests compatibility)
        self.assertIsInstance(res, dict)
        self.assertEqual(res["prime_sum"], 188)
        self.assertEqual(res["runes"], "ᚹᛖᛚᚳᚩᛗᛖ")
        self.assertIn("prime_sum", res)

        # Attribute-style access (modern clean architecture)
        self.assertEqual(res.prime_sum, 188)
        self.assertEqual(res.runes, "ᚹᛖᛚᚳᚩᛗᛖ")
        self.assertFalse(res.is_prime)

        # Conversion to plain dict
        d = res.to_dict()
        self.assertIs(type(d), dict)
        self.assertEqual(d["prime_sum"], 188)

        # JSON serializable directly
        serialized = json.dumps(res)
        self.assertIn('"prime_sum": 188', serialized)

    def test_attribute_error_on_missing_key(self):
        res = TypedResult(a=1)
        self.assertEqual(res.a, 1)
        with self.assertRaises(AttributeError):
            _ = res.nonexistent_field

    def test_workstation_methods_return_typed_results(self):
        ws = TerminalWorkstation()
        gem = ws.run_gematria("WELCOME")
        self.assertIsInstance(gem, GematriaResult)
        self.assertEqual(gem.prime_sum, 317)
        self.assertEqual(gem["prime_sum"], 317)

        atb = ws.run_atbash("00")
        self.assertIsInstance(atb, AtbashResult)
        self.assertIn("decoded_latin", atb)
        self.assertIn("A WARNING", atb.decoded_latin)

        vig = ws.run_vigenere("enc", "WELCOME", "DIVINITY")
        self.assertIsInstance(vig, VigenereResult)
        self.assertIn("result", vig)
        self.assertEqual(vig.key, "DIVINITY")


class TestRenderers(unittest.TestCase):
    """Verify ConsoleRenderer and JsonRenderer interchangeability."""

    def setUp(self):
        self.ws = TerminalWorkstation()

    def test_console_renderer_with_typed_result(self):
        buf = io.StringIO()
        renderer = ConsoleRenderer(stream=buf)
        gem = self.ws.run_gematria("WELCOME")
        renderer.print_gematria(gem)
        output = buf.getvalue()
        self.assertIn("GEMATRIA PRIMUS", output)
        self.assertIn("317", output)

    def test_json_renderer_output(self):
        buf = io.StringIO()
        renderer = JsonRenderer(stream=buf)
        gem = self.ws.run_gematria("WELCOME")
        renderer.print_gematria(gem)
        output = buf.getvalue()
        parsed = json.loads(output)
        self.assertEqual(parsed["prime_sum"], 317)
        self.assertEqual(parsed["input"], "WELCOME")

    def test_json_renderer_handles_sets(self):
        buf = io.StringIO()
        renderer = JsonRenderer(stream=buf)
        data = {"numbers": {1, 2, 3}, "name": "test"}
        renderer.print_json(data)
        parsed = json.loads(buf.getvalue())
        self.assertEqual(sorted(parsed["numbers"]), [1, 2, 3])


class TestCLIJsonFlag(unittest.TestCase):
    """Verify --json flag in CLI dispatch."""

    def test_cli_gematria_json(self):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            main(["--json", "gematria", "WELCOME"])
        raw = buf.getvalue()
        parsed = json.loads(raw)
        self.assertEqual(parsed["prime_sum"], 317)
        self.assertEqual(parsed["input"], "WELCOME")

    def test_cli_hardware_json(self):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            main(["--json", "hardware"])
        raw = buf.getvalue()
        parsed = json.loads(raw)
        self.assertIn("metal_gpu", parsed)

    def test_cli_solve_json(self):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            main(["--json", "solve", "welcome"])
        raw = buf.getvalue()
        parsed = json.loads(raw)
        self.assertEqual(parsed["id"], "welcome")
        self.assertTrue(parsed["verified"])


if __name__ == "__main__":
    unittest.main()
