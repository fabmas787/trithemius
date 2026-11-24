import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from workstation.commands import COMMAND_SPECS, COMMAND_REGISTRY, get_command
from workstation.core.workstation import TerminalWorkstation
from workstation.cli.parser import build_parser

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestCommandSpecParity(unittest.TestCase):
    """Enforce complete parity between CommandSpec table, CLI parser, and TerminalWorkstation."""

    def setUp(self):
        self.ws = TerminalWorkstation()
        self.parser = build_parser()

    def test_all_command_specs_have_valid_handlers(self):
        for spec in COMMAND_SPECS:
            with self.subTest(command=spec.name):
                # Handler must exist on either TerminalWorkstation or its UI renderer or be a built-in shell action
                has_handler = hasattr(self.ws, spec.handler) or hasattr(self.ws.ui, spec.handler) or spec.name in ("clear", "exit", "quit")
                self.assertTrue(
                    has_handler,
                    f"Command '{spec.name}' handler '{spec.handler}' not found on TerminalWorkstation"
                )

    def test_cli_subparsers_cover_all_command_specs(self):
        # Retrieve all registered subparser names from the main ArgumentParser
        subparsers_action = next(
            (action for action in self.parser._actions if action.dest == "subcommand"),
            None
        )
        self.assertIsNotNone(subparsers_action, "Subparsers action not found in CLI parser")
        cli_subcommands = set(subparsers_action.choices.keys())

        for spec in COMMAND_SPECS:
            if spec.name in ("clear", "exit", "quit"):
                continue  # REPL-only session commands
            with self.subTest(command=spec.name):
                self.assertIn(
                    spec.name,
                    cli_subcommands,
                    f"Command '{spec.name}' from CommandSpec table is missing from CLI parser subparsers"
                )

    def test_alias_resolution(self):
        self.assertEqual(get_command("/gpu").name, "hardware")
        self.assertEqual(get_command("metal").name, "hardware")
        self.assertEqual(get_command("/keys").name, "key")
        self.assertEqual(get_command("quit").name, "exit")

    def test_status_json_dual_flag_positions(self):
        for argv in (["--json", "status"], ["status", "--json"]):
            with self.subTest(argv=argv):
                proc = subprocess.run(
                    [sys.executable, os.path.join(BASE_DIR, "trithemius.py"), *argv],
                    cwd=BASE_DIR,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                payload = json.loads(proc.stdout)
                self.assertIsInstance(payload, dict)
                self.assertIn("active_model", payload)

    def test_crack_flags_and_invalid_cli_args_rejected(self):
        args = self.parser.parse_args(
            ["crack", "56", "--compound", "--no-metal", "--no-ane", "--top-k", "3"]
        )
        self.assertEqual(args.subcommand, "crack")
        self.assertEqual(args.text, "56")
        self.assertTrue(args.compound)
        self.assertTrue(args.no_metal)
        self.assertTrue(args.no_ane)
        self.assertEqual(args.top_k, 3)

        for bad_argv in (
            ["crack", "56", "--top-k", "0"],
            ["vigenere", "dec", "ᚹᛖᛚ", "DIVINITY", "--skip-indices", "1,bad"],
            ["totient-stream", "dec", "ᚹᛖᛚ", "--skip-indices", "abc"],
        ):
            with self.subTest(bad_argv=bad_argv), self.assertRaises(SystemExit) as ctx:
                with patch("sys.stderr"):
                    self.parser.parse_args(bad_argv)
            self.assertNotEqual(ctx.exception.code, 0)

    def test_agents_crew_imports_cleanly_without_crewai(self):
        code = (
            "import sys; sys.modules['crewai'] = None; sys.modules['crewai.tools'] = None; "
            "import agents.crew as c; assert not c.CREWAI_AVAILABLE; print('OK')"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("OK", proc.stdout)

    def test_agents_crew_build_crew_when_installed(self):
        import agents.crew as crew_mod
        if not getattr(crew_mod, "CREWAI_AVAILABLE", False):
            self.skipTest("crewai is not installed")
        crew_obj = crew_mod.build_crew("Test Liber Primus query")
        self.assertIsNotNone(crew_obj)


if __name__ == "__main__":
    unittest.main()
