import unittest
from workstation.commands import COMMAND_SPECS, COMMAND_REGISTRY, get_command
from workstation.core.workstation import TerminalWorkstation
from workstation.cli.parser import build_parser


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


if __name__ == "__main__":
    unittest.main()
