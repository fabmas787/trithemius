import ast
import os
import sys
import unittest
import pathlib

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
PACKAGE_DIR = BASE_DIR / "workstation"


class TestArchitectureLayering(unittest.TestCase):
    """Enforce clean architecture layering rules across the workstation package."""

    def _get_imports_from_ast(self, file_path: pathlib.Path) -> set:
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0])
        return imports

    def test_settings_layering(self):
        settings_file = PACKAGE_DIR / "settings.py"
        if not settings_file.exists():
            self.skipTest("workstation/settings.py does not exist yet")

        imports = self._get_imports_from_ast(settings_file)
        # settings must only import stdlib
        forbidden = {"workstation", "ciphers", "scripts", "agents", "chromadb", "ollama", "sqlite3", "requests"}
        violated = imports & forbidden
        self.assertFalse(violated, f"workstation/settings.py violates layering by importing: {violated}")

    def test_formatters_layering_and_heavy_imports(self):
        formatters_file = PACKAGE_DIR / "ui" / "formatters.py"
        if not formatters_file.exists():
            self.skipTest("workstation/ui/formatters.py does not exist yet")

        # Runtime import check in clean subprocess or module inspect
        forbidden_runtime = {"chromadb", "ollama", "sqlite3", "requests", "core", "cli"}
        imports = self._get_imports_from_ast(formatters_file)
        violated = imports & forbidden_runtime
        self.assertFalse(violated, f"workstation/ui/formatters.py imports forbidden modules: {violated}")

    def test_core_layering(self):
        core_file = PACKAGE_DIR / "core" / "workstation.py"
        if not core_file.exists():
            self.skipTest("workstation/core/workstation.py does not exist yet")

        imports = self._get_imports_from_ast(core_file)
        forbidden = {"cli", "repl"}
        violated = imports & forbidden
        self.assertFalse(violated, f"workstation/core/workstation.py violates layering by importing: {violated}")

    def test_repl_layering(self):
        repl_file = PACKAGE_DIR / "ui" / "repl.py"
        if not repl_file.exists():
            self.skipTest("workstation/ui/repl.py does not exist yet")

        imports = self._get_imports_from_ast(repl_file)
        forbidden = {"cli"}
        violated = imports & forbidden
        self.assertFalse(violated, f"workstation/ui/repl.py violates layering by importing: {violated}")


if __name__ == "__main__":
    unittest.main()
