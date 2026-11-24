"""
Trithemius Workstation Package.
Exposes lazy re-exports via PEP 562 to avoid eager imports of heavy modules.
"""

def __getattr__(name: str):
    if name == "TerminalWorkstation":
        from .core.workstation import TerminalWorkstation
        return TerminalWorkstation
    if name == "ConsoleRenderer":
        from .ui.formatters import ConsoleRenderer
        return ConsoleRenderer
    if name == "Settings":
        from .settings import Settings
        return Settings
    if name == "main":
        from .cli.parser import main
        return main
    if name == "JsonRenderer":
        from .ui.json_renderer import JsonRenderer
        return JsonRenderer
    if name == "TypedResult":
        from .core.results import TypedResult
        return TypedResult
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
