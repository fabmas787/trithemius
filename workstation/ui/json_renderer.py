"""
Machine-readable JSON presentation layer for headless pipelines and automated agents.
"""

import json
import sys
from typing import Any, Optional, TextIO


class JsonRenderer:
    """
    Interchangeable renderer that formats cryptanalytic and telemetry results
    as structured, indented JSON strings.
    """

    def __init__(self, stream: Optional[TextIO] = None) -> None:
        self.stream = stream if stream is not None else sys.stdout

    def _serialize(self, obj: Any) -> Any:
        if isinstance(obj, set):
            return sorted(list(obj))
        if hasattr(obj, "to_dict") and callable(obj.to_dict):
            return obj.to_dict()
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        return str(obj)

    def render_json(self, data: Any, indent: int = 2) -> str:
        """Render Python data structure or TypedResult to formatted JSON string."""
        return json.dumps(data, indent=indent, default=self._serialize)

    def print_json(self, data: Any, indent: int = 2) -> None:
        """Output serialized JSON directly to the configured output stream."""
        content = self.render_json(data, indent=indent)
        print(content, file=self.stream)

    # Interchangeable formatting methods matching ConsoleRenderer signature
    def print_gematria(self, data: Any) -> None:
        self.print_json(data)

    def print_atbash(self, data: Any) -> None:
        self.print_json(data)

    def print_vigenere(self, data: Any) -> None:
        self.print_json(data)

    def print_totient_stream(self, data: Any) -> None:
        self.print_json(data)

    def print_totient(self, data: Any) -> None:
        self.print_json(data)

    def print_solve(self, data: Any) -> None:
        self.print_json(data)

    def print_crack(self, data: Any) -> None:
        self.print_json(data)

    def print_hardware(self, data: Any) -> None:
        self.print_json(data)

    def print_ledger(self, data: Any) -> None:
        self.print_json(data)

    def print_triage(self, data: Any) -> None:
        self.print_json(data)

    def print_period(self, data: Any) -> None:
        self.print_json(data)

    def print_crib(self, data: Any) -> None:
        self.print_json(data)

    def print_running_key(self, data: Any) -> None:
        self.print_json(data)

    def print_running_key_scan(self, data: Any) -> None:
        self.print_json(data)

    def print_lexicon(self, data: Any) -> None:
        self.print_json(data)

    def print_opsec(self, data: Any) -> None:
        self.print_json(data)

    def print_layout_calibration(self, data: Any) -> None:
        self.print_json(data)

    def print_layout_page(self, data: Any) -> None:
        self.print_json(data)

    def print_status(self, telemetry: Any, probe_results: Optional[Any] = None) -> None:
        payload = dict(telemetry) if hasattr(telemetry, "items") else {"telemetry": telemetry}
        if probe_results is not None:
            payload["probe_results"] = probe_results
        self.print_json(payload)
