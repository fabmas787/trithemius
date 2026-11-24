"""
Automated test suite for Trithemius Telemetry and Textual TUI Dashboard.
Covers:
- Telemetry schema & TelemetryEmitter throttling / exception shielding
- Solver telemetry emissions, calculation traces, and cooperative cancellation
- CLI parser --tui / --no-tui flags and headless execution
- Cold-start lazy import verification (textual not imported in headless CLI)
- Textual headless app tests via App.run_test()
"""

import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

# Ensure repo root is on path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import agents.ledger as ledger

from ciphers.telemetry import (
    CalcStepEvent,
    CandidateEvent,
    CandidateUpdateEvent,
    PhaseEvent,
    PhaseStatus,
    TelemetryEmitter,
)
from ciphers.taxonomy import crack_liber_primus
from ciphers.running_key import scan_reference_directory
from workstation.cli.parser import build_parser


class TestTelemetrySchemaAndEmitter(unittest.TestCase):
    """Test telemetry contracts and TelemetryEmitter behavior."""

    def test_schema_slots_and_fields(self):
        pe = PhaseEvent(phase_id=1, total_phases=10, name="Triage", status=PhaseStatus.STARTED)
        self.assertEqual(pe.phase_id, 1)
        self.assertEqual(pe.status, PhaseStatus.STARTED)

        cs = CalcStepEvent(
            stage="Phase 1",
            module="entropy",
            formula="H = -sum(p*log(p))",
            inputs={"N": 100},
            result="H=4.7",
            verdict="PASS",
        )
        self.assertEqual(cs.module, "entropy")
        self.assertEqual(cs.verdict, "PASS")

        ce = CandidateEvent(
            candidate_id="cand_1",
            method="ATBASH",
            key="ATBASH",
            score=-2.5,
            threshold=-3.38,
            plaintext_preview="WELCOME",
        )
        self.assertIsNone(ce.z_score)

        cu = CandidateUpdateEvent(candidate_id="cand_1", z_score=2.85, is_significant=True)
        self.assertTrue(cu.is_significant)

    def test_emitter_throttling(self):
        events = []
        emitter = TelemetryEmitter(callback=events.append, min_interval_sec=0.08)

        # Immediate lifecycle events should NEVER be throttled
        emitter.emit_phase(1, 10, "P1", PhaseStatus.STARTED)
        emitter.emit_calc("Stage", "mod", "f", {}, "res")
        emitter.emit_candidate("c1", "M", "K", -2.0, -3.38, "prev")
        self.assertEqual(len(events), 3)

        # Rapid PROGRESS events should be throttled
        for i in range(10):
            emitter.emit_phase(1, 10, "P1", PhaseStatus.PROGRESS, completed=i, total=10)
        # Should only emit at most 2 progress events due to >= 80ms throttle
        progress_events = [e for e in events if isinstance(e, PhaseEvent) and e.status == PhaseStatus.PROGRESS]
        self.assertLessEqual(len(progress_events), 2)

    def test_emitter_exception_shielding(self):
        def bad_callback(evt):
            raise RuntimeError("UI render failure simulated")

        emitter = TelemetryEmitter(callback=bad_callback)
        # Emitting must NOT raise an unhandled exception
        try:
            emitter.emit_phase(1, 10, "P1", PhaseStatus.STARTED)
            emitter.emit_calc("S", "M", "F", {}, "R")
        except Exception as e:
            self.fail(f"TelemetryEmitter failed to shield callback exception: {e}")


class TestSolverTelemetryAndCancellation(unittest.TestCase):
    """Test taxonomy and running-key solver instrumentation and cooperative cancellation."""

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

    def test_crack_telemetry_emission(self):
        events = []
        res = crack_liber_primus(
            "ᚹᛖᛚᚳᚩᛗᛖ",  # Short target
            page_id="test_welcome",
            deep=False,
            progress_callback=events.append,
        )
        self.assertIsInstance(res, dict)
        self.assertIn("calc_steps", res)
        self.assertGreaterEqual(len(events), 5)

        # Check phase progression
        phases = [e for e in events if isinstance(e, PhaseEvent)]
        self.assertTrue(any(p.name.startswith("Triage") for p in phases))
        self.assertTrue(any(p.name.startswith("Canonical Solved") for p in phases))

        # Check calculation steps recorded
        calc_steps = [e for e in events if isinstance(e, CalcStepEvent)]
        self.assertGreaterEqual(len(calc_steps), 1)

        # Check candidate events have calibrated z_score
        cands = [e for e in events if isinstance(e, CandidateEvent)]
        if cands:
            self.assertIsNotNone(cands[0].z_score)

    def test_crack_cancellation(self):
        cancel_evt = threading.Event()
        cancel_evt.set()  # Immediately cancelled
        events = []
        res = crack_liber_primus(
            "ᚹᛖᛚᚳᚩᛗᛖ",
            progress_callback=events.append,
            cancel_event=cancel_evt,
        )
        self.assertTrue(res.get("cancelled", False))
        cancelled_events = [e for e in events if isinstance(e, PhaseEvent) and e.status == PhaseStatus.CANCELLED]
        self.assertGreaterEqual(len(cancelled_events), 1)

    def test_running_key_scan_telemetry(self):
        events = []
        res = scan_reference_directory(
            cipher_indices=[1, 2, 3, 4, 5],
            step=10,
            progress_callback=events.append,
        )
        self.assertIsInstance(res, list)
        self.assertTrue(any(isinstance(e, CalcStepEvent) for e in events))


class TestCLIDispatchAndColdStart(unittest.TestCase):
    """Test CLI parser flags, headless execution, and lazy import isolation."""

    def test_parser_tui_flags(self):
        parser = build_parser()
        args_default = parser.parse_args([])
        self.assertIsNone(args_default.tui)

        args_tui = parser.parse_args(["--tui"])
        self.assertTrue(args_tui.tui)

        args_no_tui = parser.parse_args(["--no-tui"])
        self.assertFalse(args_no_tui.tui)

    def test_headless_cli_never_imports_textual(self):
        # Run python trithemius.py status --json and check sys.modules
        code = (
            "import sys, subprocess\n"
            "proc = subprocess.run([sys.executable, 'trithemius.py', 'status', '--json'], capture_output=True, text=True)\n"
            "assert proc.returncode == 0\n"
            "check = subprocess.run([sys.executable, '-c', 'import trithemius; import sys; print(\"textual\" in sys.modules)'], capture_output=True, text=True)\n"
            "assert check.stdout.strip() == 'False', f'Textual imported eagerly: {check.stdout}'\n"
            "print('OK')\n"
        )
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=BASE_DIR)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OK", result.stdout)


class TestTextualAppHeadless(unittest.IsolatedAsyncioTestCase):
    """Headless integration tests for TrithemiusApp using Textual testing harness."""

    async def test_app_mount_and_widgets(self):
        from workstation.core.workstation import TerminalWorkstation
        from workstation.ui.tui_dashboard import TrithemiusApp

        ws = TerminalWorkstation()
        app = TrithemiusApp(workstation=ws)

        async with app.run_test(size=(140, 40)) as pilot:
            # Verify primary widgets exist
            header = app.query_one("#header_bar")
            self.assertIsNotNone(header)
            tabbed = app.query_one("#tabbed_content")
            self.assertIsNotNone(tabbed)
            console = app.query_one("#console_log")
            self.assertIsNotNone(console)
            leaderboard = app.query_one("#leaderboard")
            self.assertIsNotNone(leaderboard)

            # Test tab switching bindings
            await pilot.press("f2")
            self.assertEqual(tabbed.active, "tab_solver")
            await pilot.press("f1")
            self.assertEqual(tabbed.active, "tab_console")

            # Test simulated candidate event injection
            cand_event = CandidateEvent(
                candidate_id="test_cand_1",
                method="ATBASH_F29",
                key="ATBASH",
                score=-2.8123,
                threshold=-3.38,
                plaintext_preview="A WARNING TO SOME...",
                z_score=2.50,
            )
            app._apply_telemetry_event(cand_event)
            self.assertEqual(app.current_candidate_count, 1)
            self.assertEqual(leaderboard.get_cell("test_cand_1", "z_score"), "+2.50")

            # Test in-place candidate update event
            update_event = CandidateUpdateEvent(
                candidate_id="test_cand_1",
                z_score=3.14,
                is_significant=True,
            )
            app._apply_telemetry_event(update_event)
            cell_val = leaderboard.get_cell("test_cand_1", "z_score")
            self.assertIn("+3.14", cell_val)
            self.assertIn("SIG", cell_val)

            # Test /boost command execution inside TUI
            self.assertFalse(ws.boost)
            cmd_input = app.query_one("#command_input")
            cmd_input.focus()
            cmd_input.value = "/boost"
            await pilot.press("enter")
            await pilot.pause()
            await app.workers.wait_for_complete()
            self.assertTrue(ws.boost)

            cmd_input.value = "/boost off"
            await pilot.press("enter")
            await pilot.pause()
            await app.workers.wait_for_complete()
            self.assertFalse(ws.boost)


if __name__ == "__main__":
    unittest.main()
