"""
Trithemius Textual TUI Dashboard.
Responsive, event-driven interactive dashboard powered by Textual.
Provides a 3-pane split interface:
- Top HeaderBar with asynchronous telemetry hydration
- Center Workspace with TabbedContent (Console & Assistant, Solver & Live Calculation Trace)
- Bottom CommandBar with auto-completion, status badge, and history
"""

import os
import shlex
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.events import Resize
from textual.suggester import Suggester
from textual.widgets import (
    DataTable,
    Footer,
    Input,
    Label,
    ProgressBar,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from ciphers.telemetry import (
    CalcStepEvent,
    CandidateEvent,
    CandidateUpdateEvent,
    PhaseEvent,
    PhaseStatus,
    TelemetryEvent,
)


class CommandSuggester(Suggester):
    """Provides inline auto-completion for Trithemius slash commands."""

    COMMANDS = [
        "/crack",
        "/running-key-scan",
        "/running-key",
        "/gematria",
        "/atbash",
        "/vigenere",
        "/totient-stream",
        "/solve",
        "/triage",
        "/period",
        "/crib",
        "/opsec",
        "/layout",
        "/lexicon",
        "/ledger",
        "/organize",
        "/ingest",
        "/ask",
        "/web",
        "/page",
        "/boost",
        "/think",
        "/provider",
        "/model",
        "/host",
        "/profile",
        "/key",
        "/cache",
        "/status",
        "/bench",
        "/hardware",
        "/explain",
        "/trace",
        "/help",
        "/clear",
        "/cancel",
        "/exit",
    ]

    async def get_suggestion(self, value: str) -> Optional[str]:
        val = value.strip().lower()
        if not val or not val.startswith("/"):
            return None
        for cmd in self.COMMANDS:
            if cmd.startswith(val) and cmd != val:
                return cmd
        return None


class HeaderBar(Static):
    """Top status bar displaying workstation telemetry with non-blocking hydration."""

    def compose(self) -> ComposeResult:
        yield Label("TRITHEMIUS — LIBER PRIMUS CRYPTANALYTIC WORKSTATION", id="header_text")

    def update_status(
        self,
        model: str,
        provider: str,
        boost: bool,
        files: int,
        chunks: int,
        hardware: str,
    ) -> None:
        boost_tag = "[bold green]ON[/]" if boost else "[dim]OFF[/]"
        text = (
            f"[bold cyan]TRITHEMIUS[/] | Model: [bold white]{model}[/] ({provider}) | "
            f"Boost: {boost_tag} | Corpus: {files} files | Chunks: {chunks} | Accel: {hardware}"
        )
        self.query_one("#header_text", Label).update(text)


class TrithemiusApp(App):
    """Main Textual application for the Trithemius Cryptanalytic Workstation."""

    CSS_PATH = "tui_styles.tcss"

    BINDINGS = [
        Binding("ctrl+c", "cancel_job", "Cancel Job", priority=True),
        Binding("f1", "show_console", "Console"),
        Binding("f2", "show_solver", "Solver"),
        Binding("ctrl+l", "clear_tab", "Clear"),
        Binding("ctrl+q", "quit", "Quit"),
    ]

    def __init__(self, workstation: Any, **kwargs):
        super().__init__(**kwargs)
        self.ws = workstation
        self.cancel_event = threading.Event()
        self.is_running_job = False
        self.command_history: List[str] = []
        self.history_index: int = -1
        self.active_candidates_map: Dict[str, int] = {}
        self.current_candidate_count = 0

    def compose(self) -> ComposeResult:
        yield HeaderBar(id="header_bar")

        with TabbedContent(id="tabbed_content", initial="tab_console"):
            with TabPane("Console & Assistant (F1)", id="tab_console"):
                yield RichLog(id="console_log", highlight=True, markup=True, wrap=True)

            with TabPane("Solver & Calculation Trace (F2)", id="tab_solver"):
                with Container(id="solver_container"):
                    with Vertical(id="telemetry_pane"):
                        yield Label("[bold cyan]Active Phase & Calculation Trace[/]", classes="section_title")
                        yield Label("Phase: [dim]IDLE[/]", id="phase_label")
                        yield ProgressBar(total=100, show_eta=True, id="phase_progress")
                        yield RichLog(id="calc_trace", highlight=True, markup=True, wrap=True)

                    with Vertical(id="leaderboard_pane"):
                        yield Label("[bold cyan]Live Decryption Leaderboard[/]", classes="section_title")
                        yield DataTable(id="leaderboard", zebra_stripes=True)

        with Horizontal(id="command_container"):
            yield Label("IDLE", id="status_badge")
            yield Input(
                placeholder="Enter command (e.g. /crack 56, /running-key-scan 56, /help)...",
                suggester=CommandSuggester(),
                id="command_input",
            )

        yield Footer()

    def on_mount(self) -> None:
        """Initialize widgets, responsive layout, and start background telemetry hydration."""
        leaderboard = self.query_one("#leaderboard", DataTable)
        leaderboard.add_column("Rank", key="rank")
        leaderboard.add_column("Score", key="score")
        leaderboard.add_column("Method", key="method")
        leaderboard.add_column("Key", key="key")
        leaderboard.add_column("Preview", key="preview")
        leaderboard.add_column("Z-Score", key="z_score")
        leaderboard.cursor_type = "row"

        console = self.query_one("#console_log", RichLog)
        console.write("[bold cyan]Trithemius Terminal Workstation [Rich TUI][/]")
        console.write("[dim]Type '/help' for command reference or enter any query to ask the RAG assistant.[/]\n")

        # Asynchronously hydrate hardware & database metrics without blocking startup
        self.hydrate_header_telemetry()

    def on_resize(self, event: Resize) -> None:
        """Dynamically adapt layout for narrow screens (<120 cols) or short terminals (<24 rows)."""
        solver_container = self.query_one("#solver_container", Container)
        if event.size.width < 120:
            solver_container.add_class("vertical_stack")
        else:
            solver_container.remove_class("vertical_stack")

        if event.size.height < 24:
            self.screen.add_class("compact_height")
        else:
            self.screen.remove_class("compact_height")

    @work(thread=True)
    def hydrate_header_telemetry(self) -> None:
        """Non-blocking background probe for corpus, vectordb, and hardware."""
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        c_dir = os.path.join(base_dir, "corpus")
        files_count = len(os.listdir(c_dir)) if os.path.exists(c_dir) else 0

        chunks_count = 0
        try:
            coll = self.ws._ensure_collection()
            if coll:
                chunks_count = coll.count()
        except Exception:
            pass

        hardware_tags = []
        try:
            from ciphers.metal_accel import is_metal_available
            from ciphers.ane_engine import is_ane_available
            if is_metal_available():
                hardware_tags.append("[green]Metal GPU[/]")
            if is_ane_available():
                hardware_tags.append("[green]ANE[/]")
        except Exception:
            pass
        hw_str = ", ".join(hardware_tags) if hardware_tags else "[dim]CPU Only[/]"

        self.call_from_thread(
            self.query_one("#header_bar", HeaderBar).update_status,
            model=str(self.ws.active_model),
            provider=str(self.ws.provider),
            boost=bool(self.ws.boost),
            files=files_count,
            chunks=chunks_count,
            hardware=hw_str,
        )

    # -------------------------------------------------------------------------
    # Actions & Keybindings
    # -------------------------------------------------------------------------

    def action_cancel_job(self) -> None:
        """Cooperatively cancels any running background cryptanalytic worker."""
        if self.is_running_job:
            self.cancel_event.set()
            badge = self.query_one("#status_badge", Label)
            badge.update("CANCELLING...")
            badge.remove_class("running")
            badge.add_class("cancelling")
            trace = self.query_one("#calc_trace", RichLog)
            trace.write("[bold yellow][!] Cancellation requested. Waiting for worker to stop...[/]")

    def action_show_console(self) -> None:
        self.query_one("#tabbed_content", TabbedContent).active = "tab_console"

    def action_show_solver(self) -> None:
        self.query_one("#tabbed_content", TabbedContent).active = "tab_solver"

    def action_clear_tab(self) -> None:
        active_tab = self.query_one("#tabbed_content", TabbedContent).active
        if active_tab == "tab_console":
            self.query_one("#console_log", RichLog).clear()
        elif active_tab == "tab_solver":
            self.query_one("#calc_trace", RichLog).clear()
            self.query_one("#leaderboard", DataTable).clear()
            self.active_candidates_map.clear()
            self.current_candidate_count = 0

    # -------------------------------------------------------------------------
    # Telemetry Event Handlers (Called safely via call_from_thread)
    # -------------------------------------------------------------------------

    def _handle_telemetry(self, event: TelemetryEvent) -> None:
        """Thread-safe telemetry bridge routing events from cipher solvers to UI."""
        self.call_from_thread(self._apply_telemetry_event, event)

    def _apply_telemetry_event(self, event: TelemetryEvent) -> None:
        if isinstance(event, PhaseEvent):
            phase_label = self.query_one("#phase_label", Label)
            progress_bar = self.query_one("#phase_progress", ProgressBar)
            trace = self.query_one("#calc_trace", RichLog)

            status_color = "cyan"
            if event.status == PhaseStatus.COMPLETED:
                status_color = "green"
            elif event.status == PhaseStatus.CANCELLED:
                status_color = "red"
            elif event.status in (PhaseStatus.SKIPPED, PhaseStatus.EARLY_EXIT):
                status_color = "yellow"

            badge_text = f"RUNNING [{event.phase_id}/{event.total_phases}]"
            self.query_one("#status_badge", Label).update(badge_text)

            phase_label.update(
                f"Phase {event.phase_id}/{event.total_phases}: [{status_color}]{event.name}[/] "
                f"([dim]{event.status.value}[/])"
            )

            if event.total and event.completed is not None:
                progress_bar.update(total=event.total, progress=event.completed)
            elif event.status == PhaseStatus.COMPLETED:
                progress_bar.update(total=100, progress=100)

            if event.message:
                trace.write(f"[{status_color}]• Phase {event.phase_id}: {event.message} ({event.elapsed_sec:.1f}s)[/]")

        elif isinstance(event, CalcStepEvent):
            trace = self.query_one("#calc_trace", RichLog)
            v_color = "green" if event.verdict == "PASS" else ("yellow" if event.verdict == "INFO" else "red")
            trace.write(
                f"[bold cyan]{event.stage}[/] [dim]({event.module})[/]:\n"
                f"  Formula: [white]{event.formula}[/]\n"
                f"  Result:  [bold {v_color}]{event.result}[/] [{event.verdict}]"
            )

        elif isinstance(event, CandidateEvent):
            leaderboard = self.query_one("#leaderboard", DataTable)
            z_str = f"{event.z_score:+.2f}" if event.z_score is not None else "—"
            self.current_candidate_count += 1
            rank = self.current_candidate_count
            row_key = leaderboard.add_row(
                str(rank),
                f"{event.score:+.4f}",
                event.method[:24],
                event.key[:18],
                event.plaintext_preview[:35] + "...",
                z_str,
                key=event.candidate_id,
            )
            self.active_candidates_map[event.candidate_id] = rank

        elif isinstance(event, CandidateUpdateEvent):
            leaderboard = self.query_one("#leaderboard", DataTable)
            if event.candidate_id in self.active_candidates_map:
                sig_tag = " [bold green]SIG[/]" if event.is_significant else " [dim]INSIG[/]"
                z_display = f"{event.z_score:+.2f}{sig_tag}"
                try:
                    leaderboard.update_cell(
                        row_key=event.candidate_id,
                        column_key="z_score",
                        value=z_display,
                    )
                except Exception:
                    pass

    # -------------------------------------------------------------------------
    # Command Dispatch & Worker Thread
    # -------------------------------------------------------------------------

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle command input submission."""
        raw = event.value.strip()
        if not raw:
            return

        self.command_history.append(raw)
        self.history_index = len(self.command_history)
        event.input.value = ""

        if raw.lower() in ("/exit", "/quit", "exit", "quit"):
            self.exit()
            return

        if raw.lower() in ("/clear", "clear"):
            self.action_clear_tab()
            return

        if raw.lower() in ("/cancel", "cancel"):
            self.action_cancel_job()
            return

        if self.is_running_job:
            self.query_one("#console_log", RichLog).write("[!] A command is already executing. Use Ctrl+C or /cancel to abort.")
            return

        self.execute_command_async(raw)

    def execute_command_async(self, command: str) -> None:
        """Launches command in an exclusive background thread worker."""
        self.is_running_job = True
        self.cancel_event.clear()
        badge = self.query_one("#status_badge", Label)
        badge.update("RUNNING")
        badge.remove_class("cancelling")
        badge.add_class("running")
        self.run_worker_thread(command)

    @work(thread=True, exclusive=True)
    def run_worker_thread(self, command: str) -> None:
        """Background worker thread executing cryptanalysis or general commands."""
        try:
            from contextlib import redirect_stderr, redirect_stdout
            from rich.text import Text
            from workstation.ui.repl import dispatch_repl_command

            try:
                parts = shlex.split(command)
            except ValueError:
                parts = command.split()

            cmd_name = parts[0].lower() if parts else ""
            args = parts[1:]
            console = self.query_one("#console_log", RichLog)

            class _ConsoleStream:
                def __init__(self, app: "TrithemiusApp") -> None:
                    self._app = app
                    self._buf = ""

                def write(self, text: str) -> int:
                    self._buf += text
                    while "\n" in self._buf:
                        line, self._buf = self._buf.split("\n", 1)
                        self._app.call_from_thread(console.write, Text(line))
                    return len(text)

                def flush(self) -> None:
                    if self._buf:
                        rem = self._buf
                        self._buf = ""
                        self._app.call_from_thread(console.write, Text(rem))

            stream = _ConsoleStream(self)

            if cmd_name in ("/crack", "/running-key-scan") and args:
                self.call_from_thread(self.action_show_solver)
                self.call_from_thread(self.query_one("#calc_trace", RichLog).clear)
                self.call_from_thread(self.query_one("#leaderboard", DataTable).clear)
                self.active_candidates_map.clear()
                self.current_candidate_count = 0

                with redirect_stdout(stream), redirect_stderr(stream):
                    res = dispatch_repl_command(
                        self.ws,
                        command,
                        progress_callback=self._handle_telemetry,
                        cancel_event=self.cancel_event,
                    )
                stream.flush()
                if cmd_name == "/crack":
                    self.call_from_thread(self._display_crack_summary, res)
                else:
                    self.call_from_thread(self._display_running_key_summary, res)
            else:
                self.call_from_thread(self.action_show_console)
                if not cmd_name.startswith("/"):
                    self.call_from_thread(self._display_query_start, command)
                with redirect_stdout(stream), redirect_stderr(stream):
                    dispatch_repl_command(self.ws, command)
                stream.flush()
                self.hydrate_header_telemetry()

        except Exception as e:
            self.call_from_thread(self.query_one("#console_log", RichLog).write, f"[bold red]Error:[/] {e}")
        finally:
            self.is_running_job = False
            self.call_from_thread(self._finalize_job)

    def _finalize_job(self) -> None:
        badge = self.query_one("#status_badge", Label)
        badge.update("IDLE")
        badge.remove_class("running")
        badge.remove_class("cancelling")

    def _display_crack_summary(self, res: Any) -> None:
        trace = self.query_one("#calc_trace", RichLog)
        winner = getattr(res, "winner", None) or (res.get("winner") if isinstance(res, dict) else None)
        top_candidates = getattr(res, "top_candidates", []) or (res.get("top_candidates") if isinstance(res, dict) else [])
        if top_candidates:
            leaderboard = self.query_one("#leaderboard", DataTable)
            leaderboard.clear()
            self.active_candidates_map.clear()
            self.current_candidate_count = 0
            for i, cand in enumerate(top_candidates, 1):
                c_id = cand.get("candidate_id") or f"top_{i}"
                z_val = cand.get("z_score")
                if z_val is None and "significance" in cand:
                    z_val = cand["significance"].get("z_score")
                sig = cand.get("significance", {})
                is_sig = sig.get("is_statistically_significant")
                if is_sig is not None:
                    sig_tag = " [bold green]SIG[/]" if is_sig else " [dim]INSIG[/]"
                else:
                    sig_tag = ""
                z_str = f"{z_val:+.2f}{sig_tag}" if z_val is not None else "—"
                leaderboard.add_row(
                    str(i),
                    f"{cand.get('score', 0.0):+.4f}",
                    cand.get("method", "UNKNOWN")[:24],
                    str(cand.get("key_latin") or cand.get("key_runes") or "")[:18],
                    cand.get("plaintext_latin", "")[:35] + "...",
                    z_str,
                    key=c_id,
                )
                self.active_candidates_map[c_id] = i

        if winner:
            trace.write("\n[bold green]═══ TOP CRYPTANALYTIC CANDIDATE ═══[/]")
            trace.write(f"Method: [bold cyan]{winner.get('method')}[/] | Key: '{winner.get('key_latin')}'")
            trace.write(f"Score:  [bold white]{winner.get('score'):+.4f}[/]")
            latin_prev = winner.get("plaintext_latin", "").strip()[:140]
            trace.write(f"Latin:  [italic]{latin_prev}...[/]")
        else:
            trace.write("\n[yellow]Cascade solver completed with no dominant candidates.[/]")

    def _display_running_key_summary(self, res: Any) -> None:
        trace = self.query_one("#calc_trace", RichLog)
        cands = getattr(res, "candidates", []) or (res.get("candidates") if isinstance(res, dict) else [])
        if cands:
            leaderboard = self.query_one("#leaderboard", DataTable)
            leaderboard.clear()
            self.active_candidates_map.clear()
            self.current_candidate_count = 0
            for i, cand in enumerate(cands, 1):
                c_id = f"rk_top_{i}"
                z_val = cand.get("z_score")
                z_str = f"{z_val:+.2f}" if z_val is not None else "—"
                leaderboard.add_row(
                    str(i),
                    f"{cand.get('score', 0.0):+.4f}",
                    cand.get("source_file", "RUNNING_KEY")[:24],
                    f"Off {cand.get('offset', 0)} ({cand.get('mode', 'sub')})"[:18],
                    cand.get("plaintext", "")[:35] + "...",
                    z_str,
                    key=c_id,
                )
                self.active_candidates_map[c_id] = i
        trace.write(f"\n[bold green]═══ RUNNING KEY SCAN COMPLETED ({len(cands)} Candidates) ═══[/]")

    def _display_query_start(self, query: str) -> None:
        console = self.query_one("#console_log", RichLog)
        console.write(f"[bold cyan]User:[/] {query}")
        console.write("[dim]Consulting knowledge base and inferring...[/]")
