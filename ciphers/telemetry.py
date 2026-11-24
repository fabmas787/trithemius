"""
Lightweight, stdlib-only schema module defining structured events for phase lifecycle,
plain-text mathematical calculation traces, and live candidate streaming.
"""

from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Any, Callable, Dict, Optional, Union


class PhaseStatus(str, Enum):
    STARTED = "STARTED"
    PROGRESS = "PROGRESS"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    EARLY_EXIT = "EARLY_EXIT"
    CANCELLED = "CANCELLED"


@dataclass(slots=True)
class PhaseEvent:
    phase_id: int
    total_phases: int
    name: str
    status: PhaseStatus
    completed: Optional[int] = None
    total: Optional[int] = None
    rate_per_sec: Optional[float] = None
    message: str = ""
    elapsed_sec: float = 0.0


@dataclass(slots=True)
class CalcStepEvent:
    stage: str
    module: str
    formula: str
    inputs: Dict[str, Any]
    result: str
    verdict: str = "INFO"


@dataclass(slots=True)
class CandidateEvent:
    candidate_id: str
    method: str
    key: str
    score: float
    threshold: Optional[float]
    plaintext_preview: str
    z_score: Optional[float] = None
    p_adj: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CandidateUpdateEvent:
    candidate_id: str
    z_score: float
    p_adj: Optional[float] = None
    is_significant: bool = False


TelemetryEvent = Union[PhaseEvent, CalcStepEvent, CandidateEvent, CandidateUpdateEvent]


class TelemetryEmitter:
    """
    Wraps an optional progress_callback with source-level throttling and exception shielding.
    Guarantees that PhaseStatus.PROGRESS events are throttled (default >= 100ms interval),
    while lifecycle events (STARTED, COMPLETED, SKIPPED, EARLY_EXIT, CANCELLED),
    CalcStepEvents, and CandidateEvents are emitted immediately.
    """

    def __init__(
        self,
        callback: Optional[Callable[[TelemetryEvent], None]] = None,
        min_interval_sec: float = 0.10,
    ) -> None:
        self.callback = callback
        self.min_interval_sec = min_interval_sec
        self._last_progress_time: float = 0.0
        self._start_time: float = time.monotonic()

    @property
    def is_active(self) -> bool:
        return self.callback is not None

    def emit(self, event: TelemetryEvent) -> None:
        if self.callback is None:
            return

        now = time.monotonic()
        if isinstance(event, PhaseEvent) and event.status == PhaseStatus.PROGRESS:
            if now - self._last_progress_time < self.min_interval_sec:
                return
            self._last_progress_time = now

        try:
            self.callback(event)
        except Exception:
            # Defensive guard: UI rendering failures must never interrupt crypto calculations
            pass

    def emit_phase(
        self,
        phase_id: int,
        total_phases: int,
        name: str,
        status: PhaseStatus,
        completed: Optional[int] = None,
        total: Optional[int] = None,
        rate_per_sec: Optional[float] = None,
        message: str = "",
    ) -> None:
        if self.callback is None:
            return
        elapsed = time.monotonic() - self._start_time
        self.emit(
            PhaseEvent(
                phase_id=phase_id,
                total_phases=total_phases,
                name=name,
                status=status,
                completed=completed,
                total=total,
                rate_per_sec=rate_per_sec,
                message=message,
                elapsed_sec=round(elapsed, 2),
            )
        )

    def emit_calc(
        self,
        stage: str,
        module: str,
        formula: str,
        inputs: Dict[str, Any],
        result: str,
        verdict: str = "INFO",
    ) -> None:
        if self.callback is None:
            return
        self.emit(
            CalcStepEvent(
                stage=stage,
                module=module,
                formula=formula,
                inputs=inputs,
                result=result,
                verdict=verdict,
            )
        )

    def emit_candidate(
        self,
        candidate_id: str,
        method: str,
        key: str,
        score: float,
        threshold: Optional[float],
        plaintext_preview: str,
        z_score: Optional[float] = None,
        p_adj: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if self.callback is None:
            return
        self.emit(
            CandidateEvent(
                candidate_id=candidate_id,
                method=method,
                key=key,
                score=score,
                threshold=threshold,
                plaintext_preview=plaintext_preview,
                z_score=z_score,
                p_adj=p_adj,
                metadata=metadata or {},
            )
        )

    def emit_candidate_update(
        self,
        candidate_id: str,
        z_score: float,
        p_adj: Optional[float] = None,
        is_significant: bool = False,
    ) -> None:
        if self.callback is None:
            return
        self.emit(
            CandidateUpdateEvent(
                candidate_id=candidate_id,
                z_score=z_score,
                p_adj=p_adj,
                is_significant=is_significant,
            )
        )
