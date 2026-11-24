"""
Evidence — Epistemic Evidence Register and Bayesian Hypothesis Accounting.
Standard library only: sqlite3, os, datetime. Zero external dependencies.

Enforces statistical rigor in cryptanalytic accounting:
A negative result is informative only in proportion to the statistical power of the detector.
- outcome 'positive' -> 'candidate'
- outcome 'negative' with detector_power >= 0.90 -> 'excluded'
- outcome 'negative' with detector_power < 0.90 -> 'inconclusive'
- Computes Bayesian posterior probabilities following negative trials.
"""

from __future__ import annotations
import sqlite3
import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "vectordb", "ledger.sqlite3")


def evidence_status(outcome: str, detector_power: float, threshold: float = 0.9) -> str:
    """
    Classify hypothesis trial outcome:
    outcome in {'positive', 'negative'}.
    detector_power: empirical P(detect | planted cipher of this family and length).
    Returns 'candidate', 'excluded', or 'inconclusive'.
    """
    clean_outcome = outcome.strip().lower()
    if clean_outcome == "positive":
        return "candidate"
    if detector_power >= threshold:
        return "excluded"
    return "inconclusive"


def posterior_after_negative(prior: float, detector_power: float) -> float:
    """
    Bayesian update of hypothesis probability P(H) following a negative test result:
    P(neg | H) = 1 - power, P(neg | not H) = 1.
    Posterior odds = prior_odds * (1 - detector_power).
    """
    if prior <= 0.0:
        return 0.0
    if prior >= 1.0:
        return 1.0
    if detector_power >= 1.0:
        return 0.0

    prior_odds = prior / (1.0 - prior)
    post_odds = prior_odds * (1.0 - detector_power)
    return post_odds / (1.0 + post_odds)


def init_evidence_schema(db_path: str = DB_PATH) -> None:
    """Ensure detector_power table exists in SQLite database."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS detector_power (
            detector_id TEXT NOT NULL,
            family      TEXT NOT NULL,
            n_symbols   INTEGER NOT NULL,
            power       REAL NOT NULL,
            trials      INTEGER NOT NULL,
            measured_at TEXT NOT NULL,
            PRIMARY KEY (detector_id, family, n_symbols)
        );
    """)
    conn.commit()
    conn.close()


def record_detector_power(
    detector_id: str,
    family: str,
    n_symbols: int,
    power: float,
    trials: int,
    db_path: str = DB_PATH
) -> None:
    """Persist empirical detector power measurement to the ledger."""
    init_evidence_schema(db_path)
    conn = sqlite3.connect(db_path)
    ts = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        INSERT OR REPLACE INTO detector_power (
            detector_id, family, n_symbols, power, trials, measured_at
        ) VALUES (?, ?, ?, ?, ?, ?);
    """, (detector_id, family, n_symbols, float(power), int(trials), ts))
    conn.commit()
    conn.close()


def get_detector_power(
    detector_id: str,
    family: str,
    n_symbols: int,
    db_path: str = DB_PATH
) -> Optional[float]:
    """Retrieve recorded empirical power for a given detector, family, and text length."""
    if not os.path.exists(db_path):
        return None
    conn = sqlite3.connect(db_path)
    cur = conn.execute("""
        SELECT power FROM detector_power
        WHERE detector_id = ? AND family = ? AND n_symbols = ?
    """, (detector_id, family, n_symbols))
    row = cur.fetchone()
    conn.close()
    return float(row[0]) if row else None
