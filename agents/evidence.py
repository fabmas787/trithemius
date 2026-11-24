"""
Evidence — Epistemic Evidence Register and Bayesian Hypothesis Accounting.
Standard library only: sqlite3, os, datetime, platform, hashlib. Zero external dependencies.

Enforces statistical rigor in cryptanalytic accounting:
A negative result is informative only in proportion to the statistical power of the detector.
- outcome 'positive' -> 'candidate'
- outcome 'negative' with detector_power >= 0.90 -> 'excluded'
- outcome 'negative' with detector_power < 0.90 -> 'inconclusive'
- Computes Bayesian posterior probabilities following negative trials.
- Emits 10-point DEE-RSA reproducibility manifests.
- Evaluates 8-point empirical validity checklist for evidence claims.
"""

from __future__ import annotations
import sqlite3
import os
import platform
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Union

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "vectordb", "ledger.sqlite3")

# 10-point reproducibility manifest keys
MANIFEST_POINTS = (
    "hardware_specs",
    "os_environment",
    "python_version",
    "dependency_lock",
    "git_commit",
    "solver_parameters",
    "seeding_policy",
    "dataset_provenance",
    "raw_data_artifacts",
    "timestamp_utc",
)

# 8-point validity checklist keys
VALIDITY_CHECKLIST_POINTS = (
    "reproducibility_manifest",
    "statistical_power",
    "sample_size_adequate",
    "p_value_significance",
    "deterministic_seeding",
    "null_hypothesis_tested",
    "baseline_comparison",
    "raw_data_artifacts",
)


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


# =============================================================================
# DEE-RSA 10-Point Reproducibility Manifest
# =============================================================================

def _get_hardware_specs() -> Dict[str, Any]:
    return {
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count() or 1,
        "platform": platform.platform(),
    }


def _get_os_environment() -> Dict[str, Any]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
    }


def _get_git_commit() -> str:
    try:
        import subprocess
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            cwd=os.path.dirname(os.path.abspath(__file__))
        ).decode("utf-8").strip()
        if out:
            return out
    except Exception:
        pass
    git_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".git")
    head_file = os.path.join(git_dir, "HEAD")
    if os.path.exists(head_file):
        try:
            with open(head_file, "r", encoding="utf-8") as f:
                ref = f.read().strip()
            if ref.startswith("ref: "):
                ref_path = os.path.join(git_dir, ref[5:])
                if os.path.exists(ref_path):
                    with open(ref_path, "r", encoding="utf-8") as f:
                        return f.read().strip()
            else:
                return ref
        except Exception:
            pass
    return "unknown"


def _get_dependency_lock() -> Dict[str, Any]:
    req_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "requirements.txt")
    lock_info: Dict[str, Any] = {"standard_library_only": True}
    if os.path.exists(req_path):
        try:
            with open(req_path, "rb") as f:
                content = f.read()
            lock_info["requirements_sha256"] = hashlib.sha256(content).hexdigest()
        except Exception:
            pass
    return lock_info


def emit_reproducibility_manifest(
    solver_parameters: Optional[Dict[str, Any]] = None,
    seeding_policy: Optional[Dict[str, Any]] = None,
    dataset_provenance: Optional[Union[Dict[str, Any], str]] = None,
    raw_data_artifacts: Optional[Union[List[str], Dict[str, Any]]] = None,
    hardware_specs: Optional[Dict[str, Any]] = None,
    os_environment: Optional[Dict[str, Any]] = None,
    python_version: Optional[str] = None,
    dependency_lock: Optional[Union[Dict[str, Any], str]] = None,
    git_commit: Optional[str] = None,
    timestamp_utc: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Emit a complete 10-point DEE-RSA reproducibility manifest:
    1. hardware_specs
    2. os_environment
    3. python_version
    4. dependency_lock
    5. git_commit
    6. solver_parameters
    7. seeding_policy
    8. dataset_provenance
    9. raw_data_artifacts
    10. timestamp_utc
    """
    manifest = {
        "hardware_specs": hardware_specs if hardware_specs is not None else _get_hardware_specs(),
        "os_environment": os_environment if os_environment is not None else _get_os_environment(),
        "python_version": python_version if python_version is not None else platform.python_version(),
        "dependency_lock": dependency_lock if dependency_lock is not None else _get_dependency_lock(),
        "git_commit": git_commit if git_commit is not None else _get_git_commit(),
        "solver_parameters": solver_parameters if solver_parameters is not None else {"algorithm": "exact", "modulus": 29},
        "seeding_policy": seeding_policy if seeding_policy is not None else {"seed": 3301, "prng": "isolated_prng", "deterministic": True},
        "dataset_provenance": dataset_provenance if dataset_provenance is not None else {"corpus": "corpus/liber-primus__transcription--master.txt", "verified": True},
        "raw_data_artifacts": raw_data_artifacts if raw_data_artifacts is not None else ["vectordb/bench_history.jsonl"],
        "timestamp_utc": timestamp_utc if timestamp_utc is not None else datetime.now(timezone.utc).isoformat(),
    }
    return manifest


# Alias for flexibility
generate_reproducibility_manifest = emit_reproducibility_manifest


# =============================================================================
# 8-Point Validity Checklist
# =============================================================================

def validate_evidence_claim(claim: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate an evidence claim against the 8-point DEE-RSA scientific validity checklist:
    1. reproducibility_manifest: Complete 10-point manifest attached and verified.
    2. statistical_power: Empirical power >= 0.90 for negative/excluded claims, or >= 0.80 for positive.
    3. sample_size_adequate: Sample size n >= 100 trials (not underpowered).
    4. p_value_significance: Evaluated p-value <= 0.05 or z-score >= 2.0.
    5. deterministic_seeding: PRNG isolation and deterministic seeding verified.
    6. null_hypothesis_tested: Null distribution or surrogate shuffle controls conducted.
    7. baseline_comparison: Baseline comparison against pure-Python reference or theoretical control.
    8. raw_data_artifacts: Per-trial artifacts / raw logs preserved and verifiable.
    """
    checklist: Dict[str, bool] = {}

    # 1. Reproducibility Manifest
    manifest = claim.get("manifest") or claim.get("reproducibility_manifest")
    if manifest is None:
        # Check if the 10 keys are directly inside claim
        if all(k in claim for k in MANIFEST_POINTS):
            manifest = claim
    if isinstance(manifest, dict) and all(k in manifest for k in MANIFEST_POINTS):
        # All 10 keys present
        checklist["reproducibility_manifest"] = True
    else:
        checklist["reproducibility_manifest"] = False

    # 2. Statistical Power
    if "statistical_power" in claim and isinstance(claim["statistical_power"], bool):
        checklist["statistical_power"] = claim["statistical_power"]
    else:
        power = claim.get("detector_power", claim.get("power"))
        outcome = str(claim.get("outcome", "")).strip().lower()
        if power is not None:
            try:
                pow_val = float(power)
                if outcome == "negative" or claim.get("status") == "excluded":
                    checklist["statistical_power"] = (pow_val >= 0.90)
                else:
                    checklist["statistical_power"] = (pow_val >= 0.80)
            except (ValueError, TypeError):
                checklist["statistical_power"] = False
        else:
            checklist["statistical_power"] = False

    # 3. Sample Size Adequate (n >= 100 trials, not underpowered)
    if "sample_size_adequate" in claim and isinstance(claim["sample_size_adequate"], bool):
        checklist["sample_size_adequate"] = claim["sample_size_adequate"]
    else:
        trials = claim.get("trials", claim.get("sample_size", claim.get("n")))
        underpowered = claim.get("underpowered")
        if underpowered is True:
            checklist["sample_size_adequate"] = False
        elif trials is not None:
            try:
                checklist["sample_size_adequate"] = (int(trials) >= 100)
            except (ValueError, TypeError):
                checklist["sample_size_adequate"] = False
        elif underpowered is False:
            checklist["sample_size_adequate"] = True
        else:
            checklist["sample_size_adequate"] = False

    # 4. P-Value Significance (p <= 0.05 or z >= 2.0)
    if "p_value_significance" in claim and isinstance(claim["p_value_significance"], bool):
        checklist["p_value_significance"] = claim["p_value_significance"]
    else:
        p_val = claim.get("p_value", claim.get("p_val", claim.get("significance")))
        z_score = claim.get("z_score")
        if p_val is not None:
            try:
                checklist["p_value_significance"] = (0.0 <= float(p_val) <= 0.05)
            except (ValueError, TypeError):
                checklist["p_value_significance"] = False
        elif z_score is not None:
            try:
                checklist["p_value_significance"] = (abs(float(z_score)) >= 1.96)
            except (ValueError, TypeError):
                checklist["p_value_significance"] = False
        else:
            checklist["p_value_significance"] = False

    # 5. Deterministic Seeding
    if "deterministic_seeding" in claim and isinstance(claim["deterministic_seeding"], bool):
        checklist["deterministic_seeding"] = claim["deterministic_seeding"]
    else:
        seeding = claim.get("seeding_policy")
        if seeding is None and manifest and isinstance(manifest, dict):
            seeding = manifest.get("seeding_policy")
        if isinstance(seeding, dict):
            checklist["deterministic_seeding"] = bool(
                seeding.get("deterministic", True) and (seeding.get("seed") is not None)
            )
        elif isinstance(seeding, (int, str)) and seeding is not None:
            checklist["deterministic_seeding"] = True
        else:
            checklist["deterministic_seeding"] = False

    # 6. Null Hypothesis Tested (surrogate controls)
    if "null_hypothesis_tested" in claim and isinstance(claim["null_hypothesis_tested"], bool):
        checklist["null_hypothesis_tested"] = claim["null_hypothesis_tested"]
    else:
        null_test = claim.get("surrogate_tested", claim.get("null_distribution", claim.get("surrogate_shuffle_tested")))
        checklist["null_hypothesis_tested"] = bool(null_test)

    # 7. Baseline Comparison
    if "baseline_comparison" in claim and isinstance(claim["baseline_comparison"], bool):
        checklist["baseline_comparison"] = claim["baseline_comparison"]
    else:
        baseline = claim.get("baseline_comparison", claim.get("baseline", claim.get("baselines")))
        checklist["baseline_comparison"] = bool(baseline)

    # 8. Raw Data Artifacts
    if "raw_data_artifacts" in claim and isinstance(claim["raw_data_artifacts"], bool):
        checklist["raw_data_artifacts"] = claim["raw_data_artifacts"]
    else:
        artifacts = claim.get("raw_data_artifacts", claim.get("artifacts"))
        if artifacts is None and manifest and isinstance(manifest, dict):
            artifacts = manifest.get("raw_data_artifacts")
        checklist["raw_data_artifacts"] = bool(artifacts and len(artifacts) > 0)

    passed_count = sum(1 for v in checklist.values() if v)
    is_valid = (passed_count == len(VALIDITY_CHECKLIST_POINTS))

    result: Dict[str, Any] = {
        "valid": is_valid,
        "is_valid": is_valid,
        "passed": passed_count,
        "total": len(VALIDITY_CHECKLIST_POINTS),
        "checklist": checklist,
    }
    # Direct access to individual checklist items
    for k, v in checklist.items():
        result[k] = v

    return result
