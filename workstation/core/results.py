"""
Typed result domain objects for Trithemius cryptanalytic operations.
Provides 100% dictionary backward compatibility alongside typed attribute access.
"""

from typing import Any, Dict, List, Optional, Set, Union


class TypedResult(dict):
    """
    Base domain result object providing dual dictionary and attribute access.
    Guarantees seamless zero-regression interoperability with legacy dict consumers.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value

    def __delattr__(self, name: str) -> None:
        try:
            del self[name]
        except KeyError:
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

    def to_dict(self) -> Dict[str, Any]:
        """Return a clean standard Python dictionary representation."""
        return dict(self)


class GematriaResult(TypedResult):
    """Result of Gematria Primus prime sum, totient, and factor evaluation."""
    input: str
    text: str
    has_runes: bool
    runes: str
    decoded_latin: str
    direct_latin: str
    prime_sum: int
    totient: int
    is_prime: bool
    prime_factors: List[int]
    word_sums: List[Any]
    atbash_runes: str
    atbash_latin: str


class AtbashResult(TypedResult):
    """Result of Modulo-29 Atbash and Caesar-shifted reflection decryption."""
    input: str
    shift: int
    method: str
    result_runes: str
    decoded_latin: str
    ioc: float
    metrics: Dict[str, Any]


class VigenereResult(TypedResult):
    """Result of Modulo-29 / Modulo-26 Vigenère encryption or decryption."""
    mode: str
    alphabet: str
    input: str
    key: str
    f_skip: bool
    skip_indices: Optional[List[int]]
    result: str
    decoded_latin: str
    ioc: float
    metrics: Dict[str, Any]


class TotientStreamResult(TypedResult):
    """Result of Liber Primus Prime Totient Stream Cipher operation."""
    mode: str
    input: str
    offset: int
    f_skip: bool
    skip_indices: Optional[List[int]]
    result_runes: str
    decoded_latin: str
    ioc: float
    metrics: Dict[str, Any]


class SolveResult(TypedResult):
    """Result of Liber Primus canonical page verification and solution testing."""
    id: Optional[str]
    title: Optional[str]
    verified: Optional[bool]
    method: Optional[str]
    key: Optional[str]
    total: Optional[int]
    passed: Optional[int]
    failed: Optional[int]
    all_passed: Optional[bool]
    results: Optional[Dict[str, Any]]


class CrackResult(TypedResult):
    """Result of GF(29) cryptanalytic cascade solver."""
    target_input: str
    candidates: List[Dict[str, Any]]
    best_candidate: Optional[Dict[str, Any]]


class HardwareResult(TypedResult):
    """Result of system hardware telemetry inspection."""
    metal_gpu: Optional[Dict[str, Any]]
    neural_engine: Optional[Dict[str, Any]]
    benchmark: Optional[Dict[str, Any]]
    error: Optional[str]


class LedgerResult(TypedResult):
    """Result of ledger trial attempts query."""
    page: Optional[str]
    stats: Optional[Dict[str, Any]]
    similar_hypotheses: Optional[List[Dict[str, Any]]]
    error: Optional[str]


class TriageResult(TypedResult):
    """Result of statistical triage and cipher classification."""
    target_input: str
    classification: Optional[str]
    ioc: Optional[float]
    entropy: Optional[float]
    recommendations: Optional[List[str]]


class PeriodResult(TypedResult):
    """Result of key length consensus and periodogram comb scan."""
    target_input: str
    periods: List[Any]
    top_period: int


class CribResult(TypedResult):
    """Result of sliding crib search and implied key recovery."""
    target_input: str
    crib: str
    hits: List[Dict[str, Any]]
    total_tested: int


class RunningKeyResult(TypedResult):
    """Result of running key decryption against reference text."""
    target_page: str
    source_file: str
    source_file_basename: str
    mode: str
    f_skip: bool
    offset: int
    rune_count: int
    key_stream_len: int
    score: float
    passed: bool
    runes: str
    plain_latin: str


class RunningKeyScanResult(TypedResult):
    """Result of automated running key directory scan."""
    page: str
    ref_dir: str
    rune_count: int
    step: int
    top_k: int
    candidates: List[Dict[str, Any]]


class LexiconResult(TypedResult):
    """Result of philosophical lexicon generation or vocabulary lookup."""
    action: str
    limit: int
    items: Optional[List[str]]
    phrases: Optional[List[str]]
    words: Optional[List[str]]
    total: Optional[int]


class OpsecResult(TypedResult):
    """Result of PGP verification and file header inspection."""
    target: str
    is_file: bool
    file_info: Optional[Dict[str, Any]]
    pgp: Optional[Dict[str, Any]]
    features: Optional[Dict[str, Any]]
    error: Optional[str]


class StatusResult(TypedResult):
    """Result of workstation system telemetry and health probe."""
    provider_desc: str
    active_model: str
    model_key: str
    profile_desc: str
    think: bool
    boost: bool
    context_window: int
    keys_summary: str
    corpus_files: int
    chunk_count: int
    pgp_key_id: str
    pgp_fingerprint: str
    probe_results: Optional[List[Dict[str, Any]]]
