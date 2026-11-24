"""
Layout — Layout Side-Channel Mutual Information Analysis for Liber Primus.
Models Liber Primus pages as two multiplexed streams:
- Symbol Stream: rune indices mod 29 (GF(29))
- Layout Stream: separator types (᛫ ᛬ ᛭), word lengths, line lengths, Fehu interrupt positions

Estimates mutual information I(layout ; keystream shift) with Miller-Madow bias
correction and Besag-Clifford sequential Monte Carlo permutation null testing.
Logs calibrated outcomes under family 'layout-carrier' to agents/ledger.py.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Union
import math
import os
import re
import sys
import random
from collections import Counter

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(CURRENT_DIR)
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ciphers.agrippa import INDEX_BY_RUNE, RUNE_BY_INDEX, latin_to_rune
from ciphers.interrupter import canonical_key_shifts
from ciphers.taxonomy import sequential_mc_pvalue

try:
    from agents.ledger import log_canonical_attempt, log_attempt, count_attempts
except ImportError:
    log_canonical_attempt = None
    log_attempt = None
    count_attempts = None

try:
    from scripts.router import get_page_corpus_path
except ImportError:
    get_page_corpus_path = None

RUNIC_WORD_SEP = "᛫"    # U+16EB
RUNIC_CLAUSE_SEP = "᛬"  # U+16EC
RUNIC_CROSS_SEP = "᛭"   # U+16ED

SEPARATOR_MAP = {
    "᛫": 1,
    "-": 1,
    " ": 1,
    "\t": 1,
    "᛬": 2,
    ".": 2,
    ":": 2,
    "᛭": 3,
    "§": 3,
    "/": 3,
}


@dataclass
class LayoutStream:
    """
    Representation of multiplexed symbol and layout streams extracted from a transcript.
    """
    page_id: str
    symbols: List[int]
    runes: List[str]
    word_lengths: List[int]
    line_lengths: List[int]
    separators: List[str]
    separator_codes: List[int]
    pos_in_words: List[int]
    pos_in_lines: List[int]
    fehu_flags: List[int]
    fehu_distances: List[int]
    words: List[Dict[str, Any]] = field(default_factory=list)
    lines: List[Dict[str, Any]] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.symbols)

    def get_feature(self, feature_name: str) -> List[Any]:
        """Retrieve aligned discrete layout feature stream by name."""
        name = feature_name.strip().lower()
        mapping = {
            "word_lengths": self.word_lengths,
            "word_length": self.word_lengths,
            "line_lengths": self.line_lengths,
            "line_length": self.line_lengths,
            "separators": self.separators,
            "separator": self.separators,
            "separator_codes": self.separator_codes,
            "pos_in_words": self.pos_in_words,
            "pos_in_word": self.pos_in_words,
            "pos_in_lines": self.pos_in_lines,
            "pos_in_line": self.pos_in_lines,
            "fehu_flags": self.fehu_flags,
            "fehu_flag": self.fehu_flags,
            "fehu_distances": self.fehu_distances,
            "fehu_distance": self.fehu_distances,
            "symbols": self.symbols,
        }
        if name not in mapping:
            raise KeyError(f"Unknown layout feature '{feature_name}'. Supported: {list(mapping.keys())}")
        return mapping[name]


@dataclass
class MIResult:
    """Results from mutual information estimation with bias correction and permutation test."""
    feature: str
    sample_size: int
    mi_raw: float
    mi_mm: float
    bias: float
    x_cardinality: int
    y_cardinality: int
    p_value: float
    exceedances: int
    trials: int
    is_significant: bool
    outcome: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature": self.feature,
            "sample_size": self.sample_size,
            "mi_raw": self.mi_raw,
            "mi_mm": self.mi_mm,
            "bias": self.bias,
            "x_cardinality": self.x_cardinality,
            "y_cardinality": self.y_cardinality,
            "p_value": self.p_value,
            "exceedances": self.exceedances,
            "trials": self.trials,
            "is_significant": self.is_significant,
            "outcome": self.outcome,
        }


def extract_layout_stream(page_or_text: Union[str, int, os.PathLike], prefer_solved: bool = True) -> LayoutStream:
    """
    Extract multiplexed symbol and layout streams from raw text, filepath, or corpus page ID.
    Parses runes (mod 29), punctuation/separators (᛫, ᛬, ᛭), word lengths, line lengths,
    and Fehu (ᚠ) interrupt positions.
    """
    page_id = str(page_or_text)
    raw_content = ""

    # 1. Resolve from file or corpus page ID
    if isinstance(page_or_text, int) or (isinstance(page_or_text, str) and (page_or_text.isdigit() or page_or_text.lower().startswith("page_"))):
        # Look up via router or corpus directory
        norm_num = re.sub(r"^page_?", "", str(page_or_text).strip().lower())
        fpath = None
        corpus_dir = os.path.join(BASE_DIR, "corpus")
        padded = f"{int(norm_num):02d}" if norm_num.isdigit() else norm_num

        if not prefer_solved:
            cand = os.path.join(corpus_dir, f"page_{padded}_runes.md")
            if os.path.exists(cand):
                fpath = cand

        if not fpath and get_page_corpus_path:
            fpath = get_page_corpus_path(norm_num)

        if not fpath:
            cand = os.path.join(corpus_dir, f"page_{padded}_runes.md")
            if os.path.exists(cand):
                fpath = cand
        if fpath and os.path.exists(fpath):
            page_id = os.path.basename(fpath)
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                raw_content = f.read()

    elif isinstance(page_or_text, str) and os.path.exists(page_or_text):
        page_id = os.path.basename(page_or_text)
        with open(page_or_text, "r", encoding="utf-8", errors="ignore") as f:
            raw_content = f.read()
    else:
        raw_content = str(page_or_text)

    # 2. Extract runic section if markdown transcript
    transcript_text = raw_content
    if "## Rune Transcription" in raw_content:
        m = re.search(r"## Rune Transcription\s*\n(.*?)(?=\n##|\Z)", raw_content, re.DOTALL)
        if m:
            transcript_text = m.group(1)

    lines_raw = transcript_text.strip().split("\n")
    symbols: List[int] = []
    runes: List[str] = []
    word_lengths: List[int] = []
    line_lengths: List[int] = []
    separators: List[str] = []
    separator_codes: List[int] = []
    pos_in_words: List[int] = []
    pos_in_lines: List[int] = []
    fehu_flags: List[int] = []
    fehu_distances: List[int] = []
    all_words: List[Dict[str, Any]] = []
    all_lines: List[Dict[str, Any]] = []

    last_fehu_idx = -1
    symbol_counter = 0

    for line_idx, line in enumerate(lines_raw):
        clean_line = line.strip()
        runes_in_line = [c for c in clean_line if c in INDEX_BY_RUNE]
        if not runes_in_line:
            continue

        line_len = len(runes_in_line)
        line_word_tokens: List[Dict[str, Any]] = []
        curr_word_runes: List[str] = []
        line_runes_processed = 0

        # Scan line characters
        for ch in clean_line:
            if ch in INDEX_BY_RUNE:
                curr_word_runes.append(ch)
            elif ch in SEPARATOR_MAP:
                if curr_word_runes:
                    sep_char = ch
                    if sep_char in ("-", " ", "\t"):
                        sep_char = RUNIC_WORD_SEP
                    elif sep_char in (".", ":"):
                        sep_char = RUNIC_CLAUSE_SEP
                    elif sep_char in ("§", "/"):
                        sep_char = RUNIC_CROSS_SEP

                    line_word_tokens.append({
                        "runes": list(curr_word_runes),
                        "separator": sep_char,
                        "sep_code": SEPARATOR_MAP.get(ch, 1),
                        "line": line_idx,
                    })
                    curr_word_runes = []

        if curr_word_runes:
            line_word_tokens.append({
                "runes": list(curr_word_runes),
                "separator": "EOL",
                "sep_code": 0,
                "line": line_idx,
            })

        # Process runes in line words
        line_entry = {
            "line_index": line_idx,
            "rune_count": line_len,
            "words": len(line_word_tokens),
        }
        all_lines.append(line_entry)

        for w_tok in line_word_tokens:
            w_runes = w_tok["runes"]
            w_len = len(w_runes)
            w_sep = w_tok["separator"]
            w_sep_code = w_tok["sep_code"]
            all_words.append({
                "word_index": len(all_words),
                "runes": "".join(w_runes),
                "length": w_len,
                "separator": w_sep,
                "line": line_idx,
            })

            for pos_in_w, r in enumerate(w_runes):
                s_idx = INDEX_BY_RUNE[r]
                symbols.append(s_idx)
                runes.append(r)
                word_lengths.append(w_len)
                line_lengths.append(line_len)
                separators.append(w_sep)
                separator_codes.append(w_sep_code)
                pos_in_words.append(pos_in_w)
                pos_in_lines.append(line_runes_processed)

                is_fehu = 1 if s_idx == 0 else 0
                fehu_flags.append(is_fehu)

                if is_fehu:
                    fehu_dist = 0
                    last_fehu_idx = symbol_counter
                else:
                    fehu_dist = (symbol_counter - last_fehu_idx) if last_fehu_idx >= 0 else -1
                fehu_distances.append(fehu_dist)

                line_runes_processed += 1
                symbol_counter += 1

    return LayoutStream(
        page_id=page_id,
        symbols=symbols,
        runes=runes,
        word_lengths=word_lengths,
        line_lengths=line_lengths,
        separators=separators,
        separator_codes=separator_codes,
        pos_in_words=pos_in_words,
        pos_in_lines=pos_in_lines,
        fehu_flags=fehu_flags,
        fehu_distances=fehu_distances,
        words=all_words,
        lines=all_lines,
    )


def compute_discrete_mutual_information(X: List[Any], Y: List[Any]) -> Tuple[float, float, float, int, int]:
    """
    Compute empirical Shannon mutual information I(X; Y) in bits, along with
    Miller-Madow bias correction and support cardinalities.

    Formula:
      I = sum_{x,y} p(x,y) * log2(p(x,y) / (p(x) * p(y)))
      bias = (|X| - 1) * (|Y| - 1) / (2 * N * ln 2)
      I_MM = max(0.0, I - bias)

    Returns:
      (mi_raw, mi_mm, bias, |X|, |Y|)
    """
    N = len(X)
    if N <= 1:
        return 0.0, 0.0, 0.0, len(set(X)), len(set(Y))

    cnt_x = Counter(X)
    cnt_y = Counter(Y)
    cnt_xy = Counter(zip(X, Y))

    kx = len(cnt_x)
    ky = len(cnt_y)

    if kx <= 1 or ky <= 1:
        return 0.0, 0.0, 0.0, kx, ky

    mi_raw = 0.0
    for (x, y), n_xy in cnt_xy.items():
        p_xy = n_xy / N
        p_x = cnt_x[x] / N
        p_y = cnt_y[y] / N
        mi_raw += p_xy * math.log2(p_xy / (p_x * p_y))

    # Miller-Madow asymptotic bias correction in bits
    bias = ((kx - 1) * (ky - 1)) / (2.0 * N * math.log(2.0))
    mi_mm = max(0.0, mi_raw - bias)

    return mi_raw, mi_mm, bias, kx, ky


def estimate_mutual_information(
    layout_data: Union[LayoutStream, List[Any]],
    keystream: Union[List[int], str, None],
    feature_name: str = "word_lengths",
    seed: Optional[int] = 42,
    h: int = 10,
    n_max: int = 1000,
    alpha: float = 0.01,
) -> MIResult:
    """
    Estimate mutual information between a layout feature and a keystream shift sequence.
    Applies Miller-Madow bias correction and assesses significance via Besag-Clifford
    sequential Monte Carlo permutation null testing.
    """
    if isinstance(layout_data, LayoutStream):
        X = layout_data.get_feature(feature_name)
    else:
        X = list(layout_data)

    N = len(X)
    if N == 0:
        return MIResult(
            feature=feature_name,
            sample_size=0,
            mi_raw=0.0,
            mi_mm=0.0,
            bias=0.0,
            x_cardinality=0,
            y_cardinality=0,
            p_value=1.0,
            exceedances=h,
            trials=h,
            is_significant=False,
            outcome="Outcome A: Clean Negative",
        )

    # Process keystream
    if keystream is None:
        Y = [0] * N
    elif isinstance(keystream, str):
        shifts = canonical_key_shifts(keystream)
        if not shifts:
            shifts = [0]
        Y = [shifts[i % len(shifts)] for i in range(N)]
    else:
        Y = list(keystream)
        if len(Y) < N:
            # Repeat or pad
            m = len(Y)
            Y = [Y[i % m] for i in range(N)] if m > 0 else [0] * N
        elif len(Y) > N:
            Y = Y[:N]

    mi_raw, mi_mm, bias, kx, ky = compute_discrete_mutual_information(X, Y)

    # Permutation test with sequential Monte Carlo early stopping
    rng = random.Random(seed) if seed is not None else random.Random()
    y_shuffled = list(Y)

    def draw_shuffle_stat() -> float:
        rng.shuffle(y_shuffled)
        _, sh_mm, _, _, _ = compute_discrete_mutual_information(X, y_shuffled)
        return sh_mm

    # Null testing via Besag-Clifford sequential test
    p_val, exceedances, trials = sequential_mc_pvalue(
        stat_obs=mi_mm,
        shuffle_stat_fn=draw_shuffle_stat,
        h=h,
        n_max=n_max,
        rng=rng,
        alternative="greater",
    )

    is_sig = (p_val < alpha) and (mi_mm > 0.05)
    outcome = "Outcome B: Significant Carrier" if is_sig else "Outcome A: Clean Negative"

    return MIResult(
        feature=feature_name,
        sample_size=N,
        mi_raw=round(mi_raw, 5),
        mi_mm=round(mi_mm, 5),
        bias=round(bias, 5),
        x_cardinality=kx,
        y_cardinality=ky,
        p_value=p_val,
        exceedances=exceedances,
        trials=trials,
        is_significant=is_sig,
        outcome=outcome,
    )


def analyze_all_features(
    layout_stream: LayoutStream,
    keystream: Union[List[int], str, None],
    seed: Optional[int] = 42,
    features: Optional[List[str]] = None,
) -> Dict[str, MIResult]:
    """Run mutual information estimation across all standard discrete layout features."""
    if features is None:
        features = [
            "word_lengths",
            "line_lengths",
            "separators",
            "pos_in_words",
            "fehu_flags",
            "fehu_distances",
        ]

    results: Dict[str, MIResult] = {}
    for feat in features:
        res = estimate_mutual_information(
            layout_data=layout_stream,
            keystream=keystream,
            feature_name=feat,
            seed=seed,
        )
        results[feat] = res
    return results


def calibrate_solved_pages(
    db_path: Optional[str] = None,
    seed: int = 42,
    features: Optional[List[str]] = None,
    log_to_ledger: bool = True,
) -> Dict[str, Any]:
    """
    Run layout side-channel calibration across all solved Liber Primus pages
    (Pages 0, 56, 57, 73) against known ground-truth keystreams.
    Logs each evaluation to agents/ledger.py under family 'layout-carrier'.
    """
    if features is None:
        features = ["word_lengths", "line_lengths", "separators", "pos_in_words", "fehu_flags"]

    # Known solved pages specifications
    solved_specs = [
        {"page": 0, "title": "Welcome Page", "key": None, "cipher": "transliteration"},
        {"page": 56, "title": "Loss of Innocence", "key": "DIVINITY", "cipher": "rune_vigenere"},
        {"page": 57, "title": "A Warning", "key": "FIRFUMFERENFE", "cipher": "rune_vigenere"},
        {"page": 73, "title": "An End", "key": None, "cipher": "transliteration"},
    ]

    calibration_records: List[Dict[str, Any]] = []
    any_significant = False
    total_evaluations = 0

    for spec in solved_specs:
        pid = spec["page"]
        title = spec["title"]
        key_str = spec["key"]
        stream = extract_layout_stream(pid, prefer_solved=True)

        page_record = {
            "page": pid,
            "title": title,
            "cipher": spec["cipher"],
            "key": key_str,
            "rune_count": len(stream),
            "features": {},
        }

        for feat in features:
            total_evaluations += 1
            res = estimate_mutual_information(
                layout_data=stream,
                keystream=key_str,
                feature_name=feat,
                seed=seed,
            )
            page_record["features"][feat] = res.to_dict()

            if res.is_significant:
                any_significant = True

            # Write to hypothesis ledger under family 'layout-carrier'
            if log_to_ledger:
                method_name = f"layout-carrier:{feat}"
                params = {
                    "feature": feat,
                    "key": key_str or "identity",
                    "page_title": title,
                    "sample_size": res.sample_size,
                    "seed": seed,
                    "test": "miller_madow_sequential_mc",
                }
                raw_digest = f"{pid}:{feat}:{key_str}:{res.sample_size}"
                input_digest = hex(abs(hash(raw_digest)))[2:]
                preview = f"I_MM={res.mi_mm:.4f}b p={res.p_value:.3f} tr={res.trials} ({res.outcome})"

                if log_canonical_attempt:
                    log_canonical_attempt(
                        page=str(pid),
                        method=method_name,
                        parameters=params,
                        input_digest=input_digest,
                        score=res.mi_mm,
                        passed=res.is_significant,
                        result_preview=preview,
                        method_version=1,
                        scorer_version=1,
                        **({"db_path": db_path} if db_path else {})
                    )
                if log_attempt:
                    log_attempt(
                        page=str(pid),
                        method=method_name,
                        key=key_str or "none",
                        result=f"I_MM={res.mi_mm:.4f} p={res.p_value:.3f}",
                        success=res.is_significant,
                        notes=f"trials={res.trials} exc={res.exceedances} bias={res.bias:.4f}",
                        **({"db_path": db_path} if db_path else {})
                    )

        calibration_records.append(page_record)

    overall_outcome = "Outcome B: Significant Carrier Detected" if any_significant else "Outcome A: Clean Negative (Hypothesis Excluded)"

    return {
        "status": "completed",
        "family": "layout-carrier",
        "total_evaluations": total_evaluations,
        "any_significant": any_significant,
        "overall_outcome": overall_outcome,
        "pages": calibration_records,
    }
