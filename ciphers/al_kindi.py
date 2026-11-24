"""
Al-Kindi — frequency & statistical cryptanalysis module.
Named for Al-Kindi, the 9th-century polymath who invented frequency analysis.

Provides:
- Chi-squared goodness-of-fit against standard English frequencies
- Quadgram & trigram log-likelihood scoring for decrypt candidate ranking
- Common word dictionary matching ratio
- Index of Coincidence (IoC) plausibility filtering

Usage:
    from al_kindi import (
        ngram_score, chi_squared_score, english_word_ratio,
        rank_candidates, is_plausible_english,
        reduced_chi_squared, kl_divergence_english, chi_squared_p_value
    )
"""

from collections import Counter
import functools
import math
import os
import re
import string
import sys
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple, Union

ALPHABET = string.ascii_uppercase
ALPHABET_SET = set(ALPHABET)

# Standard Monogram frequencies in English (%)
ENGLISH_MONOGRAMS = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33,
    'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41,
    'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.49, 'V': 0.98,
    'K': 0.77, 'X': 0.15, 'J': 0.15, 'Q': 0.10, 'Z': 0.07
}

# High-frequency English trigrams with log10 probabilities
TOP_TRIGRAMS = {
    "THE": -2.3, "AND": -2.6, "ING": -2.7, "ENT": -2.9, "ION": -3.0, "HER": -3.0,
    "FOR": -3.1, "THA": -3.1, "NTH": -3.2, "INT": -3.2, "ERE": -3.3, "TIO": -3.3,
    "TER": -3.3, "EST": -3.4, "ERS": -3.4, "ATI": -3.4, "HAT": -3.5, "ATE": -3.5,
    "ALL": -3.5, "ETH": -3.5, "HES": -3.6, "VER": -3.6, "HIS": -3.6, "OFT": -3.7,
    "ITH": -3.7, "FTH": -3.7, "STH": -3.8, "OTH": -3.8, "RES": -3.8, "ONT": -3.8
}

# High-frequency English quadgrams with log10 probabilities
TOP_QUADGRAMS = {
    "TION": -3.4, "NTHE": -3.6, "THER": -3.7, "THAT": -3.8, "OFTH": -3.8, "FTHE": -3.9,
    "THES": -4.0, "WITH": -4.0, "INTH": -4.0, "ATIO": -4.1, "OTHE": -4.1, "TTHE": -4.2,
    "DTHE": -4.2, "INGT": -4.3, "ETHE": -4.3, "SAND": -4.4, "STHE": -4.4, "HERE": -4.5,
    "THEM": -4.5, "RTHE": -4.5, "MENT": -4.5, "THEY": -4.6, "FROM": -4.6, "THIS": -4.6,
    "TING": -4.7, "HAVE": -4.7, "WHIC": -4.7, "HICH": -4.7, "WILL": -4.8, "WERE": -4.8
}

# Core English vocabulary for dictionary hit validation (Cicada texts use philosophical & basic terms)
CORE_WORDS = {
    "THE", "OF", "AND", "TO", "IN", "IS", "YOU", "THAT", "IT", "HE", "WAS", "FOR",
    "ON", "ARE", "AS", "WITH", "HIS", "THEY", "AT", "BE", "THIS", "HAVE", "FROM",
    "OR", "ONE", "HAD", "BY", "WORD", "BUT", "NOT", "WHAT", "ALL", "WERE", "WE",
    "WHEN", "YOUR", "CAN", "SAID", "THERE", "USE", "AN", "EACH", "WHICH", "SHE",
    "DO", "HOW", "THEIR", "IF", "WILL", "UP", "OTHER", "ABOUT", "OUT", "MANY",
    "THEN", "THEM", "THESE", "SO", "SOME", "HER", "WOULD", "MAKE", "LIKE", "HIM",
    "INTO", "TIME", "HAS", "LOOK", "TWO", "MORE", "WRITE", "GO", "SEE", "NUMBER",
    "NO", "WAY", "COULD", "PEOPLE", "MY", "THAN", "FIRST", "WATER", "BEEN", "CALL",
    "WHO", "OIL", "ITS", "NOW", "FIND", "LONG", "DOWN", "DAY", "DID", "GET", "COME",
    "MADE", "MAY", "PART", "TRUTH", "WISDOM", "SACRED", "PRIME", "PILGRIM", "LIGHT",
    "SHADOW", "DIVINE", "DIVINITY", "LOSS", "INNOCENCE", "PRESERVATION", "BELIEF",
    "CIRCUMFERENCE", "KNOWLEDGE", "SEEK", "FIND", "WELCOME", "MASTER", "PATH", "END"
}

# Augment with clean master reference & solved-corpus vocabulary (excluding raw unsolved transliterations)
_CLEAN_CORPUS_PROSE_FILES: Tuple[str, ...] = (
    "page_00_welcome.md",
    "page_06_page_06.md",
    "page_56_loss_of_innocence.md",
    "page_57_a_warning.md",
    "page_73_an_end.md",
    "harvest_wikipedia_Cicada_3301.md",
    "harvest_wikipedia_Steganography.md",
    "harvest_fandom_Liber_Primus.md",
    "harvest_Solving-Cicada-3301.md",
    "harvest_cicada-3301-liber-primus.md",
)

CORE_WORDS.update({"AM", "US", "DONT"})


def _load_clean_lexicon_words() -> Set[str]:
    """Load clean English vocabulary from lexicon references and solved/wiki corpus prose."""
    words: Set[str] = set(CORE_WORDS)
    try:
        from ciphers.lexicon import (
            CORPUS_DIR as _LEX_CORPUS_DIR,
            _is_valid_corpus_word as _lex_valid_word,
            get_master_dictionary_set as _get_master_set,
        )
    except ImportError:
        try:
            from lexicon import (
                CORPUS_DIR as _LEX_CORPUS_DIR,
                _is_valid_corpus_word as _lex_valid_word,
                get_master_dictionary_set as _get_master_set,
            )
        except ImportError:
            return words

    words.update(_get_master_set(include_corpus=False, include_references=True))
    for fname in _CLEAN_CORPUS_PROSE_FILES:
        fpath = os.path.join(_LEX_CORPUS_DIR, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                for tok in re.findall(r"\b[A-Za-z]+\b", f.read()):
                    up = tok.upper()
                    if _lex_valid_word(up):
                        words.add(up)
        except OSError:
            continue
    return words


CORE_WORDS_FROZEN: FrozenSet[str] = frozenset(_load_clean_lexicon_words())
_WORD_LENGTHS: List[int] = sorted({len(w) for w in CORE_WORDS_FROZEN if len(w) >= 3})
_WORD_LENGTHS_DESC: List[int] = sorted(_WORD_LENGTHS, reverse=True)
_FUTHORC_SEPARATORS: FrozenSet[str] = frozenset({"•", "᛫", "᛬", "᛭"})
_DIGRAPHS_2CHAR: FrozenSet[str] = frozenset({"TH", "EO", "OE", "AE", "IA", "EA"})


def clean(text: str) -> str:
    """Keep only uppercase English letters."""
    return "".join(c for c in text.upper() if c in ALPHABET_SET)


def letter_frequency(text: str) -> Dict[str, float]:
    """Calculate percentage frequency of each letter."""
    cleaned = clean(text)
    n = len(cleaned)
    if not n:
        return {}
    counts = Counter(cleaned)
    return {letter: round(counts.get(letter, 0) / n * 100, 2) for letter in ALPHABET}


def chi_squared_score(text: str) -> float:
    """
    Compute Chi-Squared statistic against standard English letter frequencies.
    Lower score = closer match to English (typical English < 100, random text > 300).
    """
    cleaned = clean(text)
    n = len(cleaned)
    if not n:
        return float("inf")

    counts = Counter(cleaned)
    chi2 = 0.0
    for letter, expected_pct in ENGLISH_MONOGRAMS.items():
        expected_count = n * (expected_pct / 100.0)
        observed_count = counts.get(letter, 0)
        chi2 += ((observed_count - expected_count) ** 2) / expected_count
    return round(chi2, 2)


def ngram_score(text: str) -> float:
    """
    Compute normalized plausibility score (0.0 to 1.0) using trigrams & quadgrams.
    Higher score = more plausibly coherent English.
    """
    cleaned = clean(text)
    n = len(cleaned)
    if n < 4:
        return 0.0

    trigrams = [cleaned[i:i + 3] for i in range(n - 2)]
    quadgrams = [cleaned[i:i + 4] for i in range(n - 3)]

    trigram_hits = sum(1 for t in trigrams if t in TOP_TRIGRAMS)
    quadgram_hits = sum(1 for q in quadgrams if q in TOP_QUADGRAMS)

    # Weighted fraction
    total_checks = len(trigrams) + (len(quadgrams) * 1.5)
    total_score = trigram_hits + (quadgram_hits * 1.5)

    ratio = total_score / total_checks if total_checks > 0 else 0.0
    # Normalize to an intuitive 0.0 - 1.0 range where typical English hits 0.15 - 0.45+
    return round(min(1.0, ratio * 3.5), 4)


def english_word_ratio(text: str, min_word_len: int = 3) -> float:
    """
    Check fraction of tokens (if spaced) or characters (if unspaced) belonging to
    recognizable English words. Strictly bounded in [0.0, 1.0].
    """
    if not text:
        return 0.0
    upper = text.upper()
    raw_tokens = [t.strip(string.punctuation) for t in upper.split()]
    has_spaces = len(raw_tokens) > 1
    tokens = [t for t in raw_tokens if len(t) >= min_word_len]

    if has_spaces and tokens:
        hits = sum(1 for t in tokens if t in CORE_WORDS_FROZEN)
        return max(0.0, min(1.0, round(hits / len(tokens), 3)))

    # Substring search if unspaced (or all space-separated fragments < min_word_len)
    cleaned = clean(text)
    n_clean = len(cleaned)
    if not n_clean or n_clean < max(1, min_word_len):
        return 0.0
    covered = bytearray(n_clean)
    for w_len in _WORD_LENGTHS:
        if w_len < min_word_len:
            continue
        if w_len > n_clean:
            break
        for idx in range(n_clean - w_len + 1):
            if cleaned[idx:idx + w_len] in CORE_WORDS_FROZEN:
                covered[idx:idx + w_len] = b"\x01" * w_len
    return max(0.0, min(1.0, round(covered.count(1) / n_clean, 3)))


def length_normalized_chi_squared(text: str) -> float:
    """Compute per-symbol Chi-Squared divergence (chi2 / n) against standard English."""
    cleaned = clean(text)
    n = len(cleaned)
    if not n:
        return float("inf")
    return round(chi_squared_score(text) / n, 4)


def reduced_chi_squared(text: str, df: int = 25) -> float:
    """
    Compute reduced Chi-Squared statistic (chi2 / df) against standard English.
    For English 26-letter monogram distribution, df = 25 (26 - 1).
    """
    chi2 = chi_squared_score(text)
    if chi2 == float("inf") or df <= 0:
        return float("inf")
    return round(chi2 / df, 4)


def kl_divergence_english(text: str, epsilon: float = 1e-6) -> float:
    """
    Compute Kullback-Leibler (KL) divergence D_KL(P_obs || P_ref) against standard English.
    Length-invariant metric. Strictly satisfies Gibbs inequality (clamped to >= 0.0).
    """
    cleaned = clean(text)
    n = len(cleaned)
    if not n:
        return float("inf")
    counts = Counter(cleaned)
    total_ref = sum(ENGLISH_MONOGRAMS.values())
    kl = 0.0
    for letter in ALPHABET:
        p_obs = counts.get(letter, 0) / n
        p_ref = ENGLISH_MONOGRAMS.get(letter, 0.0) / total_ref
        if p_obs > 0.0:
            kl += p_obs * math.log((p_obs + epsilon) / (p_ref + epsilon))
    return max(0.0, kl)


def chi_squared_p_value(chi2: float, df: int = 25) -> float:
    """
    Compute analytical Chi-Squared upper-tail p-value via Wilson-Hilferty transformation.
    Pure Python implementation using math.erfc with zero external dependencies.
    """
    if chi2 < 0.0 or df <= 0 or math.isinf(chi2):
        return 0.0
    if chi2 == 0.0:
        return 1.0
    z = (((chi2 / df) ** (1.0 / 3.0)) - (1.0 - 2.0 / (9.0 * df))) / math.sqrt(2.0 / (9.0 * df))
    p = 0.5 * math.erfc(z / math.sqrt(2.0))
    return max(0.0, min(1.0, p))


def is_plausible_english(text: str, legacy_threshold: Optional[bool] = None) -> Tuple[bool, dict]:
    """
    Comprehensive gatekeeper test for decryption candidates.
    Returns (Passed: bool, metrics: dict).
    Uses length-invariant statistics (KL divergence and per-symbol chi2) by default,
    preventing long texts (L > 800) from being falsely rejected due to linear Chi2 scaling.
    Assigns composite verdict: PLAUSIBLE, UNCERTAIN, or IMPLAUSIBLE.
    Supports legacy fixed 180.0 threshold via legacy_threshold flag or TRITHEMIUS_LEGACY_CHI2 env var.
    """
    if legacy_threshold is None:
        legacy_threshold = os.environ.get("TRITHEMIUS_LEGACY_CHI2", "off").lower() in ("1", "true", "on")

    cleaned = clean(text)
    n = len(cleaned)
    chi2 = chi_squared_score(text)
    chi2_red = reduced_chi_squared(text, df=25)
    chi2_per_symbol = round(chi2 / max(1, n), 4) if n > 0 else float("inf")
    kl = kl_divergence_english(text)
    p_val = chi_squared_p_value(chi2, df=25)
    ngram = ngram_score(text)
    word_ratio = english_word_ratio(text)

    # In legacy mode: fixed chi2 < 180.0
    # In length-invariant mode: chi2_per_symbol < 0.75 OR (chi2 < 180.0)
    # Typical English scores: chi2_per_symbol ~0.15 - 0.45, KL ~0.10 - 0.40; random text > 2.0.
    if legacy_threshold:
        chi_passed = (chi2 < 180.0)
    else:
        chi_passed = (chi2 < 180.0 or chi2_per_symbol < 0.75)

    is_plausible = (chi_passed and ngram > 0.05 and kl <= 0.65) or (word_ratio >= 0.20)

    if legacy_threshold:
        passed = is_plausible
        verdict = "PLAUSIBLE" if passed else "REJECT"
    else:
        if is_plausible:
            verdict = "PLAUSIBLE"
            passed = True
        elif word_ratio >= 0.15 or (chi2_per_symbol < 0.85 and ngram > 0.02):
            verdict = "UNCERTAIN"
            passed = False
        else:
            verdict = "REJECT"
            passed = False

    metrics = {
        "passed": passed,
        "chi_squared": chi2,
        "chi_squared_per_symbol": chi2_per_symbol,
        "reduced_chi_squared": chi2_red,
        "kl_divergence": kl,
        "p_value": p_val,
        "ngram_score": ngram,
        "word_ratio": word_ratio,
        "legacy_threshold": legacy_threshold,
        "verdict": verdict,
    }
    return passed, metrics


def rank_candidates(candidates: List[str]) -> List[Tuple[str, float, dict]]:
    """Rank multiple candidate plaintexts by cryptographic plausibility."""
    scored = []
    for cand in candidates:
        passed, metrics = is_plausible_english(cand)
        # Combined composite score: higher ngram + word ratio, lower chi-squared
        composite = metrics["ngram_score"] + (metrics["word_ratio"] * 0.5) - (min(300, metrics["chi_squared"]) / 600.0)
        scored.append((cand, round(composite, 4), metrics))
    return sorted(scored, key=lambda x: -x[1])


def _expand_char_substitution(
    forms: Set[str],
    src_ch: str,
    dst_ch: str,
    max_occ: int = 3,
) -> Set[str]:
    """Return forms augmented with all non-empty subset substitutions src_ch -> dst_ch."""
    expanded: Set[str] = set(forms)
    for src in forms:
        idxs = [i for i, ch in enumerate(src) if ch == src_ch]
        if 0 < len(idxs) <= max_occ:
            for mask in range(1, 1 << len(idxs)):
                chars = list(src)
                for bit, pos in enumerate(idxs):
                    if mask & (1 << bit):
                        chars[pos] = dst_ch
                expanded.add("".join(chars))
    return expanded


@functools.lru_cache(maxsize=8192)
def _normalized_futhorc_forms(token: str) -> FrozenSet[str]:
    """Generate Liber Primus / Futhorc transliteration spelling variants for a token."""
    cleaned = re.sub(r"[^A-Z]", "", token.upper())
    if not cleaned:
        return frozenset()

    forms: Set[str] = {cleaned, cleaned.replace("V", "U")}
    for src in list(forms):
        for old, new in (
            ("TIAN", "TION"), ("SIAN", "SION"), ("IAN", "ION"),
            ("IAU", "IOU"), ("IA", "IO"), ("CW", "QU"), ("QU", "CW"),
        ):
            forms.add(src.replace(old, new))
    for src in list(forms):
        if "CW" in src:
            forms.add(src.replace("CW", "QU"))
        if "IA" in src:
            forms.add(src.replace("IA", "IO"))
    for src in list(forms):
        if "ING" in src:
            forms.add(src.replace("ING", "NG"))
        if "NG" in src:
            forms.add(src.replace("NG", "ING"))
    forms = _expand_char_substitution(forms, "U", "V")
    for src in list(forms):
        if "CC" in src:
            forms.add(src.replace("CC", "CK"))
    forms = _expand_char_substitution(forms, "C", "K")
    return frozenset(forms)


def _normalize_futhorc_token(token: str) -> Set[str]:
    """Return candidate normalized English spellings for a Futhorc-transliterated token."""
    return set(_normalized_futhorc_forms(token))


def _is_recognized_futhorc_token(token: str) -> bool:
    """Return True if any Futhorc-normalized spelling variant exists in CORE_WORDS_FROZEN."""
    return bool(_normalized_futhorc_forms(token) & CORE_WORDS_FROZEN)


def _extract_runic_word_segments(runic_text: str, index_by_rune: Dict[str, int]) -> List[str]:
    """
    Split runic text into word segments along Futhorc dividers and whitespace.
    Treats a single newline between two runes as a visual line wrap inside a word.
    """
    words: List[str] = []
    cur: List[str] = []
    n = len(runic_text)
    for i, ch in enumerate(runic_text):
        if ch in index_by_rune:
            cur.append(ch)
        elif ch == "\n":
            prev_is_rune = i > 0 and runic_text[i - 1] in index_by_rune
            next_is_rune = i + 1 < n and runic_text[i + 1] in index_by_rune
            if not (prev_is_rune and next_is_rune) and cur:
                words.append("".join(cur))
                cur = []
        elif ch in ("'", "’"):
            continue
        else:
            if cur:
                words.append("".join(cur))
                cur = []
    if cur:
        words.append("".join(cur))
    return words


def _align_unspaced_latin_to_rune_lengths(
    cleaned_latin: str,
    word_lengths: List[int],
) -> Optional[List[str]]:
    """
    Align an unspaced decoded Latin string to known Futhorc word rune-lengths via DP.
    Disambiguates digraph boundaries (e.g. T+H vs TH) while respecting exact rune counts.
    """
    m_len = len(cleaned_latin)
    n_runes = sum(word_lengths)
    if n_runes == 0 or m_len < n_runes or m_len > 3 * n_runes:
        return None

    states: Dict[int, Tuple[float, List[str]]] = {0: (0.0, [])}
    r_done = 0
    for l_j in word_lengths:
        r_next = r_done + l_j
        min_pos_next = r_next
        max_pos_next = m_len - (n_runes - r_next)
        next_states: Dict[int, Tuple[float, List[str]]] = {}

        for start_pos, (sc_so_far, path) in states.items():
            layer: Dict[int, int] = {start_pos: 0}
            for step in range(l_j):
                rem_bound = m_len - (n_runes - (r_done + step + 1))
                nxt_layer: Dict[int, int] = {}
                for pos, merges in layer.items():
                    if pos + 1 <= rem_bound:
                        if pos + 1 not in nxt_layer or merges > nxt_layer[pos + 1]:
                            nxt_layer[pos + 1] = merges
                    if pos + 2 <= m_len and pos + 2 <= rem_bound and cleaned_latin[pos:pos + 2] in _DIGRAPHS_2CHAR:
                        if pos + 2 not in nxt_layer or merges + 1 > nxt_layer[pos + 2]:
                            nxt_layer[pos + 2] = merges + 1
                    if pos + 3 <= m_len and pos + 3 <= rem_bound and cleaned_latin[pos:pos + 3] == "ING":
                        if pos + 3 not in nxt_layer or merges + 1 > nxt_layer[pos + 3]:
                            nxt_layer[pos + 3] = merges + 1
                layer = nxt_layer

            for end_pos, merges in layer.items():
                if not (min_pos_next <= end_pos <= max_pos_next):
                    continue
                word = cleaned_latin[start_pos:end_pos]
                w_bonus = (len(word) * 1.0 if len(word) >= 4 else 0.3) if _is_recognized_futhorc_token(word) else 0.0
                total_sc = sc_so_far + w_bonus + 0.01 * merges
                if end_pos not in next_states or total_sc > next_states[end_pos][0]:
                    next_states[end_pos] = (total_sc, path + [word])

        states = next_states
        if not states:
            return None
        r_done = r_next

    return states[m_len][1] if m_len in states else None


def _extract_non_overlapping_long_words(cleaned: str) -> List[str]:
    """Extract greedy longest-first non-overlapping recognized words (len >= 4) from unspaced text."""
    n = len(cleaned)
    used = bytearray(n)
    found: List[str] = []
    for w_len in _WORD_LENGTHS_DESC:
        if w_len < 4:
            break
        if w_len > n:
            continue
        for idx in range(n - w_len + 1):
            if any(used[idx:idx + w_len]):
                continue
            sub = cleaned[idx:idx + w_len]
            if sub in CORE_WORDS_FROZEN:
                used[idx:idx + w_len] = b"\x01" * w_len
                found.append(sub)
    return found


def _tokenize_latin_with_boundaries(latin_text: str) -> List[str]:
    """Split Latin text on whitespace and Futhorc dividers, ignoring pure numeric/hex tokens."""
    raw_parts = re.split(r"[\s•᛫᛬᛭;\"\-]+", latin_text.upper())
    tokens: List[str] = []
    for part in raw_parts:
        stripped = part.strip(string.punctuation)
        if not stripped or any(ch.isdigit() for ch in stripped):
            continue
        alpha = re.sub(r"[^A-Z]", "", stripped)
        if alpha:
            tokens.append(alpha)
    return tokens


def _extract_aligned_tokens(
    latin_text: str,
    runic_text: Optional[str],
    cleaned_latin: str,
) -> Tuple[Optional[List[str]], int]:
    """
    Resolve word-boundary-aligned Latin tokens and rune count from latin_text / runic_text.
    Returns (aligned_tokens_or_None, rune_count).
    """
    rune_count = len(cleaned_latin)
    latin_tokens = _tokenize_latin_with_boundaries(latin_text)
    has_latin_boundaries = len([p for p in re.split(r"[\s•᛫᛬᛭;\"\-]+", latin_text.strip()) if p]) > 1

    if runic_text:
        try:
            from ciphers.agrippa import INDEX_BY_RUNE, decode_runes
        except ImportError:
            from agrippa import INDEX_BY_RUNE, decode_runes

        runic_count = sum(1 for ch in runic_text if ch in INDEX_BY_RUNE)
        if runic_count > 0:
            rune_count = runic_count
            has_sep = any(ch in _FUTHORC_SEPARATORS or ch in (" ", "\t", ";", '"') for ch in runic_text) or "\n\n" in runic_text
            if has_sep:
                r_segments = _extract_runic_word_segments(runic_text, INDEX_BY_RUNE)
                if len(r_segments) > 1:
                    decoded_from_runes = [decode_runes(seg) for seg in r_segments]
                    if "".join(decoded_from_runes) == "".join(latin_tokens):
                        return decoded_from_runes, rune_count
                    if has_latin_boundaries and len(latin_tokens) > 1:
                        return latin_tokens, rune_count
                    dp_tokens = _align_unspaced_latin_to_rune_lengths(
                        cleaned_latin, [len(seg) for seg in r_segments]
                    )
                    if dp_tokens is not None:
                        return dp_tokens, rune_count

    if has_latin_boundaries and len(latin_tokens) > 1:
        return latin_tokens, rune_count
    return None, rune_count


def analyze_runic_lexical_coverage(
    latin_text: str,
    runic_text: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Evaluate word-boundary-aligned and Futhorc-tolerant English lexical coverage.

    Uses Futhorc word separators ('•', '᛫', '᛬', '᛭') or whitespace when available,
    weighting recognized words of length >= 4 higher than short 2-3 letter tokens.
    """
    word_ratio = english_word_ratio(latin_text)
    cleaned_latin = clean(latin_text)
    aligned_tokens, rune_count = _extract_aligned_tokens(latin_text, runic_text, cleaned_latin)
    has_word_boundaries = aligned_tokens is not None

    aligned_word_ratio = 0.0
    recognized_long: Set[str] = set()
    recognized_5plus: Set[str] = set()

    if aligned_tokens:
        total_weight = 0.0
        hit_weight = 0.0
        for tok in aligned_tokens:
            alpha = re.sub(r"[^A-Z]", "", tok.upper())
            if len(alpha) < 2:
                continue
            weight = float(len(alpha)) if len(alpha) >= 4 else 0.5
            total_weight += weight
            if _is_recognized_futhorc_token(alpha):
                hit_weight += weight
                if len(alpha) >= 4:
                    recognized_long.add(alpha)
                if len(alpha) >= 5:
                    recognized_5plus.add(alpha)
        if total_weight > 0.0:
            aligned_word_ratio = max(0.0, min(1.0, round(hit_weight / total_weight, 3)))
    else:
        long_matches = _extract_non_overlapping_long_words(cleaned_latin)
        recognized_long = set(long_matches)
        recognized_5plus = {w for w in long_matches if len(w) >= 5}

    distinct_long_words = len(recognized_long)
    distinct_5plus_words = len(recognized_5plus)

    ratio_ok = (aligned_word_ratio >= 0.20) if has_word_boundaries else (word_ratio >= 0.22)
    length_ok = (distinct_long_words >= 2) or (0 < rune_count < 100 and distinct_5plus_words >= 1)
    word_coverage_ok = bool(ratio_ok and length_ok)

    return {
        "word_ratio": word_ratio,
        "aligned_word_ratio": aligned_word_ratio,
        "distinct_long_words": distinct_long_words,
        "distinct_5plus_words": distinct_5plus_words,
        "rune_count": rune_count,
        "has_word_boundaries": has_word_boundaries,
        "recognized_words": sorted(recognized_long),
        "word_coverage_ok": word_coverage_ok,
    }


def doublet_rate_plausibility(
    indices_or_runes: Union[Sequence[int], str],
    min_length: int = 120,
    min_rate: float = 0.005,
) -> Tuple[bool, float]:
    """
    Evaluate whether adjacent identical rune frequency is plausible for English plaintext.
    Flags (False, rate) if length >= min_length and doublet rate < min_rate (< 0.5% for n >= 120).
    """
    if isinstance(indices_or_runes, str):
        try:
            from ciphers.interrupter import analyze_f_skip_periodicity
        except ImportError:
            from interrupter import analyze_f_skip_periodicity
        diag = analyze_f_skip_periodicity(indices_or_runes)
        n = int(diag.get("rune_count", 0))
        rate = float(diag.get("consecutive_doubles_rate", 0.0))
    else:
        n = len(indices_or_runes)
        if n < 2:
            rate = 0.0
        else:
            doubles = sum(1 for i in range(n - 1) if indices_or_runes[i] == indices_or_runes[i + 1])
            rate = round(doubles / (n - 1), 5)

    plausible = not (n >= min_length and rate < min_rate)
    return plausible, rate


def score_runic_candidate(rune_text: str) -> float:
    """Evaluate linguistic plausibility directly in GF(29) Futhorc rune space."""
    try:
        from ciphers.taxonomy import score_composite_runes, clean_runes_to_indices
    except ImportError:
        from taxonomy import score_composite_runes, clean_runes_to_indices
    indices = clean_runes_to_indices(rune_text)
    return score_composite_runes(indices)


def is_plausible_runic(rune_text: str) -> Tuple[bool, dict]:
    """Test candidate decryption using calibrated GF(29) runic model & surrogate test."""
    try:
        from ciphers.taxonomy import score_composite_runes, surrogate_shuffle_test, clean_runes_to_indices
    except ImportError:
        from taxonomy import score_composite_runes, surrogate_shuffle_test, clean_runes_to_indices
    indices = clean_runes_to_indices(rune_text)
    score = score_composite_runes(indices)
    mu_null, std_null, z_score, is_sig = surrogate_shuffle_test(indices, score, n_shuffles=40)
    passed = score >= -3.38 and (is_sig or z_score >= 3.0)
    return passed, {
        "score": score,
        "null_mean": mu_null,
        "null_std": std_null,
        "z_score": z_score,
        "statistically_significant": is_sig,
        "verdict": "PLAUSIBLE" if passed else "REJECT",
    }


if __name__ == "__main__":
    test_samples = [
        "WELCOME PILGRIM ON THE SACRED PATH OF KNOWLEDGE AND TRUTH",
        "XQZJVKWPLMBNFGHTYUIOPAZXCVBNM",
        "THE SACRED RUNES REVEAL THE WISDOM OF PRIMES",
        "ASDJKASDLASJDLAJSDKLASJDLASJKD",
    ]
    for text, score, metrics in rank_candidates(test_samples):
        print(f"[{metrics['verdict']}] Score: {score:+.4f} (Chi2: {metrics['chi_squared']}, Ngram: {metrics['ngram_score']}, Words: {metrics['word_ratio']}) -> {text[:45]}...")
