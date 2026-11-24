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
import math
import string
import os
import sys
from typing import List, Tuple, Dict, Optional

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

# Augment with full master cryptanalytic and corpus vocabulary (O(1) frozenset)
try:
    from ciphers.lexicon import get_master_dictionary_set
    CORE_WORDS.update(get_master_dictionary_set())
except ImportError:
    try:
        from lexicon import get_master_dictionary_set
        CORE_WORDS.update(get_master_dictionary_set())
    except ImportError:
        try:
            from ciphers.lexicon import get_master_dictionary
            CORE_WORDS.update(get_master_dictionary())
        except ImportError:
            try:
                from lexicon import get_master_dictionary
                CORE_WORDS.update(get_master_dictionary())
            except ImportError:
                pass

CORE_WORDS_FROZEN: frozenset = frozenset(CORE_WORDS)


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
    Check fraction of characters belonging to recognizable English words.
    Works on texts with spaces or scans substrings if no spaces exist.
    """
    upper = text.upper()
    tokens = [t.strip(string.punctuation) for t in upper.split()]
    tokens = [t for t in tokens if len(t) >= min_word_len]

    if tokens:
        hits = sum(1 for t in tokens if t in CORE_WORDS_FROZEN)
        return round(hits / len(tokens), 3)

    # Substring search if unspaced
    cleaned = clean(text)
    n_clean = len(cleaned)
    if n_clean < min_word_len:
        return 0.0
    matched_chars = set()
    for w in CORE_WORDS_FROZEN:
        len_w = len(w)
        if len_w > n_clean:
            continue
        start = 0
        while True:
            idx = cleaned.find(w, start)
            if idx == -1:
                break
            matched_chars.update(range(idx, idx + len_w))
            start = idx + 1
    return round(len(matched_chars) / n_clean, 3)


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
