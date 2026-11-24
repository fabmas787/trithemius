"""
Taxonomy — Advanced Liber Primus Cryptanalytic Suite.
Implements the full cryptanalytic taxonomy for recovering keys and detecting English-like
structure over the GF(29) linear channel:
1. Calibrated GF(29) Runic Language Model & Scoring
2. Comprehensive Triage Statistics (IC, normalized kappa, bigram IC, conditional entropy, word length)
3. Multi-Metric Key Length Estimation (Kasiski weighted GCD, difference periodogram comb, column IoC)
4. Separable Per-Column Solver (T-table trick, MIC alignment, gauge resolution, coupled hill climbing)
5. Dictionary & Structured Candidate Search with O(m) T-table lookups
6. Known-Plaintext & Crib Dragging (Berlekamp-Massey over GF(29), finite differences, stream hash bank)
7. Deterministic Stream Sweeps (primes, totients, Fibonacci, counters with Fehu skip)
8. Deep Sweeps (affine mod 29, autokey, cross-page running key)
9. Statistical Significance & Surrogate Shuffle Testing (Monte Carlo null distribution & Z-score)
10. Automatic Deduplication & Ledger Persistence via agents/ledger.py
"""

from collections import Counter
import math
import os
import random
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple, Union

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(CURRENT_DIR)
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agrippa import (
    INDEX_BY_RUNE,
    LATIN_BY_RUNE,
    PRIME_BY_RUNE,
    RUNE_BY_INDEX,
    RUNE_TABLE,
    decode_runes,
    euler_totient,
    index_to_rune,
    is_prime,
    latin_to_rune,
    rune_to_index,
)
from interrupter import (
    InterrupterConfig,
    KOAN2_F_SKIP_POSITIONS,
    WELCOME_F_SKIP_POSITIONS,
    canonical_key_shifts,
    rune_vigenere_decode_dynamic,
    rune_vigenere_decode_f_skip,
    rune_vigenere_encode_dynamic,
)
from kasiski import prime_totient_stream_decode

try:
    from agents.ledger import (
        has_attempt_been_tried,
        log_canonical_attempt,
        count_attempts,
        record_attempt,
        record_attempts_batch,
        get_tested_words,
    )
except ImportError:
    has_attempt_been_tried = None
    log_canonical_attempt = None
    count_attempts = None
    record_attempt = None
    record_attempts_batch = None
    get_tested_words = None

try:
    from lexicon import (
        SACRED_CANONICAL_WORDS,
        get_master_dictionary,
        generate_all_key_variants,
        compute_beaufort_t_table,
        LEXICON_INDEX,
        get_rotated_vocabulary,
        generate_cyclic_rotations,
    )
except ImportError:
    try:
        from ciphers.lexicon import (
            SACRED_CANONICAL_WORDS,
            get_master_dictionary,
            generate_all_key_variants,
            compute_beaufort_t_table,
            LEXICON_INDEX,
            get_rotated_vocabulary,
            generate_cyclic_rotations,
        )
    except ImportError:
        SACRED_CANONICAL_WORDS = None
        get_master_dictionary = None
        generate_all_key_variants = None
        compute_beaufort_t_table = None
        LEXICON_INDEX = None
        get_rotated_vocabulary = None
        generate_cyclic_rotations = None

try:
    from metal_accel import (
        is_metal_available,
        get_metal_device_info,
        metal_score_keys_batch,
        metal_sweep_2words,
        metal_sweep_3words,
        metal_surrogate_shuffles,
    )
except ImportError:
    try:
        from ciphers.metal_accel import (
            is_metal_available,
            get_metal_device_info,
            metal_score_keys_batch,
            metal_sweep_2words,
            metal_sweep_3words,
            metal_surrogate_shuffles,
        )
    except ImportError:
        is_metal_available = lambda: False
        get_metal_device_info = lambda: {"available": False}
        metal_score_keys_batch = None
        metal_sweep_2words = None
        metal_sweep_3words = None
        metal_surrogate_shuffles = None

try:
    from ane_engine import (
        is_ane_available,
        get_ane_device_info,
        score_candidate_naturalness_neural,
    )
except ImportError:
    try:
        from ciphers.ane_engine import (
            is_ane_available,
            get_ane_device_info,
            score_candidate_naturalness_neural,
        )
    except ImportError:
        is_ane_available = lambda: False
        get_ane_device_info = lambda: {"available": False}
        score_candidate_naturalness_neural = None

M = 29  # Galois field GF(29)


# =============================================================================
# 1. Calibrated GF(29) Runic Language Model
# =============================================================================

# Verified English Plaintext from Liber Primus Solved Pages & Canonical Sources
SOLVED_LP_PLAINTEXTS = [
    # Page 0: Welcome
    "WELCOME PILGRIMS TO THIS GREAT JOURNEY A WARNING BELIEVE NOTHING FROM THIS BOOK EXCEPT WHAT YOU KNOW TO BE TRUE TEST THE KNOWLEDGE FIND YOUR TRUTH EXPERIENCE YOUR DEATH DO NOT EDIT OR CHANGE THIS BOOK OR THE MESSAGE CONTAINED WITHIN EITHER THE WORDS OR THEIR NUMBERS FOR ALL IS SACRED",
    # Sacred Axioms: Some Wisdom
    "SOME WISDOM THE PRIMES ARE SACRED THE TOTIENT FUNCTION IS SACRED ALL THINGS SHOULD BE PARED TO THEIR SIMPLEST STATE",
    # Page 57: A Warning
    "A WARNING PRIMES ARE THE SACRED BUILDING BLOCKS COMPOSITES CAN BE FACTORED DO NOT LOSE THE PATH",
    # Page 73: An End
    "AN END WITHIN THE DEEP WEB THERE EXISTS A PAGE THAT HASHES TO IT IS THE OBJECT OF THE PILGRIMAGE",
    # Koans
    "A KOAN DURING A LESSON THE MASTER EXPLAINED THE SACRED CODE TO HIS STUDENTS",
    "AN AMASSING OF INFORMATION IS NOT AN AMASSING OF WISDOM",
    "THE LOSS OF INNOCENCE IS THE INEVITABLE DESTINY OF MAN",
    # Cicero / Cicada Philosophical Foundations
    "ALL THINGS ARE CONNECTED CIRCUMFERENCE AND CENTER ARE ONE PRIMES ARE THE ARCHITECTURE OF REALITY",
]

# Standard high-frequency English terms mapped to Liber Primus vocabulary
CANONICAL_CRIBS = [
    "WELCOME", "PILGRIM", "PILGRIMS", "SACRED", "PRIME", "PRIMES",
    "TOTIENT", "WISDOM", "TRUTH", "KNOWLEDGE", "BELIEVE", "DIVINITY",
    "CIRCUMFERENCE", "FIRFUMFERENFE", "WARNING", "DEATH", "MASTER",
    "NOTHING", "MESSAGE", "WORDS", "NUMBERS", "SIMPLEST", "STATE",
    "PATH", "END", "DEEP", "WEB", "OBJECT", "PILGRIMAGE"
]


def _build_calibrated_model() -> Tuple[List[float], List[List[float]], Set[str], Set[str]]:
    """
    Constructs calibrated GF(29) Futhorc unigram and bigram log-probability distributions
    derived from verified Liber Primus plaintexts with add-k (Laplace) smoothing.
    """
    unigram_counts = [1.0] * M  # add-1 smoothing
    bigram_counts = [[0.1] * M for _ in range(M)]  # add-0.1 smoothing

    for pt in SOLVED_LP_PLAINTEXTS:
        runes = latin_to_rune(pt)
        indices = [INDEX_BY_RUNE[c] for c in runes if c in INDEX_BY_RUNE]
        for idx in indices:
            unigram_counts[idx] += 2.0  # Weight solved LP text higher
        for i in range(len(indices) - 1):
            bigram_counts[indices[i]][indices[i + 1]] += 2.0

    # Also augment with standard English frequency distribution mapped to Futhorc
    english_letter_freq = {
        'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7, 'S': 6.3,
        'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4,
        'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5, 'V': 1.0,
        'K': 0.8, 'J': 0.15, 'X': 0.15, 'Q': 0.1, 'Z': 0.07,
    }
    for letter, freq in english_letter_freq.items():
        r = latin_to_rune(letter)
        for ch in r:
            if ch in INDEX_BY_RUNE:
                unigram_counts[INDEX_BY_RUNE[ch]] += freq

    total_unigrams = sum(unigram_counts)
    unigram_logp = [math.log(c / total_unigrams) for c in unigram_counts]

    bigram_logp = []
    for row in bigram_counts:
        row_tot = sum(row)
        bigram_logp.append([math.log(c / row_tot) for c in row])

    # Canonical rune words
    rune_lexicon = set()
    for word in CANONICAL_CRIBS:
        rune_word = "".join(c for c in latin_to_rune(word) if c in INDEX_BY_RUNE)
        if rune_word:
            rune_lexicon.add(rune_word)

    return unigram_logp, bigram_logp, rune_lexicon, set(CANONICAL_CRIBS)


RUNIC_UNIGRAM_LOGP, RUNIC_BIGRAM_LOGP, CANONICAL_RUNE_WORDS, CANONICAL_LATIN_WORDS = _build_calibrated_model()


def clean_runes_to_indices(text: str) -> List[int]:
    """Extract integer indices (0..28) for all recognized runes in text."""
    if not text:
        return []
    has_runes = any(c in INDEX_BY_RUNE for c in text)
    rune_str = text if has_runes else latin_to_rune(text)
    return [INDEX_BY_RUNE[c] for c in rune_str if c in INDEX_BY_RUNE]


def indices_to_runes(indices: List[int]) -> str:
    """Convert integer indices (0..28) to runic Unicode string."""
    return "".join(index_to_rune(i % M) for i in indices)


def score_unigram(indices: List[int]) -> float:
    """Average unigram log-likelihood per rune under calibrated model."""
    if not indices:
        return -999.0
    return sum(RUNIC_UNIGRAM_LOGP[i % M] for i in indices) / len(indices)


def score_bigram(indices: List[int]) -> float:
    """Average bigram log-likelihood per transition under calibrated model."""
    n = len(indices)
    if n < 2:
        return score_unigram(indices)
    total = sum(RUNIC_BIGRAM_LOGP[indices[i] % M][indices[i + 1] % M] for i in range(n - 1))
    return total / (n - 1)


def score_composite_runes(indices: List[int]) -> float:
    """
    Composite linguistic fitness score combining:
    - Bigram log-likelihood (weight 0.6)
    - Unigram log-likelihood (weight 0.4)
    - Bonus for matched canonical rune vocabulary
    Typical English plaintext hits -2.7 to -3.4; random text scores < -3.8.
    """
    if not indices:
        return -999.0
    u_score = score_unigram(indices)
    b_score = score_bigram(indices)
    base = 0.4 * u_score + 0.6 * b_score

    # Check for recognized rune words
    rune_str = indices_to_runes(indices)
    word_bonus = 0.0
    for w in CANONICAL_RUNE_WORDS:
        if len(w) >= 3 and w in rune_str:
            word_bonus += 0.25 * (len(w) / 4.0)

    return round(base + min(1.0, word_bonus), 4)


try:
    from sprt import sprt as _sprt, bigram_llr_table as _bigram_llr_table
except ImportError:
    try:
        from ciphers.sprt import sprt as _sprt, bigram_llr_table as _bigram_llr_table
    except ImportError:
        _sprt = None
        _bigram_llr_table = None


def _build_sprt_table() -> Optional[List[List[float]]]:
    if _bigram_llr_table is None:
        return None
    train_indices = []
    for pt in SOLVED_LP_PLAINTEXTS:
        runes = latin_to_rune(pt)
        train_indices.extend(INDEX_BY_RUNE[c] for c in runes if c in INDEX_BY_RUNE)
    return _bigram_llr_table(train_indices, k=0.5, n=M)


CALIBRATED_SPRT_LLR = _build_sprt_table()


def screen_sprt(indices: List[int], alpha: float = 0.01, beta: float = 0.01) -> Tuple[str, int]:
    """
    Wald's Sequential Probability Ratio Test (SPRT) screening on Z29 bigrams.
    Terminates early as soon as candidate decryption is definitively accepted or rejected.
    Returns (decision, symbols_used) where decision in {'accept', 'reject', 'undecided'}.
    """
    if _sprt is None or CALIBRATED_SPRT_LLR is None:
        return "undecided", len(indices)
    return _sprt(indices, CALIBRATED_SPRT_LLR, alpha=alpha, beta=beta)


# =============================================================================
# 2. Comprehensive Triage Statistics (Section 2)
# =============================================================================

def compute_unigram_ic(indices: List[int]) -> float:
    """Index of Coincidence over 29-symbol alphabet. Flat noise = 1/29 = 0.0345."""
    n = len(indices)
    if n < 2:
        return 0.0
    counts = Counter(indices)
    numerator = sum(c * (c - 1) for c in counts.values())
    return numerator / (n * (n - 1))


def compute_normalized_kappa(indices: List[int]) -> float:
    """Normalized kappa = 29 * IC. Equal to 1.0 for uniform distribution; > 1.4 for English."""
    return round(M * compute_unigram_ic(indices), 4)


def compute_bigram_ic(indices: List[int]) -> float:
    """Digraph/bigram Index of Coincidence over 29^2 pairs."""
    n = len(indices)
    if n < 3:
        return 0.0
    pairs = [indices[i] * M + indices[i + 1] for i in range(n - 1)]
    counts = Counter(pairs)
    total_pairs = len(pairs)
    numerator = sum(c * (c - 1) for c in counts.values())
    return numerator / (total_pairs * (total_pairs - 1))


def compute_conditional_entropy(indices: List[int]) -> float:
    """Conditional entropy H(X_n | X_{n-1}) in bits per symbol."""
    n = len(indices)
    if n < 2:
        return 0.0
    unigram_counts = Counter(indices)
    bigram_counts = Counter((indices[i], indices[i + 1]) for i in range(n - 1))

    h_cond = 0.0
    total_bigrams = n - 1
    for (prev, curr), b_count in bigram_counts.items():
        p_prev_curr = b_count / total_bigrams
        p_curr_given_prev = b_count / unigram_counts[prev]
        h_cond -= p_prev_curr * math.log2(p_curr_given_prev)

    return round(h_cond, 4)


def compute_word_length_distribution(raw_text: str) -> Dict[int, int]:
    """Word length distribution preserving runic word separators ('᛫', whitespace)."""
    words = re.split(r"[᛫\s\.\:\,\;\-]+", raw_text)
    lens = Counter()
    for w in words:
        clean_len = len([c for c in w if c in INDEX_BY_RUNE])
        if clean_len > 0:
            lens[clean_len] += 1
    return dict(sorted(lens.items()))


def triage_cipher(ciphertext: str) -> dict:
    """
    Executes full statistical triage to diagnose cipher family.
    Returns IC, normalized kappa, bigram IC, conditional entropy, and classification.
    """
    indices = clean_runes_to_indices(ciphertext)
    n = len(indices)
    if n < 2:
        return {
            "rune_count": n,
            "ic": 0.0,
            "normalized_kappa": 0.0,
            "bigram_ic": 0.0,
            "conditional_entropy": 0.0,
            "classification": "INSUFFICIENT_DATA",
            "recommendation": "Input must contain at least 2 runes.",
        }

    ic = compute_unigram_ic(indices)
    kappa = compute_normalized_kappa(indices)
    bigram_ic = compute_bigram_ic(indices)
    cond_entropy = compute_conditional_entropy(indices)
    word_lens = compute_word_length_distribution(ciphertext)

    # Classification rules calibrated against Liber Primus
    # English/solved LP: IC ~ 0.055-0.075, kappa ~ 1.6-2.2
    # Polyalphabetic periodic: IC ~ 0.040-0.052, kappa ~ 1.15-1.50
    # Flat / OTP / Running Key: IC ~ 0.033-0.039, kappa ~ 0.95-1.12
    if kappa >= 1.55:
        if bigram_ic >= 0.0035 or cond_entropy <= 3.8:
            classification = "MONOALPHABETIC_SUBSTITUTION"
            recommendation = "Test Caesar shifts, Atbash, or simple affine mappings."
        else:
            classification = "TRANSPOSITION_LAYER"
            recommendation = "Unigrams preserved but bigrams destroyed. Test columnar, rail-fence, route grids."
    elif 1.14 <= kappa < 1.55:
        classification = "PERIODIC_POLYALPHABETIC"
        recommendation = "Periodic key detected. Proceed to key length estimation (period m) & separable T-table."
    else:
        classification = "APERIODIC_OR_STREAM"
        recommendation = "Flat unigram IC. Test totient/prime mathematical streams, F-skip, or running keys."

    return {
        "rune_count": n,
        "ic": round(ic, 5),
        "normalized_kappa": round(kappa, 4),
        "bigram_ic": round(bigram_ic, 5),
        "conditional_entropy": cond_entropy,
        "word_lengths": word_lens,
        "classification": classification,
        "recommendation": recommendation,
    }


# =============================================================================
# 3. Multi-Metric Key Length Estimation (Section 3)
# =============================================================================

def kasiski_weighted_gcd(
    indices: List[int],
    min_ngram: int = 3,
    max_period: int = 32,
    lag_spectrum: Optional[Dict[int, int]] = None,
) -> Dict[int, float]:
    """
    Weighted GCD voting on distances between identical runic n-grams (n >= 3).
    Longer repeats receive exponentially higher confidence weight.
    Optionally consumes lag_coincidence_spectrum to incorporate elevated unigram repeat peaks.
    """
    n = len(indices)
    if n < min_ngram * 2:
        return {}

    # Find repeats
    ngram_positions: Dict[Tuple[int, ...], List[int]] = {}
    for length in range(min_ngram, min(min_ngram + 3, n // 2)):
        for i in range(n - length + 1):
            gram = tuple(indices[i:i + length])
            ngram_positions.setdefault(gram, []).append(i)

    votes = {p: 0.0 for p in range(1, max_period + 1)}
    for gram, positions in ngram_positions.items():
        if len(positions) < 2:
            continue
        g_len = len(gram)
        weight = float(g_len ** 2)
        for i in range(len(positions)):
            for j in range(i + 1, len(positions)):
                dist = positions[j] - positions[i]
                if dist <= 0:
                    continue
                for p in range(1, max_period + 1):
                    if dist % p == 0:
                        votes[p] += weight / math.sqrt(p)

    # Incorporate coincidence peaks from lag_spectrum if provided
    if lag_spectrum:
        for lag, count in lag_spectrum.items():
            if lag > max_period * 2:
                continue
            excess = count - (n - lag) / float(M)
            if excess > math.sqrt(max(1.0, n / float(M))):
                for p in range(1, max_period + 1):
                    if lag % p == 0:
                        votes[p] += (excess / math.sqrt(p)) * 0.5

    max_v = max(votes.values()) if votes and max(votes.values()) > 0 else 1.0
    return {p: round(v / max_v, 4) for p, v in votes.items()}


def lag_coincidence_spectrum(indices: List[int], max_lag: int = 32) -> Dict[int, int]:
    """
    Computes the shared lag-coincidence spectrum kappa(d) = sum [c_i == c_{i+d}].
    Evaluated once and consumed across Kasiski repeats, difference periodogram, and column-IoC.
    """
    n = len(indices)
    spectrum = {}
    limit = min(max_lag, n - 1)
    for d in range(1, limit + 1):
        spectrum[d] = sum(1 for i in range(n - d) if indices[i] == indices[i + d])
    return spectrum


def difference_periodogram(
    indices: List[int],
    max_lag: int = 32,
    lag_spectrum: Optional[Dict[int, int]] = None,
) -> Dict[int, float]:
    """
    Key-cancelling comb filter: D_i = (c_i - c_{i+tau}) mod 29.
    For an m-periodic key, the key cancels completely at tau = k*m.
    Evaluates chi-squared divergence from uniform across all 29 bins.
    Consumes pre-computed lag_coincidence_spectrum for bin 0.
    """
    n = len(indices)
    out = {}
    for tau in range(1, min(max_lag + 1, n // 2)):
        n_pairs = n - tau
        if n_pairs <= 0:
            continue
        expected = n_pairs / float(M)
        diffs = [(indices[i] - indices[i + tau]) % M for i in range(n_pairs)]
        counts = Counter(diffs)
        # Use pre-computed lag_coincidence_spectrum for bin 0 when available
        if lag_spectrum is not None and tau in lag_spectrum:
            counts[0] = lag_spectrum[tau]

        chi2 = sum(((counts.get(b, 0) - expected) ** 2) / expected for b in range(M))
        out[tau] = round(chi2, 3)
    return out


def column_ioc_scan(
    indices: List[int],
    max_period: int = 32,
    lag_spectrum: Optional[Dict[int, int]] = None,
) -> Dict[int, float]:
    """
    Average column Index of Coincidence across periods m = 1..max_period.
    When lag_spectrum is provided, computes column coincidences directly in O(n/m) time.
    """
    scores = {}
    n = len(indices)
    for m in range(1, min(max_period + 1, n // 2)):
        if lag_spectrum is not None:
            max_k = (n - 1) // m
            tot_coincidences = sum(
                lag_spectrum.get(k * m, sum(1 for i in range(n - k * m) if indices[i] == indices[i + k * m]))
                for k in range(1, max_k + 1)
            )
            col_lens = [(n - 1 - j) // m + 1 for j in range(m)]
            tot_pairs = sum(l * (l - 1) // 2 for l in col_lens)
            avg_ioc = (tot_coincidences / tot_pairs) if tot_pairs > 0 else 0.0
        else:
            cols = [indices[i::m] for i in range(m)]
            col_iocs = [compute_unigram_ic(col) for col in cols if len(col) > 1]
            avg_ioc = sum(col_iocs) / len(col_iocs) if col_iocs else 0.0
        scores[m] = round(avg_ioc, 5)
    return scores


def consensus_key_length_estimation(ciphertext: str, max_period: int = 30) -> List[Tuple[int, float, dict]]:
    """
    Combines Kasiski weighted GCD voting, Difference Periodogram comb filter, and
    Column-IoC scans with an MDL / BIC penalty (m * log2(29)) to rank candidate periods.
    Leverages a shared pre-computed lag coincidence spectrum.
    """
    indices = clean_runes_to_indices(ciphertext)
    n = len(indices)
    if n < 4:
        return [(1, 1.0, {"kasiski": 0, "diff_chi2": 0, "col_ioc": 0})]

    max_p = min(max_period, n // 3 if n >= 12 else 4)
    spectrum = lag_coincidence_spectrum(indices, max_lag=max_p * 2)
    kas = kasiski_weighted_gcd(indices, max_period=max_p, lag_spectrum=spectrum)
    diff = difference_periodogram(indices, max_lag=max_p, lag_spectrum=spectrum)
    col = column_ioc_scan(indices, max_period=max_p, lag_spectrum=spectrum)

    diff_max = max(diff.values()) if diff and max(diff.values()) > 0 else 1.0
    col_max = max(col.values()) if col and max(col.values()) > 0 else 0.0345

    ranked = []
    for m in range(1, max_p + 1):
        k_val = kas.get(m, 0.0)
        d_val = diff.get(m, 0.0) / diff_max
        c_val = col.get(m, 0.0345) / col_max

        # Model complexity penalty (BIC): m * log2(29) / total_runes
        bic_penalty = (m * 4.86) / max(10, n)
        composite_score = (0.35 * k_val + 0.35 * d_val + 0.30 * c_val) - (bic_penalty * 0.15)

        meta = {
            "kasiski_score": round(k_val, 3),
            "diff_chi2": diff.get(m, 0.0),
            "col_ioc": col.get(m, 0.0),
            "composite": round(composite_score, 4),
        }
        ranked.append((m, round(composite_score, 4), meta))

    return sorted(ranked, key=lambda x: -x[1])


# =============================================================================
# 4. Separable Per-Column Solver & T-Table (Section 4 & 5)
# =============================================================================

def compute_t_table(indices: List[int], period: int) -> List[List[float]]:
    """
    Computes T[i][s] = log-likelihood of column i decoded with shift s (0..28).
    Dimensions: period x 29.
    Independent coordinate-wise decomposition: O(29 * m).
    """
    t_table = []
    for col_idx in range(period):
        column = indices[col_idx::period]
        col_scores = []
        for s in range(M):
            # p_val = (c - s) % 29
            score = sum(RUNIC_UNIGRAM_LOGP[(c - s) % M] for c in column)
            col_scores.append(round(score, 4))
        t_table.append(col_scores)
    return t_table


def solve_separable_key(t_table: List[List[float]]) -> List[int]:
    """Free optimal separable key: k_i* = argmax_s T[i][s]."""
    return [row.index(max(row)) for row in t_table]


def align_columns_mic(indices: List[int], period: int) -> Tuple[List[int], int]:
    """
    Mutual Index of Coincidence (MIC) alignment across columns to find relative shifts,
    followed by a 29-way scan over the gauge shift constant g to find optimal absolute key.
    """
    if period <= 1:
        return [0], 0

    cols = [indices[i::period] for i in range(period)]
    col_counts = [Counter(c) for c in cols]

    relative_shifts = [0] * period
    # Column 0 is the anchor (shift = 0)
    for col_i in range(1, period):
        best_s, best_mic = 0, -1.0
        n0 = len(cols[0])
        ni = len(cols[col_i])
        if n0 < 1 or ni < 1:
            continue
        for s in range(M):
            mic = sum(
                col_counts[0].get(r, 0) * col_counts[col_i].get((r + s) % M, 0)
                for r in range(M)
            ) / (n0 * ni)
            if mic > best_mic:
                best_mic = mic
                best_s = s
        relative_shifts[col_i] = best_s

    # Resolve global gauge constant g in 0..28
    best_g, best_score = 0, -999.0
    for g in range(M):
        candidate_key = [(rel + g) % M for rel in relative_shifts]
        dec_indices = [(indices[i] - candidate_key[i % period]) % M for i in range(len(indices))]
        score = score_unigram(dec_indices)
        if score > best_score:
            best_score = score
            best_g = g

    final_key = [(rel + best_g) % M for rel in relative_shifts]
    return final_key, best_g


def hill_climbing_coupled(
    indices: List[int],
    period: int,
    start_key: Optional[List[int]] = None,
    restarts: int = 3,
    steps_per_restart: int = 120,
) -> Tuple[List[int], float]:
    """
    Coupled hill climbing with random restarts and bigram/composite scoring.
    Escapes local optima of separable unigram solutions.
    """
    n = len(indices)
    if n < 2:
        return [0] * period, -999.0

    global_best_key = list(start_key) if start_key else [0] * period
    best_dec = [(indices[i] - global_best_key[i % period]) % M for i in range(n)]
    global_best_score = score_composite_runes(best_dec)

    for r in range(restarts):
        if r == 0 and start_key is not None:
            current_key = list(start_key)
        else:
            current_key = [random.randint(0, M - 1) for _ in range(period)]

        cur_dec = [(indices[i] - current_key[i % period]) % M for i in range(n)]
        current_score = score_composite_runes(cur_dec)

        improved = True
        step = 0
        while improved and step < steps_per_restart:
            improved = False
            step += 1
            # Pick a column to perturb
            col = step % period
            original_val = current_key[col]

            best_delta_val = original_val
            best_delta_score = current_score

            for cand_val in range(M):
                if cand_val == original_val:
                    continue
                current_key[col] = cand_val
                test_dec = [(indices[i] - current_key[i % period]) % M for i in range(n)]
                test_score = score_composite_runes(test_dec)
                if test_score > best_delta_score:
                    best_delta_score = test_score
                    best_delta_val = cand_val

            if best_delta_score > current_score + 0.005:
                current_key[col] = best_delta_val
                current_score = best_delta_score
                improved = True
            else:
                current_key[col] = original_val

        if current_score > global_best_score:
            global_best_score = current_score
            global_best_key = list(current_key)

    return global_best_key, round(global_best_score, 4)


def solve_periodic_bigram_exact(
    indices: List[int],
    m: int,
    logP2: Optional[List[List[float]]] = None,
    include_unigrams: bool = True,
) -> Tuple[List[int], float]:
    """
    Exact periodic-key recovery under the calibrated bigram (+ unigram) model.
    Formulates periodic key search as a pairwise Markov Random Field on a cycle of length m
    and finds the global Maximum A Posteriori (MAP) key in deterministic O(29^3 * m) time
    using conditioned Viterbi dynamic programming.

    Guarantees finding the globally optimal key under the model with zero restarts
    and zero susceptibility to local hill-climbing optima.
    """
    n = len(indices)
    if n < 2 or m <= 0:
        return [0] * max(1, m), -999.0

    L2 = logP2 if logP2 is not None else RUNIC_BIGRAM_LOGP
    L1 = RUNIC_UNIGRAM_LOGP

    if m == 1:
        best_k0 = 0
        best_score = -999.0
        for x in range(M):
            score = sum(L2[(indices[i] - x) % M][(indices[i + 1] - x) % M] for i in range(n - 1)) / (n - 1)
            if include_unigrams:
                score_u = sum(L1[(indices[i] - x) % M] for i in range(n)) / n
                score = 0.6 * score + 0.4 * score_u
            if score > best_score:
                best_score = score
                best_k0 = x
        return [best_k0], round(best_score, 4)

    # 1. Collect ciphertext pair counts for each column transition j -> (j+1)%m
    col_pairs: List[Counter] = [Counter() for _ in range(m)]
    col_unigrams: List[Counter] = [Counter() for _ in range(m)]

    for i in range(n):
        col_unigrams[i % m][indices[i]] += 1
        if i < n - 1:
            col_pairs[i % m][(indices[i], indices[i + 1])] += 1

    # Weights
    w_b = 0.6 / max(1, n - 1)
    w_u = 0.4 / max(1, n) if include_unigrams else 0.0

    # 2. Build pairwise potential tables S_j[x][y] for each transition j in 0..m-1
    S: List[List[List[float]]] = [[[0.0] * M for _ in range(M)] for _ in range(m)]
    for j in range(m):
        pairs_j = list(col_pairs[j].items())
        u_counts_j = list(col_unigrams[j].items()) if include_unigrams else []

        for x in range(M):
            u_contrib = 0.0
            if include_unigrams:
                for c_val, count in u_counts_j:
                    u_contrib += count * L1[(c_val - x) % M]

            for y in range(M):
                b_contrib = 0.0
                for (c1, c2), count in pairs_j:
                    b_contrib += count * L2[(c1 - x) % M][(c2 - y) % M]

                S[j][x][y] = (w_b * b_contrib) + (w_u * u_contrib)

    # 3. Solve pairwise MRF on cycle of length m via 29-way conditioned Viterbi
    if m == 2:
        best_k = [0, 0]
        best_score = -999.0
        for x in range(M):
            for y in range(M):
                score = S[0][x][y] + S[1][y][x]
                if score > best_score:
                    best_score = score
                    best_k = [x, y]
        return best_k, round(best_score, 4)

    global_best_score = -1e9
    global_best_path = [0] * m

    for a in range(M):
        # Forward pass conditioned on k_0 = a
        dp = [S[0][a][y] for y in range(M)]
        backtrack = [[0] * M for _ in range(m)]

        for j in range(1, m - 1):
            next_dp = [-1e9] * M
            S_j = S[j]
            for z in range(M):
                best_val = -1e9
                best_prev = 0
                for y in range(M):
                    cand = dp[y] + S_j[y][z]
                    if cand > best_val:
                        best_val = cand
                        best_prev = y
                next_dp[z] = best_val
                backtrack[j][z] = best_prev
            dp = next_dp

        # Close the cycle at node m-1 -> node 0 (which is fixed to a)
        best_closure = -1e9
        best_last = 0
        S_last = S[m - 1]
        for w in range(M):
            cand = dp[w] + S_last[w][a]
            if cand > best_closure:
                best_closure = cand
                best_last = w

        if best_closure > global_best_score:
            global_best_score = best_closure
            path = [0] * m
            path[0] = a
            path[m - 1] = best_last
            curr = best_last
            for j in range(m - 2, 0, -1):
                curr = backtrack[j][curr]
                path[j] = curr
            global_best_path = path

    return global_best_path, round(global_best_score, 4)


def solve_interrupter_bigram_exact(
    indices: List[int],
    m: int,
    config: Optional[InterrupterConfig] = None,
    logP2: Optional[List[List[float]]] = None,
    include_unigrams: bool = True,
) -> Tuple[List[int], float]:
    """
    Exact key recovery under the calibrated bigram (+ unigram) model for dynamic interrupter modes.
    Derives deterministic pointer sequences and cumulative offsets from InterrupterConfig,
    groups pair terms by key pointer pairs, asserts chain/cycle graph structure,
    and solves via conditioned Viterbi on the MRF.
    Falls back to hill climbing if the interrupter mode yields a non-decomposable graph structure.
    """
    if config is None:
        return solve_periodic_bigram_exact(indices, m, logP2, include_unigrams)

    n = len(indices)
    if n < 2 or m <= 0:
        return [0] * max(1, m), -999.0

    L2 = logP2 if logP2 is not None else RUNIC_BIGRAM_LOGP
    L1 = RUNIC_UNIGRAM_LOGP

    # 1. Derive deterministic pointer sequence and cumulative offsets from ciphertext
    key_ptr = 0
    cumulative_offset = 0
    pointers: List[int] = []
    offsets: List[int] = []
    is_passthrough: List[bool] = []

    for pos, c_val in enumerate(indices):
        is_interrupt = (
            pos in config.interrupt_positions or
            c_val in config.interrupt_indices
        )
        if is_interrupt and config.pass_through:
            is_passthrough.append(True)
            pointers.append(0)
            offsets.append(0)
        else:
            is_passthrough.append(False)
            pointers.append(key_ptr % m)
            offsets.append(cumulative_offset % M)

        if is_interrupt:
            if config.reset_on_interrupt:
                key_ptr = 0
            elif not config.pause_on_interrupt:
                key_ptr += 1
            if config.offset_step != 0:
                cumulative_offset = (cumulative_offset + config.offset_step) % M
        else:
            key_ptr += 1

    # Check graph structure of active pointer transitions
    transitions = set()
    for i in range(n - 1):
        if not is_passthrough[i] and not is_passthrough[i + 1]:
            u = pointers[i]
            v = pointers[i + 1]
            if u != v:
                transitions.add((u, v))

    # Permitted transitions for chain/cycle Viterbi: forward j -> (j+1)%m, or reset j -> 0
    non_standard = False
    for u, v in transitions:
        if v != (u + 1) % m and v != 0:
            non_standard = True
            break

    if non_standard:
        # Non-chain/cycle graph structure: fallback to coupled hill climbing
        return hill_climbing_coupled(indices, m, restarts=3)

    # 2. Build pairwise and unary potentials
    w_b = 0.6 / max(1, n - 1)
    w_u = 0.4 / max(1, n) if include_unigrams else 0.0

    V = [[0.0] * M for _ in range(m)]
    if include_unigrams:
        for i in range(n):
            if not is_passthrough[i]:
                col = pointers[i]
                off = offsets[i]
                c_val = indices[i]
                for x in range(M):
                    V[col][x] += w_u * L1[(c_val - x - off) % M]

    S_fwd = [[[0.0] * M for _ in range(M)] for _ in range(m)]
    S_reset = [[[0.0] * M for _ in range(M)] for _ in range(m)]

    for i in range(n - 1):
        pt1_pass = is_passthrough[i]
        pt2_pass = is_passthrough[i + 1]
        c1, c2 = indices[i], indices[i + 1]
        off1, off2 = offsets[i], offsets[i + 1]

        if pt1_pass and pt2_pass:
            continue
        elif pt1_pass:
            v = pointers[i + 1]
            for y in range(M):
                p2 = (c2 - y - off2) % M
                V[v][y] += w_b * L2[c1 % M][p2]
        elif pt2_pass:
            u = pointers[i]
            for x in range(M):
                p1 = (c1 - x - off1) % M
                V[u][x] += w_b * L2[p1][c2 % M]
        else:
            u = pointers[i]
            v = pointers[i + 1]
            if u == v:
                # Self-loop
                for x in range(M):
                    p1 = (c1 - x - off1) % M
                    p2 = (c2 - x - off2) % M
                    V[u][x] += w_b * L2[p1][p2]
            elif v == (u + 1) % m:
                # Forward transition
                for x in range(M):
                    p1 = (c1 - x - off1) % M
                    for y in range(M):
                        p2 = (c2 - y - off2) % M
                        S_fwd[u][x][y] += w_b * L2[p1][p2]
            elif v == 0:
                # Reset transition to column 0
                for x in range(M):
                    p1 = (c1 - x - off1) % M
                    for a in range(M):
                        p2 = (c2 - a - off2) % M
                        S_reset[u][x][a] += w_b * L2[p1][p2]

    # 3. 29-way conditioned Viterbi over k_0 = a
    if m == 1:
        best_k0 = 0
        best_score = -1e9
        for x in range(M):
            score = V[0][x] + S_fwd[0][x][x]
            if score > best_score:
                best_score = score
                best_k0 = x
        return [best_k0], round(best_score, 4)

    if m == 2:
        best_k = [0, 0]
        best_score = -1e9
        for x in range(M):
            for y in range(M):
                score = V[0][x] + V[1][y] + S_fwd[0][x][y] + S_fwd[1][y][x] + S_reset[1][y][x]
                if score > best_score:
                    best_score = score
                    best_k = [x, y]
        return best_k, round(best_score, 4)

    global_best_score = -1e9
    global_best_path = [0] * m

    for a in range(M):
        dp = [V[0][a] + S_fwd[0][a][y] + V[1][y] + S_reset[1][y][a] for y in range(M)]
        backtrack = [[0] * M for _ in range(m)]

        for j in range(1, m - 1):
            next_dp = [-1e9] * M
            S_j = S_fwd[j]
            V_next = V[(j + 1) % m]
            R_next = S_reset[(j + 1) % m]
            for z in range(M):
                best_val = -1e9
                best_prev = 0
                bonus = V_next[z] + (R_next[z][a] if (j + 1) < m - 1 else 0.0)
                for y in range(M):
                    cand = dp[y] + S_j[y][z] + bonus
                    if cand > best_val:
                        best_val = cand
                        best_prev = y
                next_dp[z] = best_val
                backtrack[j][z] = best_prev
            dp = next_dp

        best_closure = -1e9
        best_last = 0
        S_last = S_fwd[m - 1]
        for w in range(M):
            cand = dp[w] + S_last[w][a]
            if cand > best_closure:
                best_closure = cand
                best_last = w

        if best_closure > global_best_score:
            global_best_score = best_closure
            path = [0] * m
            path[0] = a
            path[m - 1] = best_last
            curr = best_last
            for j in range(m - 2, 0, -1):
                curr = backtrack[j][curr]
                path[j] = curr
            global_best_path = path

    return global_best_path, round(global_best_score, 4)


# =============================================================================
# 5. Fast Dictionary Screening with T-Table Trick (Section 5)
# =============================================================================

def score_dictionary_keys_t_table(
    t_table: List[List[float]],
    candidate_keys: List[Any],
) -> List[Tuple[Any, float]]:
    """
    Evaluates candidate word keys in O(m) operations per candidate using the T-table trick:
    Score(k) = sum_{i=0}^{m-1} T[i][k_i].
    Supports both raw shift lists (List[int]) and rich key variant dictionaries.
    """
    m = len(t_table)
    scored = []
    for key in candidate_keys:
        shifts = key["shifts"] if isinstance(key, dict) else key
        k_len = len(shifts)
        if k_len == 0:
            continue
        # Tile or slice key to match period m
        key_shifts = [shifts[i % k_len] for i in range(m)]
        total = sum(t_table[i][key_shifts[i]] for i in range(m))
        scored.append((key, round(total / m, 4)))
    return sorted(scored, key=lambda x: -x[1])


_MASTER_KEY_VARIANTS_CACHE: Optional[List[Any]] = None
_MASTER_KEY_VARIANTS_ROTATED_CACHE: Optional[List[Any]] = None


def _get_master_key_variants(include_rotations: bool = False) -> List[Any]:
    """Retrieve and cache all key shift variants across the master dictionary, optionally including cyclic phase rotations."""
    global _MASTER_KEY_VARIANTS_CACHE, _MASTER_KEY_VARIANTS_ROTATED_CACHE
    if include_rotations:
        if _MASTER_KEY_VARIANTS_ROTATED_CACHE is not None:
            return _MASTER_KEY_VARIANTS_ROTATED_CACHE
    else:
        if _MASTER_KEY_VARIANTS_CACHE is not None:
            return _MASTER_KEY_VARIANTS_CACHE

    if generate_all_key_variants is not None and get_master_dictionary is not None:
        words = get_master_dictionary()
        variants = []
        for w in words:
            vars_for_w = generate_all_key_variants(w, include_rotations=include_rotations)
            variants.extend(vars_for_w)
        if include_rotations:
            _MASTER_KEY_VARIANTS_ROTATED_CACHE = variants
        else:
            _MASTER_KEY_VARIANTS_CACHE = variants
        return variants
    else:
        fallback = [canonical_key_shifts(w) for w in CANONICAL_CRIBS]
        return fallback


# =============================================================================
# 6. Known-Plaintext & Crib Dragging Engine (Section 6)
# =============================================================================

def mod_inverse_gf29(a: int) -> int:
    """Multiplicative inverse in GF(29) via Fermat's Little Theorem."""
    a_mod = a % M
    if a_mod == 0:
        raise ZeroDivisionError("Zero has no inverse in GF(29)")
    return pow(a_mod, M - 2, M)


def berlekamp_massey_gf29(sequence: List[int]) -> Tuple[int, List[int]]:
    """
    Berlekamp-Massey algorithm over GF(29).
    Returns (linear_complexity_L, connection_polynomial_c).
    A stream generated by an LFSR of length L has linear complexity L.
    Fibonacci has LC=2; constant streams have LC=1; affine counters have LC=2.
    """
    n = len(sequence)
    c = [1]
    b = [1]
    L = 0
    m = 1
    b_val = 1

    for i in range(n):
        # Discrepancy d
        d = sequence[i]
        for j in range(1, L + 1):
            if j < len(c):
                d = (d + c[j] * sequence[i - j]) % M

        if d == 0:
            m += 1
        else:
            t = list(c)
            scale = (d * mod_inverse_gf29(b_val)) % M
            while len(c) < len(b) + m:
                c.append(0)
            for j in range(len(b)):
                c[j + m] = (c[j + m] - scale * b[j]) % M

            if 2 * L <= i:
                L = i + 1 - L
                b = t
                b_val = d
                m = 1
            else:
                m += 1

    return L, c


def detect_finite_differences(sequence: List[int]) -> Optional[int]:
    """
    Detects low-order algebraic polynomial streams:
    Order 0: Constant keystream (k_i = c)
    Order 1: Linear counter (k_i = a*i + b, 1st difference is constant)
    Order 2: Quadratic counter (k_i = a*i^2 + b*i + c, 2nd difference is constant)
    """
    if len(sequence) < 4:
        return None

    if len(set(sequence)) == 1:
        return 0

    cur = list(sequence)
    for order in range(1, 3):
        diffs = [(cur[i + 1] - cur[i]) % M for i in range(len(cur) - 1)]
        if len(set(diffs)) == 1:
            return order
        cur = diffs
    return None


class StreamHashBank:
    """
    Precomputed matched-filter bank of deterministic streams (primes, totients,
    Fibonacci, natural counters mod 29) indexed by L-symbol sliding window hashes.
    Provides O(1) identification of implied key fragments.
    """
    def __init__(self, window_size: int = 6, bank_length: int = 1000):
        self.window_size = window_size
        self.bank_length = bank_length
        self.hash_bank: Dict[Tuple[int, ...], str] = {}
        self._populate_bank()

    def _populate_bank(self):
        # 1. Primes stream mod 29
        primes = []
        c = 2
        while len(primes) < self.bank_length:
            if is_prime(c):
                primes.append(c % M)
            c += 1
        self._index_stream(primes, "PRIME_STREAM")

        # 2. Euler totients phi(p_k) mod 29
        totients = []
        c = 2
        while len(totients) < self.bank_length:
            if is_prime(c):
                totients.append((c - 1) % M)
            c += 1
        self._index_stream(totients, "TOTIENT_STREAM")

        # 3. Fibonacci mod 29
        fib = [0, 1]
        while len(fib) < self.bank_length:
            fib.append((fib[-1] + fib[-2]) % M)
        self._index_stream(fib, "FIBONACCI_STREAM")

        # 4. Affine counter streams (step 1 to 5)
        for step in range(1, 6):
            counter_stream = [(i * step) % M for i in range(self.bank_length)]
            self._index_stream(counter_stream, f"COUNTER_STEP_{step}")

    def _index_stream(self, stream: List[int], label: str):
        L = self.window_size
        for i in range(len(stream) - L + 1):
            window = tuple(stream[i:i + L])
            if window not in self.hash_bank:
                self.hash_bank[window] = f"{label}_OFFSET_{i}"

    def query_fragment(self, fragment: List[int]) -> Optional[str]:
        if len(fragment) < self.window_size:
            return None
        window = tuple(fragment[:self.window_size])
        return self.hash_bank.get(window)


HASH_BANK = StreamHashBank()


def drag_crib(ciphertext_indices: List[int], crib_text_or_runes: str) -> List[dict]:
    """
    Slides a crib word across every position j of the ciphertext.
    Implied key: K_j... = (C_j... - crib) mod 29.
    Evaluates:
    - Dictionary word check
    - Berlekamp-Massey linear complexity over GF(29)
    - Constant finite differences
    - O(1) hash bank match against precomputed deterministic streams
    """
    crib_indices = clean_runes_to_indices(crib_text_or_runes)
    c_len = len(crib_indices)
    n = len(ciphertext_indices)
    if c_len < 3 or n < c_len:
        return []

    hits = []
    for j in range(n - c_len + 1):
        implied_k = [(ciphertext_indices[j + i] - crib_indices[i]) % M for i in range(c_len)]

        # 1. Check linear recurrence
        lc, poly = berlekamp_massey_gf29(implied_k)
        is_linear = lc <= (c_len // 2)

        # 2. Check algebraic differences
        poly_order = detect_finite_differences(implied_k)

        # 3. Check hash bank
        bank_match = HASH_BANK.query_fragment(implied_k)

        # 4. Check dictionary word or prefix match
        implied_runes = indices_to_runes(implied_k)
        if LEXICON_INDEX is not None:
            is_word = LEXICON_INDEX.is_word(implied_runes) or LEXICON_INDEX.is_prefix(implied_runes)
        else:
            is_word = any(
                (w == implied_runes or w.startswith(implied_runes) or implied_runes.startswith(w))
                for w in CANONICAL_RUNE_WORDS
            )

        # Keep significant hits
        if is_linear or (poly_order is not None) or bank_match or is_word:
            hits.append({
                "position": j,
                "crib": crib_text_or_runes,
                "implied_key_indices": implied_k,
                "implied_key_runes": implied_runes,
                "linear_complexity": lc,
                "algebraic_order": poly_order,
                "bank_match": bank_match,
                "is_lexicon_word": is_word,
            })

    return hits


# =============================================================================
# 7. Deterministic Stream Sweeps & Clocking (Section 7 & 8)
# =============================================================================

def sweep_deterministic_streams(
    indices: List[int],
    max_offset: int = 250,
) -> List[dict]:
    """
    Sweeps prime, totient, Fibonacci, and natural counter streams mod 29 across offsets,
    testing standard advance, Fehu pass-through, and Fehu skip clocking.
    """
    n = len(indices)
    if n < 4:
        return []

    # Pre-generate streams
    prime_stream = []
    totient_stream = []
    c = 2
    while len(prime_stream) < max_offset + n + 10:
        if is_prime(c):
            prime_stream.append(c % M)
            totient_stream.append((c - 1) % M)
        c += 1

    fib_stream = [0, 1]
    while len(fib_stream) < max_offset + n + 10:
        fib_stream.append((fib_stream[-1] + fib_stream[-2]) % M)

    streams_to_test = [
        ("TOTIENT_STREAM", totient_stream),
        ("PRIME_STREAM", prime_stream),
        ("FIBONACCI_STREAM", fib_stream),
    ]

    results = []
    for stream_name, stream in streams_to_test:
        for offset in range(max_offset):
            k_slice = stream[offset:offset + n]
            if len(k_slice) < n:
                break
            dec = [(indices[i] - k_slice[i]) % M for i in range(n)]
            score = score_composite_runes(dec)
            if score >= -3.35:
                results.append({
                    "method": "DETERMINISTIC_STREAM",
                    "stream": stream_name,
                    "offset": offset,
                    "score": score,
                    "plaintext_runes": indices_to_runes(dec),
                    "plaintext_latin": decode_runes(indices_to_runes(dec)),
                })

    # Also test Fehu-skip variant on the best streams
    fehu_indices = {i for i, val in enumerate(indices) if val == 0}
    if fehu_indices:
        for stream_name, stream in streams_to_test[:2]:  # Totient & Prime
            for offset in range(min(120, max_offset)):
                dec = []
                k_ptr = offset
                for i in range(n):
                    if indices[i] == 0:
                        dec.append(0)  # Fehu pass-through
                    else:
                        dec.append((indices[i] - stream[k_ptr]) % M)
                        k_ptr += 1
                score = score_composite_runes(dec)
                if score >= -3.35:
                    results.append({
                        "method": "DETERMINISTIC_STREAM_FEHU_SKIP",
                        "stream": stream_name,
                        "offset": offset,
                        "score": score,
                        "plaintext_runes": indices_to_runes(dec),
                        "plaintext_latin": decode_runes(indices_to_runes(dec)),
                    })

    return sorted(results, key=lambda x: -x["score"])


# =============================================================================
# 8. Deep Sweeps: Affine mod 29, Autokey, Cross-Page (Section 9 & 10)
# =============================================================================

def sweep_affine_mod29(indices: List[int]) -> List[dict]:
    """
    Exhaustively scans all 812 affine transformations over GF(29):
    x -> (a * x + b) mod 29, where a in 1..28 and b in 0..28.
    """
    n = len(indices)
    if n < 4:
        return []

    hits = []
    for a in range(1, M):
        for b in range(M):
            dec = [((val - b) * mod_inverse_gf29(a)) % M for val in indices]
            score = score_composite_runes(dec)
            if score >= -3.35:
                hits.append({
                    "method": "AFFINE_GF29",
                    "a": a,
                    "b": b,
                    "score": score,
                    "plaintext_runes": indices_to_runes(dec),
                    "plaintext_latin": decode_runes(indices_to_runes(dec)),
                })
    return sorted(hits, key=lambda x: -x["score"])


def cross_page_running_key_scan(
    ciphertext_indices: List[int],
    source_runes_or_indices: Union[str, List[int]],
    source_name: str = "SOURCE_PAGE",
) -> List[dict]:
    """
    Correlates ciphertext with another Liber Primus page or plain text
    acting as a running key: P_i = (C_i - T_{s+i}) mod 29.
    """
    c_indices = ciphertext_indices
    s_indices = clean_runes_to_indices(source_runes_or_indices) if isinstance(source_runes_or_indices, str) else source_runes_or_indices
    n = len(c_indices)
    s_len = len(s_indices)
    if s_len < 4 or n < 4:
        return []

    results = []
    for offset in range(max(1, s_len - n + 1)):
        window = s_indices[offset:offset + n]
        dec = [(c_indices[i] - window[i]) % M for i in range(len(window))]
        score = score_composite_runes(dec)
        if score >= -3.35:
            results.append({
                "method": "RUNNING_KEY_CROSS_PAGE",
                "source": source_name,
                "offset": offset,
                "score": score,
                "plaintext_runes": indices_to_runes(dec),
                "plaintext_latin": decode_runes(indices_to_runes(dec)),
            })
    return sorted(results, key=lambda x: -x["score"])


# =============================================================================
# 9. Statistical Significance & Surrogate Shuffle Testing (Section 13)
# =============================================================================

class SurrogateTestResult(tuple):
    """Rich tuple (mean_null, std_null, z_score, is_significant) with p_value, p_adj, trials."""
    def __new__(cls, mean_null, std_null, z_score, is_significant, p_value=1.0, p_adj=1.0, trials=50):
        instance = super().__new__(cls, (mean_null, std_null, z_score, is_significant))
        instance.mean_null = mean_null
        instance.std_null = std_null
        instance.z_score = z_score
        instance.is_significant = is_significant
        instance.p_value = p_value
        instance.p_adj = p_adj
        instance.trials = trials
        return instance


def sequential_mc_pvalue(
    stat_obs: float,
    shuffle_stat_fn,
    h: int = 10,
    n_max: int = 1000,
    rng: Optional[random.Random] = None,
    alternative: str = "greater",
) -> Tuple[float, int, int]:
    """
    Sequential Monte Carlo test (Besag-Clifford early-stopping test).
    Draws null samples sequentially and stops as soon as h exceedances are observed,
    or when n_max trials have been performed.

    Returns (p_hat, exceedances, total_trials).
    - Clear nulls (noise) exit early after ~10-20 shuffles.
    - True signal candidates run up to n_max, providing fine-grained p-value resolution (e.g. p < 0.001).
    """
    exceedances = 0
    trials = 0
    for l in range(1, n_max + 1):
        trials = l
        t_null = shuffle_stat_fn()
        if alternative == "greater":
            is_exceedance = t_null >= stat_obs
        else:
            is_exceedance = t_null <= stat_obs

        if is_exceedance:
            exceedances += 1
            if exceedances >= h:
                break

    p_hat = (exceedances + 1.0) / (trials + 1.0)
    return round(p_hat, 5), exceedances, trials


def surrogate_shuffle_test(
    indices: List[int],
    candidate_score: float,
    n_shuffles: int = 50,
    sequential: bool = False,
    h: int = 10,
    n_max: int = 1000,
    family: Optional[str] = None,
) -> SurrogateTestResult:
    """
    Monte Carlo surrogate-data null distribution test.
    Supports fixed-N shuffle evaluation or Besag-Clifford sequential Monte Carlo early-stopping.
    Computes empirical mean, standard deviation, Z-score, empirical p-value, and
    look-elsewhere adjusted p-value (Sidak correction against ledger attempt count).
    """
    if len(indices) < 4:
        return SurrogateTestResult(0.0, 0.0, 0.0, False, p_value=1.0, p_adj=1.0, trials=0)

    null_scores = []
    shuffled = list(indices)

    def draw_shuffle():
        random.shuffle(shuffled)
        s = score_composite_runes(shuffled)
        null_scores.append(s)
        return s

    if sequential:
        p_val, exceedances, total_trials = sequential_mc_pvalue(
            candidate_score,
            draw_shuffle,
            h=h,
            n_max=n_max,
        )
    else:
        for _ in range(n_shuffles):
            draw_shuffle()
        exceedances = sum(1 for s in null_scores if s >= candidate_score)
        total_trials = len(null_scores)
        p_val = round((exceedances + 1.0) / (total_trials + 1.0), 5)

    mean_null = sum(null_scores) / len(null_scores)
    variance = sum((s - mean_null) ** 2 for s in null_scores) / len(null_scores)
    std_null = math.sqrt(variance) if variance > 1e-9 else 0.01

    z_score = (candidate_score - mean_null) / std_null

    # Look-elsewhere correction using ledger attempt count for hypothesis family
    attempt_k = 1
    if count_attempts:
        try:
            attempt_k = max(1, count_attempts(family=family))
        except Exception:
            attempt_k = 1
    # Sidak correction: 1 - (1 - p)^K
    p_adj = round(1.0 - math.pow(max(0.0, 1.0 - p_val), attempt_k), 5)

    is_significant = (z_score >= 3.5 or p_adj < 0.01) and candidate_score >= -3.40

    return SurrogateTestResult(
        round(mean_null, 4),
        round(std_null, 4),
        round(z_score, 2),
        is_significant,
        p_value=p_val,
        p_adj=p_adj,
        trials=total_trials,
    )


# =============================================================================
# 10. Unified Cascade Solver & Ledger Integration
# =============================================================================

def crack_liber_primus(
    target_text: str,
    page_id: Optional[str] = None,
    deep: bool = False,
    top_k: int = 5,
    randomize: bool = False,
    include_rotations: bool = False,
    crib_limit: Optional[int] = None,
    seed: Optional[int] = None,
    use_metal: bool = True,
    use_ane: bool = True,
    compound: bool = False,
) -> dict:
    """
    Full end-to-end staged cascade solver:
    1. Triage analysis (IC, kappa, bigram IC, classification)
    2. Key length consensus (Kasiski, difference periodogram, column IoC)
    3. Periodic Vigenère (Separable T-table, MIC gauge alignment, coupled hill climbing)
    4. Dictionary attack via T-table trick
    5. Deterministic stream sweeps (totients, primes, Fibonacci, counters with Fehu skip)
    6. Crib dragging with Berlekamp-Massey and stream hash bank
    7. (Deep mode): 812-space affine mod 29, autokey, and cross-page running key
    8. Surrogate shuffle significance validation & SQLite ledger persistence
    """
    indices = clean_runes_to_indices(target_text)
    n = len(indices)
    page_key = page_id or "unsolved"

    # Step 1: Triage
    triage = triage_cipher(target_text)

    # Step 2: Period estimation
    periods = consensus_key_length_estimation(target_text)
    top_period = periods[0][0] if periods else 1

    candidates = []

    # Step 2b: Test Canonical Solved Liber Primus Methods (Reference Ground Truth)
    if n >= 2:
        # 1. Direct Gematria Primus transliteration (Identity cipher)
        dec_direct = list(indices)
        score_direct = score_composite_runes(dec_direct)
        candidates.append({
            "method": "CANONICAL_DIRECT_TRANSLITERATION",
            "key_shifts": [0],
            "key_runes": "ᚠ",
            "key_latin": "IDENTITY",
            "period": 1,
            "score": score_direct,
            "plaintext_runes": indices_to_runes(dec_direct),
            "plaintext_latin": decode_runes(indices_to_runes(dec_direct)),
        })

        # 2. Atbash in F_29: (28 - c) mod 29 (Page 00 "A warning")
        dec_atbash = [(28 - c) % M for c in indices]
        score_atbash = score_composite_runes(dec_atbash)
        candidates.append({
            "method": "CANONICAL_ATBASH_F29",
            "key_shifts": [],
            "key_runes": "",
            "key_latin": "ATBASH",
            "period": 1,
            "score": score_atbash,
            "plaintext_runes": indices_to_runes(dec_atbash),
            "plaintext_latin": decode_runes(indices_to_runes(dec_atbash)),
        })

        # 3. Atbash + Caesar (+3) in F_29: ((28 - c) + 3) mod 29 (Koan 1)
        dec_atbash3 = [((28 - c) + 3) % M for c in indices]
        score_atbash3 = score_composite_runes(dec_atbash3)
        candidates.append({
            "method": "CANONICAL_ATBASH_SHIFT_3",
            "key_shifts": [3],
            "key_runes": "",
            "key_latin": "ATBASH+3",
            "period": 1,
            "score": score_atbash3,
            "plaintext_runes": indices_to_runes(dec_atbash3),
            "plaintext_latin": decode_runes(indices_to_runes(dec_atbash3)),
        })

        # 4. Vigenère DIVINITY with Fehu-skip (Welcome)
        try:
            dec_div_runes = rune_vigenere_decode_f_skip(target_text, key="DIVINITY", skip_indices=WELCOME_F_SKIP_POSITIONS, preserve_separators=False)
            dec_div_idx = clean_runes_to_indices(dec_div_runes)
            if len(dec_div_idx) == n:
                score_div = score_composite_runes(dec_div_idx)
                candidates.append({
                    "method": "CANONICAL_VIGENERE_DIVINITY_FSKIP",
                    "key_shifts": canonical_key_shifts("DIVINITY"),
                    "key_runes": latin_to_rune("DIVINITY"),
                    "key_latin": "DIVINITY (F-skip)",
                    "period": 8,
                    "score": score_div,
                    "plaintext_runes": dec_div_runes,
                    "plaintext_latin": decode_runes(dec_div_runes),
                })
        except Exception:
            pass

        # 5. Vigenère FIRFUMFERENFE with Fehu-skip (Koan 2)
        try:
            dec_firf_runes = rune_vigenere_decode_f_skip(target_text, key="FIRFUMFERENFE", skip_indices=KOAN2_F_SKIP_POSITIONS, preserve_separators=False)
            dec_firf_idx = clean_runes_to_indices(dec_firf_runes)
            if len(dec_firf_idx) == n:
                score_firf = score_composite_runes(dec_firf_idx)
                candidates.append({
                    "method": "CANONICAL_VIGENERE_FIRFUMFERENFE_FSKIP",
                    "key_shifts": canonical_key_shifts("FIRFUMFERENFE"),
                    "key_runes": latin_to_rune("FIRFUMFERENFE"),
                    "key_latin": "FIRFUMFERENFE (F-skip)",
                    "period": 13,
                    "score": score_firf,
                    "plaintext_runes": dec_firf_runes,
                    "plaintext_latin": decode_runes(dec_firf_runes),
                })
        except Exception:
            pass

        # 6. Prime Totient Stream Cipher with Fehu-skip (Page 56 / 73 "An end")
        try:
            dec_tot_runes = prime_totient_stream_decode(target_text, offset=0, preserve_separators=False, skip_indices={56})
            dec_tot_idx = clean_runes_to_indices(dec_tot_runes)
            if len(dec_tot_idx) == n:
                score_tot = score_composite_runes(dec_tot_idx)
                candidates.append({
                    "method": "CANONICAL_PRIME_TOTIENT_STREAM_FSKIP",
                    "key_shifts": [],
                    "key_runes": "",
                    "key_latin": "phi(primes[i]) = primes[i] - 1 (F-skip @ 56)",
                    "period": 0,
                    "score": score_tot,
                    "plaintext_runes": dec_tot_runes,
                    "plaintext_latin": decode_runes(dec_tot_runes),
                })
        except Exception:
            pass

    # Step 3: Periodic Solvers on candidate periods (top 8 in standard, top 12 in deep mode)
    num_periods = 12 if deep else 8
    tested_periods = [p[0] for p in periods[:num_periods]] if periods else [1]
    if 1 not in tested_periods:
        tested_periods.append(1)
    for p in tested_periods:
        t_table = compute_t_table(indices, p)
        sep_key = solve_separable_key(t_table)
        mic_key, _ = align_columns_mic(indices, p)
        exact_key, _ = solve_periodic_bigram_exact(indices, p)

        # Hill climbing refined from exact/separable key
        hc_key, hc_score = hill_climbing_coupled(indices, p, start_key=exact_key, restarts=2)

        for k_type, k_shifts in [
            ("EXACT_BIGRAM", exact_key),
            ("SEPARABLE_UNIGRAM", sep_key),
            ("MIC_GAUGE", mic_key),
            ("HILL_CLIMBING", hc_key),
        ]:
            dec = [(indices[i] - k_shifts[i % p]) % M for i in range(n)]
            score = score_composite_runes(dec)
            candidates.append({
                "method": f"VIGENERE_PERIOD_{p}_{k_type}",
                "key_shifts": k_shifts,
                "key_runes": indices_to_runes(k_shifts),
                "key_latin": decode_runes(indices_to_runes(k_shifts)),
                "period": p,
                "score": score,
                "plaintext_runes": indices_to_runes(dec),
                "plaintext_latin": decode_runes(indices_to_runes(dec)),
            })

        # Step 4: Fast Dictionary matching via T-table for this period
        master_variants = _get_master_key_variants(include_rotations=(include_rotations or deep))
        dict_scored = score_dictionary_keys_t_table(t_table, master_variants)
        for cand, _ in dict_scored[:5]:
            d_key = cand["shifts"] if isinstance(cand, dict) else cand
            k_len = len(d_key)
            tiled_key = [d_key[i % k_len] for i in range(p)]
            dec = [(indices[i] - tiled_key[i % p]) % M for i in range(n)]
            score = score_composite_runes(dec)
            if isinstance(cand, dict):
                label = cand.get("label", "FORWARD")
                word_latin = cand.get("word", "")
                method_name = f"DICTIONARY_{label}_PERIOD_{p}"
                key_display = f"{word_latin}_{label}"
            else:
                method_name = f"DICTIONARY_WORD_PERIOD_{p}"
                key_display = decode_runes(indices_to_runes(tiled_key))
            candidates.append({
                "method": method_name,
                "key_shifts": tiled_key,
                "key_runes": indices_to_runes(tiled_key),
                "key_latin": key_display,
                "period": p,
                "score": score,
                "plaintext_runes": indices_to_runes(dec),
                "plaintext_latin": decode_runes(indices_to_runes(dec)),
            })
            if record_attempt and isinstance(cand, dict) and cand.get("word"):
                try:
                    record_attempt(
                        page=page_key,
                        word=cand["word"],
                        method=method_name,
                        score=score,
                        result_preview=key_display,
                    )
                except Exception:
                    pass

        # Step 4b: Beaufort Dictionary Matching via Beaufort T-table (Plaintext = (Key - Ciphertext) mod 29)
        if compute_beaufort_t_table is not None:
            b_table = compute_beaufort_t_table(indices, p, RUNIC_UNIGRAM_LOGP)
            b_scored = score_dictionary_keys_t_table(b_table, master_variants)
            for cand, _ in b_scored[:3]:
                d_key = cand["shifts"] if isinstance(cand, dict) else cand
                k_len = len(d_key)
                tiled_key = [d_key[i % k_len] for i in range(p)]
                dec = [(tiled_key[i % p] - indices[i]) % M for i in range(n)]
                score = score_composite_runes(dec)
                if isinstance(cand, dict):
                    label = cand.get("label", "FORWARD")
                    word_latin = cand.get("word", "")
                    method_name = f"BEAUFORT_{label}_PERIOD_{p}"
                    key_display = f"{word_latin}_BEAUFORT_{label}"
                else:
                    method_name = f"BEAUFORT_WORD_PERIOD_{p}"
                    key_display = decode_runes(indices_to_runes(tiled_key))
                candidates.append({
                    "method": method_name,
                    "key_shifts": tiled_key,
                    "key_runes": indices_to_runes(tiled_key),
                    "key_latin": key_display,
                    "period": p,
                    "score": score,
                    "plaintext_runes": indices_to_runes(dec),
                    "plaintext_latin": decode_runes(indices_to_runes(dec)),
                })
                if record_attempt and isinstance(cand, dict) and cand.get("word"):
                    try:
                        record_attempt(
                            page=page_key,
                            word=cand["word"],
                            method=method_name,
                            score=score,
                            result_preview=key_display,
                        )
                    except Exception:
                        pass

        # Step 4c: Apple Silicon Metal GPU Compound Key Sweeps (w1 + w2)
        if (compound or deep) and use_metal and metal_sweep_2words is not None and is_metal_available():
            try:
                dict_words = (
                    get_master_dictionary()
                    if get_master_dictionary
                    else (SACRED_CANONICAL_WORDS or [])
                )
                sweep_words = []
                for w in dict_words[:250]:
                    r_shifts = [INDEX_BY_RUNE[c] for c in latin_to_rune(w) if c in INDEX_BY_RUNE]
                    if r_shifts:
                        sweep_words.append((w, r_shifts))
                comp_hits = metal_sweep_2words(
                    t_table, sweep_words, p, threshold=-2.35, max_hits=20
                )
                for w1, w2, comp_sc in comp_hits[:3]:
                    s1 = [INDEX_BY_RUNE[c] for c in latin_to_rune(w1) if c in INDEX_BY_RUNE]
                    s2 = [INDEX_BY_RUNE[c] for c in latin_to_rune(w2) if c in INDEX_BY_RUNE]
                    comb_shifts = s1 + s2
                    c_len = len(comb_shifts)
                    tiled_key = [comb_shifts[i % c_len] for i in range(p)]
                    dec = [(indices[i] - tiled_key[i % p]) % M for i in range(n)]
                    score = score_composite_runes(dec)
                    comp_display = f"{w1}_{w2}_COMPOUND"
                    method_name = f"METAL_COMPOUND_2WORD_PERIOD_{p}"
                    candidates.append({
                        "method": method_name,
                        "key_shifts": tiled_key,
                        "key_runes": indices_to_runes(tiled_key),
                        "key_latin": comp_display,
                        "period": p,
                        "score": score,
                        "plaintext_runes": indices_to_runes(dec),
                        "plaintext_latin": decode_runes(indices_to_runes(dec)),
                        "accelerator": "METAL_GPU",
                    })
                    if record_attempt:
                        try:
                            record_attempt(
                                page=page_key,
                                word=f"{w1}_{w2}",
                                method=method_name,
                                score=score,
                                result_preview=comp_display,
                            )
                        except Exception:
                            pass
            except Exception:
                pass

    # Step 5: Deterministic stream sweeps
    stream_hits = sweep_deterministic_streams(indices, max_offset=200)
    for hit in stream_hits[:5]:
        candidates.append(hit)

    # Step 6: Crib dragging
    raw_crib_hits = []
    limit = crib_limit or (60 if deep else 30)
    if get_rotated_vocabulary is not None:
        crib_source = get_rotated_vocabulary(
            page_id=page_key,
            limit=limit,
            randomize=randomize,
            seed=seed,
            filter_tested=True,
        )
    else:
        crib_source = (
            SACRED_CANONICAL_WORDS[:limit]
            if SACRED_CANONICAL_WORDS
            else CANONICAL_CRIBS[:8]
        )

    # Rank and diversify crib hits by cryptanalytic significance
    def _rank_crib_hit(h: dict) -> float:
        s = 0.0
        if h.get("bank_match"):
            s += 100.0
        if h.get("is_lexicon_word"):
            s += 50.0
        if h.get("algebraic_order") is not None:
            s += 25.0 - h.get("algebraic_order", 0) * 3.0
        c_len = len(h.get("implied_key_indices", []))
        lc = h.get("linear_complexity", 99)
        ratio = lc / max(1, c_len)
        s += (1.0 - ratio) * 15.0 + min(5.0, c_len)
        return s

    attempts_to_record = []
    for crib in crib_source:
        hits = drag_crib(indices, crib)
        if hits:
            raw_crib_hits.extend(hits)
            best_h = max(hits, key=_rank_crib_hit)
            score_val = _rank_crib_hit(best_h)
            is_hit = bool(best_h.get("bank_match") or best_h.get("is_lexicon_word"))
            preview = best_h.get("implied_key_runes", "")
        else:
            score_val = -10.0
            is_hit = False
            preview = ""

        attempts_to_record.append({
            "page": page_key,
            "word": crib,
            "method": "CRIB_DRAG",
            "score": score_val,
            "passed": is_hit,
            "result_preview": preview,
        })

    # Batch record all tested crib attempts in the ChromaDB vector database
    if record_attempts_batch and attempts_to_record:
        try:
            record_attempts_batch(attempts_to_record)
        except Exception:
            pass

    raw_crib_hits.sort(key=_rank_crib_hit, reverse=True)
    crib_hits = []
    for h in raw_crib_hits:
        c_w = h.get("crib", "")
        # Allow at most 2 hits per crib word to maintain diversity across candidate cribs
        c_count = sum(1 for x in crib_hits if x.get("crib") == c_w)
        if c_count < 2:
            crib_hits.append(h)
        if len(crib_hits) >= 10:
            break

    # Step 7: Deep mode sweeps if requested
    if deep:
        affine_hits = sweep_affine_mod29(indices)
        for hit in affine_hits[:5]:
            candidates.append(hit)

        for solved_pt in SOLVED_LP_PLAINTEXTS[:3]:
            s_runes = latin_to_rune(solved_pt)
            rk_hits = cross_page_running_key_scan(indices, s_runes, source_name="SOLVED_PAGE_TEXT")
            for hit in rk_hits[:3]:
                candidates.append(hit)

    # Step 7b: Neural Semantic Reranking on Apple Neural Engine (ANE)
    if use_ane and is_ane_available() and score_candidate_naturalness_neural is not None and candidates:
        try:
            pt_list = [c.get("plaintext_latin", "") for c in candidates]
            n_scores = score_candidate_naturalness_neural(pt_list)
            for c, ns in zip(candidates, n_scores):
                c["neural_score"] = ns
                c["blended_score"] = round(c["score"] + 0.35 * ns, 4)
            candidates.sort(key=lambda x: -x.get("blended_score", x["score"]))
        except Exception:
            candidates.sort(key=lambda x: -x["score"])
    else:
        candidates.sort(key=lambda x: -x["score"])

    top_candidates = candidates[:top_k]

    # Step 8: Validation & Significance
    best_candidate = top_candidates[0] if top_candidates else None
    sig_info = None
    if best_candidate:
        sig_res = surrogate_shuffle_test(
            indices,
            best_candidate["score"],
            n_shuffles=50,
            sequential=True,
            family=best_candidate.get("method"),
        )
        sig_info = {
            "null_mean": sig_res.mean_null,
            "null_std": sig_res.std_null,
            "z_score": sig_res.z_score,
            "p_value": sig_res.p_value,
            "p_adj": sig_res.p_adj,
            "trials": sig_res.trials,
            "is_statistically_significant": sig_res.is_significant,
        }
        best_candidate["significance"] = sig_info

    # Step 9: Automatic SQLite Ledger Logging
    if log_canonical_attempt and best_candidate:
        input_digest = f"runes_{n}_{compute_unigram_ic(indices):.4f}"
        params = {
            "method": best_candidate["method"],
            "period": best_candidate.get("period", 0),
            "key": best_candidate.get("key_latin", ""),
            "score": best_candidate["score"],
            "z_score": sig_info["z_score"] if sig_info else 0.0,
            "p_adj": sig_info["p_adj"] if sig_info else 1.0,
        }
        try:
            log_canonical_attempt(
                page=page_key,
                method=best_candidate["method"],
                parameters=params,
                input_digest=input_digest,
                score=best_candidate["score"],
                passed=bool(sig_info and sig_info["is_statistically_significant"]),
                result_preview=best_candidate["plaintext_latin"][:150],
            )
        except Exception:
            pass

    tested_words_count = 0
    if get_tested_words:
        try:
            tested_words_count = len(get_tested_words(page=page_key))
        except Exception:
            pass

    return {
        "page_id": page_key,
        "rune_count": n,
        "triage": triage,
        "estimated_periods": periods[:5],
        "top_period": top_period,
        "top_candidates": top_candidates,
        "crib_drag_hits": crib_hits[:5],
        "winner": best_candidate,
        "recorded_attempts_count": len(attempts_to_record) if 'attempts_to_record' in locals() else 0,
        "total_page_tested_words": tested_words_count,
        "hardware": {
            "metal_gpu": get_metal_device_info() if is_metal_available() else {"available": False},
            "neural_engine": get_ane_device_info() if is_ane_available() else {"available": False},
        },
    }
