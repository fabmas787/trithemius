# Conversation Carry-Over: Candidate Ranking, Z-Scores & False-Positive Mitigation

**Date:** 2026-11-24  
**Workspace:** `/Users/fabio/Downloads/trithemius-cicada`  
**Python Environment:** `./venv/bin/python` (Python 3.11; system `python3` is 3.7 and fails on `@dataclass(slots=True)` and `frozenset[str]` type hints).

---

## 1. How Candidates Are Ordered

- **Fitness Metric (`ciphers/taxonomy.py` — `score_composite_runes`):** Combines `0.4 * score_unigram(indices) + 0.6 * score_bigram(indices)` plus up to `+1.0` in bonus points for recognized `CANONICAL_RUNE_WORDS` of length ≥ 3. Typical English plaintext scores `-2.7` to `-3.4`; random text scores `< -3.8`.
- **Sorting (`ciphers/taxonomy.py` — `crack_liber_primus`, lines 2300–2313):**
  - Default: sorted descending by `score` (`candidates.sort(key=lambda x: -x["score"])`), keeping `top_k` as `top_candidates` (`top_candidates[0]` = `winner`).
  - When Apple Neural Engine scoring is enabled and available (`use_ane and is_ane_available()`): sorted descending by `blended_score = round(c["score"] + 0.35 * neural_score, 4)`.
- **Running-Key Scanner (`ciphers/running_key.py`, lines 319–321):** Sorts `scored_offsets` descending by `score_composite_runes`.
- **TUI Leaderboard (`workstation/ui/tui_dashboard.py`):** Live `CandidateEvent` rows append in discovery order while running; on completion, `_display_cascade_summary` clears the table and repopulates `top_candidates` in sorted rank order.

---

## 2. What the Z-Score Means

$$Z = \frac{\text{Score} - \mu_{\text{null}}}{\sigma_{\text{null}}}$$

- **Null Baseline (`ciphers/taxonomy.py` — `surrogate_shuffle_test`, lines 1653–1728):** Randomly shuffles ciphertext `indices` (preserving unigram frequencies while destroying bigram/word order) and scores each permutation with `score_composite_runes` to get `mean_null` and `std_null` (floored at `0.01`).
- **Two Computation Stages in `crack_liber_primus`:**
  1. **Phase 2 real-time baseline (lines 1831–1859):** Runs `n_shuffles=30` (fallback `null_mean = -3.45`, `null_std = 0.15`) to assign an immediate `z_score` to every registered candidate.
  2. **Phase 10 final validation (lines 2322–2357):** Re-evaluates *only* `best_candidate` (`#1`) with `sequential=True` (Besag-Clifford early stopping, `h=10`, `n_max=1000`), updating `#1`'s `z_score`, `p_value`, `p_adj` (Bonferroni if `n_trials > 1`, else Šidák against ledger attempts), and `is_significant`.
  - This is why `#1` and `#2` with identical raw scores can display different Z-scores (e.g., `+18.16` vs `+14.09` on `page_18`).
- **Significance Gate (`ciphers/taxonomy.py`, line 1718):** `is_significant = (z_score >= 3.5 or p_adj < 0.01) and candidate_score >= -3.40` (rendered as `SIG` vs `INSIG` in the TUI).

---

## 3. Verification & Observed Runs

### Unit Tests (`./venv/bin/python`)
- `./venv/bin/python -m unittest discover -s tests -q`: **396 tests ran in 77.569s — OK (skipped=1)**.
- `./venv/bin/python -m unittest tests/test_al_kindi_statistical_rigor.py tests/test_canonical_solved_pages.py tests/test_telemetry_and_tui.py -v`: **50 tests ran in 6.188s — OK**.

### Canonical Solved Pages (`crack_liber_primus` on `SOLVED_PAGES_REGISTRY`)
All 9 canonical solved pages passed `sig = True`, with scores `-1.6578` to `-2.2620` and Z-scores `+13.08` to `+44.32`:
- `A warning` (184 runes): `CANONICAL_ATBASH_F29`, `score=-1.6592`, `z=+43.19`, `null_mean=-4.363`, `null_std=0.0626`, `p_adj=0.0149`
- `Welcome` (515 runes): `CANONICAL_VIGENERE_DIVINITY_FSKIP`, `score=-1.7977`, `z=+44.32`, `null_mean=-4.4163`, `null_std=0.0591`, `p_adj=0.001`
- `Some wisdom` (157 runes): `CANONICAL_DIRECT_TRANSLITERATION`, `score=-1.8812`, `z=+21.32`, `null_mean=-3.3797`, `null_std=0.0703`, `p_adj=0.01883`
- `Koan 1` (778 runes): `CANONICAL_ATBASH_SHIFT_3`, `score=-1.913`, `z=+34.97`, `null_mean=-4.3809`, `null_std=0.0706`, `p_adj=0.001`
- `The loss of divinity` (755 runes): `CANONICAL_DIRECT_TRANSLITERATION`, `score=-1.8091`, `z=+13.73`, `null_mean=-3.2872`, `null_std=0.1077`, `p_adj=0.01981`
- `Koan 2` (319 runes): `CANONICAL_VIGENERE_FIRFUMFERENFE_FSKIP`, `score=-1.7216`, `z=+36.68`, `null_mean=-4.2017`, `null_std=0.0676`, `p_adj=0.001`
- `An instruction` (89 runes): `CANONICAL_DIRECT_TRANSLITERATION`, `score=-2.262`, `z=+13.08`, `null_mean=-3.3303`, `null_std=0.0817`, `p_adj=0.02079`
- `An end` (85 runes): `CANONICAL_PRIME_TOTIENT_STREAM_FSKIP`, `score=-1.6578`, `z=+35.91`, `null_mean=-4.2814`, `null_std=0.0731`, `p_adj=0.001`
- `Parable` (95 runes): `CANONICAL_DIRECT_TRANSLITERATION`, `score=-1.6835`, `z=+16.32`, `null_mean=-3.1949`, `null_std=0.0926`, `p_adj=0.02177`

### Unsolved Pages Tested (False-Positive Examples)
- **`corpus/page_18_runes.md` (217 runes):**
  - `#1 VIGENERE_PERIOD_25_EXACT_BIGRAM`: `score=-3.236`, `z=+18.16`, `sig=True`, `null_mean=-4.3227`, `null_std=0.0598`, `p_adj=0.001`
  - `#2 VIGENERE_PERIOD_25_HILL_CLIMBING`: `score=-3.236`, `z=+14.09`
- **`corpus/page_34_runes.md` (271 runes):**
  - `#1 VIGENERE_PERIOD_18_HILL_CLIMBING` (`period=18`, `key=HYIAGNEAHGSINGCXPAEAEWES`): `score=-3.2455`, `z=+19.34`, `sig=True`, `null_mean=-4.3401`, `null_std=0.0566`, `p_adj=0.00399`
  - `#2 VIGENERE_PERIOD_18_EXACT_BIGRAM` (`key=HBIAGNEAHGSINGCXPAEAEWES`): `score=-3.3478`, `z=+13.9`
  - `#3 VIGENERE_PERIOD_16_HILL_CLIMBING`: `score=-3.4375`, `z=+12.63`
  - `#4 VIGENERE_PERIOD_16_EXACT_BIGRAM`: `score=-3.5873`, `z=+10.51`
  - `#5 VIGENERE_PERIOD_12_EXACT_BIGRAM`: `score=-3.6694`, `z=+9.35`

**Root Cause of `+18` to `+20+` False Positives:** Tight `null_std` (`~0.06`) amplifies small score gains, and unconstrained long-period solvers (`period` 16–25) overfit bigram frequencies on short ciphertexts while being compared against *unoptimized* random shuffles.

---

## 4. Recommended Next Steps to Eliminate False Positives

1. **Enforce unicity / identifiability bounds (`ciphers/unicity.py` — `max_periodic_key_length`):** Cap unconstrained `EXACT_BIGRAM` / `HILL_CLIMBING` periods at the resolvable key length for `n_symbols`, or apply a `period / n` complexity penalty.
2. **Tighten score gate & require dictionary word coverage (`ciphers/al_kindi.py` — `english_word_ratio`, `is_plausible_english`):** Gate or penalize candidates that pack bigrams (`ING`, `TH`, `FOR`) without forming real English words, and consider raising the `-3.40` floor closer to the `-2.26` solved-page bound.
3. **Holdout (split-half) validation:** Fit periodic keys on the first half of the ciphertext and verify `score_composite_runes` / `Z` on the held-out second half.
4. **Match null model to optimizer degrees of freedom:** Account for the `29^p` search space via `n_trials` or by running the same optimizer on shuffled surrogates.
5. **Key naturalness / tiering:** Penalize high-entropy non-lexical keys or separate unconstrained hill-climbed keys from dictionary/structural candidates in the leaderboard.

*No repository code files were modified in this session (only `CARRYOVER.md` was created).*
