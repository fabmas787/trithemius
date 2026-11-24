import os
import random
import sys
import tempfile
from typing import Any, Callable, Dict, List, Tuple
import unittest
from unittest.mock import patch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import agents.ledger as ledger
from ciphers.agrippa import INDEX_BY_RUNE, decode_runes, latin_to_rune
from ciphers.al_kindi import (
    _normalize_futhorc_token,
    analyze_runic_lexical_coverage,
    chi_squared_p_value,
    doublet_rate_plausibility,
    english_word_ratio,
    is_plausible_english,
    kl_divergence_english,
    reduced_chi_squared,
)
from ciphers.interrupter import (
    analyze_f_skip_periodicity,
    canonical_key_shifts,
    rune_vigenere_encode_f_skip,
)
from ciphers.kasiski import rune_vigenere_encode
from ciphers.solved_pages import (
    SOLVED_PAGES_REGISTRY,
    extract_runes_from_file,
    load_solved_page_transcript,
    resolve_solved_page,
    solve_page,
)
import ciphers.taxonomy as taxonomy
from ciphers.telemetry import CandidateUpdateEvent


def _make_doublet_suppressed_sequence(
    length: int,
    target_doublets: int = 2,
    seed: int = 3301,
) -> List[int]:
    """Generate a deterministic Z_29 sequence with controlled adjacent doublets."""
    rng = random.Random(seed)
    seq: List[int] = []
    for _ in range(length):
        val = rng.randrange(29)
        while seq and val == seq[-1]:
            val = rng.randrange(29)
        seq.append(val)

    if target_doublets > 0 and length >= 4:
        step = max(3, (length - 2) // max(1, target_doublets))
        placed = 0
        pos = 10
        while placed < target_doublets and pos + 1 < length:
            seq[pos + 1] = seq[pos]
            placed += 1
            pos += step
    return seq


class TestAlKindiStatisticalRigor(unittest.TestCase):
    def test_kl_divergence_non_negative_and_invariant(self):
        english_short = "WELCOME PILGRIMS ON THE SACRED PATH OF WISDOM AND TRUTH"
        english_long = english_short * 15
        kl_short = kl_divergence_english(english_short)
        kl_long = kl_divergence_english(english_long)
        self.assertGreaterEqual(kl_short, 0.0)
        self.assertGreaterEqual(kl_long, 0.0)
        self.assertAlmostEqual(kl_short, kl_long, places=3)
        self.assertLess(kl_short, 0.45)

    def test_reduced_chi_squared(self):
        english = "WELCOME PILGRIMS ON THE SACRED PATH OF WISDOM AND TRUTH"
        chi2_red = reduced_chi_squared(english)
        self.assertLess(chi2_red, 5.0)

    def test_wilson_hilferty_p_value(self):
        p_mid = chi_squared_p_value(25.0, df=25)
        self.assertGreater(p_mid, 0.40)
        self.assertLess(p_mid, 0.60)
        p_extreme = chi_squared_p_value(200.0, df=25)
        self.assertLess(p_extreme, 1e-5)

    def test_composite_gatekeeper_verdict(self):
        valid = "THE PRESERVATION OF ALL THINGS IS ROOTED IN THE DIVINE PRIMES"
        gibberish = "XQZJVKWPLMBNFGHTYUIOPAZXCVBNMQ"
        passed_v, met_v = is_plausible_english(valid)
        passed_g, met_g = is_plausible_english(gibberish)
        self.assertTrue(passed_v)
        self.assertEqual(met_v["verdict"], "PLAUSIBLE")
        self.assertFalse(passed_g)
        self.assertIn(met_g["verdict"], ("REJECT", "IMPLAUSIBLE"))

    def test_long_text_not_rejected_by_chi2_scaling(self):
        sample = (
            "WELCOME PILGRIMS TO THIS GREAT JOURNEY A WARNING BELIEVE NOTHING FROM THIS BOOK "
            "EXCEPT WHAT YOU KNOW TO BE TRUE "
        ) * 15
        self.assertGreater(len(sample), 800)
        passed, metrics = is_plausible_english(sample)
        self.assertTrue(passed)
        self.assertEqual(metrics["verdict"], "PLAUSIBLE")

    def test_english_word_ratio_unspaced_overlapping_bounded(self):
        # All tokens < 3 chars forces the unspaced substring branch on cleaned='THEIRTHERE'
        # Overlapping words ("THE", "HEIR", "THEIR", "THERE", "HERE", "HER") must not double-count > 1.0
        ratio = english_word_ratio("TH EI RT HE RE")
        self.assertGreaterEqual(ratio, 0.0)
        self.assertLessEqual(ratio, 1.0)
        self.assertEqual(ratio, 1.0)

        ratio_partial = english_word_ratio("TH EI RX QZ")
        self.assertGreater(ratio_partial, 0.0)
        self.assertLess(ratio_partial, 1.0)

        ratio_single_tok = english_word_ratio("THEIRTHERE")
        self.assertGreaterEqual(ratio_single_tok, 0.0)
        self.assertLessEqual(ratio_single_tok, 1.0)


class TestLexicalAndDoubletGates(unittest.TestCase):
    """Tests for non-overlapping lexical ratio, Futhorc-aligned coverage, and doublet plausibility."""

    def test_english_word_ratio_strictly_bounded_all_modes(self):
        samples = [
            "",
            "...",
            "THE SACRED PRIMES ARE WISDOM AND TRUTH",
            "SACREDPRIMESWISDOMTRUTH",
            "THEIRTHEREHERE",
            "XQZJVKWPLMBNFGHTYUIOPAZXCVBNMQ",
            "TH ER EW AS ON CE",
        ]
        for text in samples:
            ratio = english_word_ratio(text)
            self.assertGreaterEqual(ratio, 0.0, f"ratio < 0 for {text!r}")
            self.assertLessEqual(ratio, 1.0, f"ratio > 1 for {text!r}")
        self.assertEqual(english_word_ratio(""), 0.0)
        self.assertEqual(english_word_ratio("... ---"), 0.0)

    def test_normalize_futhorc_token_canonical_spellings(self):
        cases = {
            "THNGS": "THINGS",
            "NOTHNG": "NOTHING",
            "BOOC": "BOOK",
            "CNOW": "KNOW",
            "YOVR": "YOUR",
            "INSTRVCTIAN": "INSTRUCTION",
            "CWESTIAN": "QUESTION",
            "CONSVMPTIAN": "CONSUMPTION",
        }
        for futhorc_tok, expected_english in cases.items():
            forms = _normalize_futhorc_token(futhorc_tok)
            self.assertIn(expected_english, forms, f"Missing {expected_english} for {futhorc_tok}")

    def test_analyze_runic_lexical_coverage_canonical_vs_noise(self):
        for page_id in ("page_00", "welcome", "instruction", "an_end", "koan_2"):
            solved = solve_page(page_id)
            cov_spaced = analyze_runic_lexical_coverage(
                solved["plaintext_latin"], solved["decrypted_runes"]
            )
            self.assertTrue(cov_spaced["word_coverage_ok"], f"Spaced gate failed on {page_id}: {cov_spaced}")
            self.assertTrue(cov_spaced["has_word_boundaries"])
            self.assertGreaterEqual(cov_spaced["aligned_word_ratio"], 0.20)

            unspaced_latin = decode_runes(solved["decrypted_runes"], preserve_punctuation=False).replace(" ", "")
            cov_unspaced = analyze_runic_lexical_coverage(unspaced_latin, solved["decrypted_runes"])
            self.assertTrue(cov_unspaced["word_coverage_ok"], f"Unspaced aligned gate failed on {page_id}: {cov_unspaced}")

        # Word-boundary-separated Futhorc gibberish and short 2-3 letter noise must fail
        gibberish_runes = "ᛉᛈᚣᛡᛇ᛫ᛉᚣᛉᛈᚫ᛫ᛗᛉᛡᛈᛇ᛫ᛉᛈᚣᛇᛉ᛫ᛉᛈᛡᚫᛇ᛫ᚫᛉᛈᛇᚣ"
        gibberish_cov = analyze_runic_lexical_coverage(decode_runes(gibberish_runes), gibberish_runes)
        self.assertFalse(gibberish_cov["word_coverage_ok"])
        self.assertEqual(gibberish_cov["distinct_long_words"], 0)

        short_noise_latin = "THE AND FOR XQZ JVK WPL MBN FGH"
        short_cov = analyze_runic_lexical_coverage(short_noise_latin)
        self.assertFalse(short_cov["word_coverage_ok"])

        for rel_path in ("corpus/page_18_runes.md", "corpus/page_34_runes.md"):
            raw_runes = extract_runes_from_file(os.path.join(BASE_DIR, rel_path))
            raw_cov = analyze_runic_lexical_coverage(decode_runes(raw_runes), raw_runes)
            self.assertFalse(raw_cov["word_coverage_ok"], f"Unsolved raw runes passed lexical gate: {rel_path}")

    def test_doublet_rate_plausibility_and_canonical_pages(self):
        # Suppressed adjacent doublets on >= 120 runes must fail
        zero_doublets = _make_doublet_suppressed_sequence(180, target_doublets=0, seed=11)
        ok_zero, rate_zero = doublet_rate_plausibility(zero_doublets)
        self.assertFalse(ok_zero)
        self.assertEqual(rate_zero, 0.0)

        one_doublet_250 = _make_doublet_suppressed_sequence(250, target_doublets=1, seed=19)
        ok_one, rate_one = doublet_rate_plausibility(one_doublet_250)
        self.assertFalse(ok_one)
        self.assertLess(rate_one, 0.005)

        # Short sequences < 120 runes are never rejected for zero doublets
        short_zero = _make_doublet_suppressed_sequence(90, target_doublets=0, seed=23)
        ok_short, rate_short = doublet_rate_plausibility(short_zero)
        self.assertTrue(ok_short)
        self.assertEqual(rate_short, 0.0)

        # All 9 canonical solved pages must pass doublet plausibility
        for page in SOLVED_PAGES_REGISTRY:
            solved = solve_page(page)
            ok_page, rate_page = doublet_rate_plausibility(solved["decrypted_runes"])
            self.assertTrue(ok_page, f"{page.id} failed doublet plausibility (rate={rate_page})")


class TestPiecewiseHoldoutAndLocoGates(unittest.TestCase):
    """Tests for piecewise multi-segment consistency, split-half holdout, and LOCO sensitivity."""

    def test_piecewise_key_consistency_canonical_pages(self):
        expected_segments = {
            "welcome": 4,
            "page_00": 3,
            "instruction": 2,
        }
        for page_id, exp_k in expected_segments.items():
            solved = solve_page(page_id)
            raw_ct = load_solved_page_transcript(resolve_solved_page(page_id))
            dec_idx = taxonomy.clean_runes_to_indices(solved["decrypted_runes"])
            cand = {
                "method": f"CANONICAL_{page_id.upper()}",
                "plaintext_runes": solved["decrypted_runes"],
                "plaintext_latin": solved["plaintext_latin"],
                "period": 8 if page_id == "welcome" else 1,
            }
            pw = taxonomy.evaluate_piecewise_key_consistency(cand, raw_ct, dec_idx, null_mean=-3.45, null_std=0.15)
            self.assertEqual(pw["k_segments"], exp_k)
            self.assertTrue(pw["segment_consistency_ok"], f"Canonical {page_id} failed piecewise gate: {pw}")
            self.assertGreaterEqual(pw["consistent_segment_ratio"], 0.65)
            self.assertGreaterEqual(pw["min_segment_score"], -3.65)

    def test_piecewise_key_consistency_rejects_partial_overfit_and_phase_shift(self):
        # Case A: Localized overfitting in first ~60 runes followed by ~180 scrambled runes
        english_prefix = latin_to_rune("WELCOME PILGRIMS TO THE SACRED PATH OF WISDOM AND TRUTH SEEK KNOWLEDGE")
        rng = random.Random(404)
        noise_indices = [rng.randrange(29) for _ in range(180)]
        noise_chunks = [taxonomy.indices_to_runes(noise_indices[i:i + 6]) for i in range(0, len(noise_indices), 6)]
        mixed_runes = english_prefix + "᛫" + "᛫".join(noise_chunks)
        mixed_idx = taxonomy.clean_runes_to_indices(mixed_runes)
        pw_partial = taxonomy.evaluate_piecewise_key_consistency(
            {"method": "LOCAL_OVERFIT", "plaintext_runes": mixed_runes, "plaintext_latin": decode_runes(mixed_runes), "period": 1},
            mixed_runes,
            mixed_idx,
            null_mean=-3.45,
            null_std=0.15,
        )
        self.assertEqual(pw_partial["k_segments"], 4)
        self.assertFalse(pw_partial["segment_consistency_ok"])
        self.assertLess(pw_partial["consistent_segment_ratio"], 0.65)
        self.assertLess(pw_partial["min_segment_score"], -3.65)
        self.assertGreater(pw_partial["segment_scores"][0], pw_partial["segment_scores"][-1])

        # Case B: Mid-stream periodic phase jump (delta = 3) detected by best_phase_shift
        prose = (
            "WELCOME PILGRIMS TO THE SACRED PATH OF WISDOM AND KNOWLEDGE "
            "EVERY SEEKER SHALL FIND HIDDEN TRUTH BEYOND THE VEIL OF SHADOWS "
            "MEASURE ALL NUMBERS WITH CARE AND PRESERVE THE ANCIENT ORDER "
            "BELIEVE NOTHING EXCEPT WHAT YOU PROVE THROUGH REASON"
        )
        pt_runes = latin_to_rune(prose)
        pt_idx = taxonomy.clean_runes_to_indices(pt_runes)
        div_shifts = canonical_key_shifts("DIVINITY")
        p = len(div_shifts)
        half = len(pt_idx) // 2
        ct_idx = [
            (pt_idx[i] + div_shifts[i % p]) % 29
            if i < half
            else (pt_idx[i] + div_shifts[(i + 3) % p]) % 29
            for i in range(len(pt_idx))
        ]
        dec_unshifted = [(ct_idx[i] - div_shifts[i % p]) % 29 for i in range(len(ct_idx))]
        pw_shift = taxonomy.evaluate_piecewise_key_consistency(
            {
                "method": "VIGENERE_PERIOD_8_EXACT_BIGRAM",
                "key_shifts": div_shifts,
                "period": p,
                "plaintext_runes": taxonomy.indices_to_runes(dec_unshifted),
                "plaintext_latin": decode_runes(taxonomy.indices_to_runes(dec_unshifted)),
            },
            pt_runes,
            ct_idx,
            null_mean=-3.45,
            null_std=0.15,
        )
        self.assertFalse(pw_shift["segment_consistency_ok"])
        self.assertEqual(pw_shift["best_phase_shift"], 3)
        self.assertGreater(pw_shift["best_phase_shift_jump"], 0.5)

    def test_split_half_holdout_rejects_noisy_high_period_and_passes_true_periodic(self):
        # 1. Noisy period 18..25 fits on random / doublet-suppressed ciphertext must fail holdout
        rand_seq = _make_doublet_suppressed_sequence(250, target_doublets=2, seed=77)
        for p in (18, 22, 25):
            ho = taxonomy.validate_periodic_holdout(rand_seq, p, solver_kind="EXACT_BIGRAM")
            self.assertTrue(ho["applicable"], f"Expected holdout applicable for n=250, p={p}")
            self.assertFalse(ho["holdout_ok"], f"Holdout failed to reject noisy p={p}: {ho}")

        # 2. True periodic English (period 8 and period 18) must pass holdout
        prose_p8 = (
            "SEEK TRUTH BEYOND THE VEIL OF APPEARANCES FOR EVERY NUMBER HOLDS AN ORDER "
            "HIDDEN FROM THE CARELESS EYE AND ONLY THOSE WHO QUESTION SHALL UNDERSTAND "
            "THE SILENT ARCHITECTURE OF PRIMES AND LIGHT"
        )
        ct_p8 = rune_vigenere_encode(latin_to_rune(prose_p8), "DIVINITY")
        idx_p8 = taxonomy.clean_runes_to_indices(ct_p8)
        ho_p8 = taxonomy.validate_periodic_holdout(idx_p8, 8, solver_kind="EXACT_BIGRAM")
        self.assertTrue(ho_p8["applicable"])
        self.assertTrue(ho_p8["holdout_ok"], f"True period-8 failed holdout: {ho_p8}")
        self.assertGreaterEqual(ho_p8["mean_holdout_z"], 3.0)
        self.assertGreaterEqual(ho_p8["mean_holdout_score"], -3.30)

        prose_p18 = (
            "BEYOND THE SILENT HORIZON OF THOUGHT EACH SEEKER WALKS THROUGH SHADOW AND LIGHT "
            "MEASURING THE HIDDEN HARMONY OF PRIMES WHILE GUARDING THE ANCIENT MEMORY OF WISDOM "
            "TRUTH REMAINS CONSTANT EVEN WHEN FORMS DISSOLVE INTO DUST AND ECHOES FADE AWAY "
            "EVERY NUMBER IN THE SACRED ARCHITECTURE SPEAKS TO THOSE WHO LISTEN WITH CARE "
            "NEVER SURRENDER YOUR REASON TO BLIND BELIEF FOR KNOWLEDGE IS EARNED THROUGH TRIAL"
        )
        key_p18 = [INDEX_BY_RUNE[c] for c in latin_to_rune("SACREDPRIMESWISDOM")][:18]
        ct_p18 = rune_vigenere_encode(latin_to_rune(prose_p18), key_p18)
        idx_p18 = taxonomy.clean_runes_to_indices(ct_p18)
        ho_p18 = taxonomy.validate_periodic_holdout(idx_p18, 18, solver_kind="EXACT_BIGRAM")
        self.assertTrue(ho_p18["applicable"])
        self.assertTrue(ho_p18["holdout_ok"], f"True period-18 failed holdout: {ho_p18}")
        self.assertGreaterEqual(ho_p18["mean_holdout_z"], 3.0)

    def test_loco_column_key_sensitivity(self):
        # True periodic English passes LOCO column cliff check
        prose = (
            "WELCOME PILGRIMS TO THE SACRED PATH OF WISDOM AND KNOWLEDGE "
            "BELIEVE NOTHING EXCEPT WHAT YOU PROVE THROUGH REASON AND EXPERIENCE "
            "ALL THINGS ARE CONNECTED WITHIN THE DIVINE PRIMES"
        )
        ct_p8 = rune_vigenere_encode(latin_to_rune(prose), "DIVINITY")
        idx_p8 = taxonomy.clean_runes_to_indices(ct_p8)
        true_k8 = canonical_key_shifts("DIVINITY")
        loco_true = taxonomy.validate_column_key_sensitivity(idx_p8, true_k8)
        self.assertTrue(loco_true["applicable"])
        self.assertTrue(loco_true["column_cliff_ok"])
        self.assertGreaterEqual(loco_true["active_column_ratio"], 0.80)

        # Corrupted columns (3 of 8 wrong) fail LOCO sensitivity threshold
        corrupt_k8 = list(true_k8)
        corrupt_k8[1] = (corrupt_k8[1] + 7) % 29
        corrupt_k8[4] = (corrupt_k8[4] + 11) % 29
        corrupt_k8[6] = (corrupt_k8[6] + 15) % 29
        loco_corrupt = taxonomy.validate_column_key_sensitivity(idx_p8, corrupt_k8)
        self.assertTrue(loco_corrupt["applicable"])
        self.assertFalse(loco_corrupt["column_cliff_ok"])
        self.assertLess(loco_corrupt["active_column_ratio"], 0.80)

        # Random period-20 key on random doublet-suppressed sequence fails LOCO
        rand_seq = _make_doublet_suppressed_sequence(250, target_doublets=2, seed=99)
        rng = random.Random(99)
        rand_k20 = [rng.randrange(29) for _ in range(20)]
        loco_rand = taxonomy.validate_column_key_sensitivity(rand_seq, rand_k20)
        self.assertTrue(loco_rand["applicable"])
        self.assertFalse(loco_rand["column_cliff_ok"])

        # Period <= 2 bypasses LOCO check safely
        loco_p2 = taxonomy.validate_column_key_sensitivity(idx_p8, [3, 14])
        self.assertFalse(loco_p2["applicable"])
        self.assertTrue(loco_p2["column_cliff_ok"])


class TestEndToEndRigorAndPlantRecover(unittest.TestCase):
    """End-to-end crack_liber_primus tests for Phase 10 top-5 consistency and plant-and-recover controls."""

    def setUp(self):
        tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(tmp_dir.cleanup)
        db_path = os.path.join(tmp_dir.name, "ledger.sqlite3")
        vector_dir = os.path.join(tmp_dir.name, "vectordb")
        os.makedirs(vector_dir, exist_ok=True)

        orig_db = ledger.DB_PATH
        orig_vec = ledger.VECTOR_DIR
        saved_defaults: List[Tuple[Callable[..., Any], Tuple[Any, ...]]] = []
        for name in dir(ledger):
            fn = getattr(ledger, name)
            if callable(fn) and getattr(fn, "__defaults__", None):
                defs = fn.__defaults__
                if orig_db in defs or orig_vec in defs:
                    saved_defaults.append((fn, defs))
                    fn.__defaults__ = tuple(
                        db_path if d == orig_db else (vector_dir if d == orig_vec else d)
                        for d in defs
                    )

        ledger._VECTOR_CLIENT = None
        ledger._VECTOR_COLLECTION = None
        p_db = patch.object(ledger, "DB_PATH", db_path)
        p_vec = patch.object(ledger, "VECTOR_DIR", vector_dir)
        p_db.start()
        p_vec.start()

        def _cleanup_ledger() -> None:
            ledger._VECTOR_CLIENT = None
            ledger._VECTOR_COLLECTION = None
            for fn, defs in saved_defaults:
                fn.__defaults__ = defs

        self.addCleanup(p_db.stop)
        self.addCleanup(p_vec.stop)
        self.addCleanup(_cleanup_ledger)

    def _assert_phase10_uniform_fields(self, top_candidates: List[Dict[str, Any]]) -> None:
        required_keys = (
            "significance",
            "z_score",
            "z_crit",
            "p_value",
            "p_adj",
            "e_value",
            "e_value_adj",
            "is_significant",
            "piecewise",
            "holdout",
            "column_sensitivity",
            "lexical_coverage",
            "doublet_rate_ok",
        )
        for rank_idx, cand in enumerate(top_candidates):
            for key in required_keys:
                self.assertIn(key, cand, f"Missing Phase 10 key {key!r} on candidate #{rank_idx + 1}")
            self.assertEqual(
                cand["z_score"],
                cand["significance"]["z_score"],
                f"Candidate #{rank_idx + 1} retained stale z_score",
            )
            self.assertEqual(cand["is_significant"], cand["significance"]["is_significant"])

    def test_top5_uniform_phase10_zscore_consistency(self):
        # 1. Canonical page_00 produces multiple identical-score candidates in top 5
        raw_p0 = load_solved_page_transcript(resolve_solved_page("page_00"))
        events_p0: List[Any] = []
        res_p0 = taxonomy.crack_liber_primus(
            raw_p0,
            page_id="rigor_p0",
            deep=False,
            top_k=5,
            use_metal=False,
            use_ane=False,
            progress_callback=events_p0.append,
        )
        top_p0 = res_p0["top_candidates"]
        self.assertEqual(len(top_p0), 5)
        self._assert_phase10_uniform_fields(top_p0)

        # Candidates sharing identical raw_score and tier=1 must share identical Phase 10 z_score/p_value/e_value
        by_sig_group: Dict[Tuple[int, float], List[Dict[str, Any]]] = {}
        for cand in top_p0:
            if cand["tier"] == 1:
                by_sig_group.setdefault((cand["tier"], cand["raw_score"]), []).append(cand)
        tied_groups = [grp for grp in by_sig_group.values() if len(grp) >= 2]
        self.assertTrue(tied_groups, "Expected at least one tied tier-1 score group on page_00")
        for grp in tied_groups:
            z_vals = {c["z_score"] for c in grp}
            p_vals = {c["p_value"] for c in grp}
            e_vals = {c["e_value"] for c in grp}
            self.assertEqual(len(z_vals), 1, f"Inconsistent Z-scores for identical-score candidates: {z_vals}")
            self.assertEqual(len(p_vals), 1, f"Inconsistent p-values for identical-score candidates: {p_vals}")
            self.assertEqual(len(e_vals), 1, f"Inconsistent e-values for identical-score candidates: {e_vals}")

        update_events = [e for e in events_p0 if isinstance(e, CandidateUpdateEvent)]
        self.assertEqual(len(update_events), len(top_p0))

        # 2. Mixed tier-1 and tier-2 top-5 on periodic Vigenere ciphertext has no stale Phase 2 Z-scores
        prose = (
            "SEEK TRUTH BEYOND THE VEIL OF APPEARANCES FOR EVERY NUMBER HOLDS AN ORDER "
            "HIDDEN FROM THE CARELESS EYE AND ONLY THOSE WHO QUESTION SHALL UNDERSTAND "
            "THE SILENT ARCHITECTURE OF PRIMES AND LIGHT"
        )
        ct_vig = rune_vigenere_encode(latin_to_rune(prose), "DIVINITY")
        res_vig = taxonomy.crack_liber_primus(
            ct_vig,
            page_id="rigor_mixed_top5",
            deep=False,
            top_k=5,
            use_metal=False,
            use_ane=False,
        )
        top_vig = res_vig["top_candidates"]
        self.assertEqual(len(top_vig), 5)
        self._assert_phase10_uniform_fields(top_vig)
        for cand in top_vig:
            if cand["tier"] == 1:
                self.assertEqual(cand["z_score"], cand["significance"]["z_raw"])

    def test_plant_and_recover_positive_control_f_skip(self):
        # Unseen ~180-rune Futhorc-transliterable philosophical prose (no 'Q') with multiple 'F'/'ᚠ' triggers
        unseen_prose = (
            "EVERY SEEKER FINDS FORGOTTEN PATHS BENEATH SILENT STARS "
            "AND WATCHES HOW ANCIENT NUMBERS SHAPE OUR INNER VOICE "
            "FROM SERENE FAITH SPRINGS CLEAR VISION BEYOND SHADOWED FEAR "
            "WALK FORWARD WITHOUT DOUBT AND REMEMBER THE SACRED ORDER"
        )
        unseen_runes = latin_to_rune(unseen_prose)
        n_runes = len(taxonomy.clean_runes_to_indices(unseen_runes))
        self.assertGreaterEqual(n_runes, 170)
        self.assertLessEqual(n_runes, 210)
        self.assertIn("᛫", unseen_runes)
        self.assertGreaterEqual(unseen_runes.count("ᚠ"), 4)

        key = "PILGRIMS"
        ct_runes, skips = rune_vigenere_encode_f_skip(unseen_runes, key, preserve_separators=True)
        self.assertGreaterEqual(len(skips), 4)

        res = taxonomy.crack_liber_primus(
            ct_runes,
            page_id="plant_recover_pos_fskip",
            deep=False,
            top_k=5,
            use_metal=False,
            use_ane=False,
        )
        winner = res["winner"]
        self.assertIsNotNone(winner)
        self.assertTrue(winner["is_significant"], f"Positive control failed significance: {winner.get('significance')}")
        self.assertEqual(winner["key_shifts"], canonical_key_shifts(key))
        self.assertEqual(winner["plaintext_runes"], unseen_runes)
        self.assertEqual(winner["plaintext_latin"], decode_runes(unseen_runes))
        self.assertTrue(winner["word_coverage_ok"])
        self.assertTrue(winner["doublet_rate_ok"])
        self.assertTrue(winner["segment_consistency_ok"])
        self.assertTrue(winner["holdout_ok"])
        self.assertTrue(winner["column_cliff_ok"])

    def test_plant_and_recover_negative_control_doublet_suppressed(self):
        # ~250-rune random Z_29 sequence matching Liber Primus doublet deficit (~0.66%-0.80% adjacent doublets)
        seq = _make_doublet_suppressed_sequence(250, target_doublets=2, seed=202611)
        raw_runes = taxonomy.indices_to_runes(seq)
        chunked_runes = "᛫".join(raw_runes[i:i + 5] for i in range(0, len(raw_runes), 5))

        diag = analyze_f_skip_periodicity(chunked_runes)
        self.assertEqual(diag["rune_count"], 250)
        self.assertLess(diag["consecutive_doubles_rate"], 0.01)

        res = taxonomy.crack_liber_primus(
            chunked_runes,
            page_id="plant_recover_neg_doublet_deficit",
            deep=False,
            top_k=5,
            use_metal=False,
            use_ane=False,
        )
        top_cands = res["top_candidates"]
        self.assertGreater(len(top_cands), 0)
        for idx, cand in enumerate(top_cands):
            self.assertFalse(
                cand["is_significant"],
                f"Negative control false positive on candidate #{idx + 1} ({cand['method']}): {cand['significance']}",
            )


if __name__ == "__main__":
    unittest.main()
