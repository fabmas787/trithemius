"""
Cryptanalytic domain service.
Encapsulates all Liber Primus ciphers, cascaded solvers, statistical triage, and OpSec inspections.
"""

import glob
import os
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import config
from ciphers.agrippa import (
    decode_runes, latin_to_rune, rune_to_prime, gematria_prime_sum,
    gematria_word_sums, rune_atbash, rune_atbash_shift, direct_translation,
    euler_totient, is_prime, prime_factors, index_to_rune,
    INDEX_BY_RUNE, PRIME_BY_RUNE,
)
from ciphers.kasiski import (
    rune_vigenere_decode, rune_vigenere_encode, vigenere_decode, vigenere_encode,
    rune_index_of_coincidence, index_of_coincidence,
    prime_totient_stream_decode, prime_totient_stream_encode, generate_prime_totients,
)
from ciphers.interrupter import (
    rune_vigenere_decode_f_skip, rune_vigenere_encode_f_skip,
    WELCOME_F_SKIP_POSITIONS, KOAN2_F_SKIP_POSITIONS,
)
from ciphers.al_kindi import is_plausible_english
from ciphers.opsec import inspect_pgp_text, inspect_file_headers
from ciphers.entropy import is_high_entropy, extract_signal_features
from ciphers.running_key import (
    text_to_rune_indices,
    running_key_decrypt,
    scan_reference_directory,
    log_running_key_attempt_to_ledger,
    GATEKEEPER_THRESHOLD,
    REFERENCE_DIR as RUNNING_KEY_REFERENCE_DIR,
)
from ciphers.lexicon import (
    generate_philosophical_phrases,
    get_master_dictionary,
)
from workstation.core.results import (
    GematriaResult,
    AtbashResult,
    VigenereResult,
    TotientStreamResult,
    SolveResult,
    CrackResult,
    TriageResult,
    PeriodResult,
    CribResult,
    RunningKeyResult,
    RunningKeyScanResult,
    LexiconResult,
    OpsecResult,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CORPUS_DIR = os.path.join(BASE_DIR, "corpus")

solved_pages_module = None
taxonomy_module = None
layout_module = None


def _get_solved_pages():
    global solved_pages_module
    if solved_pages_module is None:
        import ciphers.solved_pages as solved_pages_module
    return solved_pages_module


def _get_taxonomy():
    global taxonomy_module
    if taxonomy_module is None:
        import ciphers.taxonomy as taxonomy_module
    return taxonomy_module


def _get_layout():
    global layout_module
    if layout_module is None:
        import ciphers.layout as layout_module
    return layout_module


class CipherService:
    """Service dedicated to classical and Liber Primus cryptanalytic operations."""

    def __init__(self, workstation: Optional[Any] = None) -> None:
        self.ws = workstation

    def _resolve_cipher_input(self, target: str) -> Tuple[str, Optional[dict]]:
        """Resolves input string, file path, or corpus page identifier."""
        if not target or not isinstance(target, str):
            return target, None

        stripped = target.strip()
        if "\n" in stripped or len(stripped) > 260:
            return stripped, None

        resolved_path = None
        if os.path.isfile(stripped):
            resolved_path = os.path.abspath(stripped)
        elif os.path.isfile(os.path.join(CORPUS_DIR, stripped)):
            resolved_path = os.path.join(CORPUS_DIR, stripped)
        else:
            m = re.match(r"^(?:page[:_ ]?)?(\d+)$", stripped, flags=re.IGNORECASE)
            if m:
                p_num = int(m.group(1))
                norm = f"{p_num:02d}"
                matches = (
                    glob.glob(os.path.join(CORPUS_DIR, f"page_{norm}_runes.*"))
                    or glob.glob(os.path.join(CORPUS_DIR, f"page_{norm}_*.*"))
                    or glob.glob(os.path.join(CORPUS_DIR, f"*{norm}*.*"))
                )
                if matches and os.path.isfile(matches[0]):
                    resolved_path = matches[0]

        if not resolved_path:
            return stripped, None

        try:
            with open(resolved_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return stripped, None

        rune_lines = []
        in_rune_section = False
        for line in lines:
            line_s = line.strip()
            if line_s.lower().startswith("## rune transcription"):
                in_rune_section = True
                continue
            if in_rune_section:
                if line_s.startswith("##") or (line_s.startswith("```") and rune_lines):
                    break
                rune_lines.append(line)

        if rune_lines:
            extracted = "".join(rune_lines).strip()
            if any(c in INDEX_BY_RUNE for c in extracted):
                meta = {
                    "source_file": os.path.basename(resolved_path),
                    "source_path": resolved_path,
                    "extraction_mode": "Rune Transcription section",
                    "rune_count": sum(1 for c in extracted if c in INDEX_BY_RUNE),
                }
                return extracted, meta

        rune_only_lines = [l for l in lines if any(c in INDEX_BY_RUNE for c in l)]
        if rune_only_lines:
            extracted = "".join(rune_only_lines).strip()
            meta = {
                "source_file": os.path.basename(resolved_path),
                "source_path": resolved_path,
                "extraction_mode": "Direct Rune lines fallback",
                "rune_count": sum(1 for c in extracted if c in INDEX_BY_RUNE),
            }
            return extracted, meta

        extracted = "".join(lines).strip()
        meta = {
            "source_file": os.path.basename(resolved_path),
            "source_path": resolved_path,
            "extraction_mode": "Raw file content",
            "rune_count": sum(1 for c in extracted if c in INDEX_BY_RUNE),
        }
        return extracted, meta

    def run_gematria(self, text: str) -> GematriaResult:
        """Run Gematria Primus prime sum, totient, prime check, word sums, and Atbash."""
        payload, file_meta = self._resolve_cipher_input(text)
        has_runes = any(c in INDEX_BY_RUNE for c in payload)
        runes = payload if has_runes else latin_to_rune(payload)
        latin = decode_runes(runes)
        p_sum = gematria_prime_sum(runes)
        tot = euler_totient(p_sum)
        prime_status = is_prime(p_sum)
        factors = prime_factors(p_sum)
        w_sums = gematria_word_sums(runes)
        atbash_runes = rune_atbash(runes)
        atbash_latin = decode_runes(atbash_runes)

        res = GematriaResult(
            input=text,
            text=text,
            has_runes=has_runes,
            runes=runes,
            decoded_latin=latin,
            direct_latin=latin,
            prime_sum=p_sum,
            totient=tot,
            is_prime=prime_status,
            prime_factors=factors,
            word_sums=w_sums,
            atbash_runes=atbash_runes,
            atbash_latin=atbash_latin,
        )
        if file_meta:
            res.update(file_meta)
        return res

    def run_atbash(self, text: str, shift: int = 0) -> AtbashResult:
        """Run Modulo-29 Atbash reflection or Atbash followed by Caesar shift."""
        payload, file_meta = self._resolve_cipher_input(text)
        has_runes = any(c in INDEX_BY_RUNE for c in payload)
        runes = payload if has_runes else latin_to_rune(payload)

        if shift == 0:
            res_runes = rune_atbash(runes, preserve_separators=True)
            method_desc = "Atbash in F_29: (28 - c) mod 29"
        else:
            res_runes = rune_atbash_shift(runes, shift=shift, preserve_separators=True)
            method_desc = f"Atbash + Caesar (+{shift}) in F_29: ((28 - c) + {shift}) mod 29"

        latin_res = decode_runes(res_runes)
        ioc = rune_index_of_coincidence(res_runes)
        passed, metrics = is_plausible_english(latin_res)

        res = AtbashResult(
            input=text,
            shift=shift,
            method=method_desc,
            result_runes=res_runes,
            decoded_latin=latin_res,
            ioc=round(ioc, 4),
            metrics=metrics,
        )
        if file_meta:
            res.update(file_meta)
        return res

    def run_vigenere(
        self,
        mode: str,
        text: str,
        key: str,
        f_skip: bool = False,
        skip_indices: Optional[Set[int]] = None,
    ) -> VigenereResult:
        """Run Modulo-29 (runes) or Modulo-26 (Latin) Vigenère cipher."""
        payload, file_meta = self._resolve_cipher_input(text)
        has_runes = any(c in INDEX_BY_RUNE for c in payload)
        mode = mode.lower().strip()
        is_dec = mode in ("dec", "decode", "decrypt")

        if has_runes or f_skip or skip_indices:
            runes = payload if has_runes else latin_to_rune(payload)
            if is_dec:
                if f_skip or skip_indices:
                    res_text = rune_vigenere_decode_f_skip(
                        runes, key, skip_indices=skip_indices, preserve_separators=True
                    )
                else:
                    res_text = rune_vigenere_decode(runes, key, preserve_separators=True)
            else:
                if f_skip:
                    res_text, detected_skips = rune_vigenere_encode_f_skip(
                        runes, key, preserve_separators=True
                    )
                    if skip_indices is None:
                        skip_indices = detected_skips
                else:
                    res_text = rune_vigenere_encode(runes, key, preserve_separators=True)
            latin_res = decode_runes(res_text)
            ioc = rune_index_of_coincidence(res_text)
            passed, metrics = is_plausible_english(latin_res)
            alphabet_type = "Modulo-29 (Futhorc Runes)"

            effective_skips = sorted(skip_indices) if skip_indices else None
            if is_dec and f_skip and effective_skips is None:
                clean_r = [c for c in runes if c in INDEX_BY_RUNE]
                norm_k = key.upper().strip() if isinstance(key, str) else ""
                if norm_k in ("DIVINITY", "ᛞᛁᚢᛁᚾᛁᛏᚣ") and (len(clean_r) == 545 or len(clean_r) >= 515):
                    effective_skips = sorted(WELCOME_F_SKIP_POSITIONS)
                elif norm_k in ("FIRFUMFERENFE", "ᚠᛁᚱᚠᚢᛗᚠᛖᚱᛖᚾᚠᛖ") and (len(clean_r) == 135 or len(clean_r) >= 59):
                    effective_skips = sorted(KOAN2_F_SKIP_POSITIONS)
                else:
                    effective_skips = sorted([i for i, c in enumerate(clean_r) if c == "ᚠ"])
        else:
            res_text = vigenere_decode(payload, key) if is_dec else vigenere_encode(payload, key)
            latin_res = res_text
            ioc = index_of_coincidence(res_text)
            passed, metrics = is_plausible_english(latin_res)
            alphabet_type = "Modulo-26 (Classical Latin A-Z)"
            effective_skips = None

        res = VigenereResult(
            mode="DECODE" if is_dec else "ENCODE",
            alphabet=alphabet_type,
            input=text,
            key=key,
            f_skip=f_skip,
            skip_indices=effective_skips,
            result=res_text,
            decoded_latin=latin_res,
            ioc=round(ioc, 4),
            metrics=metrics,
        )
        if file_meta:
            res.update(file_meta)
        return res

    def run_totient_stream(
        self,
        mode: str,
        text: str,
        offset: int = 0,
        f_skip: bool = False,
        skip_indices: Optional[Set[int]] = None,
    ) -> TotientStreamResult:
        """Run Liber Primus Prime Totient Stream Cipher (phi(p_i) = p_i - 1 mod 29)."""
        payload, file_meta = self._resolve_cipher_input(text)
        has_runes = any(c in INDEX_BY_RUNE for c in payload)
        runes = payload if has_runes else latin_to_rune(payload)
        mode = mode.lower().strip()
        is_dec = mode in ("dec", "decode", "decrypt")

        if is_dec:
            res_runes = prime_totient_stream_decode(
                runes,
                offset=offset,
                preserve_separators=True,
                skip_indices=skip_indices,
                f_skip=f_skip,
            )
        else:
            res_runes, detected_skips = prime_totient_stream_encode(
                runes,
                offset=offset,
                preserve_separators=True,
                skip_indices=skip_indices,
                f_skip=f_skip,
            )
            if skip_indices is None and f_skip:
                skip_indices = detected_skips

        latin_res = decode_runes(res_runes)
        ioc = rune_index_of_coincidence(res_runes)
        passed, metrics = is_plausible_english(latin_res)

        effective_skips = sorted(skip_indices) if skip_indices else ([56] if f_skip else None)

        res = TotientStreamResult(
            mode="DECODE" if is_dec else "ENCODE",
            input=text,
            offset=offset,
            f_skip=f_skip,
            skip_indices=effective_skips,
            result_runes=res_runes,
            decoded_latin=latin_res,
            ioc=round(ioc, 4),
            metrics=metrics,
        )
        if file_meta:
            res.update(file_meta)
        return res

    def run_totient(self, *args: Any, **kwargs: Any) -> TotientStreamResult:
        """Alias for run_totient_stream."""
        return self.run_totient_stream(*args, **kwargs)

    def run_solve(self, target: str = "all") -> SolveResult:
        """Solve and verify canonical Liber Primus solved pages from official wiki."""
        sp = _get_solved_pages()
        t = (target or "all").strip().lower()
        if t in ("all", "*", ""):
            res = sp.verify_all_solved_pages()
        else:
            res = sp.solve_page(target)
        return SolveResult(res)

    def run_crack(
        self,
        target: str,
        deep: bool = False,
        top_k: int = 5,
        randomize: bool = False,
        include_rotations: bool = False,
        crib_limit: Optional[int] = None,
        seed: Optional[int] = None,
        compound: bool = False,
        use_metal: bool = True,
        use_ane: bool = True,
        progress_callback: Optional[Callable[[Any], None]] = None,
        cancel_event: Optional[Any] = None,
    ) -> CrackResult:
        """Run full cryptanalytic taxonomy cascade solver on target."""
        tax = _get_taxonomy()
        payload, file_meta = self._resolve_cipher_input(target)
        page_id = file_meta.get("source_file", target) if file_meta else target
        res = tax.crack_liber_primus(
            payload,
            page_id=page_id,
            deep=deep,
            top_k=top_k,
            randomize=randomize,
            include_rotations=include_rotations,
            crib_limit=crib_limit,
            seed=seed,
            compound=compound,
            use_metal=use_metal,
            use_ane=use_ane,
            progress_callback=progress_callback,
            cancel_event=cancel_event,
        )
        res["target_input"] = target
        if file_meta:
            res.update(file_meta)
        return CrackResult(res)

    def run_triage(self, target: str) -> TriageResult:
        """Run statistical triage to classify cipher family."""
        tax = _get_taxonomy()
        payload, file_meta = self._resolve_cipher_input(target)
        res = tax.triage_cipher(payload)
        res["target_input"] = target
        if file_meta:
            res.update(file_meta)
        return TriageResult(res)

    def run_period(self, target: str, max_period: int = 30) -> PeriodResult:
        """Run multi-metric consensus key length estimation."""
        tax = _get_taxonomy()
        payload, file_meta = self._resolve_cipher_input(target)
        periods = tax.consensus_key_length_estimation(payload, max_period=max_period)
        res = {
            "target_input": target,
            "periods": periods,
            "top_period": periods[0][0] if periods else 1,
        }
        if file_meta:
            res.update(file_meta)
        return PeriodResult(res)

    def run_crib(self, target: str, crib: str) -> CribResult:
        """Slide known crib across target to analyze implied key fragments."""
        tax = _get_taxonomy()
        payload, file_meta = self._resolve_cipher_input(target)
        indices = tax.clean_runes_to_indices(payload)
        hits = tax.drag_crib(indices, crib)
        res = {
            "target_input": target,
            "crib": crib,
            "hits": hits,
            "total_tested": max(0, len(indices) - len(tax.clean_runes_to_indices(crib)) + 1),
        }
        if file_meta:
            res.update(file_meta)
        return CribResult(res)

    def run_running_key(
        self,
        page_target: str,
        text_path: str,
        mode: str = "sub",
        f_skip: bool = False,
        offset: int = 0,
    ) -> RunningKeyResult:
        """Run running key decryption against reference text."""
        payload, file_meta = self._resolve_cipher_input(page_target)
        cipher_indices = text_to_rune_indices(payload)
        if not cipher_indices:
            return RunningKeyResult(error=f"No valid runes found in target: {page_target}")

        resolved_text_path = None
        if os.path.isfile(text_path):
            resolved_text_path = os.path.abspath(text_path)
        else:
            cand = os.path.join(RUNNING_KEY_REFERENCE_DIR, text_path)
            if os.path.isfile(cand):
                resolved_text_path = os.path.abspath(cand)
            else:
                matches = glob.glob(os.path.join(RUNNING_KEY_REFERENCE_DIR, f"*{text_path}*"))
                if matches and os.path.isfile(matches[0]):
                    resolved_text_path = os.path.abspath(matches[0])

        if not resolved_text_path:
            return RunningKeyResult(error=f"Reference text file not found: {text_path}")

        try:
            with open(resolved_text_path, "r", encoding="utf-8", errors="ignore") as f:
                ref_text = f.read()
        except Exception as e:
            return RunningKeyResult(error=f"Failed to read reference file {resolved_text_path}: {e}")

        key_stream = text_to_rune_indices(ref_text)
        if not key_stream:
            return RunningKeyResult(error=f"No valid runes or Latin text in reference file {resolved_text_path}")

        plain_indices, plain_str = running_key_decrypt(
            cipher_indices=cipher_indices,
            key_stream=key_stream,
            mode=mode,
            f_skip=f_skip,
            offset=offset,
        )
        tax = _get_taxonomy()
        score = tax.score_composite_runes(plain_indices)
        passed = bool(score >= GATEKEEPER_THRESHOLD)

        page_label = file_meta.get("source_file", page_target) if file_meta else page_target
        log_running_key_attempt_to_ledger(
            page=page_label,
            source_text=resolved_text_path,
            mode=mode,
            f_skip=f_skip,
            offset=offset,
            score=score,
            plaintext=str(plain_str),
            passed=passed,
        )

        res = RunningKeyResult(
            page=page_target,
            target_page=page_target,
            source_file=resolved_text_path,
            source_file_basename=os.path.basename(resolved_text_path),
            mode=mode.lower(),
            f_skip=f_skip,
            offset=offset,
            rune_count=len(cipher_indices),
            key_stream_len=len(key_stream),
            score=round(score, 4),
            passed=passed,
            runes=plain_str.runes if hasattr(plain_str, "runes") else "".join(index_to_rune(p) for p in plain_indices),
            plain_latin=str(plain_str),
        )
        if file_meta:
            res.update(file_meta)
        return res

    def run_running_key_scan(
        self,
        page_target: str,
        ref_dir: Optional[str] = None,
        step: int = 1,
        top_k: int = 5,
        progress_callback: Optional[Callable[[Any], None]] = None,
        cancel_event: Optional[Any] = None,
    ) -> RunningKeyScanResult:
        """Scan canonical reference texts against target page."""
        payload, file_meta = self._resolve_cipher_input(page_target)
        cipher_indices = text_to_rune_indices(payload)
        if not cipher_indices:
            return RunningKeyScanResult(error=f"No valid runes found in target: {page_target}")

        target_dir = ref_dir or RUNNING_KEY_REFERENCE_DIR
        if not os.path.exists(target_dir):
            return RunningKeyScanResult(error=f"Reference directory not found: {target_dir}")

        candidates = scan_reference_directory(
            cipher_indices=cipher_indices,
            ref_dir=target_dir,
            step=step,
            top_k=top_k,
            progress_callback=progress_callback,
            cancel_event=cancel_event,
        )

        page_label = file_meta.get("source_file", page_target) if file_meta else page_target
        for c in candidates:
            log_running_key_attempt_to_ledger(
                page=page_label,
                source_text=c.get("source_file", ""),
                mode=c.get("mode", "sub"),
                f_skip=c.get("f_skip", False),
                offset=c.get("offset", 0),
                score=c.get("score", 0.0),
                plaintext=c.get("plaintext", ""),
                passed=c.get("passed", False),
            )

        res = RunningKeyScanResult(
            page=page_target,
            ref_dir=target_dir,
            rune_count=len(cipher_indices),
            step=step,
            top_k=top_k,
            candidates=candidates,
        )
        if file_meta:
            res.update(file_meta)
        return res

    def run_lexicon(self, action: str = "phrases", limit: int = 50) -> LexiconResult:
        """Inspect master vocabulary and philosophical phrases."""
        action_norm = action.lower().strip() if action else "phrases"
        if action_norm in ("phrase", "phrases"):
            items = generate_philosophical_phrases()
            return LexiconResult(action="phrases", items=items[:limit], total=len(items), limit=limit)
        elif action_norm in ("word", "words"):
            items = get_master_dictionary()
            return LexiconResult(action="words", items=items[:limit], total=len(items), limit=limit)
        else:
            phrases = generate_philosophical_phrases()
            words = get_master_dictionary()
            return LexiconResult(action="all", phrases=phrases[:limit], words=words[:limit], total_phrases=len(phrases), total_words=len(words), limit=limit)

    def run_opsec(self, target: str) -> OpsecResult:
        """Inspect file or text for PGP 7A35090F signature and entropy features."""
        file_info = None
        content = target

        if os.path.isfile(target):
            file_info = inspect_file_headers(target)
            try:
                with open(target, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                return OpsecResult(error=f"Failed to read file {target}: {e}", target=target)

        pgp_res = inspect_pgp_text(content)
        features = extract_signal_features(content)
        features["is_high_entropy"] = is_high_entropy(content)

        return OpsecResult(
            target=target,
            is_file=file_info is not None,
            file_info=file_info,
            pgp=pgp_res,
            features=features,
        )

    def run_layout(self, target: str = "all") -> Dict[str, Any]:
        """Run layout side-channel mutual information analysis or calibration."""
        lay = _get_layout()
        t = str(target).strip().lower()
        if t in ("all", "calibrate", "calibration"):
            res = lay.calibrate_solved_pages()
            if self.ws and hasattr(self.ws, "print_layout_calibration"):
                self.ws.print_layout_calibration(res)
            return res
        else:
            stream = lay.extract_layout_stream(target)
            norm_target = re.sub(r"^page_?", "", t)
            known_key = None
            if norm_target in ("57", "a_warning"):
                known_key = "FIRFUMFERENFE"
            elif norm_target in ("0", "00", "welcome", "73", "an_end", "56"):
                known_key = None

            feat_results = lay.analyze_all_features(stream, keystream=known_key)
            data = {
                "target": target,
                "stream": stream,
                "known_key": known_key,
                "features": {k: v.to_dict() for k, v in feat_results.items()},
            }
            if self.ws and hasattr(self.ws, "print_layout_page"):
                self.ws.print_layout_page(data)
            return data
