"""
Running-Key Cipher Engine — GF(29) Futhorc Running-Key & Book Cipher Engine.
Provides comprehensive running-key cryptanalysis for Liber Primus and Cicada 3301
canonical texts over GF(29) Futhorc with Fehu-skip support.

Features:
- Arbitrary Latin / Runic text to GF(29) Futhorc keystream conversion
- Multi-mode running key encryption and decryption (sub, add, beaufort)
- Dynamic Fehu-skip keystream propagation (pointer pauses when cleartext is 0 / Fehu)
- Sliding window keystream scanning with calibrated runic linguistic scoring
- Reference text and directory batch scanning
- Persistent ledger logging into SQLite canonical attempts
"""

import os
import sys
import hashlib
from typing import Any, Dict, List, Optional, Tuple, Union

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(CURRENT_DIR)
CORPUS_DIR = os.path.join(BASE_DIR, "corpus")
REFERENCE_DIR = os.path.join(CORPUS_DIR, "reference_texts")

if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agrippa import (
    INDEX_BY_RUNE,
    RUNE_BY_INDEX,
    latin_to_rune,
    decode_runes,
    index_to_rune,
)
from kasiski import (
    GATEKEEPER_THRESHOLD,
    score_unigram,
    score_composite_runes,
    score_quadgram,
)

M = 29  # Field size GF(29)


class DecodedString(str):
    """
    Decoded string result that behaves as human-readable Latin plaintext by default,
    while also exposing the authentic Futhorc runes and matching comparisons to both.
    """
    def __new__(cls, latin: str, runes: str):
        obj = str.__new__(cls, latin)
        obj.latin = latin
        obj.runes = runes
        return obj

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            return str(self) == other or self.runes == other
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(str(self))

    def __repr__(self) -> str:
        return f"DecodedString({super().__repr__()}, runes={self.runes!r})"


def text_to_rune_indices(text: str) -> List[int]:
    """
    Converts text (Latin or Futhorc runes) into rune indices in GF(29) [0..28].
    Uses latin_to_rune and INDEX_BY_RUNE from agrippa.py.
    """
    if not text:
        return []
    # If text contains Latin letters, convert via latin_to_rune (which also preserves existing runes)
    has_latin = any(c.isalpha() and c.isascii() for c in text)
    rune_str = latin_to_rune(text) if has_latin else text
    return [INDEX_BY_RUNE[c] for c in rune_str if c in INDEX_BY_RUNE]


def running_key_decrypt(
    cipher_indices: List[int],
    key_stream: List[int],
    mode: str = "sub",
    f_skip: bool = False,
    offset: int = 0,
) -> Tuple[List[int], str]:
    """
    Decrypts cipher rune indices using a running keystream over GF(29).

    Modes:
      - 'sub': Standard Vigenère subtraction: P_i = (C_i - K) mod 29
      - 'add': Additive inverse: P_i = (C_i + K) mod 29
      - 'beaufort': Beaufort cipher: P_i = (K - C_i) mod 29

    Fehu-skip:
      When f_skip=True, if plaintext rune index is 0 (Fehu), the key pointer
      does not advance for the subsequent rune.

    Returns:
      (plain_indices, plain_str)
    """
    if not cipher_indices:
        return [], DecodedString("", "")
    if not key_stream:
        raise ValueError("Keystream cannot be empty")

    mode_norm = mode.lower().strip()
    k_len = len(key_stream)
    plain_indices: List[int] = []
    k_ptr = offset

    for c_val in cipher_indices:
        k_val = key_stream[k_ptr % k_len]
        if mode_norm == "sub":
            p_val = (c_val - k_val) % M
        elif mode_norm == "add":
            p_val = (c_val + k_val) % M
        elif mode_norm in ("beaufort", "variant_beaufort"):
            p_val = (k_val - c_val) % M
        else:
            raise ValueError(f"Unsupported decryption mode '{mode}'. Use 'sub', 'add', or 'beaufort'.")

        plain_indices.append(p_val)

        if f_skip and p_val == 0:
            # Fehu-skip: pointer does NOT advance
            pass
        else:
            k_ptr += 1

    rune_str = "".join(index_to_rune(p) for p in plain_indices)
    latin_str = decode_runes(rune_str)
    return plain_indices, DecodedString(latin_str, rune_str)


def running_key_encrypt(
    plain_indices: List[int],
    key_stream: List[int],
    mode: str = "sub",
    f_skip: bool = False,
    offset: int = 0,
) -> List[int]:
    """
    Encrypts plain rune indices using a running keystream over GF(29).
    Exact mathematical inverse of running_key_decrypt.

    Modes:
      - 'sub': Inverse of P = (C - K) mod 29 -> C = (P + K) mod 29
      - 'add': Inverse of P = (C + K) mod 29 -> C = (P - K) mod 29
      - 'beaufort': Inverse of P = (K - C) mod 29 -> C = (K - P) mod 29

    Fehu-skip:
      When f_skip=True, if plaintext rune index is 0 (Fehu), the key pointer
      does not advance for the subsequent rune.
    """
    if not plain_indices:
        return []
    if not key_stream:
        raise ValueError("Keystream cannot be empty")

    mode_norm = mode.lower().strip()
    k_len = len(key_stream)
    cipher_indices: List[int] = []
    k_ptr = offset

    for p_val in plain_indices:
        k_val = key_stream[k_ptr % k_len]
        if mode_norm == "sub":
            c_val = (p_val + k_val) % M
        elif mode_norm == "add":
            c_val = (p_val - k_val) % M
        elif mode_norm in ("beaufort", "variant_beaufort"):
            c_val = (k_val - p_val) % M
        else:
            raise ValueError(f"Unsupported encryption mode '{mode}'. Use 'sub', 'add', or 'beaufort'.")

        cipher_indices.append(c_val)

        if f_skip and p_val == 0:
            # Fehu-skip: pointer does NOT advance
            pass
        else:
            k_ptr += 1

    return cipher_indices


def scan_keystream(
    cipher_indices: List[int],
    key_stream: List[int],
    mode: str = "sub",
    f_skip: bool = False,
    step: int = 1,
    top_k: int = 5,
) -> List[Dict[str, Any]]:
    """
    Slides over all valid offsets in key_stream with the given step, decrypts,
    scores candidates using calibrated GF(29) runic composite and unigram models,
    and checks against GATEKEEPER_THRESHOLD (-3.38).

    Returns:
      Top-k scored candidate dictionaries sorted by score descending.
    """
    n_c = len(cipher_indices)
    n_k = len(key_stream)
    if n_c == 0 or n_k < n_c:
        return []

    max_offset = n_k - n_c
    mode_norm = mode.lower().strip()
    step_val = max(1, step)

    # Fast arithmetic loop: decrypt integer indices directly without string decoding
    scored_offsets: List[Tuple[float, int, List[int]]] = []

    for offset in range(0, max_offset + 1, step_val):
        if not f_skip:
            sub_key = key_stream[offset:offset + n_c]
            if mode_norm == "sub":
                plain_indices = [(c - k) % M for c, k in zip(cipher_indices, sub_key)]
            elif mode_norm == "add":
                plain_indices = [(c + k) % M for c, k in zip(cipher_indices, sub_key)]
            elif mode_norm in ("beaufort", "variant_beaufort"):
                plain_indices = [(k - c) % M for c, k in zip(cipher_indices, sub_key)]
            else:
                raise ValueError(f"Unsupported decryption mode '{mode}'. Use 'sub', 'add', or 'beaufort'.")
        else:
            plain_indices = []
            k_ptr = offset
            for c_val in cipher_indices:
                k_val = key_stream[k_ptr % n_k]
                if mode_norm == "sub":
                    p_val = (c_val - k_val) % M
                elif mode_norm == "add":
                    p_val = (c_val + k_val) % M
                elif mode_norm in ("beaufort", "variant_beaufort"):
                    p_val = (k_val - c_val) % M
                else:
                    raise ValueError(f"Unsupported decryption mode '{mode}'. Use 'sub', 'add', or 'beaufort'.")
                plain_indices.append(p_val)
                if p_val != 0:
                    k_ptr += 1

        score = score_composite_runes(plain_indices)
        scored_offsets.append((score, offset, plain_indices))

    # Sort descending by score and keep top_k
    scored_offsets.sort(key=lambda x: -x[0])
    top_candidates = scored_offsets[:top_k]

    # Decode only the top-k candidates
    candidates: List[Dict[str, Any]] = []
    for score, offset, plain_indices in top_candidates:
        rune_str = "".join(index_to_rune(p) for p in plain_indices)
        latin_str = decode_runes(rune_str)
        plain_str = DecodedString(latin_str, rune_str)
        passed = bool(score >= GATEKEEPER_THRESHOLD)

        candidates.append({
            "offset": offset,
            "mode": mode,
            "f_skip": f_skip,
            "score": round(score, 4),
            "passed": passed,
            "plain_indices": plain_indices,
            "runes": rune_str,
            "plaintext": str(plain_str),
        })

    return candidates


def scan_reference_file(
    cipher_indices: List[int],
    file_path: str,
    modes: Optional[List[str]] = None,
    f_skips: Optional[List[bool]] = None,
    step: int = 1,
    top_k: int = 5,
) -> List[Dict[str, Any]]:
    """
    Scans a reference text file as a running key against the given cipher indices
    across specified modes and f_skip options.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Reference file not found: {file_path}")

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    key_stream = text_to_rune_indices(content)
    if not key_stream or len(key_stream) < len(cipher_indices):
        return []

    if modes is None:
        modes = ["sub", "add", "beaufort"]
    if f_skips is None:
        f_skips = [False, True]

    all_candidates: List[Dict[str, Any]] = []
    fname = os.path.basename(file_path)

    for m in modes:
        for fs in f_skips:
            res = scan_keystream(
                cipher_indices=cipher_indices,
                key_stream=key_stream,
                mode=m,
                f_skip=fs,
                step=step,
                top_k=top_k,
            )
            for c in res:
                c["source_file"] = fname
                c["file_path"] = file_path
                all_candidates.append(c)

    all_candidates.sort(key=lambda x: -x["score"])
    return all_candidates[:top_k]


def scan_reference_directory(
    cipher_indices: List[int],
    ref_dir: str = REFERENCE_DIR,
    modes: Optional[List[str]] = None,
    f_skips: Optional[List[bool]] = None,
    step: int = 1,
    top_k: int = 5,
) -> List[Dict[str, Any]]:
    """
    Scans all text files in reference directory across modes and f_skip settings.
    """
    if not os.path.exists(ref_dir):
        return []

    all_candidates: List[Dict[str, Any]] = []
    for fname in sorted(os.listdir(ref_dir)):
        if fname.endswith(".txt"):
            fpath = os.path.join(ref_dir, fname)
            file_results = scan_reference_file(
                cipher_indices=cipher_indices,
                file_path=fpath,
                modes=modes,
                f_skips=f_skips,
                step=step,
                top_k=top_k,
            )
            all_candidates.extend(file_results)

    all_candidates.sort(key=lambda x: -x["score"])
    return all_candidates[:top_k]


def log_running_key_attempt_to_ledger(
    page: str,
    source_text: str,
    mode: str,
    f_skip: bool,
    offset: int,
    score: float,
    plaintext: str,
    passed: bool,
) -> bool:
    """
    Records a running-key cryptanalytic evaluation in the persistent SQLite ledger.
    """
    parameters = {
        "source_text": os.path.basename(source_text),
        "mode": mode,
        "f_skip": f_skip,
        "offset": offset,
    }
    input_digest = hashlib.sha256(
        f"{os.path.basename(source_text)}:{mode}:{f_skip}:{offset}:{len(plaintext)}".encode("utf-8")
    ).hexdigest()[:16]

    try:
        from agents.ledger import log_canonical_attempt, log_attempt
        logged = log_canonical_attempt(
            page=page,
            method="running_key",
            parameters=parameters,
            input_digest=input_digest,
            score=score,
            passed=passed,
            result_preview=plaintext[:200],
        )
        log_attempt(
            page=str(page),
            method=f"running_key_{mode}",
            key=f"{os.path.basename(source_text)}:off={offset}:f_skip={f_skip}",
            result=plaintext[:200],
            success=passed,
            notes=f"score={score:.4f}, passed={passed}",
        )
        return logged
    except Exception:
        return False
