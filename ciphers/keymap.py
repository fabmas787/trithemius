"""
KeyMap — Canonical Byte -> Z29 Mapping Pipeline & Keystream Screening.
Standard library only: collections. Zero external dependencies.

Translates candidate byte sources (hashes, PGP blocks, image headers)
into Z29 keystreams across three canonical mathematical mappings:
1. 'mod29': b % 29 (biased: residues 0..23 have probability 9/256 vs 8/256 for 24..28)
2. 'reject232': rejection sampling for bytes b < 232 = 8 * 29 (exact uniform distribution)
3. 'base29': big-integer base-29 positional expansion
Screens candidate keystreams in both raw and cumulative chain forms with both signs (+/-).
"""

from __future__ import annotations
from collections import Counter
from typing import Dict, List, Sequence, Tuple, Any, Callable

N = 29
REJECT_LIMIT = (256 // N) * N  # 232: bytes below it map uniformly with b % 29


def map_mod(bs: bytes) -> List[int]:
    """Modulo mapping: b % 29."""
    return [b % N for b in bs]


def map_reject(bs: bytes) -> List[int]:
    """Unbiased rejection sampling: b % 29 for b < 232."""
    return [b % N for b in bs if b < REJECT_LIMIT]


def map_base29(bs: bytes) -> List[int]:
    """Base-29 positional expansion of the byte array interpreted as a big-endian unsigned integer."""
    if not bs:
        return []
    v = int.from_bytes(bs, "big")
    out = []
    while v > 0:
        v, r = divmod(v, N)
        out.append(r)
    return out[::-1] if out else [0]


MAPPINGS: Dict[str, Callable[[bytes], List[int]]] = {
    "mod29": map_mod,
    "reject232": map_reject,
    "base29": map_base29,
}


def _ioc_n(c: Sequence[int]) -> float:
    L = len(c)
    if L < 2:
        return 0.0
    return N * sum(v * (v - 1) for v in Counter(c).values()) / (L * (L - 1))


def screen(cipher: Sequence[int], key: Sequence[int]) -> Tuple[float, Optional[Tuple[str, int]]]:
    """
    Screen candidate key against ciphertext across:
    - form: 'raw' (k_i) vs 'chain' (cumulative sum K_i = sum k_j mod 29)
    - sign: +1 (c_i - k_i) vs -1 (c_i + k_i)
    Returns (best_ioc_n, (best_form, best_sign)).
    Flat random decryptions yield IoC*N ~ 1.00; true English keys yield IoC*N ~ 1.8 - 2.0.
    """
    n = min(len(cipher), len(key))
    if n < 2:
        return 0.0, None

    cipher_trunc = cipher[:n]
    key_trunc = key[:n]

    # Compute cumulative chain form
    chain = []
    s = 0
    for k in key_trunc:
        s = (s + k) % N
        chain.append(s)

    best_score = 0.0
    best_config: Optional[Tuple[str, int]] = None

    for form, ks in (("raw", key_trunc), ("chain", chain)):
        for sign in (1, -1):
            out = [(c - sign * k) % N for c, k in zip(cipher_trunc, ks)]
            score = _ioc_n(out)
            if score > best_score:
                best_score = score
                best_config = (form, sign)

    return best_score, best_config


def screen_byte_source(cipher: Sequence[int], source_bytes: bytes) -> Dict[str, Any]:
    """
    Screen a candidate byte source across all three canonical mappings.
    Returns results and marks the top-scoring configuration.
    """
    results = {}
    best_overall_score = 0.0
    best_mapping = None
    best_config = None

    for name, mapper in MAPPINGS.items():
        mapped_key = mapper(source_bytes)
        score, cfg = screen(cipher, mapped_key)
        results[name] = {
            "key_length": len(mapped_key),
            "best_ioc_n": score,
            "best_config": cfg,
        }
        if score > best_overall_score:
            best_overall_score = score
            best_mapping = name
            best_config = cfg

    return {
        "best_score": best_overall_score,
        "best_mapping": best_mapping,
        "best_config": best_config,
        "mappings": results,
    }
