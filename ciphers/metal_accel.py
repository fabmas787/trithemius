"""
Metal GPU Acceleration Interface for Trithemius & Cicada 3301 Cryptanalysis.
Leverages Apple Silicon Metal Compute Shaders and Unified Memory Architecture (UMA)
to perform high-throughput combinatorial key scoring, compound phrase multi-word sweeps,
and parallel Monte Carlo surrogate shuffles.
"""

from __future__ import annotations

import math
import os
import sys
import ctypes
import subprocess
import logging
from typing import List, Tuple, Dict, Any, Optional, Sequence

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None
    HAS_NUMPY = False

logger = logging.getLogger("metal_accel")

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DYLIB_PATH = os.path.join(CURRENT_DIR, "metal_engine.dylib")
SOURCE_PATH = os.path.join(CURRENT_DIR, "metal_engine.m")

_LIB: Optional[ctypes.CDLL] = None
_METAL_AVAILABLE: Optional[bool] = None


def compile_metal_dylib() -> bool:
    """Compile the Metal Objective-C compute engine into a shared library using system clang."""
    if not os.path.exists(SOURCE_PATH):
        logger.warning(f"Metal engine source file not found at {SOURCE_PATH}")
        return False
    
    cmd = [
        "clang",
        "-shared",
        "-fPIC",
        "-framework", "Metal",
        "-framework", "Foundation",
        "-framework", "Accelerate",
        "-O3",
        "-o", DYLIB_PATH,
        SOURCE_PATH
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return os.path.exists(DYLIB_PATH)
    except Exception as e:
        logger.warning(f"Compilation of Metal engine failed: {e}")
        return False


def _load_metal_lib() -> Optional[ctypes.CDLL]:
    """Load and initialize the Metal dynamic library via ctypes."""
    global _LIB, _METAL_AVAILABLE
    if _LIB is not None:
        return _LIB

    if not os.path.exists(DYLIB_PATH):
        if not compile_metal_dylib():
            _METAL_AVAILABLE = False
            return None

    try:
        lib = ctypes.CDLL(DYLIB_PATH)
        
        # Configure function prototypes
        lib.metal_init.restype = ctypes.c_int
        lib.metal_init.argtypes = []

        lib.metal_get_device_name.restype = ctypes.c_char_p
        lib.metal_get_device_name.argtypes = []

        lib.metal_get_max_buffer_size.restype = ctypes.c_uint64
        lib.metal_get_max_buffer_size.argtypes = []

        lib.metal_score_keys_batch.restype = ctypes.c_int
        lib.metal_score_keys_batch.argtypes = [
            ctypes.POINTER(ctypes.c_float),          # t_table
            ctypes.POINTER(ctypes.c_uint8),          # keys
            ctypes.c_int,                            # num_keys
            ctypes.c_int,                            # period
            ctypes.POINTER(ctypes.c_float),          # out_scores
        ]

        lib.metal_sweep_2words.restype = ctypes.c_int
        lib.metal_sweep_2words.argtypes = [
            ctypes.POINTER(ctypes.c_float),          # t_table
            ctypes.POINTER(ctypes.c_uint8),          # words_chars
            ctypes.c_int,                            # total_chars
            ctypes.POINTER(ctypes.c_uint32),         # offsets
            ctypes.POINTER(ctypes.c_uint32),         # lengths
            ctypes.c_int,                            # num_words
            ctypes.c_int,                            # period
            ctypes.c_float,                          # threshold
            ctypes.c_int,                            # max_hits
            ctypes.POINTER(ctypes.c_uint32),         # out_i
            ctypes.POINTER(ctypes.c_uint32),         # out_j
            ctypes.POINTER(ctypes.c_float),          # out_scores
            ctypes.POINTER(ctypes.c_int),            # out_num_hits
        ]

        lib.metal_sweep_3words.restype = ctypes.c_int
        lib.metal_sweep_3words.argtypes = [
            ctypes.POINTER(ctypes.c_float),          # t_table
            ctypes.POINTER(ctypes.c_uint8),          # words_chars
            ctypes.c_int,                            # total_chars
            ctypes.POINTER(ctypes.c_uint32),         # offsets
            ctypes.POINTER(ctypes.c_uint32),         # lengths
            ctypes.c_int,                            # num_words
            ctypes.c_int,                            # period
            ctypes.c_float,                          # threshold
            ctypes.c_int,                            # max_hits
            ctypes.POINTER(ctypes.c_uint32),         # out_i
            ctypes.POINTER(ctypes.c_uint32),         # out_j
            ctypes.POINTER(ctypes.c_uint32),         # out_l
            ctypes.POINTER(ctypes.c_float),          # out_scores
            ctypes.POINTER(ctypes.c_int),            # out_num_hits
        ]

        lib.metal_surrogate_shuffles.restype = ctypes.c_int
        lib.metal_surrogate_shuffles.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),          # ciphertext
            ctypes.c_int,                            # n
            ctypes.POINTER(ctypes.c_float),          # unigram_logp
            ctypes.c_int,                            # period
            ctypes.c_int,                            # num_trials
            ctypes.c_uint32,                         # base_seed
            ctypes.POINTER(ctypes.c_float),          # out_scores
        ]

        init_res = lib.metal_init()
        if init_res != 0:
            logger.warning(f"metal_init returned non-zero code: {init_res}")
            _METAL_AVAILABLE = False
            return None

        _LIB = lib
        _METAL_AVAILABLE = True
        return _LIB
    except Exception as e:
        logger.warning(f"Failed to load Metal library: {e}")
        _METAL_AVAILABLE = False
        return None


def is_metal_available() -> bool:
    """Return True if Apple Metal GPU compute acceleration is operational."""
    global _METAL_AVAILABLE
    if not HAS_NUMPY:
        return False
    if _METAL_AVAILABLE is None:
        _load_metal_lib()
    return bool(_METAL_AVAILABLE)


def get_metal_device_info() -> Dict[str, Any]:
    """Return metadata about the Apple Silicon Metal GPU device."""
    if not is_metal_available():
        return {
            "available": False,
            "device_name": "None",
            "max_buffer_bytes": 0,
            "max_buffer_mb": 0.0,
        }
    lib = _load_metal_lib()
    if not lib:
        return {
            "available": False,
            "device_name": "None",
            "max_buffer_bytes": 0,
            "max_buffer_mb": 0.0,
        }
    
    dev_name = lib.metal_get_device_name().decode("utf-8")
    max_buf = lib.metal_get_max_buffer_size()
    return {
        "available": True,
        "device_name": dev_name,
        "max_buffer_bytes": max_buf,
        "max_buffer_mb": round(max_buf / (1024 * 1024), 2),
        "unified_memory": True,
    }


def metal_score_keys_batch(
    t_table: Sequence[Sequence[float]],
    keys: Sequence[Sequence[int]],
    period: int
) -> List[float]:
    """
    Score a batch of candidate keys against a T-table on the Metal GPU in parallel.
    Falls back to vectorized CPU scoring if Metal is unavailable.
    """
    num_keys = len(keys)
    if num_keys == 0:
        return []

    lib = _load_metal_lib()
    if lib and is_metal_available():
        try:
            # Flatten T-table: period x 29
            flat_table = np.array(t_table, dtype=np.float32).reshape((period * 29,))
            
            # Pad or tile keys to exact length `period`
            key_matrix = np.zeros((num_keys, period), dtype=np.uint8)
            for i, k in enumerate(keys):
                k_len = len(k)
                if k_len == 0:
                    continue
                for j in range(period):
                    key_matrix[i, j] = k[j % k_len] % 29

            out_scores = np.zeros(num_keys, dtype=np.float32)

            t_ptr = flat_table.ctypes.data_as(ctypes.POINTER(ctypes.c_float))
            k_ptr = key_matrix.ctypes.data_as(ctypes.POINTER(ctypes.c_uint8))
            s_ptr = out_scores.ctypes.data_as(ctypes.POINTER(ctypes.c_float))

            rc = lib.metal_score_keys_batch(t_ptr, k_ptr, num_keys, period, s_ptr)
            if rc == 0:
                return [round(float(s), 4) for s in out_scores]
        except Exception as e:
            logger.warning(f"Metal scoring failed, using CPU fallback: {e}")

    # CPU Fallback
    scores = []
    for k in keys:
        k_len = len(k)
        if k_len == 0:
            scores.append(0.0)
            continue
        total = sum(t_table[i][k[i % k_len] % 29] for i in range(period))
        scores.append(round(total / period, 4))
    return scores


def metal_sweep_2words(
    t_table: Sequence[Sequence[float]],
    words_shifts: Sequence[Tuple[str, Sequence[int]]],
    period: int,
    threshold: float = -2.5,
    max_hits: int = 50000
) -> List[Tuple[str, str, float]]:
    """
    Exhaustively evaluate all (W x W) compound 2-word combinations on the Metal GPU.
    Each combination w1 + w2 is evaluated against the column T-table.
    Returns list of (word1, word2, score) sorted descending by score.
    """
    num_words = len(words_shifts)
    if num_words == 0:
        return []

    lib = _load_metal_lib()
    if lib and is_metal_available():
        try:
            words_names = [w[0] for w in words_shifts]
            shifts_list = [w[1] for w in words_shifts]

            offsets = []
            lengths = []
            flat_chars = []
            curr_off = 0
            for s in shifts_list:
                s_bytes = [int(x) % 29 for x in s]
                offsets.append(curr_off)
                lengths.append(len(s_bytes))
                flat_chars.extend(s_bytes)
                curr_off += len(s_bytes)

            total_chars = len(flat_chars)
            flat_table = np.array(t_table, dtype=np.float32).reshape((period * 29,))
            chars_arr = np.array(flat_chars, dtype=np.uint8)
            offsets_arr = np.array(offsets, dtype=np.uint32)
            lengths_arr = np.array(lengths, dtype=np.uint32)

            out_i = np.zeros(max_hits, dtype=np.uint32)
            out_j = np.zeros(max_hits, dtype=np.uint32)
            out_scores = np.zeros(max_hits, dtype=np.float32)
            out_num_hits = ctypes.c_int(0)

            t_ptr = flat_table.ctypes.data_as(ctypes.POINTER(ctypes.c_float))
            c_ptr = chars_arr.ctypes.data_as(ctypes.POINTER(ctypes.c_uint8))
            off_ptr = offsets_arr.ctypes.data_as(ctypes.POINTER(ctypes.c_uint32))
            len_ptr = lengths_arr.ctypes.data_as(ctypes.POINTER(ctypes.c_uint32))
            oi_ptr = out_i.ctypes.data_as(ctypes.POINTER(ctypes.c_uint32))
            oj_ptr = out_j.ctypes.data_as(ctypes.POINTER(ctypes.c_uint32))
            sc_ptr = out_scores.ctypes.data_as(ctypes.POINTER(ctypes.c_float))

            rc = lib.metal_sweep_2words(
                t_ptr, c_ptr, total_chars, off_ptr, len_ptr,
                num_words, period, float(threshold), max_hits,
                oi_ptr, oj_ptr, sc_ptr, ctypes.byref(out_num_hits)
            )

            if rc == 0:
                n_hits = out_num_hits.value
                hits = []
                for k in range(n_hits):
                    i_idx = int(out_i[k])
                    j_idx = int(out_j[k])
                    sc = round(float(out_scores[k]), 4)
                    hits.append((words_names[i_idx], words_names[j_idx], sc))
                hits.sort(key=lambda x: -x[2])
                return hits
        except Exception as e:
            logger.warning(f"Metal 2-word sweep failed, using CPU fallback: {e}")

    # CPU Fallback
    results = []
    for w1, s1 in words_shifts:
        l1 = len(s1)
        for w2, s2 in words_shifts:
            comb = list(s1) + list(s2)
            c_len = len(comb)
            if c_len == 0:
                continue
            total = sum(t_table[i][comb[i % c_len] % 29] for i in range(period))
            sc = round(total / period, 4)
            if sc >= threshold:
                results.append((w1, w2, sc))
                if len(results) >= max_hits:
                    break
        if len(results) >= max_hits:
            break
    results.sort(key=lambda x: -x[2])
    return results


def metal_sweep_3words(
    t_table: Sequence[Sequence[float]],
    words_shifts: Sequence[Tuple[str, Sequence[int]]],
    period: int,
    threshold: float = -2.3,
    max_hits: int = 20000
) -> List[Tuple[str, str, str, float]]:
    """
    Exhaustively evaluate all (W x W x W) compound 3-word combinations on the Metal GPU.
    Returns list of (w1, w2, w3, score) sorted descending by score.
    """
    num_words = len(words_shifts)
    if num_words == 0:
        return []

    lib = _load_metal_lib()
    if lib and is_metal_available():
        try:
            words_names = [w[0] for w in words_shifts]
            shifts_list = [w[1] for w in words_shifts]

            offsets = []
            lengths = []
            flat_chars = []
            curr_off = 0
            for s in shifts_list:
                s_bytes = [int(x) % 29 for x in s]
                offsets.append(curr_off)
                lengths.append(len(s_bytes))
                flat_chars.extend(s_bytes)
                curr_off += len(s_bytes)

            total_chars = len(flat_chars)
            flat_table = np.array(t_table, dtype=np.float32).reshape((period * 29,))
            chars_arr = np.array(flat_chars, dtype=np.uint8)
            offsets_arr = np.array(offsets, dtype=np.uint32)
            lengths_arr = np.array(lengths, dtype=np.uint32)

            out_i = np.zeros(max_hits, dtype=np.uint32)
            out_j = np.zeros(max_hits, dtype=np.uint32)
            out_l = np.zeros(max_hits, dtype=np.uint32)
            out_scores = np.zeros(max_hits, dtype=np.float32)
            out_num_hits = ctypes.c_int(0)

            t_ptr = flat_table.ctypes.data_as(ctypes.POINTER(ctypes.c_float))
            c_ptr = chars_arr.ctypes.data_as(ctypes.POINTER(ctypes.c_uint8))
            off_ptr = offsets_arr.ctypes.data_as(ctypes.POINTER(ctypes.c_uint32))
            len_ptr = lengths_arr.ctypes.data_as(ctypes.POINTER(ctypes.c_uint32))
            oi_ptr = out_i.ctypes.data_as(ctypes.POINTER(ctypes.c_uint32))
            oj_ptr = out_j.ctypes.data_as(ctypes.POINTER(ctypes.c_uint32))
            ol_ptr = out_l.ctypes.data_as(ctypes.POINTER(ctypes.c_uint32))
            sc_ptr = out_scores.ctypes.data_as(ctypes.POINTER(ctypes.c_float))

            rc = lib.metal_sweep_3words(
                t_ptr, c_ptr, total_chars, off_ptr, len_ptr,
                num_words, period, float(threshold), max_hits,
                oi_ptr, oj_ptr, ol_ptr, sc_ptr, ctypes.byref(out_num_hits)
            )

            if rc == 0:
                n_hits = out_num_hits.value
                hits = []
                for k in range(n_hits):
                    i_idx = int(out_i[k])
                    j_idx = int(out_j[k])
                    l_idx = int(out_l[k])
                    sc = round(float(out_scores[k]), 4)
                    hits.append((words_names[i_idx], words_names[j_idx], words_names[l_idx], sc))
                hits.sort(key=lambda x: -x[3])
                return hits
        except Exception as e:
            logger.warning(f"Metal 3-word sweep failed, using CPU fallback: {e}")

    # CPU Fallback
    results = []
    for w1, s1 in words_shifts:
        for w2, s2 in words_shifts:
            for w3, s3 in words_shifts:
                comb = list(s1) + list(s2) + list(s3)
                c_len = len(comb)
                if c_len == 0:
                    continue
                total = sum(t_table[i][comb[i % c_len] % 29] for i in range(period))
                sc = round(total / period, 4)
                if sc >= threshold:
                    results.append((w1, w2, w3, sc))
                    if len(results) >= max_hits:
                        break
            if len(results) >= max_hits:
                break
        if len(results) >= max_hits:
            break
    results.sort(key=lambda x: -x[3])
    return results


def metal_surrogate_shuffles(
    ciphertext_indices: Sequence[int],
    unigram_logp: Sequence[float],
    period: int,
    num_trials: int = 10000,
    base_seed: int = 1337
) -> List[float]:
    """
    Run parallel Monte Carlo surrogate shuffles on the Metal GPU to calibrate exact empirical p-values.
    """
    n = len(ciphertext_indices)
    if n == 0 or num_trials == 0:
        return []

    lib = _load_metal_lib()
    if lib and is_metal_available():
        try:
            cipher_arr = np.array(ciphertext_indices, dtype=np.uint8)
            logp_arr = np.array(unigram_logp, dtype=np.float32)
            out_scores = np.zeros(num_trials, dtype=np.float32)

            c_ptr = cipher_arr.ctypes.data_as(ctypes.POINTER(ctypes.c_uint8))
            lp_ptr = logp_arr.ctypes.data_as(ctypes.POINTER(ctypes.c_float))
            os_ptr = out_scores.ctypes.data_as(ctypes.POINTER(ctypes.c_float))

            rc = lib.metal_surrogate_shuffles(
                c_ptr, n, lp_ptr, period, num_trials, ctypes.c_uint32(base_seed), os_ptr
            )
            if rc == 0:
                return [round(float(s), 4) for s in out_scores]
        except Exception as e:
            logger.warning(f"Metal surrogate shuffles failed, using CPU fallback: {e}")

    # CPU Fallback
    import random
    rng = random.Random(base_seed)
    scores = []
    c_list = list(ciphertext_indices)
    for _ in range(num_trials):
        trial_score = 0.0
        for col in range(period):
            col_chars = c_list[col::period]
            if not col_chars:
                continue
            # apply random shift
            shift = rng.randint(0, 28)
            col_sum = sum(unigram_logp[(c + shift) % 29] for c in col_chars)
            trial_score += col_sum / len(col_chars)
        scores.append(round(trial_score / period, 4))
    return scores


def benchmark_metal_throughput(num_words: int = 1000, period: int = 17) -> Dict[str, Any]:
    """
    Benchmark the Apple Silicon Metal GPU throughput against synthetic vocabulary.
    Evaluates 1,000,000 combinations (1000 x 1000 pairs).
    """
    import time
    if not is_metal_available():
        return {"error": "Metal GPU is not available"}

    # Generate synthetic 1000 words
    synthetic_words = []
    for i in range(num_words):
        shifts = [(i * 7 + j * 3) % 29 for j in range(5 + (i % 7))]
        synthetic_words.append((f"WORD_{i}", shifts))

    # Generate synthetic T-table
    t_table = [[-2.5 - 0.5 * math.sin(i + j) for j in range(29)] for i in range(period)]

    t0 = time.perf_counter()
    hits = metal_sweep_2words(t_table, synthetic_words, period, threshold=-2.3, max_hits=5000)
    elapsed = time.perf_counter() - t0

    total_pairs = num_words * num_words
    rate = total_pairs / elapsed if elapsed > 0 else 0.0

    return {
        "device": get_metal_device_info().get("device_name", "Apple GPU"),
        "combinations_tested": total_pairs,
        "elapsed_seconds": round(elapsed, 4),
        "combinations_per_second": round(rate, 2),
        "throughput_m_keys_per_sec": round(rate / 1_000_000, 2),
        "hits_found": len(hits),
    }
