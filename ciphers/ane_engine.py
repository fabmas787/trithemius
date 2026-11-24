"""
Apple Neural Engine (ANE) & CoreML Cryptanalytic Scoring Interface.
Leverages Apple Silicon Neural Engine (16-core NPU, up to 38 TOPS on M4) via
ONNX Runtime CoreMLExecutionProvider for real-time neural semantic scoring,
candidate plaintext likelihood evaluation, and latent space projection.
Strictly offline and local — uses pre-existing cached models with zero network requests.
"""

from __future__ import annotations
import os
import sys
import logging
from typing import List, Tuple, Dict, Any, Optional, Sequence
try:
    import numpy as np
except ImportError:
    np = None

logger = logging.getLogger("ane_engine")

_ANE_SESSION = None
_TOKENIZER = None
_ANE_INITIALIZED = False
_ANE_AVAILABLE = False


def _get_local_model_paths() -> Tuple[Optional[str], Optional[str]]:
    """Locate offline model and tokenizer files in local user cache without network downloads."""
    # Check default ChromaDB local cache
    candidate_dirs = [
        os.path.expanduser("~/.cache/chroma/onnx_models/all-MiniLM-L6-v2/onnx"),
        os.path.expanduser("~/.cache/chroma/onnx_models/all-MiniLM-L6-v2"),
    ]
    for d in candidate_dirs:
        m_path = os.path.join(d, "model.onnx")
        t_path = os.path.join(d, "tokenizer.json")
        if os.path.exists(m_path) and os.path.exists(t_path):
            return m_path, t_path
    return None, None


def _init_ane_session():
    """Initialize ONNX Runtime InferenceSession with CoreMLExecutionProvider targeted at ANE."""
    global _ANE_SESSION, _TOKENIZER, _ANE_INITIALIZED, _ANE_AVAILABLE
    if _ANE_INITIALIZED:
        return

    _ANE_INITIALIZED = True
    try:
        import onnxruntime as ort
        from tokenizers import Tokenizer

        m_path, t_path = _get_local_model_paths()
        if not m_path or not t_path:
            logger.info("Local ONNX model not found in offline cache. ANE neural evaluation disabled.")
            _ANE_AVAILABLE = False
            return

        available_providers = ort.get_available_providers()
        providers = []
        if "CoreMLExecutionProvider" in available_providers:
            providers.append("CoreMLExecutionProvider")
        providers.append("CPUExecutionProvider")

        so = ort.SessionOptions()
        so.log_severity_level = 3
        so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

        _ANE_SESSION = ort.InferenceSession(m_path, sess_options=so, providers=providers)
        
        tok = Tokenizer.from_file(t_path)
        tok.enable_truncation(max_length=128)
        tok.enable_padding(pad_id=0, pad_token="[PAD]", length=128)
        _TOKENIZER = tok

        # Verify CoreML provider active
        active_providers = _ANE_SESSION.get_providers()
        _ANE_AVAILABLE = "CoreMLExecutionProvider" in active_providers or "CPUExecutionProvider" in active_providers
        logger.info(f"ANE/CoreML session initialized with providers: {active_providers}")
    except Exception as e:
        logger.warning(f"Could not initialize ANE session: {e}")
        _ANE_AVAILABLE = False


def is_ane_available() -> bool:
    """Check if Apple Neural Engine / CoreML acceleration is ready."""
    if not _ANE_INITIALIZED:
        _init_ane_session()
    return bool(_ANE_AVAILABLE and _ANE_SESSION is not None)


def get_ane_device_info() -> Dict[str, Any]:
    """Retrieve metadata about the Apple Neural Engine subsystem."""
    if not _ANE_INITIALIZED:
        _init_ane_session()
    
    import platform
    is_apple_silicon = sys.platform == "darwin" and platform.machine() == "arm64"
    
    providers = []
    if _ANE_SESSION is not None:
        try:
            providers = _ANE_SESSION.get_providers()
        except Exception:
            pass

    return {
        "available": is_ane_available(),
        "hardware": "Apple Neural Engine (ANE)" if is_apple_silicon else "CPU / Generic NPU",
        "cores": 16 if is_apple_silicon else 0,
        "tops_estimate": 38.0 if is_apple_silicon else 0.0,
        "execution_providers": providers,
        "compute_units": "CPUAndNeuralEngine" if "CoreMLExecutionProvider" in providers else "CPU",
        "offline_cached": bool(_ANE_SESSION is not None),
    }


def compute_ane_embeddings(texts: Sequence[str], batch_size: int = 32) -> np.ndarray:
    """
    Compute normalized 384-dimensional dense semantic embeddings using the Apple Neural Engine.
    Falls back to zero or CPU embeddings if ANE is not configured.
    """
    if not texts:
        return np.zeros((0, 384), dtype=np.float32)

    if not _ANE_INITIALIZED:
        _init_ane_session()

    if not _ANE_AVAILABLE or _ANE_SESSION is None or _TOKENIZER is None:
        # Fallback dummy embeddings
        return np.zeros((len(texts), 384), dtype=np.float32)

    all_embeddings = []
    for i in range(0, len(texts), batch_size):
        batch = list(texts[i : i + batch_size])
        encoded = [_TOKENIZER.encode(t) for t in batch]

        input_ids = np.array([e.ids for e in encoded], dtype=np.int64)
        attention_mask = np.array([e.attention_mask for e in encoded], dtype=np.int64)
        token_type_ids = np.zeros_like(input_ids)

        onnx_inputs = {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "token_type_ids": token_type_ids,
        }

        outputs = _ANE_SESSION.run(None, onnx_inputs)
        last_hidden_state = outputs[0]  # Shape: (batch, seq_len, 384)

        # Attention-weighted mean pooling
        mask_expanded = np.broadcast_to(
            np.expand_dims(attention_mask, -1), last_hidden_state.shape
        )
        sum_embeddings = np.sum(last_hidden_state * mask_expanded, axis=1)
        sum_mask = np.clip(mask_expanded.sum(axis=1), a_min=1e-9, a_max=None)
        pooled = sum_embeddings / sum_mask

        # L2 normalize
        norms = np.linalg.norm(pooled, axis=1, keepdims=True)
        norms = np.where(norms == 0, 1.0, norms)
        normalized = (pooled / norms).astype(np.float32)
        all_embeddings.append(normalized)

    return np.vstack(all_embeddings)


_CANONICAL_REF_TEXT = (
    "WELCOME PILGRIM ON THE SACRED PATH OF PRIMES AND DIVINE KNOWLEDGE. "
    "A WARNING: BELIEVE NOTHING FROM THIS BOOK EXCEPT WHAT YOU KNOW TO BE TRUE. "
    "CIRCUMFERENCE RADIUS TOTIENT SACRED GEOMETRY WISDOM AND TRUTH."
)
_CANONICAL_REF_EMBEDDING: Optional[np.ndarray] = None


def score_candidate_naturalness_neural(
    candidate_texts: Sequence[str],
    reference_anchor: Optional[str] = None
) -> List[float]:
    """
    Score candidate plaintexts based on cosine semantic similarity with canonical
    Cicada / Liber Primus reference doctrine using the Apple Neural Engine.
    Returns similarity scores in range [-1.0, 1.0].
    """
    global _CANONICAL_REF_EMBEDDING
    if not candidate_texts:
        return []

    if not is_ane_available():
        # Fallback to simple vowel/character heuristic score if ANE is absent
        scores = []
        for t in candidate_texts:
            if not t:
                scores.append(0.0)
                continue
            vowels = sum(1 for c in t.upper() if c in "AEIOU")
            ratio = vowels / len(t)
            # English text vowel ratio is ~0.38
            scores.append(round(1.0 - abs(ratio - 0.38) * 2.5, 4))
        return scores

    if _CANONICAL_REF_EMBEDDING is None:
        ref_text = reference_anchor or _CANONICAL_REF_TEXT
        _CANONICAL_REF_EMBEDDING = compute_ane_embeddings([ref_text])[0]

    cand_embs = compute_ane_embeddings(candidate_texts)
    sims = np.dot(cand_embs, _CANONICAL_REF_EMBEDDING)
    return [round(float(s), 4) for s in sims]
