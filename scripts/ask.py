"""
Interactive RAG query loop against the Liber Primus corpus.

Retrieves top-k relevant chunks from ChromaDB (with page filtering and rune awareness),
injects them as context, and queries the local LLM (SparkLLM or MoE) with live streaming.

Run:
    python3 scripts/ask.py
    python3 scripts/ask.py --moe       # run with DeepSeek MoE
    python3 scripts/ask.py --model spark
"""

import os
import sys
import argparse
import re
import json
import time
import hashlib
import sqlite3
from typing import Optional, List, Dict, Tuple, Any
import ollama
import chromadb

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config
from config import get_model, MODELS, MODEL_NAME, DEFAULT_NUM_CTX, DEFAULT_NUM_PREDICT
DB_DIR = os.path.join(os.path.dirname(__file__), "..", "vectordb")
EMBED_MODEL = "nomic-embed-text"
TOP_K = 5
CONTEXT_WINDOW = DEFAULT_NUM_CTX

_CHROMA_CLIENT = None
_CHROMA_COLLECTION = None


def get_collection(db_dir: str = DB_DIR):
    """Return cached persistent ChromaDB collection."""
    global _CHROMA_CLIENT, _CHROMA_COLLECTION
    if _CHROMA_COLLECTION is None:
        _CHROMA_CLIENT = chromadb.PersistentClient(path=db_dir)
        _CHROMA_COLLECTION = _CHROMA_CLIENT.get_or_create_collection(
            name="liber_primus",
            metadata={"hnsw:space": "cosine"}
        )
    return _CHROMA_COLLECTION

SYSTEM_PROMPT = """You are Trithemius, an advanced cryptanalysis and research engine \
dedicated to investigating the Cicada 3301 mystery and deciphering the Liber Primus. \
You have access to retrieved context from solved/unsolved pages, cryptographic writeups, \
and community research.

Directives:
1. No Self-Introductions: Never open responses with greetings, pleasantries, meta-disclaimers, \
or self-introductions (e.g. avoid 'I am Trithemius', 'As an assistant', or 'Based on a strict review of the corpus'). \
Begin directly with the substantive analysis.
2. Fluid, Cohesive Prose: Write well-developed narrative paragraphs with natural flow. \
Strictly avoid fragmenting your response into choppy bulleted lists, outline hierarchies, \
or one-sentence bullet points unless explicitly asked for a list or when specifying concrete \
mathematical keys, rune mappings, or formulas. Weave facts, citations, and context into continuous prose.
3. English Output: Always formulate and write your entire response in clear, precise English, \
even when the inquiry is written in Italian or another language. Understand foreign-language questions \
completely, but provide the analysis exclusively in fluent, articulate English.
4. Epistemic Rigor & Grounding: Ground answers strictly in the retrieved corpus, \
mathematical principles (Gematria Primus, Vigenere mod-29, Euler totients, primes), \
and verified facts. State uncertainties clearly instead of assuming or hallucinating unverified claims. \
Never declare an unsolved page 'solved' without cryptographic consensus.
5. Completeness: Deliver fully articulated, unbroken explanations without premature truncation."""

PAGE_QUERY_REGEX = re.compile(r"(?:page|pagina|pg\.?)\s*([0-9]{1,2})", re.IGNORECASE)

CACHE_DB_PATH = os.path.join(DB_DIR, "cache.sqlite3")
PROMPT_VERSION = hashlib.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest()[:16]
SEP = "\x1f"


import unicodedata

RAG_CACHE_KEY_VERSION = "v2"


def normalize_query_for_cache(query: str) -> str:
    """Normalize query using NFKC decomposition, casefolding, and whitespace collapsing."""
    if not query:
        return ""
    norm = unicodedata.normalize("NFKC", str(query)).casefold()
    return " ".join(norm.split())


def rag_cache_key(query: str, corpus_digest: str, provider: str, model: str,
                  think: bool, prompt_version: str = PROMPT_VERSION,
                  retrieval_mode: str = "bm25", boost: bool = False,
                  key_version: str = RAG_CACHE_KEY_VERSION) -> str:
    """Generate deterministic cache key for exact RAG answer caching."""
    q = normalize_query_for_cache(query)
    raw = SEP.join([
        key_version,
        q,
        corpus_digest,
        provider.lower(),
        model,
        str(int(think)),
        str(int(boost)),
        prompt_version,
        retrieval_mode,
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _get_cache_db(db_path: str = CACHE_DB_PATH):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rag_cache (
            cache_key TEXT PRIMARY KEY,
            query_norm TEXT NOT NULL,
            corpus_digest TEXT NOT NULL,
            provider TEXT NOT NULL,
            model TEXT NOT NULL,
            think_flag INTEGER NOT NULL,
            prompt_version TEXT NOT NULL,
            retrieval_mode TEXT NOT NULL,
            response_text TEXT NOT NULL,
            sources_json TEXT NOT NULL,
            created_at REAL NOT NULL,
            last_access_at REAL NOT NULL,
            hit_count INTEGER DEFAULT 0
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rag_cache_access ON rag_cache (last_access_at)")
    # TTL: Purge entries older than 7 days (604800 seconds)
    cutoff = time.time() - 604800
    conn.execute("DELETE FROM rag_cache WHERE created_at < ?", (cutoff,))
    conn.commit()
    return conn


def lookup_rag_cache(cache_key: str, db_path: str = CACHE_DB_PATH) -> Optional[dict]:
    """Lookup exact RAG cache. Returns dict with response and sources, or None."""
    if os.environ.get("TRITHEMIUS_CACHE", "on").lower() == "off":
        return None
    if not os.path.exists(db_path):
        return None
    try:
        conn = _get_cache_db(db_path)
        now = time.time()
        cur = conn.execute(
            "SELECT response_text, sources_json FROM rag_cache WHERE cache_key = ?",
            (cache_key,)
        )
        row = cur.fetchone()
        if row:
            conn.execute(
                "UPDATE rag_cache SET last_access_at = ?, hit_count = hit_count + 1 WHERE cache_key = ?",
                (now, cache_key)
            )
            conn.commit()
            conn.close()
            return {
                "response": row[0],
                "sources": json.loads(row[1]) if row[1] else [],
            }
        conn.close()
    except Exception:
        pass
    return None


def store_rag_cache(cache_key: str, query: str, corpus_digest: str, provider: str,
                    model: str, think: bool, prompt_version: str, retrieval_mode: str,
                    response_text: str, sources: list, db_path: str = CACHE_DB_PATH,
                    max_entries: int = 2000, boost: bool = False) -> None:
    """Store complete RAG response in exact cache with LRU eviction."""
    if os.environ.get("TRITHEMIUS_CACHE", "on").lower() == "off":
        return
    if not response_text or not response_text.strip():
        return
    try:
        conn = _get_cache_db(db_path)
        now = time.time()
        q_norm = normalize_query_for_cache(query)
        sources_str = json.dumps(sources)
        conn.execute("""
            INSERT OR REPLACE INTO rag_cache (
                cache_key, query_norm, corpus_digest, provider, model, think_flag,
                prompt_version, retrieval_mode, response_text, sources_json, created_at, last_access_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cache_key, q_norm, corpus_digest, provider.lower(), model, int(think),
            prompt_version, retrieval_mode, response_text.strip(), sources_str, now, now
        ))
        cur = conn.execute("SELECT COUNT(*) FROM rag_cache")
        count = cur.fetchone()[0]
        if count > max_entries:
            excess = count - max_entries
            conn.execute("""
                DELETE FROM rag_cache WHERE cache_key IN (
                    SELECT cache_key FROM rag_cache ORDER BY last_access_at ASC LIMIT ?
                )
            """, (excess,))
        conn.commit()
        conn.close()
    except Exception:
        pass


def clear_rag_cache(db_path: str = CACHE_DB_PATH) -> bool:
    """Clear all cached responses from rag_cache."""
    try:
        if os.path.exists(db_path):
            conn = _get_cache_db(db_path)
            conn.execute("DELETE FROM rag_cache")
            conn.commit()
            conn.close()
        return True
    except Exception:
        return False


RUNE_REGEX = re.compile(r"[\u16A0-\u16FF]")
try:
    from ciphers.agrippa import decode_runes, latin_to_rune
except Exception:
    try:
        from agrippa import decode_runes, latin_to_rune
    except Exception:
        decode_runes = None
        latin_to_rune = None


PAGE_TITLES_MAP = {
    "loss of innocence": "56",
    "innocence": "56",
    "a warning": "57",
    "warning": "57",
    "an end": "73",
    "welcome pilgrim": "0",
    "welcome": "0",
    "gematria primus table": "gematria_primus_table",
    "gematria table": "gematria_primus_table",
}


def detect_page_in_query(query: str):
    """Detect if the user is asking about a specific page number or named canonical page."""
    m = PAGE_QUERY_REGEX.search(query)
    if m:
        return m.group(1)
    q_lower = query.lower()
    for title, page_str in PAGE_TITLES_MAP.items():
        if title in q_lower:
            return page_str
    return None


def _calculate_relevance_boost(doc: str, meta: dict, query: str, query_runes: list) -> float:
    """Compute lexical and cryptographic relevance boost for hybrid reranking."""
    score = 0.0
    doc_lower = (doc or "").lower()
    query_lower = query.lower()

    # Keyword overlap boost
    keywords = [w for w in re.findall(r"\w+", query_lower) if len(w) >= 3 and w not in ("page", "pagina", "the", "and", "for", "with")]
    if keywords:
        matches = sum(1 for kw in keywords if kw in doc_lower)
        score += (matches / len(keywords)) * 0.35

    # Direct rune match boost
    if query_runes:
        query_rune_str = "".join(query_runes)
        if query_rune_str in (doc or ""):
            score += 0.50
        elif any(r in (doc or "") for r in query_runes):
            score += 0.25

    # Transliteration match
    if decode_runes and query_runes:
        latin_trans = decode_runes("".join(query_runes)).lower()
        if latin_trans and latin_trans in doc_lower:
            score += 0.40

    # Cryptographic metadata priority
    if meta:
        if meta.get("has_runes") and any(w in query_lower for w in ("rune", "runes", "futhorc", "gematria")):
            score += 0.20
        if meta.get("is_pgp_signed") and any(w in query_lower for w in ("pgp", "signature", "signed", "key", "opsec")):
            score += 0.30

    # Provenance prior in retrieval (P2): verified 1.5, unsigned 1.0, mismatch 0.4
    prior = 1.0
    if meta:
        sig_status = meta.get("sig_status")
        if not sig_status:
            sig_status = "verified_7A35090F" if meta.get("is_pgp_signed") else "unsigned"

        if sig_status == "verified_7A35090F":
            prior = 1.5
        elif sig_status == "mismatch":
            prior = 0.4
        elif sig_status == "unsigned":
            prior = 1.0

        if meta.get("overlay_flag"):
            prior *= 1.2

    multiplier = 2.0 if os.environ.get("TRITHEMIUS_BOOST", "off").lower() in ("on", "true", "1") else 1.0
    return score * prior * multiplier


import math
import glob

CORPUS_DIR = os.path.join(os.path.dirname(__file__), "..", "corpus")


BM25_INDEX_PATH = os.path.join(DB_DIR, "bm25_index.json")
BM25_FORMAT_VERSION = 1
BM25_TOKENIZER_VERSION = 1
BM25_K1 = 1.5
BM25_B = 0.75

_BM25_MEMORY_CACHE: Optional[dict] = None
_BM25_MEMORY_CACHE_MTIME: Optional[float] = None
_BM25_MEMORY_CACHE_DIGEST: Optional[str] = None


def load_persisted_bm25(corpus_dir: str = CORPUS_DIR, index_path: str = BM25_INDEX_PATH) -> Optional[dict]:
    """Load pre-computed BM25 index with in-memory caching for sub-millisecond retrieval."""
    global _BM25_MEMORY_CACHE, _BM25_MEMORY_CACHE_MTIME, _BM25_MEMORY_CACHE_DIGEST
    if os.environ.get("TRITHEMIUS_BM25_PERSIST", "on").lower() == "off":
        return None
    if not os.path.exists(index_path):
        return None
    try:
        try:
            from scripts.bodleian import compute_corpus_digest
        except ImportError:
            from bodleian import compute_corpus_digest
        current_digest = compute_corpus_digest(corpus_dir)
        idx_mtime = os.path.getmtime(index_path)

        if (_BM25_MEMORY_CACHE is not None and
            _BM25_MEMORY_CACHE_MTIME == idx_mtime and
            _BM25_MEMORY_CACHE_DIGEST == current_digest):
            return _BM25_MEMORY_CACHE

        with open(index_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if (data.get("format_version") == BM25_FORMAT_VERSION and
            data.get("tokenizer_version") == BM25_TOKENIZER_VERSION and
            data.get("k1") == BM25_K1 and
            data.get("b") == BM25_B and
            data.get("corpus_digest") == current_digest):
            _BM25_MEMORY_CACHE = data
            _BM25_MEMORY_CACHE_MTIME = idx_mtime
            _BM25_MEMORY_CACHE_DIGEST = current_digest
            return data
    except Exception:
        return None
    return None


def save_persisted_bm25(index_data: dict, index_path: str = BM25_INDEX_PATH) -> None:
    """Atomic write of BM25 index data to disk and update in-memory cache."""
    global _BM25_MEMORY_CACHE, _BM25_MEMORY_CACHE_MTIME, _BM25_MEMORY_CACHE_DIGEST
    if os.environ.get("TRITHEMIUS_BM25_PERSIST", "on").lower() == "off":
        return
    try:
        os.makedirs(os.path.dirname(index_path), exist_ok=True)
        tmp_path = f"{index_path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(index_data, f)
        os.replace(tmp_path, index_path)
        _BM25_MEMORY_CACHE = index_data
        _BM25_MEMORY_CACHE_MTIME = os.path.getmtime(index_path)
        _BM25_MEMORY_CACHE_DIGEST = index_data.get("corpus_digest")
    except Exception:
        pass


def bm25_retrieve(query: str, corpus_dir: str = CORPUS_DIR, k: int = TOP_K, index_path: str = BM25_INDEX_PATH) -> list:
    """
    Zero-VRAM BM25 / lexical retriever fallback against corpus/ documents.
    Operates in pure Python with 0 MB VRAM, 0 GPU, and loads precomputed index in <1ms.
    """
    if not os.path.exists(corpus_dir):
        return []

    page_target = detect_page_in_query(query)
    query_runes = RUNE_REGEX.findall(query)
    q_tokens = [w.lower() for w in re.findall(r"\w+", query) if len(w) >= 2]

    # Attempt to load valid persisted index
    cached = load_persisted_bm25(corpus_dir=corpus_dir, index_path=index_path)

    if cached:
        chunks = cached["chunks"]
        doc_term_freqs = cached["doc_term_freqs"]
        doc_lens = cached["doc_lens"]
        df = cached["df"]
        N = cached["N"]
        avgdl = cached["avgdl"]
    else:
        # Gather documents and build index
        try:
            from scripts.bodleian import iter_corpus_documents
        except ImportError:
            from bodleian import iter_corpus_documents
        docs = iter_corpus_documents(corpus_dir)
        if not docs:
            return []

        chunks = []
        for rel_path, fpath in docs:
            fname = os.path.basename(fpath)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            if not content.strip():
                continue

            page_val = "general"
            pm = re.search(r"page_([0-9]{1,2})", fname, re.IGNORECASE)
            if pm:
                page_val = str(int(pm.group(1)))
            else:
                hdr_m = PAGE_QUERY_REGEX.search(content[:300])
                if hdr_m:
                    page_val = hdr_m.group(1)

            has_runes = bool(RUNE_REGEX.search(content))
            is_pgp = "-----BEGIN PGP" in content
            if is_pgp:
                sig_status = "verified_7A35090F" if "7A35090F" in content.upper() else "mismatch"
            else:
                sig_status = "unsigned"

            meta = {
                "source": rel_path if "/" in rel_path else fname,
                "page": page_val,
                "has_runes": has_runes,
                "is_pgp_signed": is_pgp,
                "sig_status": sig_status,
                "overlay_flag": False,
            }

            paragraphs = content.split("\n\n")
            cur_chunk = []
            cur_len = 0
            for p in paragraphs:
                p_str = p.strip()
                if not p_str:
                    continue
                cur_chunk.append(p_str)
                cur_len += len(p_str)
                if cur_len >= 1200:
                    chunk_text = "\n\n".join(cur_chunk)
                    chunks.append((chunk_text, meta))
                    cur_chunk = []
                    cur_len = 0
            if cur_chunk:
                chunk_text = "\n\n".join(cur_chunk)
                chunks.append((chunk_text, meta))

        if not chunks:
            return []

        N = len(chunks)
        doc_tokens_list = [[w.lower() for w in re.findall(r"\w+", c[0])] for c in chunks]
        doc_lens = [len(dt) for dt in doc_tokens_list]
        avgdl = sum(doc_lens) / max(1, N)

        df = {}
        doc_term_freqs = []
        for dt in doc_tokens_list:
            counts = {}
            for t in dt:
                counts[t] = counts.get(t, 0) + 1
            doc_term_freqs.append(counts)
            for token in counts.keys():
                df[token] = df.get(token, 0) + 1

        # Atomically save index
        try:
            try:
                from scripts.bodleian import compute_corpus_digest
            except ImportError:
                from bodleian import compute_corpus_digest
            digest = compute_corpus_digest(corpus_dir)
            index_data = {
                "format_version": BM25_FORMAT_VERSION,
                "tokenizer_version": BM25_TOKENIZER_VERSION,
                "k1": BM25_K1,
                "b": BM25_B,
                "corpus_digest": digest,
                "timestamp": time.time(),
                "N": N,
                "avgdl": avgdl,
                "df": df,
                "doc_term_freqs": doc_term_freqs,
                "doc_lens": doc_lens,
                "chunks": chunks,
            }
            save_persisted_bm25(index_data, index_path=index_path)
        except Exception:
            pass

    k1 = BM25_K1
    b = BM25_B
    candidates = []

    for idx, (chunk_text, meta) in enumerate(chunks):
        counts = doc_term_freqs[idx]
        dl = doc_lens[idx]
        score = 0.0

        for qt in q_tokens:
            if qt in counts:
                tf = counts[qt]
                doc_freq = df.get(qt, 0)
                idf = math.log(1.0 + (N - doc_freq + 0.5) / (doc_freq + 0.5))
                num = tf * (k1 + 1.0)
                den = tf + k1 * (1.0 - b + b * (dl / max(1.0, avgdl)))
                score += idf * (num / den)

        boost = _calculate_relevance_boost(chunk_text, meta, query, query_runes)
        score += boost * 2.0

        if page_target and meta.get("page") == str(int(page_target) if page_target.isdigit() else page_target):
            score += 5.0

        candidates.append((score, chunk_text, meta))

    candidates.sort(key=lambda x: x[0], reverse=True)
    actual_k = 10 if (k == TOP_K and os.environ.get("TRITHEMIUS_BOOST", "off").lower() in ("on", "true", "1")) else k
    return [(c[1], c[2]) for c in candidates[:actual_k]]


def retrieve(collection, query: str, k: int = TOP_K) -> list:
    """Retrieve top-k chunks with page-aware metadata filtering and hybrid rune/keyword reranking."""
    if k == TOP_K and os.environ.get("TRITHEMIUS_BOOST", "off").lower() in ("on", "true", "1"):
        k = 10
    page_target = detect_page_in_query(query)
    query_runes = RUNE_REGEX.findall(query)

    query_embedding = None
    if collection is not None:
        try:
            query_embedding = ollama.embeddings(model=EMBED_MODEL, prompt=query)["embedding"]
        except Exception:
            # Fall back to zero-VRAM BM25 lexical retriever
            return bm25_retrieve(query, k=k)

    if query_embedding is None or collection is None:
        return bm25_retrieve(query, k=k)

    # If user asked about a specific page, prioritize page filtering (checking normalized formats)
    if page_target:
        possible_pages = [str(page_target)]
        if str(page_target).isdigit():
            norm_val = str(int(page_target))
            if norm_val not in possible_pages:
                possible_pages.append(norm_val)
            pad_val = f"{int(page_target):02d}"
            if pad_val not in possible_pages:
                possible_pages.append(pad_val)
        for pt in possible_pages:
            try:
                page_results = collection.query(
                    query_embeddings=[query_embedding],
                    n_results=k,
                    where={"page": pt}
                )
                docs = page_results.get("documents", [[]])[0]
                metas = page_results.get("metadatas", [[]])[0]
                if docs:
                    return list(zip(docs, metas))
            except Exception:
                pass

    # Standard vector similarity query with candidate pool for hybrid reranking
    fetch_count = min(max(k * 2, 8), 25)
    results = collection.query(query_embeddings=[query_embedding], n_results=fetch_count)
    docs = results.get("documents", [[]])[0]
    metas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0] if "distances" in results else [0.0] * len(docs)

    if not docs:
        return bm25_retrieve(query, k=k)

    # Calculate hybrid score combining vector distance and lexical/rune relevance
    candidates = []
    for idx, (doc, meta) in enumerate(zip(docs, metas)):
        dist = distances[idx] if idx < len(distances) else 0.5
        # Cosine distance to similarity: sim = 1.0 - dist
        sim = max(0.0, 1.0 - dist)
        boost = _calculate_relevance_boost(doc, meta or {}, query, query_runes)
        hybrid_score = (sim * 0.65) + boost
        candidates.append((hybrid_score, doc, meta))

    candidates.sort(key=lambda c: c[0], reverse=True)
    return [(c[1], c[2]) for c in candidates[:k]]


def build_prompt(
    query: str,
    retrieved: list,
    web_context: str = None,
    max_context_chars: int = 2500,
    deterministic_context: str = None,
) -> str:
    """
    Construct RAG prompt enforcing a strict character budget across retrieved chunks
    to keep prompt evaluation time under ~3 seconds while preserving source/page metadata.
    """
    context_blocks = []
    current_chars = 0
    for doc, meta in retrieved:
        if not doc:
            continue
        meta = meta or {}
        src = meta.get("source", "unknown")
        page = meta.get("page", "general")
        header = f"[Source: {src} | Page: {page}]\n"
        remaining = max_context_chars - current_chars
        min_required = len(header) + 20
        if remaining < min_required:
            break

        doc_slice = doc[: remaining - len(header)]
        block = f"{header}{doc_slice}"
        context_blocks.append(block)
        current_chars += len(block)
        if current_chars >= max_context_chars:
            break

    corpus_section = "\n\n---\n\n".join(context_blocks) if context_blocks else "[No local corpus matches found]"
    web_section = f"\n\nLive Web Search Results:\n{web_context}\n" if web_context else ""
    dt_section = f"\n\n{deterministic_context}\n" if deterministic_context else ""

    return f"""Context from Liber Primus Corpus:

{corpus_section}
{web_section}{dt_section}
---

Research Question: {query}

Provide a comprehensive, continuous analytical answer in English (regardless of the language used in the question). Synthesize the findings into fluid narrative paragraphs without relying on bulleted outlines or fragmented lists, and cite specific pages or sources naturally within the text."""


def stream_chat(model_name: str, prompt: str, think: bool = False, provider: str = None) -> str:
    """Stream model response to stdout in real-time, streaming both reasoning and content. Returns full response text."""
    p = (provider or getattr(config, "ACTIVE_PROVIDER", "ollama")).lower()
    full_content = []

    # If local default Ollama, call ollama.chat directly to preserve exact mock compatibility for existing tests
    if p == "ollama" and getattr(config, "OLLAMA_HOST", "http://localhost:11434") == "http://localhost:11434" and not getattr(config, "OLLAMA_API_KEY", ""):
        stream = ollama.chat(
            model=model_name,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            options={"num_ctx": CONTEXT_WINDOW, "num_predict": DEFAULT_NUM_PREDICT},
            stream=True,
            think=think,
        )
        in_thinking = False
        for chunk in stream:
            msg = chunk.get("message", {})
            thinking = msg.get("thinking")
            content = msg.get("content")

            if thinking and think:
                if not in_thinking:
                    print("\033[2m[Reasoning: ", end="", flush=True)
                    in_thinking = True
                print(thinking, end="", flush=True)

            if content:
                if in_thinking:
                    print("]\033[0m\n", end="", flush=True)
                    in_thinking = False
                print(content, end="", flush=True)
                full_content.append(content)

        if in_thinking:
            print("]\033[0m\n", end="", flush=True)
        print("\n")
        return "".join(full_content)
    else:
        # Route through unified multi-provider engine (Groq, OpenAI, Gemini, Claude, OpenRouter, or remote Ollama)
        from scripts.providers import stream_completion
        stream = stream_completion(
            provider=p,
            model=model_name,
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT,
            think=think,
        )
        in_thinking = False
        for kind, text in stream:
            if kind == "thinking" and think:
                if not in_thinking:
                    print("\033[2m[Reasoning: ", end="", flush=True)
                    in_thinking = True
                print(text, end="", flush=True)
            elif kind == "content":
                if in_thinking:
                    print("]\033[0m\n", end="", flush=True)
                    in_thinking = False
                print(text, end="", flush=True)
                full_content.append(text)

        if in_thinking:
            print("]\033[0m\n", end="", flush=True)
        print("\n")
        return "".join(full_content)


def main():
    parser = argparse.ArgumentParser(description="Trithemius Liber Primus RAG Assistant")
    parser.add_argument("--moe", action="store_true", help="Use DeepSeek MoE model")
    parser.add_argument("--model", type=str, default="", help="Select model key (spark, moe, tiny, groq, etc.)")
    parser.add_argument("--provider", type=str, default="", help="Inference provider (ollama, groq, openai, gemini, anthropic, openrouter)")
    parser.add_argument("--think", action="store_true", help="Enable Chain-of-Thought reasoning (CoT)")
    args = parser.parse_args()

    chosen_provider = (args.provider or getattr(config, "ACTIVE_PROVIDER", "ollama")).lower()
    chosen_key = "moe" if args.moe else (args.model or "")
    active_model = get_model(chosen_key, provider=chosen_provider)

    collection = None
    try:
        collection = get_collection()
    except Exception:
        pass

    print(f"=== Trithemius Online [Provider: {chosen_provider.upper()} | Model: {active_model}] ===")
    print("Commands:")
    print("  /web <query>  -> retrieve live web results alongside local corpus")
    print("  /page <N>     -> focus inquiry on page N")
    print("  exit / quit   -> shutdown\n")

    while True:
        try:
            query = input("You: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nShutting down Trithemius.")
            break

        if not query:
            continue
        if query.lower() in ("exit", "quit"):
            break

        use_web = query.startswith("/web ")
        if use_web:
            query = query[len("/web "):].strip()

        print(f"\n[Retrieving knowledge from vector DB...]")
        retrieved = retrieve(collection, query)

        web_context = None
        if use_web:
            print("[Searching live web via Bacon module...]")
            try:
                web_context = web_context_block(query, max_results=3, fetch_full=False)
            except Exception as e:
                web_context = f"[Web search failed: {e}]"

        if not retrieved and not web_context:
            print("Trithemius: No ingested corpus documents found yet. Place files in corpus/ and run 'python3 scripts/bodleian.py'.\n")
            continue

        prompt = build_prompt(query, retrieved, web_context)

        print("\nTrithemius: ", end="", flush=True)
        try:
            stream_chat(active_model, prompt, think=args.think)
        except Exception as e:
            print(f"\n[Error communicating with model {active_model} via Ollama: {e}]")
            print("Check that Ollama is running and the model is pulled (`ollama pull <model>`).\n")


if __name__ == "__main__":
    main()
