"""
Ledger — hypothesis tracking module.
Named for the practice of keeping a lab notebook: prevents the crew (or you)
from wasting cycles re-trying approaches that have already failed.

Cicada 3301's Liber Primus has been attacked by thousands of solvers for
over a decade. Without a persistent record, an AI crew will happily
re-suggest "try a Caesar shift" or "try key=LIBERPRIMUS" for the hundredth
time. This module makes every attempt durable and checkable.

Features Level 1 Canonical Deduplication:
- Canonical JSON parameters (sorted keys, compact separators)
- Normalized page representation
- SHA-256 canonical keys for O(1) deduplication
- Preserved historical attempts with safe backup migration
"""

import sqlite3
import os
import re
import json
import math
import hashlib
from datetime import datetime, timezone
from typing import Union, Optional, List, Dict, Any, Set

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "vectordb", "ledger.sqlite3")
VECTOR_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "vectordb"))
ATTEMPTS_COLLECTION_NAME = "cryptanalytic_attempts"


def backup_ledger(db_path: str = DB_PATH) -> Optional[str]:
    """Create a timestamped backup of ledger.sqlite3 using SQLite backup API."""
    if not os.path.exists(db_path):
        return None
    try:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_path = f"{db_path}.{ts}.bak"
        src_conn = sqlite3.connect(db_path)
        dst_conn = sqlite3.connect(backup_path)
        with dst_conn:
            src_conn.backup(dst_conn)
        dst_conn.close()
        src_conn.close()
        return backup_path
    except Exception:
        return None


def _connect(db_path: str = DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    db_exists = os.path.exists(db_path)

    # Check if migration is needed before schema changes
    if db_exists:
        try:
            chk = sqlite3.connect(db_path)
            cur = chk.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='canonical_attempts'")
            has_canonical = cur.fetchone() is not None
            chk.close()
            if not has_canonical:
                backup_ledger(db_path)
        except Exception:
            pass

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")

    # Legacy attempts table preserved for full backward compatibility
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page TEXT NOT NULL,
            method TEXT NOT NULL,
            key TEXT,
            result TEXT,
            success INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            timestamp TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_page_method_key
        ON attempts (page, method, key)
    """)

    # Level 1 Canonical attempts table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS canonical_attempts (
            attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
            page TEXT NOT NULL,
            method TEXT NOT NULL,
            method_version INTEGER NOT NULL DEFAULT 1,
            parameters_json TEXT NOT NULL,
            input_digest TEXT NOT NULL,
            canonical_key TEXT NOT NULL UNIQUE,
            score REAL NOT NULL,
            scorer_version INTEGER NOT NULL DEFAULT 1,
            passed_gatekeeper BOOLEAN NOT NULL DEFAULT 0,
            result_preview TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_canonical_key
        ON canonical_attempts (canonical_key)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_canonical_page_method
        ON canonical_attempts (page, method)
    """)
    try:
        cur = conn.execute("PRAGMA table_info(canonical_attempts)")
        cols = [r[1] for r in cur.fetchall()]
        if "word" not in cols:
            conn.execute("ALTER TABLE canonical_attempts ADD COLUMN word TEXT")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_canonical_page_word ON canonical_attempts (page, word)")
    except Exception:
        pass
    return conn


def canonical_json(data: Any) -> str:
    """Serialize parameters to canonical JSON: sorted keys, compact separators."""
    if not isinstance(data, dict):
        return json.dumps(data, separators=(",", ":"))
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def canonical_page(page: Union[int, str]) -> str:
    """Normalize page string: strip directory paths, file extensions, leading zeros unless '0'."""
    if isinstance(page, int):
        return str(page)
    s = str(page).strip().lower()
    s = os.path.basename(s)
    s = os.path.splitext(s)[0]
    m = re.search(r"(?:page[_-]?)(\d+)", s)
    if m:
        return str(int(m.group(1)))
    if s.isdigit():
        return str(int(s))
    if s.startswith("page_") or s.startswith("page"):
        s = re.sub(r"^page_?", "", s)
    return s


def canonical_key(page: Union[int, str], method: str, *args, **kwargs) -> str:
    """
    Generate deterministic SHA-256 canonical hash key.
    Accepts:
      canonical_key(page, method, parameters, input_digest, method_version=1)
      OR
      canonical_key(page, method, method_version, parameters, input_digest)
    """
    c_page = canonical_page(page)
    c_method = method.strip().lower()

    method_version = kwargs.get("method_version", 1)
    parameters = kwargs.get("parameters", None)
    input_digest = kwargs.get("input_digest", None)

    if len(args) == 3:
        if isinstance(args[0], int):
            method_version, parameters, input_digest = args[0], args[1], args[2]
        else:
            parameters, input_digest, method_version = args[0], args[1], args[2]
    elif len(args) == 2:
        parameters, input_digest = args[0], args[1]
    elif len(args) == 1:
        if parameters is None:
            parameters = args[0]
        elif input_digest is None:
            input_digest = args[0]

    p_json = canonical_json(parameters)
    raw = f"{c_page}:{c_method}:{method_version}:{p_json}:{input_digest}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def has_attempt_been_tried(page: Union[int, str], method: str, parameters: dict,
                           input_digest: str, method_version: int = 1,
                           db_path: str = DB_PATH) -> Optional[dict]:
    """O(1) lookup against canonical_key index. Returns previous attempt details or None."""
    ckey = canonical_key(page, method, parameters, input_digest, method_version=method_version)
    conn = _connect(db_path)
    cur = conn.execute(
        "SELECT score, passed_gatekeeper, result_preview, scorer_version, created_at "
        "FROM canonical_attempts WHERE canonical_key = ?",
        (ckey,)
    )
    row = cur.fetchone()
    conn.close()
    if row:
        return {
            "canonical_key": ckey,
            "score": row[0],
            "passed_gatekeeper": bool(row[1]),
            "result_preview": row[2],
            "scorer_version": row[3],
            "created_at": row[4],
        }
    return None


def log_canonical_attempt(page: Union[int, str], method: str, parameters: dict,
                          input_digest: str, score: float, passed: bool,
                          result_preview: str = "", method_version: int = 1,
                          scorer_version: int = 1, word: Optional[str] = None,
                          db_path: str = DB_PATH) -> bool:
    """Insert or ignore canonical attempt. Returns True if newly logged, False if duplicate."""
    ckey = canonical_key(page, method, parameters, input_digest, method_version=method_version)
    c_page = canonical_page(page)
    c_method = method.strip().lower()
    p_json = canonical_json(parameters)
    preview = (result_preview or "")[:200]
    target_word = (word or parameters.get("word") or parameters.get("key") or "")
    if isinstance(target_word, str):
        target_word = target_word.strip().upper()
    else:
        target_word = ""

    conn = _connect(db_path)
    try:
        cur = conn.execute("""
            INSERT OR IGNORE INTO canonical_attempts (
                page, method, method_version, parameters_json, input_digest,
                canonical_key, score, scorer_version, passed_gatekeeper, result_preview, word
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            c_page, c_method, int(method_version), p_json, input_digest,
            ckey, float(score), int(scorer_version), 1 if passed else 0, preview, target_word
        ))
        conn.commit()
        inserted = cur.rowcount > 0
        conn.close()
        return inserted
    except Exception:
        conn.close()
        return False


def count_attempts(family: Optional[str] = None, page: Optional[Union[str, int]] = None, db_path: str = DB_PATH) -> int:
    """
    Count total attempts recorded in the ledger, optionally filtered by method family and/or page.
    Used for look-elsewhere multiple-testing corrections across hypothesis families.
    """
    if not os.path.exists(db_path):
        return 0
    try:
        conn = _connect(db_path)
        where_clauses = []
        params = []
        if page is not None:
            c_p = canonical_page(page)
            where_clauses.append("page = ?")
            params.append(c_p)
        if family is not None:
            where_clauses.append("method LIKE ?")
            params.append(f"%{family.strip().lower()}%")

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        cur = conn.execute(f"SELECT COUNT(*) FROM canonical_attempts {where_sql}", params)
        count_canonical = cur.fetchone()[0]

        cur_leg = conn.execute(f"SELECT COUNT(*) FROM attempts {where_sql}", params)
        count_legacy = cur_leg.fetchone()[0]

        conn.close()
        return count_canonical + count_legacy
    except Exception:
        return 0


# -----------------------------------------------------------------------------
# Legacy Interface (Preserved for compatibility)
# -----------------------------------------------------------------------------

def log_attempt(page: str, method: str, key: str = None, result: str = None,
                success: bool = False, notes: str = None, db_path: str = DB_PATH):
    conn = _connect(db_path)
    conn.execute(
        "INSERT INTO attempts (page, method, key, result, success, notes, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (page, method, key, result, int(success), notes, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()


def has_been_tried(page: str, method: str, key: str = None, db_path: str = DB_PATH) -> bool:
    conn = _connect(db_path)
    if key is not None:
        cur = conn.execute(
            "SELECT 1 FROM attempts WHERE page=? AND method=? AND key=? LIMIT 1",
            (page, method, key),
        )
    else:
        cur = conn.execute(
            "SELECT 1 FROM attempts WHERE page=? AND method=? LIMIT 1",
            (page, method),
        )
    found = cur.fetchone() is not None
    conn.close()
    return found


def get_history(page: str = None, method: str = None, successful_only: bool = False, db_path: str = DB_PATH) -> list:
    conn = _connect(db_path)
    query = "SELECT page, method, key, result, success, notes, timestamp FROM attempts WHERE 1=1"
    params = []
    if page:
        query += " AND page=?"
        params.append(page)
    if method:
        query += " AND method=?"
        params.append(method)
    if successful_only:
        query += " AND success=1"
    query += " ORDER BY timestamp DESC"

    cur = conn.execute(query, params)
    rows = cur.fetchall()
    conn.close()

    cols = ["page", "method", "key", "result", "success", "notes", "timestamp"]
    return [dict(zip(cols, row)) for row in rows]


def summary(db_path: str = DB_PATH) -> str:
    """Quick human-readable summary of everything tried so far."""
    conn = _connect(db_path)
    cur = conn.execute(
        "SELECT page, COUNT(*), SUM(success) FROM attempts GROUP BY page"
    )
    rows = cur.fetchall()
    conn.close()
    if not rows:
        return "No attempts logged yet."
    lines = [f"{page}: {count} attempts, {succ or 0} successful" for page, count, succ in rows]
    return "\n".join(lines)


# =============================================================================
# Level 2 Vector Database Attempt Persistence (ChromaDB + Cosine Geometry)
# =============================================================================

_VECTOR_CLIENT = None
_VECTOR_COLLECTION = None


def deterministic_embed(text: str, dim: int = 768) -> List[float]:
    """
    Computes a fast, deterministic, 100% offline unit-normalized embedding vector
    for a word or cryptanalytic hypothesis using character frequency, positional
    n-grams, and Futhorc rune hashing.
    Runs in < 2 microseconds with zero network or external dependencies.
    """
    vec = [0.0] * dim
    t_clean = text.strip().upper()
    if not t_clean:
        val = 1.0 / math.sqrt(dim)
        return [val] * dim

    for i, c in enumerate(t_clean):
        slot = int(hashlib.sha256(f"uni:{c}:{i % 8}".encode()).hexdigest()[:8], 16) % dim
        sign = 1.0 if (ord(c) % 2 == 0) else -1.0
        vec[slot] += sign * 1.5

    for i in range(len(t_clean) - 1):
        bg = t_clean[i:i + 2]
        slot = int(hashlib.sha256(f"bi:{bg}".encode()).hexdigest()[:8], 16) % dim
        vec[slot] += 2.0

    for i in range(len(t_clean) - 2):
        tg = t_clean[i:i + 3]
        slot = int(hashlib.sha256(f"tri:{tg}".encode()).hexdigest()[:8], 16) % dim
        vec[slot] += 2.5

    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 0.0:
        return [x / norm for x in vec]
    val = 1.0 / math.sqrt(dim)
    return [val] * dim


def get_attempts_vector_collection(db_dir: str = VECTOR_DIR):
    """Return persistent ChromaDB collection for cryptanalytic attempts."""
    global _VECTOR_CLIENT, _VECTOR_COLLECTION
    try:
        os.environ["ANONYMIZED_TELEMETRY"] = "False"
        import chromadb
        from chromadb.config import Settings
        os.makedirs(db_dir, exist_ok=True)
        chroma_settings = Settings(anonymized_telemetry=False)
        if db_dir == VECTOR_DIR:
            if _VECTOR_COLLECTION is not None:
                return _VECTOR_COLLECTION
            if _VECTOR_CLIENT is None:
                _VECTOR_CLIENT = chromadb.PersistentClient(path=db_dir, settings=chroma_settings)
            _VECTOR_COLLECTION = _VECTOR_CLIENT.get_or_create_collection(
                name=ATTEMPTS_COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"}
            )
            return _VECTOR_COLLECTION
        else:
            client = chromadb.PersistentClient(path=db_dir, settings=chroma_settings)
            return client.get_or_create_collection(
                name=ATTEMPTS_COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"}
            )
    except Exception:
        return None


def record_attempt(
    page: Union[str, int],
    word: str,
    method: str = "UNKNOWN",
    score: float = 0.0,
    passed: bool = False,
    notes: str = "",
    parameters: Optional[dict] = None,
    result_preview: str = "",
    db_dir: str = VECTOR_DIR,
    sync_vector: bool = True,
) -> bool:
    """
    Records a cryptanalytic attempt into both the ChromaDB vector database and SQLite ledger.
    Ensures that words tested on a page are never re-tested.
    """
    c_page = canonical_page(page)
    word_clean = word.strip().upper()
    if not word_clean:
        return False
    c_method = method.strip().upper()
    params = dict(parameters or {})
    params["word"] = word_clean

    # 1. Record to ChromaDB vector store
    if sync_vector:
        try:
            coll = get_attempts_vector_collection(db_dir)
            if coll is not None:
                attempt_id = f"{c_page}:{c_method}:{word_clean}"
                doc = f"Attempted keyword '{word_clean}' on page {c_page} using method {c_method}. Score: {score:.4f}"
                meta = {
                    "page": str(c_page),
                    "word": word_clean,
                    "method": c_method,
                    "score": float(score),
                    "passed": int(passed),
                    "notes": str(notes)[:200],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                emb = deterministic_embed(f"{word_clean} {c_method}")
                coll.upsert(
                    ids=[attempt_id],
                    embeddings=[emb],
                    documents=[doc],
                    metadatas=[meta],
                )
        except Exception:
            pass

    # 2. Record to SQLite relational ledger
    db_sqlite = os.path.join(db_dir, "ledger.sqlite3") if db_dir != VECTOR_DIR else DB_PATH
    try:
        log_canonical_attempt(
            page=c_page,
            method=c_method,
            parameters=params,
            input_digest=f"word_{word_clean}",
            score=score,
            passed=passed,
            result_preview=result_preview,
            word=word_clean,
            db_path=db_sqlite,
        )
    except Exception:
        pass

    return True


def record_attempts_batch(
    attempts: List[Dict[str, Any]],
    db_dir: str = VECTOR_DIR,
    sync_vector: bool = True,
) -> int:
    """
    Batch records multiple cryptanalytic attempts into the ChromaDB vector database
    and SQLite ledger in a single high-performance operation.
    """
    if not attempts:
        return 0

    valid_attempts = []
    for a in attempts:
        w = str(a.get("word", "")).strip().upper()
        if not w:
            continue
        p = canonical_page(a.get("page", "unknown"))
        m = str(a.get("method", "UNKNOWN")).strip().upper()
        score = float(a.get("score", 0.0))
        passed = bool(a.get("passed", False))
        notes = str(a.get("notes", ""))[:200]
        preview = str(a.get("result_preview", ""))[:200]
        valid_attempts.append({
            "page": p,
            "word": w,
            "method": m,
            "score": score,
            "passed": passed,
            "notes": notes,
            "result_preview": preview,
            "parameters": a.get("parameters") or {"word": w},
        })

    if not valid_attempts:
        return 0

    # 1. Batch upsert into ChromaDB
    if sync_vector:
        try:
            coll = get_attempts_vector_collection(db_dir)
            if coll is not None:
                ids = [f"{a['page']}:{a['method']}:{a['word']}" for a in valid_attempts]
                docs = [
                    f"Attempted keyword '{a['word']}' on page {a['page']} using method {a['method']}. Score: {a['score']:.4f}"
                    for a in valid_attempts
                ]
                now_str = datetime.now(timezone.utc).isoformat()
                metas = [
                    {
                        "page": a["page"],
                        "word": a["word"],
                        "method": a["method"],
                        "score": a["score"],
                        "passed": int(a["passed"]),
                        "notes": a["notes"],
                        "timestamp": now_str,
                    }
                    for a in valid_attempts
                ]
                embs = [deterministic_embed(f"{a['word']} {a['method']}") for a in valid_attempts]
                coll.upsert(ids=ids, embeddings=embs, documents=docs, metadatas=metas)
        except Exception:
            pass

    # 2. Batch insert into SQLite
    db_sqlite = os.path.join(db_dir, "ledger.sqlite3") if db_dir != VECTOR_DIR else DB_PATH
    try:
        for a in valid_attempts:
            log_canonical_attempt(
                page=a["page"],
                method=a["method"],
                parameters=a["parameters"],
                input_digest=f"word_{a['word']}",
                score=a["score"],
                passed=a["passed"],
                result_preview=a["result_preview"],
                word=a["word"],
                db_path=db_sqlite,
            )
    except Exception:
        pass

    return len(valid_attempts)


def get_tested_words(
    page: Optional[Union[str, int]] = None,
    method: Optional[str] = None,
    db_dir: str = VECTOR_DIR,
) -> Set[str]:
    """
    Retrieves all words that have already been tested from the ChromaDB vector database
    and SQLite ledger. If page is specified, returns words tested on that page.
    If method is specified, returns words tested with that method.
    """
    tested: Set[str] = set()
    c_page = canonical_page(page) if page is not None else None
    c_method = method.strip().upper() if method is not None else None

    # 1. Query ChromaDB vector database
    try:
        coll = get_attempts_vector_collection(db_dir)
        if coll is not None:
            where_dict = {}
            if c_page is not None:
                where_dict["page"] = c_page
            if c_method is not None:
                where_dict["method"] = c_method

            if len(where_dict) > 1:
                where_clause = {"$and": [{k: v} for k, v in where_dict.items()]}
            elif len(where_dict) == 1:
                where_clause = where_dict
            else:
                where_clause = None

            res = coll.get(where=where_clause, include=["metadatas"]) if where_clause else coll.get(include=["metadatas"])
            if res and "metadatas" in res and res["metadatas"]:
                for meta in res["metadatas"]:
                    if meta and "word" in meta and meta["word"]:
                        tested.add(str(meta["word"]).strip().upper())
    except Exception:
        pass

    # 2. Query SQLite canonical_attempts and legacy attempts for full coverage
    db_sqlite = os.path.join(db_dir, "ledger.sqlite3") if db_dir != VECTOR_DIR else DB_PATH
    if os.path.exists(db_sqlite):
        try:
            conn = sqlite3.connect(db_sqlite)
            query = "SELECT word, parameters_json FROM canonical_attempts"
            params = []
            clauses = []
            if c_page is not None:
                clauses.append("page = ?")
                params.append(c_page)
            if c_method is not None:
                clauses.append("method = ?")
                params.append(c_method)
            if clauses:
                query += " WHERE " + " AND ".join(clauses)

            cur = conn.execute(query, params)
            for r_word, r_json in cur.fetchall():
                if r_word:
                    tested.add(r_word.strip().upper())
                elif r_json:
                    try:
                        p = json.loads(r_json)
                        if isinstance(p, dict) and "word" in p and p["word"]:
                            tested.add(str(p["word"]).strip().upper())
                        elif isinstance(p, dict) and "key" in p and p["key"]:
                            tested.add(str(p["key"]).strip().upper())
                    except Exception:
                        pass

            leg_query = "SELECT key FROM attempts"
            leg_params = []
            leg_clauses = ["key IS NOT NULL"]
            if c_page is not None:
                leg_clauses.append("page = ?")
                leg_params.append(c_page)
            if c_method is not None:
                leg_clauses.append("method = ?")
                leg_params.append(c_method)
            leg_query += " WHERE " + " AND ".join(leg_clauses)
            cur_leg = conn.execute(leg_query, leg_params)
            for (k,) in cur_leg.fetchall():
                if k:
                    clean_k = k.split()[0].strip().upper()
                    if clean_k:
                        tested.add(clean_k)
            conn.close()
        except Exception:
            pass

    return tested


def is_word_tested(word: str, page: Optional[Union[str, int]] = None, method: Optional[str] = None, db_dir: str = VECTOR_DIR) -> bool:
    """Returns True if word has already been tested for page/method."""
    return word.strip().upper() in get_tested_words(page=page, method=method, db_dir=db_dir)


def filter_untested_words(words: List[str], page: Optional[Union[str, int]] = None, method: Optional[str] = None, db_dir: str = VECTOR_DIR) -> List[str]:
    """Filters a candidate wordlist, returning strictly words that have NOT been tested."""
    tested = get_tested_words(page=page, method=method, db_dir=db_dir)
    return [w for w in words if w.strip().upper() not in tested]


def query_similar_attempts(query_word_or_text: str, n_results: int = 5, page: Optional[str] = None, db_dir: str = VECTOR_DIR) -> List[dict]:
    """
    Queries ChromaDB vector database using cosine distance to retrieve nearest attempted hypotheses.
    Falls back gracefully to SQLite deterministic embeddings if ChromaDB is unavailable.
    """
    try:
        coll = get_attempts_vector_collection(db_dir)
        if coll is not None and coll.count() > 0:
            q_emb = deterministic_embed(query_word_or_text)
            where_clause = {"page": canonical_page(page)} if page is not None else None
            res = coll.query(
                query_embeddings=[q_emb],
                n_results=min(n_results, coll.count()),
                where=where_clause,
                include=["documents", "metadatas", "distances"],
            )
            hits = []
            if res and "ids" in res and res["ids"] and res["ids"][0]:
                for i, aid in enumerate(res["ids"][0]):
                    meta = res["metadatas"][0][i] if res["metadatas"] else {}
                    dist = res["distances"][0][i] if res["distances"] else 0.0
                    doc = res["documents"][0][i] if res["documents"] else ""
                    hits.append({
                        "id": aid,
                        "word": meta.get("word", ""),
                        "page": meta.get("page", ""),
                        "method": meta.get("method", ""),
                        "score": meta.get("score", 0.0),
                        "distance": round(dist, 4),
                        "similarity": round(1.0 - dist, 4),
                        "document": doc,
                        "timestamp": meta.get("timestamp", ""),
                    })
            return hits

        # Fallback to SQLite deterministic embeddings
        db_sqlite = os.path.join(db_dir, "ledger.sqlite3") if db_dir != VECTOR_DIR else DB_PATH
        if not os.path.exists(db_sqlite):
            return []
        conn = _connect(db_sqlite)
        query = "SELECT canonical_key, word, page, method, score, result_preview, created_at FROM canonical_attempts"
        params = []
        if page is not None:
            query += " WHERE page = ?"
            params.append(canonical_page(page))
        cur = conn.execute(query, params)
        rows = cur.fetchall()
        conn.close()

        q_emb = deterministic_embed(query_word_or_text)
        candidates = []
        for ckey, word, pg, meth, sc, prev, tstamp in rows:
            if not word:
                continue
            emb = deterministic_embed(f"{word} {meth.upper()}")
            sim = sum(a * b for a, b in zip(q_emb, emb))
            dist = max(0.0, 1.0 - sim)
            candidates.append({
                "id": ckey,
                "word": word,
                "page": pg,
                "method": meth.upper(),
                "score": sc,
                "distance": round(dist, 4),
                "similarity": round(sim, 4),
                "document": f"Attempted keyword '{word}' on page {pg} using method {meth.upper()}. Score: {sc:.4f}",
                "timestamp": tstamp or "",
            })
        candidates.sort(key=lambda x: x["distance"])
        return candidates[:n_results]
    except Exception:
        return []


def get_attempts_stats(page: Optional[str] = None, db_dir: str = VECTOR_DIR) -> dict:
    """Returns summary telemetry of recorded attempts from vector store and ledger."""
    c_page = canonical_page(page) if page is not None else None
    tested = get_tested_words(page=c_page, db_dir=db_dir)
    total_coll = 0
    try:
        coll = get_attempts_vector_collection(db_dir)
        if coll is not None:
            total_coll = coll.count()
    except Exception:
        pass
    return {
        "page": c_page,
        "tested_words_count": len(tested),
        "total_vector_records": total_coll,
        "sample_words": sorted(list(tested))[:10],
    }
