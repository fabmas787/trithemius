"""
Bodleian — Liber Primus corpus ingestion module.
Named for Thomas Bodley, founder of the Bodleian Library: this module's job
is collecting, structuring, and indexing the research corpus.

Ingests text files (.txt, .md, .json, .csv) in ../corpus/ into a local
ChromaDB vector store, extracting Liber Primus page metadata and rune detection,
using Ollama's nomic-embed-text for high-dimensional embeddings.

Run:
    python3 scripts/bodleian.py
"""

import os
import re
import glob
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional
try:
    import ollama
except ImportError:
    ollama = None

try:
    import chromadb
except ImportError:
    chromadb = None
import sys
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from ciphers.entropy import shannon_entropy, index_of_coincidence, is_high_entropy
    from ciphers.opsec import inspect_pgp_text
except ImportError:
    from entropy import shannon_entropy, index_of_coincidence, is_high_entropy
    from opsec import inspect_pgp_text

try:
    from scripts.porta import normalized_sha256
except ImportError:
    try:
        from porta import normalized_sha256
    except ImportError:
        normalized_sha256 = None

try:
    from ciphers.agrippa import decode_runes, gematria_prime_sum
except ImportError:
    try:
        from agrippa import decode_runes, gematria_prime_sum
    except ImportError:
        decode_runes = None
        gematria_prime_sum = None

from pathlib import Path
import time

CORPUS_DIR = os.path.join(os.path.dirname(__file__), "..", "corpus")
DB_DIR = os.path.join(os.path.dirname(__file__), "..", "vectordb")
CACHE_PATH = os.path.join(DB_DIR, "ingest_cache.json")
CORPUS_META_PATH = os.path.join(DB_DIR, "corpus_meta.json")

_MEMO: Dict[Tuple[str, int, int], str] = {}
READS = 0


ALLOWED_EXTENSIONS = {".txt", ".md", ".json", ".csv"}


def clear_digest_memo() -> None:
    global READS
    _MEMO.clear()
    READS = 0


def iter_corpus_documents(corpus_dir: str | os.PathLike = CORPUS_DIR) -> List[Tuple[str, Path]]:
    """Enumerate valid corpus documents recursively, excluding hidden and private directories."""
    root = Path(corpus_dir)
    if not root.exists():
        return []
    results: List[Tuple[str, Path]] = []
    for p in sorted(root.rglob("*"), key=lambda q: q.relative_to(root).as_posix()):
        rel = p.relative_to(root)
        if not p.is_file():
            continue
        if any(part.startswith((".", "_")) for part in rel.parts):
            continue
        if p.suffix.lower() not in ALLOWED_EXTENSIONS:
            continue
        results.append((rel.as_posix(), p))
    return results


def _iter_files(corpus_dir: Path):
    for rel, p in iter_corpus_documents(corpus_dir):
        yield rel, p


def compute_corpus_digest(corpus_dir: str | os.PathLike = CORPUS_DIR) -> str:
    global READS
    root = Path(corpus_dir)
    if not root.exists():
        return hashlib.sha256(b"").hexdigest()
    parts = []
    for rel, p in iter_corpus_documents(root):
        st = p.stat()
        key = (rel, st.st_size, st.st_mtime_ns)
        if key not in _MEMO:
            READS += 1
            _MEMO[key] = hashlib.sha256(p.read_bytes()).hexdigest()
        parts.append(f"{_MEMO[key]}:{rel}")
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def get_corpus_digest(corpus_dir: str | os.PathLike = CORPUS_DIR) -> str:
    digest = compute_corpus_digest(corpus_dir)
    if str(corpus_dir) == CORPUS_DIR:
        try:
            os.makedirs(DB_DIR, exist_ok=True)
            with open(CORPUS_META_PATH, "w", encoding="utf-8") as f:
                json.dump({"corpus_digest": digest, "timestamp": time.time()}, f, indent=2)
        except Exception:
            pass
    return digest

CHUNK_SIZE = 250         # approx words per chunk
CHUNK_OVERLAP = 40
MAX_CHUNK_CHARS = 1800   # nomic-embed-text safety limit and compact chunking
MAX_WORKERS = 4
EMBED_MODEL = "nomic-embed-text"

# Futhorc Rune Unicode block detector (16A0 - 16FF)
RUNE_REGEX = re.compile(r"[\u16A0-\u16FF]")
PAGE_HEADER_REGEX = re.compile(
    r"(?:^|\n)(?:#+\s*)?(?:Page|Pagina|PG\.?)\s*([0-9]{1,2}|unsolved|solved)",
    re.IGNORECASE
)


def contains_runes(text: str) -> bool:
    """Return True if text contains Futhorc runes."""
    return bool(RUNE_REGEX.search(text))


def extract_page_number(text: str) -> Optional[str]:
    """Extract page reference (e.g. '56', '0', 'unsolved') from text chunk or header."""
    match = PAGE_HEADER_REGEX.search(text)
    if match:
        val = match.group(1).lower()
        if val.isdigit():
            return str(int(val))
        return val
    return None


def extract_page_from_filename(filename: str) -> Optional[str]:
    """Extract page number from filename convention like page_56_... or page_00_..."""
    m = re.search(r"page_([0-9]{1,2})", filename, re.IGNORECASE)
    if m:
        return str(int(m.group(1)))
    return None


def extract_doc_title(text: str, filename: str) -> str:
    """Extract document title from first Markdown H1 or format from filename."""
    m = re.search(r"^#+\s+(.+)$", text, re.MULTILINE)
    if m:
        clean = m.group(1).strip()
        # Clean markdown formatting
        return re.sub(r"[*_`]", "", clean)
    base = os.path.splitext(filename)[0]
    return base.replace("_", " ").title()


def _annotate_chunk_with_runes(chunk_str: str) -> Tuple[str, int, int]:
    """
    Extract runes, compute rune count and Gematria prime sum,
    and append dual-script transliteration note if space permits.
    """
    runes = RUNE_REGEX.findall(chunk_str)
    rune_count = len(runes)
    g_sum = 0
    if rune_count > 0 and decode_runes and gematria_prime_sum:
        try:
            rune_seq = "".join(runes)
            g_sum = gematria_prime_sum(rune_seq)
            # Generate short transliteration preview for semantic search
            latin_preview = decode_runes(rune_seq[:60]).strip()
            if latin_preview and "[Latin Transliteration:" not in chunk_str:
                annotation = f"\n[Latin Transliteration: {latin_preview} | Gematria Sum: {g_sum}]"
                if len(chunk_str) + len(annotation) <= MAX_CHUNK_CHARS:
                    chunk_str += annotation
        except Exception:
            pass
    return chunk_str, rune_count, g_sum


def chunk_document(text: str, filename: str) -> List[Dict]:
    """
    Intelligently chunk text preserving paragraphs, page headers, rune blocks,
    and document title breadcrumbs with dual-script transliteration.
    Returns list of dicts with keys: {'text', 'page', 'has_runes', 'rune_count',
    'gematria_sum', 'title', 'chunk_index'}.
    """
    doc_title = extract_doc_title(text, filename)
    filename_page = extract_page_from_filename(filename)
    paragraphs = text.split("\n\n")
    chunks = []
    current_words = []
    current_page = filename_page

    def finalize_chunk(words_list: List[str], pg: Optional[str]) -> Dict:
        raw_str = " ".join(words_list)
        if len(raw_str) > MAX_CHUNK_CHARS:
            raw_str = raw_str[:MAX_CHUNK_CHARS]
        processed_str, r_count, g_val = _annotate_chunk_with_runes(raw_str)
        if len(processed_str) > MAX_CHUNK_CHARS:
            processed_str = processed_str[:MAX_CHUNK_CHARS]

        pgp_info = inspect_pgp_text(processed_str)
        if pgp_info["has_pgp_block"]:
            sig_status = "verified_7A35090F" if pgp_info["is_official_key"] else "mismatch"
        else:
            sig_status = "unsigned"

        c_hash = normalized_sha256(processed_str) if normalized_sha256 else hashlib.sha256(processed_str.encode("utf-8")).hexdigest()

        return {
            "text": processed_str,
            "page": pg or "general",
            "has_runes": contains_runes(processed_str),
            "rune_count": r_count,
            "gematria_sum": g_val,
            "title": doc_title,
            "sig_status": sig_status,
            "content_sha256": c_hash,
            "overlay_flag": False,
        }

    for para in paragraphs:
        para_clean = para.strip()
        if not para_clean:
            continue

        # Check for page markers in heading
        detected_page = extract_page_number(para_clean)
        if detected_page:
            current_page = detected_page

        para_words = para_clean.split()
        if len(current_words) + len(para_words) <= CHUNK_SIZE:
            current_words.extend(para_words)
        else:
            if current_words:
                chunks.append(finalize_chunk(current_words, current_page))
                # Retain overlap from end of current chunk
                overlap_words = current_words[-CHUNK_OVERLAP:] if len(current_words) > CHUNK_OVERLAP else []
                current_words = overlap_words + para_words
            else:
                # Handle single huge paragraph
                for i in range(0, len(para_words), CHUNK_SIZE - CHUNK_OVERLAP):
                    slice_words = para_words[i:i + CHUNK_SIZE]
                    chunks.append(finalize_chunk(slice_words, current_page))
                current_words = []

    if current_words:
        chunks.append(finalize_chunk(current_words, current_page))

    # Add chunk index
    for i, c in enumerate(chunks):
        c["chunk_index"] = i
    return chunks


def file_hash(filepath: str) -> str:
    """Compute SHA256 of file content to detect modifications."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def load_cache() -> dict:
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cache(cache: dict):
    os.makedirs(DB_DIR, exist_ok=True)
    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


def embed_chunk(fname: str, chunk_data: dict) -> Tuple[str, dict, Optional[List[float]], Optional[str]]:
    """Generate embedding for a single chunk via Ollama nomic-embed-text."""
    try:
        resp = ollama.embeddings(model=EMBED_MODEL, prompt=chunk_data["text"])
        return (fname, chunk_data, resp["embedding"], None)
    except Exception as e:
        return (fname, chunk_data, None, str(e))


def main():
    clear_digest_memo()
    client = chromadb.PersistentClient(path=DB_DIR)
    collection = client.get_or_create_collection(
        name="liber_primus",
        metadata={"hnsw:space": "cosine"}
    )
    cache = load_cache()

    docs = iter_corpus_documents(CORPUS_DIR)
    if not docs:
        print(f"[*] No documents found in {CORPUS_DIR}.")
        print("[*] Place Liber Primus transcripts, analysis, or wiki files in corpus/ to ingest.")
        return

    to_process = []
    skipped_unchanged = 0
    for rel_path, filepath in docs:
        fname = os.path.basename(filepath)
        h = file_hash(str(filepath))
        if cache.get(rel_path) == h or cache.get(fname) == h:
            skipped_unchanged += 1
            continue
        to_process.append((str(filepath), fname, rel_path, h))

    if skipped_unchanged:
        print(f"[*] Skipping {skipped_unchanged} unchanged file(s) (already up to date).")

    if not to_process:
        print("[*] Corpus is fully up to date in ChromaDB.")
        return

    print(f"[*] Ingesting {len(to_process)} new or modified file(s)...")

    total_chunks_added = 0
    for filepath, fname, rel_path, h in to_process:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception as e:
            print(f"[!] Error reading {fname}: {e}")
            continue

        chunks = chunk_document(text, fname)
        if not chunks:
            continue

        print(f"  -> [{fname}] parsed into {len(chunks)} chunks.")

        # Embed concurrently
        results = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(embed_chunk, fname, c) for c in chunks]
            for future in as_completed(futures):
                results.append(future.result())

        results.sort(key=lambda r: r[1]["chunk_index"])

        ids, embeddings, documents, metadatas = [], [], [], []
        for _, chunk_data, embedding, error in results:
            if error or not embedding:
                print(f"  [!] Skipped chunk {chunk_data['chunk_index']} of {fname}: {error}")
                continue

            chunk_text_str = chunk_data["text"]
            h_val = shannon_entropy(chunk_text_str)
            ioc_val = index_of_coincidence(chunk_text_str)
            pgp_res = inspect_pgp_text(chunk_text_str)

            chunk_id = f"{fname}-{chunk_data['chunk_index']}"
            ids.append(chunk_id)
            embeddings.append(embedding)
            documents.append(chunk_text_str)
            metadatas.append({
                "source": fname,
                "chunk_index": chunk_data["chunk_index"],
                "page": str(chunk_data["page"]),
                "has_runes": int(chunk_data["has_runes"]),
                "rune_count": int(chunk_data.get("rune_count", 0)),
                "gematria_sum": int(chunk_data.get("gematria_sum", 0)),
                "doc_title": str(chunk_data.get("title", "")),
                "char_length": len(chunk_text_str),
                "entropy": float(h_val),
                "ioc": float(ioc_val),
                "is_high_entropy": int(is_high_entropy(chunk_text_str)),
                "is_pgp_signed": int(pgp_res["has_pgp_block"]),
                "is_official_cicada": int(pgp_res["is_official_key"]),
            })

        if ids:
            collection.upsert(
                ids=ids,
                embeddings=embeddings,
                documents=documents,
                metadatas=metadatas
            )
            total_chunks_added += len(ids)

        cache[rel_path] = h
        cache[fname] = h
        save_cache(cache)

    print(f"[+] Done. Added/updated {total_chunks_added} chunks into vector store ({DB_DIR}).")


if __name__ == "__main__":
    main()
