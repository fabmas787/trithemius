"""
Porta — Autonomous corpus organization, classification, and deduplication module.
Named for Giambattista della Porta, Italian Renaissance polymath and cryptographer
who authored 'De Furtivis Literarum Notis' (1563), the definitive treatise that
systematically classified and organized cipher systems and encrypted manuscripts.

Features:
- Scans corpus/ and identifies duplicate or redundant files using Normalized SHA-256
- Preserves runic characters (᛫, ᛬, ᛭) and cryptographic structure
- Moves duplicates safely to corpus/_duplicates/ instead of deleting
- Inspects content and automatically classifies Liber Primus pages, analysis writeups, and transcripts
- Standardizes file naming (e.g. page_00_welcome.txt, page_56_loss_of_innocence.txt)
- Enriches document headers with metadata (page number, rune count, Gematria sum, PGP status)
- Operates 100% in lightweight Python with 0 VRAM usage

Usage:
    python3 scripts/porta.py
    python3 scripts/porta.py --dedup
"""

import os
import sys
import re
import hashlib
import unicodedata
import argparse
from collections import defaultdict
from typing import List, Dict, Tuple, Optional, Union, Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ciphers"))
from agrippa import gematria_prime_sum
from entropy import shannon_entropy, index_of_coincidence
from opsec import inspect_pgp_text

CORPUS_DIR = os.path.join(os.path.dirname(__file__), "..", "corpus")
SYSTEM_RESERVED_FILES = {
    "pages_index.json",
    "index.json",
    "catalog.json",
    "README.md",
    "liber-primus__transcription--master.txt",
    "runes_liber-primus__transcription--master.txt",
}

KNOWN_PAGE_SIGNATURES = [
    {
        "page": "00",
        "title": "welcome",
        "keywords": ["WELCOME PILGRIMS", "A WARNING", "BELIEVE NOTHING FROM THIS BOOK"],
        "rune_sample": "ᚹᛖᛚᚳᚩᛗᛖ",
    },
    {
        "page": "56",
        "title": "loss_of_innocence",
        "keywords": ["LOSS OF INNOCENCE", "SOME WISDOM", "THE PRIMES ARE SACRED"],
        "rune_sample": "ᛋᚩᛗᛖ᛫ᚹᛁᛋᛞᚩᛗ",
    },
    {
        "page": "57",
        "title": "a_warning",
        "keywords": ["A WARNING", "CIRCUMFERENCE", "FIRFUMFERENFE"],
        "rune_sample": "ᚪ᛫ᚹᚪᚱᚾᛁᛝ",
    },
    {
        "page": "73",
        "title": "an_end",
        "keywords": ["AN END", "WITHIN THE DEEP WEB", "HASHES TO"],
        "rune_sample": "ᚪᚾ᛫ᛖᚾᛞ",
    },
]


_FILE_HASH_CACHE = {}


def file_sha256(filepath: str) -> str:
    """Raw SHA-256 of file bytes with stat-based memoization."""
    try:
        st = os.stat(filepath)
        cache_key = (filepath, st.st_mtime, st.st_size)
        if cache_key in _FILE_HASH_CACHE:
            return _FILE_HASH_CACHE[cache_key]
    except Exception:
        cache_key = None

    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
    digest = hasher.hexdigest()
    if cache_key:
        _FILE_HASH_CACHE[cache_key] = digest
    return digest


def normalize_for_hash(content: Union[str, bytes]) -> str:
    """
    Normalize text content for cryptographic duplicate detection:
    1. Decode to Unicode (utf-8 with fallback)
    2. Strip BOM (\\ufeff)
    3. NFC normalization (preserves runic distinctions)
    4. Normalize line endings to \\n
    5. Strip trailing whitespace per line
    6. Strip Porta metadata headers
    7. Collapse multiple horizontal spaces/tabs to single space (preserves runic punctuation ᛫, ᛬, ᛭)
    8. Collapse consecutive blank lines to single blank line
    9. Strip leading/trailing empty lines
    """
    if isinstance(content, bytes):
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = content.decode("utf-8", errors="replace")
    else:
        text = str(content)

    if text.startswith("\ufeff"):
        text = text[1:]

    # Unicode NFC normalization
    text = unicodedata.normalize("NFC", text)

    # Line endings
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    lines = text.split("\n")
    cleaned_lines = []
    for line in lines:
        stripped = line.strip()
        # Strip Porta/Cicada metadata header comments
        if re.match(r"^<!--\s*(?:porta|cicada):.*-->$", stripped, re.IGNORECASE):
            continue
        # Collapse multiple horizontal whitespace, preserve non-space characters (including runes)
        line_collapsed = re.sub(r"[ \t]+", " ", line).rstrip()
        cleaned_lines.append(line_collapsed)

    # Collapse consecutive blank lines
    collapsed_lines = []
    prev_empty = False
    for line in cleaned_lines:
        is_empty = (line == "")
        if is_empty:
            if not prev_empty:
                collapsed_lines.append("")
                prev_empty = True
        else:
            collapsed_lines.append(line)
            prev_empty = False

    # Strip leading/trailing empty lines
    while collapsed_lines and collapsed_lines[0] == "":
        collapsed_lines.pop(0)
    while collapsed_lines and collapsed_lines[-1] == "":
        collapsed_lines.pop()

    return "\n".join(collapsed_lines)


def normalized_sha256(content: Union[str, bytes]) -> str:
    """Compute SHA-256 of normalized text content."""
    norm = normalize_for_hash(content)
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


def file_normalized_sha256(filepath: str) -> str:
    """Read file content and compute its normalized SHA-256."""
    try:
        with open(filepath, "rb") as f:
            content = f.read()
        return normalized_sha256(content)
    except Exception:
        return file_sha256(filepath)


def classify_content(text: str, filename: str) -> Dict[str, Any]:
    """Inspect text content and determine page, category, and metadata."""
    upper = text.upper()
    has_runes = bool(re.search(r"[\u16A0-\u16FF]", text))
    pgp_info = inspect_pgp_text(text)

    # Check for known page signatures
    identified_page = None
    page_title = None

    for sig in KNOWN_PAGE_SIGNATURES:
        if sig["rune_sample"] in text or any(kw in upper for kw in sig["keywords"]):
            identified_page = sig["page"]
            page_title = sig["title"]
            break

    # Check if filename already indicates a page structure
    m_fn = re.match(r"^page_([0-9]{1,2})_([a-zA-Z0-9_-]+)", filename, re.IGNORECASE)
    if m_fn and not identified_page:
        identified_page = f"{int(m_fn.group(1)):02d}"
        page_title = m_fn.group(2)

    # Fallback regex for page numbers
    if not identified_page:
        m = re.search(r"(?:page|pg\.?|pagina)\s*([0-9]{1,2})", text, re.IGNORECASE)
        if m:
            num = int(m.group(1))
            identified_page = f"{num:02d}"
            page_title = f"page_{identified_page}"

    category = "page_transcript" if identified_page else ("analysis_writeup" if not has_runes else "misc_runic")

    if pgp_info["has_pgp_block"]:
        sig_status = "verified_7A35090F" if pgp_info["is_official_key"] else "mismatch"
    else:
        sig_status = "unsigned"

    return {
        "page": identified_page,
        "title": page_title,
        "category": category,
        "has_runes": has_runes,
        "entropy": shannon_entropy(text),
        "ioc": index_of_coincidence(text),
        "pgp_status": pgp_info["verdict"],
        "is_official_pgp": pgp_info["is_official_key"],
        "sig_status": sig_status,
        "content_sha256": normalized_sha256(text),
        "overlay_flag": False,
    }


def find_and_remove_duplicates(remove: bool = False, corpus_dir: str = CORPUS_DIR) -> List[Tuple[str, str]]:
    """Scan corpus for identical files by normalized SHA-256 hash.
    Moves duplicates to corpus/_duplicates/ instead of deleting."""
    hashes = defaultdict(list)
    dup_dir = os.path.join(corpus_dir, "_duplicates")

    if not os.path.exists(corpus_dir):
        return []

    for fname in sorted(os.listdir(corpus_dir)):
        fpath = os.path.join(corpus_dir, fname)
        if os.path.isfile(fpath) and not fname.startswith(".") and not fname.startswith("_") and fname not in SYSTEM_RESERVED_FILES:
            h = file_normalized_sha256(fpath)
            hashes[h].append(fpath)

    duplicates = []
    for h, files in hashes.items():
        if len(files) > 1:
            # Deterministically prefer canonical page files (page_XX) over generic harvest files
            files.sort(key=lambda p: (0 if "page_" in os.path.basename(p) else 1, os.path.basename(p)))
            primary = files[0]
            for dup in files[1:]:
                duplicates.append((dup, primary))
                if remove:
                    try:
                        os.makedirs(dup_dir, exist_ok=True)
                        dest = os.path.join(dup_dir, os.path.basename(dup))
                        if os.path.exists(dest):
                            os.remove(dest)
                        os.rename(dup, dest)
                        print(f"  [-] Moved duplicate: {os.path.basename(dup)} -> _duplicates/ (matches {os.path.basename(primary)})")
                    except Exception as e:
                        print(f"  [!] Error moving duplicate {dup}: {e}")
    return duplicates


def organize_corpus(auto_rename: bool = True, corpus_dir: str = CORPUS_DIR) -> Dict[str, Any]:
    """Scan, classify, standardize and organize all files in corpus/."""
    print("=== Porta: Organizing and Classifying Corpus ===")
    if not os.path.exists(corpus_dir):
        return {"total_files": 0, "organized": 0}

    # First deduplicate
    dups = find_and_remove_duplicates(remove=True, corpus_dir=corpus_dir)
    if dups:
        print(f"[*] Relocated {len(dups)} duplicate file(s) to _duplicates/.")

    files = [f for f in os.listdir(corpus_dir) if os.path.isfile(os.path.join(corpus_dir, f)) and not f.startswith(".") and not f.startswith("_") and f not in SYSTEM_RESERVED_FILES]
    organized_count = 0

    for fname in files:
        fpath = os.path.join(corpus_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue

        meta = classify_content(content, fname)

        # Build standardized filename
        ext = os.path.splitext(fname)[1] or ".txt"
        if meta["page"] and meta["title"]:
            target_name = f"page_{meta['page']}_{meta['title']}{ext}"
        elif meta["has_runes"]:
            target_name = fname if (fname.startswith("runes_") or fname.startswith("page_")) else f"runes_{fname}"
        else:
            target_name = fname

        target_path = os.path.join(corpus_dir, target_name)
        if auto_rename and target_name != fname and not os.path.exists(target_path):
            os.rename(fpath, target_path)
            print(f"  [>] Renamed: {fname} -> {target_name} (Classified as: {meta['category']})")
            organized_count += 1
        else:
            print(f"  [*] Verified: {fname} (Category: {meta['category']}, Entropy: {meta['entropy']})")

    print(f"[+] Organization complete. Processed {len(files)} file(s).")
    return {"total_files": len(files), "organized": organized_count}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trithemius Corpus Librarian")
    parser.add_argument("--dedup", action="store_true", help="Only run deduplication")
    args = parser.parse_args()

    if args.dedup:
        find_and_remove_duplicates(remove=True)
    else:
        organize_corpus(auto_rename=True)
