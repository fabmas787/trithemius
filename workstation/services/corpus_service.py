"""
Corpus management and document inspection service.
Handles corpus deduplication, classification (Porta), vector chunk ingestion (Bodleian), and page browsing.
"""

import glob
import os
from typing import Any, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CORPUS_DIR = os.path.join(BASE_DIR, "corpus")

porta_module = None
bodleian_module = None


def _get_porta():
    global porta_module
    if porta_module is None:
        import scripts.porta as porta_module
    return porta_module


def _get_bodleian():
    global bodleian_module
    if bodleian_module is None:
        import scripts.bodleian as bodleian_module
    return bodleian_module


class CorpusService:
    """Service dedicated to Liber Primus research corpus indexing and inspection."""

    def __init__(self, workstation: Optional[Any] = None) -> None:
        self.ws = workstation

    def run_organize(self) -> None:
        """Deduplicate and classify corpus."""
        print("\n[*] Invoking Porta Corpus Librarian...")
        porta = _get_porta()
        res = porta.organize_corpus(auto_rename=True)
        print(f"[+] Porta complete. Total: {res['total_files']}, Reorganized: {res['organized']}.\n")

    def run_ingest(self) -> None:
        """Chunk corpus and embed into ChromaDB."""
        print("\n[*] Invoking Bodleian Vector Ingestion Engine...")
        bodleian = _get_bodleian()
        bodleian.main()
        if self.ws:
            self.ws.collection = None
        print("[+] Ingestion complete. Vector store updated.\n")

    def run_page(self, page_num: str) -> None:
        """Inspect specific Liber Primus page from corpus."""
        norm_page = f"{int(page_num):02d}" if page_num.isdigit() else page_num
        pattern = os.path.join(CORPUS_DIR, f"page_{norm_page}_*.*")
        matches = glob.glob(pattern)
        if not matches:
            pattern = os.path.join(CORPUS_DIR, f"*{page_num}*.*")
            matches = glob.glob(pattern)

        if not matches:
            print(f"[-] No corpus files found matching page {page_num}.")
            return

        print(f"\n+--- [LIBER PRIMUS PAGE {norm_page}] ----------------------------------------")
        for match in matches:
            fname = os.path.basename(match)
            print(f"| Document: {fname}")
            try:
                with open(match, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                print(f"| Total Lines: {len(lines)}")
                preview = "".join(lines[:15]).strip()
                print(f"| Preview:\n{preview}")
                if len(lines) > 15:
                    print("|   [...] (run 'cat corpus/" + fname + "' for full document)")
            except Exception as e:
                print(f"| Error reading file: {e}")
        print("+--------------------------------------------------------------------------\n")
