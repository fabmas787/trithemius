"""
Assistant & RAG knowledge engine service.
Encapsulates deterministic routing, hybrid retrieval (ChromaDB + BM25), response caching, and LLM inference streaming.
"""

import os
from typing import Any, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CORPUS_DIR = os.path.join(BASE_DIR, "corpus")
DB_DIR = os.path.join(BASE_DIR, "vectordb")

ask_module = None
router_module = None
bodleian_module = None


def _get_ask():
    global ask_module
    if ask_module is None:
        import scripts.ask as ask_module
    return ask_module


def _get_router():
    global router_module
    if router_module is None:
        import scripts.router as router_module
    return router_module


def _get_bodleian():
    global bodleian_module
    if bodleian_module is None:
        import scripts.bodleian as bodleian_module
    return bodleian_module


class AssistantService:
    """Service dedicated to cryptanalytic RAG queries and autonomous AI pairing."""

    def __init__(self, workstation: Optional[Any] = None) -> None:
        self.ws = workstation
        self.collection = None

    def _ensure_collection(self) -> Any:
        if self.collection is None:
            try:
                ask = _get_ask()
                self.collection = ask.get_collection(DB_DIR)
            except Exception:
                self.collection = None
        return self.collection

    def run_ask(self, query: str, use_web: bool = False, fresh: bool = False) -> Optional[str]:
        """Execute hybrid RAG query with deterministic routing, live streaming, and exact caching."""
        provider = self.ws.provider if self.ws else "ollama"
        active_model = self.ws.active_model if self.ws else "SparkLLM/Spark-X2.5-4B"
        think = self.ws.think if self.ws else False
        boost = self.ws.boost if self.ws else False

        deterministic_context = None
        if os.environ.get("TRITHEMIUS_ROUTER", "on").lower() != "off":
            router = _get_router()
            route = router.classify_query(query, corpus_dir=CORPUS_DIR)
            if route["mode"] == "deterministic":
                resp = router.execute_deterministic(route, corpus_dir=CORPUS_DIR, workstation=self.ws)
                print(f"\n{resp}\n")
                return resp
            elif route["mode"] == "hybrid":
                deterministic_context = router.format_ground_truth_for_prompt(route.get("ground_truth"))

        ask = _get_ask()
        coll = self._ensure_collection()
        retrieval_mode = "chroma" if coll is not None else "bm25"

        cache_allowed = (not use_web) and (not fresh) and (os.environ.get("TRITHEMIUS_CACHE", "on").lower() != "off")
        corpus_digest = ""
        ckey = None
        if cache_allowed:
            try:
                bodleian = _get_bodleian()
                corpus_digest = bodleian.get_corpus_digest()
            except Exception:
                corpus_digest = "unknown"
            ckey = ask.rag_cache_key(
                query=query,
                corpus_digest=corpus_digest,
                provider=provider,
                model=active_model,
                think=think,
                boost=boost,
                retrieval_mode=retrieval_mode,
            )
            cached_res = ask.lookup_rag_cache(ckey)
            if cached_res:
                print(f"\nTrithemius ({provider.upper()}:{active_model}) [cached]: {cached_res['response']}\n")
                return cached_res["response"]

        if coll is not None:
            print(f"[*] Querying vector store for: '{query}'...")
        else:
            print(f"[*] Searching corpus via zero-VRAM BM25 retriever for: '{query}'...")

        if use_web:
            print("[*] Note: Live web reconnaissance has been retired; all Liber Primus transcripts are preserved offline in corpus/.")

        top_k = 10 if boost else ask.TOP_K
        retrieved = ask.retrieve(coll, query, k=top_k)

        if not retrieved:
            print("[-] No matching corpus knowledge found. Try '/ingest' to index the corpus.\n")
            return None

        max_context = 4000 if boost else 2500
        prompt = ask.build_prompt(
            query,
            retrieved,
            max_context_chars=max_context,
            deterministic_context=deterministic_context,
        )
        print(f"\nTrithemius ({provider.upper()}:{active_model}): ", end="", flush=True)
        try:
            resp = ask.stream_chat(active_model, prompt, think=think, provider=provider)
            if cache_allowed and ckey and resp:
                sources = [d.get("metadata", {}) for d in retrieved if isinstance(d, dict)]
                ask.store_rag_cache(
                    cache_key=ckey,
                    query=query,
                    corpus_digest=corpus_digest,
                    provider=provider,
                    model=active_model,
                    think=think,
                    prompt_version=ask.PROMPT_VERSION,
                    retrieval_mode=retrieval_mode,
                    response_text=resp,
                    sources=sources,
                    boost=boost,
                )
            return resp
        except Exception as e:
            print(f"\n[!] Inference Error ({provider.upper()} - {active_model}): {e}\n")
            return None
