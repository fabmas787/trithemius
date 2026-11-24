#!/usr/bin/env python3
"""
Trithemius — Unified Terminal Cryptanalytic Workstation Kernel.
Clean modular orchestrator composing domain services:
- ciphers: CipherService
- corpus: CorpusService
- assistant: AssistantService
- system: SystemService
"""

import os
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import config
from config import get_model, MODELS, SUPPORTED_PROVIDERS
from workstation.ui.formatters import ConsoleRenderer
from workstation.core.results import (
    TypedResult,
    GematriaResult,
    AtbashResult,
    VigenereResult,
    TotientStreamResult,
    SolveResult,
    CrackResult,
    HardwareResult,
    LedgerResult,
    TriageResult,
    PeriodResult,
    CribResult,
    RunningKeyResult,
    RunningKeyScanResult,
    LexiconResult,
    OpsecResult,
    StatusResult,
)
from workstation.services.cipher_service import CipherService
from workstation.services.corpus_service import CorpusService
from workstation.services.assistant_service import AssistantService
from workstation.services.system_service import SystemService

CORPUS_DIR = os.path.join(BASE_DIR, "corpus")
DB_DIR = os.path.join(BASE_DIR, "vectordb")

from workstation.services.assistant_service import _get_ask


class TerminalWorkstation:
    """
    Unified Cryptanalytic Workstation orchestrator.
    Composes specialized domain services while exposing an identical public API.
    """

    COMMAND_DOCS = ConsoleRenderer.COMMAND_DOCS

    def __init__(
        self,
        model_key: str = None,
        provider: str = None,
        think: bool = False,
        boost: Optional[bool] = None,
        low_spec: bool = False,
        ollama_host: str = None,
        api_key: str = None,
        renderer: Optional[Any] = None,
    ) -> None:
        self.provider = (provider or config.ACTIVE_PROVIDER).lower()
        if self.provider not in SUPPORTED_PROVIDERS:
            self.provider = "ollama"

        if ollama_host:
            config.OLLAMA_HOST = ollama_host.strip()

        if api_key:
            config.set_api_key(self.provider, api_key)

        self.low_spec = low_spec or config.LOW_SPEC_MODE
        if self.low_spec:
            config.LOW_SPEC_MODE = True
            config.DEFAULT_NUM_CTX = 2048

        self.model_key = model_key or config.ACTIVE_MODEL_KEY
        self.active_model = get_model(self.model_key, provider=self.provider)
        self.think = bool(think) if think is not None else False
        if boost is not None:
            self.boost = bool(boost)
            os.environ["TRITHEMIUS_BOOST"] = "on" if self.boost else "off"
        else:
            self.boost = (os.environ.get("TRITHEMIUS_BOOST", "off").lower() in ("on", "true", "1"))
            if self.boost:
                os.environ["TRITHEMIUS_BOOST"] = "on"

        self.ui = renderer if renderer is not None else ConsoleRenderer()

        # Domain Services Composition
        self.ciphers = CipherService(self)
        self.corpus = CorpusService(self)
        self.assistant = AssistantService(self)
        self.system = SystemService(self)

    @property
    def collection(self) -> Any:
        return self.assistant.collection

    @collection.setter
    def collection(self, val: Any) -> None:
        self.assistant.collection = val

    def _ensure_collection(self) -> Any:
        return self.assistant._ensure_collection()

    def _resolve_cipher_input(self, target: str) -> Tuple[str, Optional[dict]]:
        return self.ciphers._resolve_cipher_input(target)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("print_") or name in ("render_json", "print_json"):
            return getattr(self.ui, name)
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

    def repl(self) -> None:
        from workstation.ui.repl import run_repl
        return run_repl(self)

    # -------------------------------------------------------------------------
    # Cryptanalytic Operations (Delegated to CipherService)
    # -------------------------------------------------------------------------

    def run_gematria(self, text: str) -> GematriaResult:
        return self.ciphers.run_gematria(text)

    def run_atbash(self, text: str, shift: int = 0) -> AtbashResult:
        return self.ciphers.run_atbash(text, shift=shift)

    def run_vigenere(
        self,
        mode: str,
        text: str,
        key: str,
        f_skip: bool = False,
        skip_indices: Optional[Set[int]] = None,
    ) -> VigenereResult:
        return self.ciphers.run_vigenere(mode, text, key, f_skip=f_skip, skip_indices=skip_indices)

    def run_totient_stream(
        self,
        mode: str,
        text: str,
        offset: int = 0,
        f_skip: bool = False,
        skip_indices: Optional[Set[int]] = None,
    ) -> TotientStreamResult:
        return self.ciphers.run_totient_stream(mode, text, offset=offset, f_skip=f_skip, skip_indices=skip_indices)

    def run_totient(self, *args: Any, **kwargs: Any) -> TotientStreamResult:
        return self.ciphers.run_totient(*args, **kwargs)

    def run_solve(self, target: str = "all") -> SolveResult:
        return self.ciphers.run_solve(target)

    def run_crack(
        self,
        target: str,
        deep: bool = False,
        top_k: int = 5,
        randomize: bool = False,
        include_rotations: bool = False,
        crib_limit: Optional[int] = None,
        seed: Optional[int] = None,
        compound: bool = False,
        use_metal: bool = True,
        use_ane: bool = True,
        include_ecc: bool = False,
    ) -> CrackResult:
        return self.ciphers.run_crack(
            target,
            deep=deep,
            top_k=top_k,
            randomize=randomize,
            include_rotations=include_rotations,
            crib_limit=crib_limit,
            seed=seed,
            compound=compound,
            use_metal=use_metal,
            use_ane=use_ane,
            include_ecc=include_ecc,
        )

    def run_triage(self, target: str) -> TriageResult:
        return self.ciphers.run_triage(target)

    def run_period(self, target: str, max_period: int = 30) -> PeriodResult:
        return self.ciphers.run_period(target, max_period=max_period)

    def run_crib(self, target: str, crib: str) -> CribResult:
        return self.ciphers.run_crib(target, crib)

    def run_running_key(
        self,
        page_target: str,
        text_path: str,
        mode: str = "sub",
        f_skip: bool = False,
        offset: int = 0,
    ) -> RunningKeyResult:
        return self.ciphers.run_running_key(page_target, text_path, mode=mode, f_skip=f_skip, offset=offset)

    def run_running_key_scan(
        self,
        page_target: str,
        ref_dir: Optional[str] = None,
        step: int = 1,
        top_k: int = 5,
    ) -> RunningKeyScanResult:
        return self.ciphers.run_running_key_scan(page_target, ref_dir=ref_dir, step=step, top_k=top_k)

    def run_lexicon(self, action: str = "phrases", limit: int = 50) -> LexiconResult:
        return self.ciphers.run_lexicon(action=action, limit=limit)

    def run_opsec(self, target: str) -> OpsecResult:
        return self.ciphers.run_opsec(target)

    def run_layout(self, target: str = "all") -> Dict[str, Any]:
        return self.ciphers.run_layout(target)

    # -------------------------------------------------------------------------
    # Corpus & Document Operations (Delegated to CorpusService)
    # -------------------------------------------------------------------------

    def run_organize(self) -> None:
        return self.corpus.run_organize()

    def run_ingest(self) -> None:
        return self.corpus.run_ingest()

    def run_page(self, page_num: str) -> None:
        return self.corpus.run_page(page_num)

    # -------------------------------------------------------------------------
    # Assistant & Knowledge Engine Operations (Delegated to AssistantService)
    # -------------------------------------------------------------------------

    def run_ask(self, query: str, use_web: bool = False, fresh: bool = False) -> Optional[str]:
        return self.assistant.run_ask(query, use_web=use_web, fresh=fresh)

    # -------------------------------------------------------------------------
    # System, Hardware & Telemetry Operations (Delegated to SystemService)
    # -------------------------------------------------------------------------

    def run_boost(self, mode: Optional[str] = None) -> bool:
        return self.system.run_boost(mode=mode)

    def run_hardware(self) -> HardwareResult:
        return self.system.run_hardware()

    def run_ledger(self, target: Optional[str] = None) -> LedgerResult:
        return self.system.run_ledger(target=target)

    def run_key_section(self, args: Optional[List[str]] = None) -> None:
        return self.system.run_key_section(args=args)

    def run_think(self, state: Optional[str] = None) -> bool:
        return self.system.run_think(state=state)

    def run_provider(self, name: Optional[str] = None) -> str:
        return self.system.run_provider(name=name)

    def run_model(self, model_key: Optional[str] = None) -> str:
        return self.system.run_model(model_key=model_key)

    def run_host(self, url: Optional[str] = None) -> str:
        return self.system.run_host(url=url)

    def run_profile(self, mode: Optional[str] = None) -> bool:
        return self.system.run_profile(mode=mode)

    def run_cache(self, action: str = "clear") -> bool:
        return self.system.run_cache(action=action)

    def run_status(self, probe: bool = False) -> StatusResult:
        return self.system.run_status(probe=probe)

    def run_bench(
        self,
        profile: bool = False,
        skip_vector: bool = False,
        include_llm: bool = False,
        compare: str = None,
        save_baseline: str = None,
    ) -> None:
        return self.system.run_bench(
            profile=profile,
            skip_vector=skip_vector,
            include_llm=include_llm,
            compare=compare,
            save_baseline=save_baseline,
        )
