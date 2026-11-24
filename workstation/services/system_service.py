"""
System, hardware, ledger, telemetry, and configuration service.
Manages hardware acceleration (Metal/ANE), cryptographic ledger, provider profiles, and system telemetry.
"""

import os
from typing import Any, List, Optional

import config
from config import get_model, MODELS, SUPPORTED_PROVIDERS
from ciphers.opsec import CICADA_KEY_ID, CICADA_FINGERPRINT
from workstation.core.results import HardwareResult, LedgerResult, StatusResult

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CORPUS_DIR = os.path.join(BASE_DIR, "corpus")

ask_module = None


def _get_ask():
    global ask_module
    if ask_module is None:
        import scripts.ask as ask_module
    return ask_module


class SystemService:
    """Service dedicated to workstation system telemetry, hardware acceleration, and provider settings."""

    def __init__(self, workstation: Optional[Any] = None) -> None:
        self.ws = workstation

    def run_boost(self, mode: Optional[str] = None) -> bool:
        """Toggle, enable, disable, or query Deep Cryptanalytic Retrieval & Reranking Boost mode."""
        ws_boost = self.ws.boost if self.ws else False
        if mode is not None:
            m = mode.strip().lower()
            if m in ("on", "true", "1", "yes", "enable"):
                ws_boost = True
            elif m in ("off", "false", "0", "no", "disable"):
                ws_boost = False
            elif m in ("toggle",):
                ws_boost = not ws_boost
            elif m in ("status", "check", "info"):
                pass
            else:
                print(f"[!] Invalid boost mode '{mode}'. Valid options: on | off | toggle | status")
                return ws_boost
        else:
            ws_boost = not ws_boost

        if self.ws:
            self.ws.boost = ws_boost
        os.environ["TRITHEMIUS_BOOST"] = "on" if ws_boost else "off"
        status_str = "ENABLED (Top-K=10, 2x Rerank Multiplier)" if ws_boost else "DISABLED"
        print(f"[*] Deep Cryptanalytic Retrieval & Boost: {status_str}\n")
        return ws_boost

    def run_hardware(self) -> HardwareResult:
        """Query and benchmark Apple Silicon Metal GPU and Apple Neural Engine acceleration."""
        try:
            from ciphers.metal_accel import get_metal_device_info, benchmark_metal_throughput, is_metal_available
            from ciphers.ane_engine import get_ane_device_info

            metal_info = get_metal_device_info()
            bm = benchmark_metal_throughput(num_words=1000, period=17) if is_metal_available() else {}
            ane_info = get_ane_device_info()
            return HardwareResult(
                metal_gpu=metal_info,
                benchmark=bm,
                neural_engine=ane_info,
            )
        except Exception as e:
            return HardwareResult(error=str(e))

    def run_ledger(self, target: Optional[str] = None) -> LedgerResult:
        """Inspect recorded cryptanalytic attempts in the ChromaDB vector database & SQLite ledger."""
        try:
            from agents.ledger import get_attempts_stats, query_similar_attempts, canonical_page
            c_page = canonical_page(target) if target else None
            stats = get_attempts_stats(page=c_page)
            sim_hits = []
            if target and not target.isdigit() and len(target) >= 3:
                sim_hits = query_similar_attempts(target, n_results=5, page=c_page)
            return LedgerResult(
                page=c_page,
                stats=stats,
                similar_hypotheses=sim_hits,
            )
        except Exception as e:
            return LedgerResult(error=str(e), page=target)

    def run_key_section(self, args: Optional[List[str]] = None) -> None:
        """Dedicated AI API Key & Cloud Provider Configuration Section."""
        args = list(args) if args else []

        if args and args[0].lower() in ("clear", "delete", "rm", "remove"):
            if len(args) < 2:
                print("Usage: /key clear <provider>  (e.g. /key clear groq)\n")
                return
            p = args[1].lower()
            if p in SUPPORTED_PROVIDERS:
                if config.clear_api_key(p):
                    print(f"[+] Successfully removed API key for {p.upper()}.\n")
                else:
                    print(f"[!] Error removing API key for {p.upper()}.\n")
            else:
                print(f"[!] Unknown provider '{p}'. Supported: {', '.join(SUPPORTED_PROVIDERS)}\n")
            return

        if len(args) >= 2 and args[0].lower() in SUPPORTED_PROVIDERS:
            p, k = args[0].lower(), args[1].strip()
            if config.set_api_key(p, k):
                masked = f"{k[:4]}...{k[-4:]}" if len(k) > 8 else "CONFIGURED"
                print(f"[+] Successfully saved and persisted API key for {p.upper()} ({masked}).\n")
            else:
                print(f"[!] Error saving API key for {p.upper()}.\n")
            return

        if len(args) == 1 and args[0].lower() not in ("show", "list", "status", "view", "help", "info"):
            p = args[0].lower()
            if p in SUPPORTED_PROVIDERS:
                val = config.get_api_key(p)
                masked = f"{val[:4]}...{val[-4:]}" if val and len(val) > 8 else ("CONFIGURED" if val else "NOT SET")
                print(f"\n[*] Provider {p.upper()}: Key is {masked}")
                print(f"    To update: /key {p} <your_new_key>\n")
                return
            else:
                print(f"[!] Unknown provider or action '{args[0]}'. Supported: {', '.join(SUPPORTED_PROVIDERS)}\n")
                return

        provider_notes = {
            "groq": "Fast Llama 3.3 70B / Qwen 2.5",
            "openai": "GPT-4o, GPT-4o-mini, o1",
            "gemini": "Gemini 2.0 Flash / Pro",
            "anthropic": "Claude 3.5 Sonnet / Haiku",
            "openrouter": "DeepSeek-R1, Mistral, 200+ models",
        }

        provider = self.ws.provider if self.ws else config.ACTIVE_PROVIDER
        active_model = self.ws.active_model if self.ws else config.MODEL_NAME

        print("\n+--- [AI API KEYS & CLOUD PROVIDERS] -----------------------------------------")
        active_status = "CONFIGURED" if config.get_api_key(provider) or provider == "ollama" else "KEY MISSING"
        print(f"| Active Provider: {provider.upper():<11} | Model: {active_model} ({active_status})")
        print("|")
        print("| Cloud Provider Key Status:")

        for p in ("groq", "openai", "gemini", "anthropic", "openrouter"):
            val = config.get_api_key(p)
            if val and len(val) > 8:
                masked = f"({val[:4]}...{val[-4:]})"
                status_badge = "[CONFIGURED]"
            elif val:
                masked = "(CONFIGURED)"
                status_badge = "[CONFIGURED]"
            else:
                masked = ""
                status_badge = "[NOT SET]   "
            note = provider_notes.get(p, "")
            print(f"|   {p.upper():<10} {status_badge} {masked:<13} {note}")

        print(f"|   OLLAMA     [LOCAL]       Host: {config.OLLAMA_HOST:<18} (No key required)")
        print("|")
        print("| Storage & Security:")
        print(f"|   Persisted in: {config.CREDENTIALS_FILE} (chmod 0600 - user read/write only)")
        print("|")
        print("| Management Commands:")
        print("|   /key <provider> <api_key>   Set and persist API key for provider")
        print("|   /key clear <provider>       Remove saved API key for provider")
        print("|   /provider <name>            Switch active provider (e.g. /provider groq)")
        print("|   /model <name>               Switch active model (e.g. /model moe)")
        print("+-----------------------------------------------------------------------------\n")

    def run_think(self, state: Optional[str] = None) -> bool:
        """Toggle or set Chain-of-Thought (CoT) reasoning stream mode."""
        ws_think = self.ws.think if self.ws else False
        if state:
            val = state.strip().lower()
            if val in ("on", "true", "1", "yes", "enable", "enabled"):
                ws_think = True
            elif val in ("off", "false", "0", "no", "disable", "disabled"):
                ws_think = False
            elif val in ("toggle",):
                ws_think = not ws_think
            else:
                print(f"[!] Invalid think mode '{state}'. Valid options: on | off")
                return ws_think
        else:
            ws_think = not ws_think
        if self.ws:
            self.ws.think = ws_think
        print(f"[*] Chain-of-Thought reasoning: {'ENABLED' if ws_think else 'DISABLED'}\n")
        return ws_think

    def run_provider(self, name: Optional[str] = None) -> str:
        """Display or switch active inference provider."""
        provider = self.ws.provider if self.ws else config.ACTIVE_PROVIDER
        if not name:
            print(f"[*] Current provider: {provider.upper()}")
            print(f"Available providers: {', '.join(SUPPORTED_PROVIDERS)}")
            return provider
        p = name.lower().strip()
        if p in SUPPORTED_PROVIDERS:
            if self.ws:
                self.ws.provider = p
                self.ws.active_model = get_model(self.ws.model_key, provider=self.ws.provider)
                provider = self.ws.provider
                active_model = self.ws.active_model
            else:
                provider = p
                active_model = get_model(config.ACTIVE_MODEL_KEY, provider=p)
            print(f"[+] Switched provider to: {provider.upper()} (Default Model: {active_model})\n")
        else:
            print(f"[!] Unknown provider '{p}'. Supported: {', '.join(SUPPORTED_PROVIDERS)}\n")
        return provider

    def run_model(self, model_key: Optional[str] = None) -> str:
        """Display or switch active model selection."""
        provider = self.ws.provider if self.ws else config.ACTIVE_PROVIDER
        active_model = self.ws.active_model if self.ws else config.MODEL_NAME
        current_key = self.ws.model_key if self.ws else config.ACTIVE_MODEL_KEY
        if not model_key:
            print(f"[*] Current provider: {provider.upper()} | Model: {active_model} ({current_key})")
            print(f"Available keys: {', '.join(MODELS.keys())}")
            return active_model
        key = model_key.strip()
        if key.lower() in MODELS:
            new_key = key.lower()
            new_model = get_model(new_key, provider=provider)
        else:
            new_key = "custom"
            new_model = key
        if self.ws:
            self.ws.model_key = new_key
            self.ws.active_model = new_model
        print(f"[+] Switched to model: {new_model}\n")
        return new_model

    def run_host(self, url: Optional[str] = None) -> str:
        """Display or set remote Ollama host endpoint."""
        if not url:
            print(f"[*] Current Ollama Host: {config.OLLAMA_HOST}")
            return config.OLLAMA_HOST
        new_host = url.strip()
        config.OLLAMA_HOST = new_host
        print(f"[+] Ollama streaming host set to: {config.OLLAMA_HOST}\n")
        return config.OLLAMA_HOST

    def run_profile(self, mode: Optional[str] = None) -> bool:
        """Display or toggle hardware memory and context window profile."""
        low_spec = self.ws.low_spec if self.ws else config.LOW_SPEC_MODE
        if not mode:
            prof = "LOW-SPEC (num_ctx: 2048)" if low_spec else f"STANDARD (num_ctx: {config.DEFAULT_NUM_CTX})"
            print(f"[*] Current Profile: {prof}")
            print("Usage: /profile <standard|low-spec>")
            return low_spec
        choice = mode.lower().strip()
        if choice in ("low", "low-spec", "lowspec"):
            low_spec = True
            config.LOW_SPEC_MODE = True
            config.DEFAULT_NUM_CTX = 2048
            print("[+] Hardware Profile: LOW-SPEC enabled (num_ctx: 2048, reduced memory footprint).\n")
        elif choice in ("standard", "std", "high"):
            low_spec = False
            config.LOW_SPEC_MODE = False
            config.DEFAULT_NUM_CTX = 8192
            print("[+] Hardware Profile: STANDARD enabled (num_ctx: 8192).\n")
        else:
            print("[!] Valid options: /profile standard | /profile low-spec")
        if self.ws:
            self.ws.low_spec = low_spec
        return low_spec

    def run_cache(self, action: str = "clear") -> bool:
        """Clear or inspect exact RAG response cache."""
        if action.lower() == "clear":
            ask = _get_ask()
            ask.clear_rag_cache()
            print("[+] Exact RAG response cache cleared.\n")
            return True
        print("Usage: /cache clear\n")
        return False

    def run_status(self, probe: bool = False) -> StatusResult:
        """Print status telemetry and optional provider probe."""
        files = [f for f in os.listdir(CORPUS_DIR) if os.path.isfile(os.path.join(CORPUS_DIR, f)) and not f.startswith(".")] if os.path.exists(CORPUS_DIR) else []
        coll = self.ws._ensure_collection() if self.ws else None
        chunk_count = coll.count() if coll else 0
        keys_status = config.get_all_keys_status()
        active_keys = [k.upper() for k, configured in keys_status.items() if configured]
        keys_summary = ", ".join(active_keys) if active_keys else "None (Local Mode)"

        provider = self.ws.provider if self.ws else config.ACTIVE_PROVIDER
        active_model = self.ws.active_model if self.ws else config.MODEL_NAME
        model_key = self.ws.model_key if self.ws else config.ACTIVE_MODEL_KEY
        low_spec = self.ws.low_spec if self.ws else config.LOW_SPEC_MODE
        think = self.ws.think if self.ws else False
        boost = self.ws.boost if self.ws else False

        provider_desc = provider.upper()
        if provider == "ollama":
            provider_desc += f" (Host: {config.OLLAMA_HOST})"
        else:
            has_k = bool(config.get_api_key(provider))
            provider_desc += f" (Cloud API - Key: {'CONFIGURED' if has_k else 'MISSING'})"

        profile_desc = "LOW-SPEC (num_ctx: 2048)" if low_spec else f"STANDARD (num_ctx: {config.DEFAULT_NUM_CTX})"

        probe_results = None
        if probe:
            import scripts.providers as providers_mod
            print("[*] Probing configured providers and model endpoints...")
            probe_results = providers_mod.probe_all_configured()

        telemetry = StatusResult(
            provider_desc=provider_desc,
            active_model=active_model,
            model_key=model_key,
            profile_desc=profile_desc,
            think=think,
            boost=boost,
            context_window=config.DEFAULT_NUM_CTX,
            keys_summary=keys_summary,
            corpus_files=len(files),
            chunk_count=chunk_count,
            pgp_key_id=CICADA_KEY_ID,
            pgp_fingerprint=CICADA_FINGERPRINT[:19],
            probe_results=probe_results,
        )
        if self.ws and hasattr(self.ws, "ui"):
            self.ws.ui.print_status(telemetry, probe_results=probe_results)
        return telemetry

    def run_bench(
        self,
        profile: bool = False,
        skip_vector: bool = False,
        include_llm: bool = False,
        compare: str = None,
        save_baseline: str = None,
    ) -> None:
        """Execute microsecond latency benchmark suite and profiling directly from workstation."""
        import scripts.benchmark as bench_module
        if profile:
            import cProfile, pstats
            pr = cProfile.Profile()
            pr.enable()
            bench_module.run_benchmark(skip_vector=skip_vector, include_llm=include_llm)
            pr.disable()
            pr.dump_stats(bench_module.PROFILE_PSTATS)
            print(f"[+] Saved cProfile stats to: {bench_module.PROFILE_PSTATS}")
            print("\n=== Top 20 Hotspots by Cumulative Time ===")
            ps = pstats.Stats(pr).sort_stats(pstats.SortKey.CUMULATIVE)
            ps.print_stats(20)
        else:
            res = bench_module.run_benchmark(skip_vector=skip_vector, include_llm=include_llm)
            bench_module.save_history_entry(res)
            baseline_data = None
            if compare:
                baselines = bench_module.load_baselines()
                if compare in baselines:
                    baseline_data = baselines[compare]["results"]
                else:
                    print(f"[!] Warning: baseline '{compare}' not found.")
            bench_module.print_telemetry_table(res, baseline_results=baseline_data, baseline_name=compare)
            if save_baseline:
                bench_module.save_baseline(save_baseline, res)
                print(f"[+] Saved baseline '{save_baseline}'.")
