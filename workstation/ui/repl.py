"""
Interactive REPL loop for Trithemius Workstation.
"""

import os
import sys
import shlex
from typing import List, Optional

import config
from workstation.core.workstation import CORPUS_DIR
from workstation.services.assistant_service import _get_ask

def run_repl(self):
        files_count = len(os.listdir(CORPUS_DIR)) if os.path.exists(CORPUS_DIR) else 0
        coll = self._ensure_collection()
        chunks = coll.count() if coll else 0

        print("=" * 78)
        print("TRITHEMIUS — LIBER PRIMUS CRYPTANALYTIC WORKSTATION [TERMINAL CORE]")
        print(f"Model: {self.active_model} | Chunks: {chunks} | Corpus: {files_count} files | Boost: {'ON' if self.boost else 'OFF'}")
        print("=" * 78)
        print("Tip: Type '/help' for full command manual or '/help <cmd>' for focused guide.\n")

        try:
            import readline
            from workstation.commands import COMMAND_REGISTRY
            def _completer(text, state):
                options = [f"/{c}" for c in COMMAND_REGISTRY.keys() if f"/{c}".startswith(text)]
                if state < len(options):
                    return options[state]
                return None
            readline.set_completer(_completer)
            readline.parse_and_bind("tab: complete")
        except Exception:
            pass

        while True:
            self.print_command_list()
            try:
                raw = input("trithemius> ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n[*] Exiting Trithemius Terminal Workstation.")
                break

            if not raw:
                continue

            if raw.lower() in ("/exit", "/quit", "exit", "quit"):
                print("[*] Workstation session terminated.")
                break

            if raw.lower() in ("/clear", "clear"):
                os.system("clear" if os.name != "nt" else "cls")
                continue

            # Handle slash commands
            if raw.startswith("/"):
                try:
                    parts = shlex.split(raw)
                except ValueError:
                    parts = raw.split()
                cmd = parts[0].lower()
                args = parts[1:]

                if cmd == "/help":
                    target_cmd = args[0] if args else None
                    self.print_help(target_cmd)

                elif cmd == "/boost":
                    arg = args[0] if args else None
                    self.run_boost(arg)

                elif cmd in ("/clear",):
                    os.system("clear" if os.name != "nt" else "cls")

                elif cmd == "/bench":
                    profile = "--profile" in args
                    skip_vector = "--skip-vector" in args
                    include_llm = "--llm" in args
                    compare = None
                    save_baseline = None
                    for i, a in enumerate(args):
                        if a == "--compare" and i + 1 < len(args):
                            compare = args[i + 1]
                        if a == "--save-baseline" and i + 1 < len(args):
                            save_baseline = args[i + 1]
                    self.run_bench(
                        profile=profile,
                        skip_vector=skip_vector,
                        include_llm=include_llm,
                        compare=compare,
                        save_baseline=save_baseline,
                    )

                elif cmd == "/cache":
                    if args and args[0].lower() == "clear":
                        ask = _get_ask()
                        ask.clear_rag_cache()
                        print("[+] Exact RAG response cache cleared.\n")
                    else:
                        print("Usage: /cache clear\n")

                elif cmd == "/ask":
                    fresh = False
                    if args and args[0] == "--fresh":
                        fresh = True
                        args = args[1:]
                    q = " ".join(args)
                    if not q:
                        print("Usage: /ask [--fresh] <question>")
                    else:
                        self.run_ask(q, use_web=False, fresh=fresh)

                elif cmd == "/web":
                    q = " ".join(args)
                    if not q:
                        print("Usage: /web <query>")
                    else:
                        self.run_ask(q, use_web=True)

                elif cmd == "/page":
                    if not args:
                        print("Usage: /page <page_number>")
                    else:
                        self.run_page(args[0])

                elif cmd == "/gematria":
                    if not args:
                        print("Usage: /gematria <runes_or_latin_text>")
                    else:
                        res = self.run_gematria(" ".join(args))
                        self.print_gematria(res)

                elif cmd == "/atbash":
                    if not args:
                        print("Usage: /atbash <text_or_page> [--shift N]\n")
                    else:
                        shift = 0
                        explicit_shift = False
                        clean_args = []
                        i = 0
                        while i < len(args):
                            if args[i] in ("--shift", "-s") and i + 1 < len(args):
                                try:
                                    shift = int(args[i + 1])
                                    explicit_shift = True
                                except ValueError:
                                    pass
                                i += 2
                            else:
                                clean_args.append(args[i])
                                i += 1
                        if not explicit_shift and len(clean_args) == 2 and clean_args[0].isdigit() and clean_args[1].isdigit():
                            shift = int(clean_args.pop())
                        target = " ".join(clean_args)
                        res = self.run_atbash(target, shift=shift)
                        self.print_atbash(res)

                elif cmd == "/vigenere":
                    if len(args) < 3:
                        print("Usage: /vigenere <enc|dec> <text> <key> [--f-skip] [--skip-indices ...]\n")
                    else:
                        mode = args[0]
                        text = args[1]
                        key = args[2]
                        f_skip = "--f-skip" in args
                        skips = None
                        for i, a in enumerate(args):
                            if a == "--skip-indices" and i + 1 < len(args):
                                skips = set()
                                for x in args[i + 1].split(","):
                                    try:
                                        skips.add(int(x.strip()))
                                    except ValueError:
                                        pass
                        res = self.run_vigenere(mode, text, key, f_skip=f_skip, skip_indices=skips)
                        self.print_vigenere(res)

                elif cmd in ("/totient-stream", "/totient"):
                    if len(args) < 2:
                        print("Usage: /totient-stream <enc|dec> <text_or_page> [--offset N] [--f-skip] [--skip-indices ...]\n")
                    else:
                        mode = args[0]
                        offset = 0
                        explicit_offset = False
                        f_skip = False
                        skips = None
                        clean_args = []
                        i = 1
                        while i < len(args):
                            if args[i] in ("--offset", "-o") and i + 1 < len(args):
                                try:
                                    offset = int(args[i + 1])
                                    explicit_offset = True
                                except ValueError:
                                    pass
                                i += 2
                            elif args[i] == "--f-skip":
                                f_skip = True
                                i += 1
                            elif args[i] == "--no-f-skip":
                                f_skip = False
                                i += 1
                            elif args[i] == "--skip-indices" and i + 1 < len(args):
                                skips = set()
                                for x in args[i + 1].split(","):
                                    try:
                                        skips.add(int(x.strip()))
                                    except ValueError:
                                        pass
                                i += 2
                            else:
                                clean_args.append(args[i])
                                i += 1
                        if not explicit_offset and len(clean_args) == 2 and clean_args[0].isdigit() and clean_args[1].isdigit():
                            offset = int(clean_args.pop())
                        target = " ".join(clean_args)
                        res = self.run_totient_stream(mode, target, offset=offset, f_skip=f_skip, skip_indices=skips)
                        self.print_totient_stream(res)

                elif cmd == "/solve":
                    target = args[0] if args else "all"
                    res = self.run_solve(target)
                    self.print_solve(res)

                elif cmd == "/crack":
                    if not args:
                        print("Usage: /crack <text_or_page> [--deep] [--compound] [--random] [--rotations] [--no-metal] [--no-ane]\n")
                    else:
                        deep = False
                        compound = False
                        randomize = False
                        rotations = False
                        include_ecc = False
                        use_metal = True
                        use_ane = True
                        clean_args = []
                        for a in args:
                            if a.startswith("-"):
                                norm_flag = a.lstrip("-").lower()
                                if norm_flag in ("deep", "d"):
                                    deep = True
                                elif norm_flag in ("compound", "comp", "c"):
                                    compound = True
                                elif norm_flag in ("random", "rand", "rnd", "r"):
                                    randomize = True
                                elif norm_flag in ("rotations", "rotation", "rot", "rots"):
                                    rotations = True
                                elif norm_flag in ("include-ecc", "ecc"):
                                    include_ecc = True
                                elif norm_flag in ("no-metal", "nometal"):
                                    use_metal = False
                                elif norm_flag in ("no-ane", "noane"):
                                    use_ane = False
                                elif norm_flag in ("metal", "gpu"):
                                    use_metal = True
                                elif norm_flag in ("ane",):
                                    use_ane = True
                            else:
                                clean_args.append(a)

                        if not clean_args:
                            print("Usage: /crack <text_or_page> [--deep] [--compound] [--random] [--rotations] [--include-ecc] [--no-metal] [--no-ane]\n")
                        else:
                            target = " ".join(clean_args)
                            res = self.run_crack(
                                target,
                                deep=deep,
                                compound=compound,
                                randomize=randomize,
                                include_rotations=rotations,
                                use_metal=use_metal,
                                use_ane=use_ane,
                                include_ecc=include_ecc,
                            )
                            self.print_crack(res)

                elif cmd in ("/hardware", "/gpu", "/metal", "/ane"):
                    res = self.run_hardware()
                    self.print_hardware(res)

                elif cmd in ("/ledger", "/attempts"):
                    target = args[0] if args else None
                    res = self.run_ledger(target)
                    self.print_ledger(res)

                elif cmd == "/triage":
                    if not args:
                        print("Usage: /triage <text_or_page>\n")
                    else:
                        res = self.run_triage(" ".join(args))
                        self.print_triage(res)

                elif cmd == "/period":
                    if not args:
                        print("Usage: /period <text_or_page> [max_period]\n")
                    else:
                        max_p = 30
                        target = args[0]
                        if len(args) > 1 and args[1].isdigit():
                            max_p = int(args[1])
                        res = self.run_period(target, max_period=max_p)
                        self.print_period(res)

                elif cmd == "/crib":
                    if len(args) < 2:
                        print("Usage: /crib <text_or_page> <crib_word>\n")
                    else:
                        res = self.run_crib(args[0], args[1])
                        self.print_crib(res)

                elif cmd == "/opsec":
                    if not args:
                        print("Usage: /opsec <text_or_filepath>")
                    else:
                        res = self.run_opsec(" ".join(args))
                        self.print_opsec(res)

                elif cmd == "/layout":
                    target = args[0] if args else "all"
                    self.run_layout(target)

                elif cmd == "/organize":
                    self.run_organize()

                elif cmd == "/ingest":
                    self.run_ingest()

                elif cmd == "/running-key":
                    if len(args) < 2:
                        print("Usage: /running-key <page> <text_file> [--mode sub|add|beaufort] [--f-skip] [--offset N]\n")
                    else:
                        page = args[0]
                        text_file = args[1]
                        mode = "sub"
                        f_skip = "--f-skip" in args
                        offset = 0
                        i = 2
                        while i < len(args):
                            if args[i] in ("--mode", "-m") and i + 1 < len(args):
                                mode = args[i + 1]
                                i += 2
                            elif args[i] in ("--offset", "-o") and i + 1 < len(args):
                                try:
                                    offset = int(args[i + 1])
                                except ValueError:
                                    pass
                                i += 2
                            else:
                                i += 1
                        res = self.run_running_key(page, text_file, mode=mode, f_skip=f_skip, offset=offset)
                        self.print_running_key(res)

                elif cmd == "/running-key-scan":
                    if not args:
                        print("Usage: /running-key-scan <page> [--ref-dir DIR] [--step N] [--top-k N]\n")
                    else:
                        page = args[0]
                        ref_dir = None
                        step = 1
                        top_k = 5
                        i = 1
                        while i < len(args):
                            if args[i] == "--ref-dir" and i + 1 < len(args):
                                ref_dir = args[i + 1]
                                i += 2
                            elif args[i] in ("--step", "-s") and i + 1 < len(args):
                                try:
                                    step = int(args[i + 1])
                                except ValueError:
                                    pass
                                i += 2
                            elif args[i] in ("--top-k", "-k", "--limit", "-l") and i + 1 < len(args):
                                try:
                                    top_k = int(args[i + 1])
                                except ValueError:
                                    pass
                                i += 2
                            else:
                                i += 1
                        res = self.run_running_key_scan(page, ref_dir=ref_dir, step=step, top_k=top_k)
                        self.print_running_key_scan(res)

                elif cmd == "/lexicon":
                    action = args[0] if args else "phrases"
                    limit = 50
                    if len(args) > 1 and args[1].isdigit():
                        limit = int(args[1])
                    res = self.run_lexicon(action=action, limit=limit)
                    self.print_lexicon(res)

                elif cmd == "/status":
                    probe = bool(args and ("--probe" in args or "-p" in args or "probe" in args))
                    self.run_status(probe=probe)

                elif cmd == "/think":
                    if args:
                        val = args[0].lower()
                        self.think = val in ("on", "true", "1", "yes")
                    else:
                        self.think = not self.think
                    print(f"[*] Chain-of-Thought reasoning: {'ENABLED' if self.think else 'DISABLED'}\n")

                elif cmd == "/provider":
                    if not args:
                        print(f"[*] Current provider: {self.provider.upper()}")
                        print(f"Available providers: {', '.join(SUPPORTED_PROVIDERS)}")
                    else:
                        p = args[0].lower()
                        if p in SUPPORTED_PROVIDERS:
                            self.provider = p
                            self.active_model = get_model(self.model_key, provider=self.provider)
                            print(f"[+] Switched provider to: {self.provider.upper()} (Default Model: {self.active_model})\n")
                        else:
                            print(f"[!] Unknown provider '{p}'. Supported: {', '.join(SUPPORTED_PROVIDERS)}\n")

                elif cmd == "/model":
                    if not args:
                        print(f"[*] Current provider: {self.provider.upper()} | Model: {self.active_model} ({self.model_key})")
                        print(f"Available keys: {', '.join(MODELS.keys())}")
                    else:
                        key = args[0]
                        if key.lower() in MODELS:
                            self.model_key = key.lower()
                            self.active_model = get_model(self.model_key, provider=self.provider)
                        else:
                            self.model_key = "custom"
                            self.active_model = key
                        print(f"[+] Switched to model: {self.active_model}\n")

                elif cmd in ("/key", "/keys", "/api"):
                    self.run_key_section(args)

                elif cmd in ("/menu", "/commands"):
                    self.print_command_list()

                elif cmd == "/host":
                    if not args:
                        print(f"[*] Current Ollama Host: {config.OLLAMA_HOST}")
                    else:
                        new_host = args[0].strip()
                        config.OLLAMA_HOST = new_host
                        print(f"[+] Ollama streaming host set to: {config.OLLAMA_HOST}\n")

                elif cmd == "/profile":
                    if not args:
                        prof = "LOW-SPEC (num_ctx: 2048)" if self.low_spec else f"STANDARD (num_ctx: {config.DEFAULT_NUM_CTX})"
                        print(f"[*] Current Profile: {prof}")
                        print("Usage: /profile <standard|low-spec>")
                    else:
                        choice = args[0].lower()
                        if choice in ("low", "low-spec", "lowspec"):
                            self.low_spec = True
                            config.LOW_SPEC_MODE = True
                            config.DEFAULT_NUM_CTX = 2048
                            print("[+] Hardware Profile: LOW-SPEC enabled (num_ctx: 2048, reduced memory footprint).\n")
                        elif choice in ("standard", "std", "high"):
                            self.low_spec = False
                            config.LOW_SPEC_MODE = False
                            config.DEFAULT_NUM_CTX = 8192
                            print("[+] Hardware Profile: STANDARD enabled (num_ctx: 8192).\n")
                        else:
                            print("[!] Valid options: /profile standard | /profile low-spec")

                else:
                    print(f"[!] Unknown command '{cmd}'. Type '/help' for command list.")
            else:
                # Direct natural language query routes to RAG
                self.run_ask(raw, use_web=False)

