"""
Command-Line Interface argument parser and dispatcher for Trithemius.
"""

import os
import sys
import argparse
from typing import Optional, List

from config import SUPPORTED_PROVIDERS
from workstation.core.workstation import TerminalWorkstation, CORPUS_DIR, DB_DIR
from workstation.ui.json_renderer import JsonRenderer

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Trithemius Liber Primus Cryptanalytic Workstation")
    parser.add_argument("--model", type=str, default="", help="Model key or custom model name")
    parser.add_argument("--moe", action="store_true", help="Shortcut for --model moe")
    parser.add_argument("--provider", type=str, default=None, help=f"Inference provider ({', '.join(SUPPORTED_PROVIDERS)})")
    parser.add_argument("--api-key", type=str, default=None, help="Personal API key for selected cloud provider")
    parser.add_argument("--ollama-host", type=str, default=None, help="Remote Ollama host URL (e.g. http://remote:11434)")
    parser.add_argument("--low-spec", action="store_true", default=None, help="Enable low-RAM/CPU profile (num_ctx: 2048)")
    parser.add_argument("--think", action="store_true", default=None, help="Enable Chain-of-Thought reasoning")
    parser.add_argument("--boost", action="store_true", default=None, help="Enable Deep Cryptanalytic Retrieval and Reranking Boost mode")
    parser.add_argument("--json", action="store_true", help="Format CLI output as machine-readable JSON")

    subparsers = parser.add_subparsers(dest="subcommand", help="Direct CLI subcommand")

    # boost subcommand
    p_bst = subparsers.add_parser("boost", help="Toggle, set, or inspect Cryptanalytic Boost mode")
    p_bst.add_argument("state", nargs="?", choices=["on", "off", "status", "toggle"], default="status", help="Boost mode (default: status)")

    # help subcommand
    p_hlp = subparsers.add_parser("help", help="Display command reference manual or command details")
    p_hlp.add_argument("command", nargs="?", default=None, help="Command to look up (e.g. gematria, boost, vigenere)")

    # web subcommand
    p_web = subparsers.add_parser("web", help="Query RAG knowledge engine with live web reconnaissance")
    p_web.add_argument("query", type=str, help="Research question")

    # ask subcommand
    p_ask = subparsers.add_parser("ask", help="Query RAG knowledge engine")
    p_ask.add_argument("query", type=str, help="Research question")
    p_ask.add_argument("--web", action="store_true", help="Inject live web search context")
    p_ask.add_argument("--fresh", action="store_true", help="Bypass cache and force fresh inference")

    # gematria subcommand
    p_gem = subparsers.add_parser("gematria", help="Gematria Primus prime sum, totient, and Atbash")
    p_gem.add_argument("text", type=str, help="Runes, Latin text, filepath, or corpus page number")

    # atbash subcommand
    p_atb = subparsers.add_parser("atbash", help="Modulo-29 Atbash and Caesar-shifted Atbash reflection cipher")
    p_atb.add_argument("text", type=str, help="Ciphertext, plaintext, filepath, or corpus page number")
    p_atb.add_argument("--shift", "-s", type=int, default=0, help="Caesar shift applied after Atbash in F_29 (default: 0; Koan 1 uses 3)")

    # vigenere subcommand
    p_vig = subparsers.add_parser("vigenere", help="Modulo-29 or Modulo-26 Vigenère cryptanalysis")
    p_vig.add_argument("mode", choices=["enc", "dec", "encode", "decode"], help="Cipher mode")
    p_vig.add_argument("text", type=str, help="Plaintext, ciphertext, filepath, or corpus page number")
    p_vig.add_argument("key", type=str, help="Key string or runes")
    p_vig.add_argument("--f-skip", action="store_true", help="Enable cleartext Fehu keystream pause")
    p_vig.add_argument("--skip-indices", type=str, default=None, help="Comma-separated explicit skip indices")

    # totient-stream subcommand
    p_tot = subparsers.add_parser("totient-stream", help="Liber Primus Prime Totient Stream Cipher (phi(p) = p - 1)")
    p_tot.add_argument("mode", choices=["enc", "dec", "encode", "decode"], help="Cipher mode")
    p_tot.add_argument("text", type=str, help="Plaintext, ciphertext, filepath, or corpus page number")
    p_tot.add_argument("--offset", type=int, default=0, help="Prime sequence offset (default: 0)")
    p_tot.add_argument("--f-skip", action="store_true", help="Enable cleartext Fehu keystream pause (skip index 56)")
    p_tot.add_argument("--skip-indices", type=str, default=None, help="Comma-separated explicit skip indices")

    # totient subcommand (alias for totient-stream)
    p_tot2 = subparsers.add_parser("totient", help="Liber Primus Prime Totient Stream Cipher (phi(p) = p - 1)")
    p_tot2.add_argument("mode", choices=["enc", "dec", "encode", "decode"], help="Cipher mode")
    p_tot2.add_argument("text", type=str, help="Plaintext, ciphertext, filepath, or corpus page number")
    p_tot2.add_argument("--offset", type=int, default=0, help="Prime sequence offset (default: 0)")
    p_tot2.add_argument("--f-skip", action="store_true", help="Enable cleartext Fehu keystream pause (skip index 56)")
    p_tot2.add_argument("--skip-indices", type=str, default=None, help="Comma-separated explicit skip indices")

    # solve subcommand
    p_slv = subparsers.add_parser("solve", help="Solve and verify canonical Liber Primus solved pages")
    p_slv.add_argument("target", nargs="?", default="all", help="Target page identifier (e.g. 0, welcome, koan1, 56, all)")

    # crack subcommand
    p_crk = subparsers.add_parser("crack", help="Liber Primus GF(29) Cryptanalytic Cascade Solver")
    p_crk.add_argument("text", type=str, help="Ciphertext, filepath, or corpus page number")
    p_crk.add_argument("--deep", action="store_true", help="Enable deep search (affine mod 29, autokey, cross-page)")

    # triage subcommand
    p_trg = subparsers.add_parser("triage", help="Statistical triage & cipher classification")
    p_trg.add_argument("text", type=str, help="Ciphertext, filepath, or corpus page number")

    # period subcommand
    p_prd = subparsers.add_parser("period", help="Key length consensus & periodogram comb estimation")
    p_prd.add_argument("text", type=str, help="Ciphertext, filepath, or corpus page number")
    p_prd.add_argument("max_period", nargs="?", type=int, default=30, help="Maximum period to scan (default: 30)")

    # crib subcommand
    p_crb = subparsers.add_parser("crib", help="Slide crib word for implied key analysis")
    p_crb.add_argument("text", type=str, help="Ciphertext, filepath, or corpus page number")
    p_crb.add_argument("crib", type=str, help="Crib word or runes")

    # opsec subcommand
    p_ops = subparsers.add_parser("opsec", help="Inspect PGP 7A35090F signature and Shannon entropy")
    p_ops.add_argument("target", type=str, help="Filepath or text string")

    # layout subcommand
    p_lay = subparsers.add_parser("layout", help="Layout side-channel mutual information analysis")
    p_lay.add_argument("target", nargs="?", default="all", help="Target page number, filepath, or 'calibrate' (default: all)")

    # organize subcommand
    subparsers.add_parser("organize", help="Deduplicate and classify corpus via Porta")

    # ingest subcommand
    subparsers.add_parser("ingest", help="Chunk and embed corpus into ChromaDB via Bodleian")

    # page subcommand
    p_pg = subparsers.add_parser("page", help="Inspect specific Liber Primus page from corpus")
    p_pg.add_argument("page_num", type=str, help="Page number (e.g. 56, 00, 73)")

    # bench subcommand
    p_bench = subparsers.add_parser("bench", help="Run microsecond latency benchmark and profiling")
    p_bench.add_argument("--profile", action="store_true", help="Run cProfile hotspot profiling")
    p_bench.add_argument("--save-baseline", type=str, default=None, help="Save run as tagged baseline")
    p_bench.add_argument("--compare", type=str, default=None, help="Compare results against a saved baseline")
    p_bench.add_argument("--skip-vector", action="store_true", help="Skip ChromaDB vector query benchmark")
    p_bench.add_argument("--llm", action="store_true", help="Include LLM time-to-first-token benchmark")

    # status subcommand
    p_status = subparsers.add_parser("status", help="Display system telemetry and corpus health")
    p_status.add_argument("--probe", "-p", action="store_true", help="Probe configured providers and models")
    p_status.add_argument("--json", action="store_true", help="Format CLI output as machine-readable JSON")

    # running-key subcommand
    p_rk = subparsers.add_parser("running-key", help="GF(29) running-key decryption against reference text")
    p_rk.add_argument("pos_page", nargs="?", default=None, help="Ciphertext page or number (positional)")
    p_rk.add_argument("pos_text", nargs="?", default=None, help="Path to reference text file (positional)")
    p_rk.add_argument("--page", "-p", type=str, default=None, help="Ciphertext page or number")
    p_rk.add_argument("--text", "-t", type=str, default=None, help="Path to reference text file")
    p_rk.add_argument("--mode", "-m", choices=["sub", "add", "beaufort"], default="sub", help="Decryption mode (default: sub)")
    p_rk.add_argument("--f-skip", action="store_true", help="Enable cleartext Fehu keystream pause")
    p_rk.add_argument("--offset", "-o", type=int, default=0, help="Keystream offset (default: 0)")

    # running-key-scan subcommand
    p_rks = subparsers.add_parser("running-key-scan", help="Scan canonical reference texts against target page")
    p_rks.add_argument("pos_page", nargs="?", default=None, help="Ciphertext page or number (positional)")
    p_rks.add_argument("--page", "-p", type=str, default=None, help="Ciphertext page or number")
    p_rks.add_argument("--ref-dir", type=str, default=None, help="Reference texts directory (default: corpus/reference_texts)")
    p_rks.add_argument("--step", type=int, default=1, help="Sliding window step size (default: 1)")
    p_rks.add_argument("--top-k", type=int, default=5, help="Number of top candidates to display (default: 5)")
    p_rks.add_argument("--limit", "-l", type=int, default=None, help="Alias for --top-k")

    # lexicon subcommand
    p_lex = subparsers.add_parser("lexicon", help="Master vocabulary and philosophical phrase inspector")
    p_lex.add_argument("action", nargs="?", choices=["phrases", "words", "all"], default="phrases", help="Action (default: phrases)")
    p_lex.add_argument("--limit", type=int, default=50, help="Maximum items to display (default: 50)")

    # key subcommand (AI API key & cloud provider configuration section)
    p_key = subparsers.add_parser("key", help="AI API key and cloud provider configuration section")
    p_key.add_argument("key_args", nargs="*", help="Arguments: 'show', 'clear <provider>', or '<provider> <key>'")

    # keys subcommand (alias)
    p_keys = subparsers.add_parser("keys", help="Alias for 'key'")
    p_keys.add_argument("key_args", nargs="*", help="Arguments")

    # hardware subcommand
    subparsers.add_parser("hardware", help="Query and benchmark Apple Silicon hardware")
    subparsers.add_parser("gpu", help="Alias for 'hardware'")
    subparsers.add_parser("metal", help="Alias for 'hardware'")
    subparsers.add_parser("ane", help="Alias for 'hardware'")

    # ledger subcommand
    p_led = subparsers.add_parser("ledger", help="Display cryptanalytic ledger")
    p_led.add_argument("target", nargs="?", default=None, help="Target page")

    # think subcommand
    p_thk = subparsers.add_parser("think", help="Toggle Chain-of-Thought")
    p_thk.add_argument("state", nargs="?", default=None, choices=["on", "off", "toggle"])

    # provider subcommand
    p_prov = subparsers.add_parser("provider", help="Switch active provider")
    p_prov.add_argument("name", nargs="?", default=None)

    # model subcommand
    p_mdl = subparsers.add_parser("model", help="Switch active model")
    p_mdl.add_argument("model_key", nargs="?", default=None)

    # host subcommand
    p_hst = subparsers.add_parser("host", help="Set Ollama host")
    p_hst.add_argument("url", nargs="?", default=None)

    # profile subcommand
    p_prf = subparsers.add_parser("profile", help="Toggle hardware profile")
    p_prf.add_argument("mode", nargs="?", default=None, choices=["standard", "low-spec"])

    # cache subcommand
    p_cch = subparsers.add_parser("cache", help="Manage RAG cache")
    p_cch.add_argument("action", nargs="?", default="clear")

    return parser


def cli_dispatch(parsed_args: argparse.Namespace, ws: TerminalWorkstation, parser: Optional[argparse.ArgumentParser] = None):
    if parsed_args.subcommand is None:
        # Launch interactive REPL
        ws.repl()
    elif parsed_args.subcommand == "boost":
        ws.run_boost(parsed_args.state)
    elif parsed_args.subcommand == "help":
        ws.print_help(parsed_args.command)
    elif parsed_args.subcommand == "web":
        ws.run_ask(parsed_args.query, use_web=True)
    elif parsed_args.subcommand == "bench":
        ws.run_bench(
            profile=parsed_args.profile,
            skip_vector=parsed_args.skip_vector,
            include_llm=parsed_args.llm,
            compare=parsed_args.compare,
            save_baseline=parsed_args.save_baseline,
        )
    elif parsed_args.subcommand == "ask":
        ws.run_ask(parsed_args.query, use_web=parsed_args.web, fresh=parsed_args.fresh)
    elif parsed_args.subcommand == "gematria":
        res = ws.run_gematria(parsed_args.text)
        ws.print_gematria(res)
    elif parsed_args.subcommand == "atbash":
        res = ws.run_atbash(parsed_args.text, shift=parsed_args.shift)
        ws.print_atbash(res)
    elif parsed_args.subcommand == "vigenere":
        skips = None
        if parsed_args.skip_indices:
            skips = set()
            for x in parsed_args.skip_indices.split(","):
                try:
                    skips.add(int(x.strip()))
                except ValueError:
                    pass
        res = ws.run_vigenere(
            parsed_args.mode, parsed_args.text, parsed_args.key,
            f_skip=parsed_args.f_skip, skip_indices=skips
        )
        ws.print_vigenere(res)
    elif parsed_args.subcommand in ("totient-stream", "totient"):
        skips = None
        if parsed_args.skip_indices:
            skips = set()
            for x in parsed_args.skip_indices.split(","):
                try:
                    skips.add(int(x.strip()))
                except ValueError:
                    pass
        res = ws.run_totient_stream(
            parsed_args.mode, parsed_args.text,
            offset=parsed_args.offset,
            f_skip=parsed_args.f_skip,
            skip_indices=skips
        )
        ws.print_totient_stream(res)
    elif parsed_args.subcommand == "solve":
        res = ws.run_solve(parsed_args.target)
        ws.print_solve(res)
    elif parsed_args.subcommand == "crack":
        res = ws.run_crack(parsed_args.text, deep=parsed_args.deep)
        ws.print_crack(res)
    elif parsed_args.subcommand == "triage":
        res = ws.run_triage(parsed_args.text)
        ws.print_triage(res)
    elif parsed_args.subcommand == "period":
        res = ws.run_period(parsed_args.text, max_period=parsed_args.max_period)
        ws.print_period(res)
    elif parsed_args.subcommand == "crib":
        res = ws.run_crib(parsed_args.text, parsed_args.crib)
        ws.print_crib(res)
    elif parsed_args.subcommand == "opsec":
        res = ws.run_opsec(parsed_args.target)
        ws.print_opsec(res)
    elif parsed_args.subcommand == "layout":
        ws.run_layout(parsed_args.target)
    elif parsed_args.subcommand == "organize":
        ws.run_organize()
    elif parsed_args.subcommand == "ingest":
        ws.run_ingest()
    elif parsed_args.subcommand == "page":
        ws.run_page(parsed_args.page_num)
    elif parsed_args.subcommand == "status":
        ws.run_status(probe=parsed_args.probe)
    elif parsed_args.subcommand == "running-key":
        page_val = parsed_args.page or parsed_args.pos_page
        text_val = parsed_args.text or parsed_args.pos_text
        if not page_val or not text_val:
            parser.error("running-key requires --page and --text (or positional arguments: page text)")
        res = ws.run_running_key(
            page_target=page_val,
            text_path=text_val,
            mode=parsed_args.mode,
            f_skip=parsed_args.f_skip,
            offset=parsed_args.offset,
        )
        ws.print_running_key(res)
    elif parsed_args.subcommand == "running-key-scan":
        page_val = parsed_args.page or parsed_args.pos_page
        if not page_val:
            parser.error("running-key-scan requires --page (or positional page argument)")
        effective_top_k = parsed_args.limit if parsed_args.limit is not None else parsed_args.top_k
        res = ws.run_running_key_scan(
            page_target=page_val,
            ref_dir=parsed_args.ref_dir,
            step=parsed_args.step,
            top_k=effective_top_k,
        )
        ws.print_running_key_scan(res)
    elif parsed_args.subcommand == "lexicon":
        res = ws.run_lexicon(
            action=parsed_args.action,
            limit=parsed_args.limit,
        )
        ws.print_lexicon(res)
    elif parsed_args.subcommand in ("key", "keys"):
        ws.run_key_section(parsed_args.key_args)
    elif parsed_args.subcommand in ("hardware", "gpu", "metal", "ane"):
        res = ws.run_hardware()
        ws.print_hardware(res)
    elif parsed_args.subcommand == "ledger":
        res = ws.run_ledger(parsed_args.target)
        ws.print_ledger(res)
    elif parsed_args.subcommand == "think":
        t = ws.run_think(parsed_args.state)
        if getattr(parsed_args, "json", False):
            ws.ui.print_json({"think": t, "state": "on" if t else "off"})
    elif parsed_args.subcommand == "provider":
        p = ws.run_provider(parsed_args.name)
        if getattr(parsed_args, "json", False):
            ws.ui.print_json({"provider": ws.provider})
    elif parsed_args.subcommand == "model":
        m = ws.run_model(parsed_args.model_key)
        if getattr(parsed_args, "json", False):
            ws.ui.print_json({"model": ws.active_model, "model_key": ws.model_key})
    elif parsed_args.subcommand == "host":
        h = ws.run_host(parsed_args.url)
        if getattr(parsed_args, "json", False):
            import config
            ws.ui.print_json({"host": config.OLLAMA_HOST})
    elif parsed_args.subcommand == "profile":
        low = ws.run_profile(parsed_args.mode)
        if getattr(parsed_args, "json", False):
            ws.ui.print_json({"low_spec": ws.low_spec})
    elif parsed_args.subcommand == "cache":
        c = ws.run_cache(parsed_args.action)
        if getattr(parsed_args, "json", False):
            ws.ui.print_json({"cache_action": parsed_args.action, "success": c})


def main(args=None):
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    chosen_model = "moe" if parsed_args.moe else (parsed_args.model or None)
    renderer = JsonRenderer() if getattr(parsed_args, "json", False) else None
    ws = TerminalWorkstation(
        model_key=chosen_model,
        provider=parsed_args.provider,
        think=parsed_args.think,
        boost=parsed_args.boost,
        low_spec=parsed_args.low_spec,
        ollama_host=parsed_args.ollama_host,
        api_key=parsed_args.api_key,
        renderer=renderer,
    )
    return cli_dispatch(parsed_args, ws, parser=parser)


if __name__ == "__main__":
    main()
