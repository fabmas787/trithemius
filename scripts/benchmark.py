"""
Benchmark and profiling harness for Trithemius Cryptanalytic Workstation.
Measures execution latencies with microsecond accuracy using time.perf_counter,
isolating cold vs warm paths (accounting for LRU caches), storing baseline runs,
and providing optional cProfile hotspot profiling.
"""

import os
import sys
import gc
import json
import time
import cProfile
import pstats
import platform
from typing import Dict, Any, List, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "ciphers"))
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))

import config
import agrippa
import kasiski
import entropy
import ask
import taxonomy

BENCH_DIR = os.environ.get("TRITHEMIUS_BENCH_DIR", os.path.join(BASE_DIR, "vectordb"))
DB_DIR = os.path.join(BASE_DIR, "vectordb")
HISTORY_FILE = os.path.join(BENCH_DIR, "bench_history.jsonl")
BASELINES_FILE = os.path.join(BENCH_DIR, "bench_baselines.json")
PROFILE_PSTATS = os.path.join(BENCH_DIR, "benchmark_profile.pstats")


def time_callable(fn, *args, iterations: int = 20, warmup: int = 3, clear_cache_fn=None) -> Dict[str, float]:
    """Execute a callable with warmup, optional cache clearing per iteration, and guaranteed GC restoration."""
    # Warmup
    for _ in range(warmup):
        if clear_cache_fn:
            clear_cache_fn()
        fn(*args)

    durations: List[float] = []
    gc_was_enabled = gc.isenabled()
    try:
        for _ in range(iterations):
            if clear_cache_fn:
                clear_cache_fn()
            gc.collect()
            gc.disable()
            try:
                t0 = time.perf_counter()
                fn(*args)
                t1 = time.perf_counter()
                durations.append(t1 - t0)
            finally:
                if gc_was_enabled:
                    gc.enable()
    finally:
        if gc_was_enabled and not gc.isenabled():
            gc.enable()

    if not durations:
        return {
            "p50_ms": 0.0,
            "p95_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
            "mean_ms": 0.0,
            "iterations": 0,
        }

    durations.sort()
    n = len(durations)
    p50 = durations[n // 2]
    p95_idx = min(n - 1, int(round(0.95 * (n - 1))))
    p95 = durations[p95_idx]
    min_t = durations[0]
    max_t = durations[-1]
    mean_t = sum(durations) / max(1, n)

    # Convert to milliseconds
    return {
        "p50_ms": p50 * 1000.0,
        "p95_ms": p95 * 1000.0,
        "min_ms": min_t * 1000.0,
        "max_ms": max_t * 1000.0,
        "mean_ms": mean_t * 1000.0,
        "iterations": n,
    }


def clear_agrippa_caches():
    agrippa.is_prime.cache_clear()
    agrippa.prime_factors.cache_clear()


def run_benchmark(skip_vector: bool = False, include_llm: bool = False) -> Dict[str, Any]:
    """Run all benchmark components and return structured metrics."""
    os.makedirs(DB_DIR, exist_ok=True)
    sample_rune_page = "ᛋᚩᛗᛖ᛫ᚹᛁᛋᛞᚩᛗ᛫ᚦᛖ᛫ᛈᚱᛁᛗᛖᛋ᛫ᚪᚱᛖ᛫ᛋᚪᚳᚱᛖᛞ"
    sample_key = "DIVINITY"
    sample_num = 3301

    results: Dict[str, Any] = {}

    # 1. Modulo-29 Runic Vigenère Decryption
    def bench_vigenere():
        kasiski.rune_vigenere_decode(sample_rune_page, sample_key)

    results["vigenere_mod29_warm"] = time_callable(bench_vigenere, iterations=50)

    # 2. Gematria Primus Arithmetic & Totient
    def bench_gematria():
        s = agrippa.gematria_prime_sum(sample_rune_page)
        agrippa.euler_totient(sample_num)
        agrippa.is_prime(sample_num)
        agrippa.prime_factors(sample_num)
        return s

    results["gematria_sacred_math_cold"] = time_callable(bench_gematria, iterations=25, clear_cache_fn=clear_agrippa_caches)
    results["gematria_sacred_math_warm"] = time_callable(bench_gematria, iterations=50)

    # 3. Shannon Entropy & Signal Features
    sample_text = sample_rune_page * 10
    def bench_entropy():
        entropy.extract_signal_features(sample_text)

    results["entropy_features"] = time_callable(bench_entropy, iterations=30)

    # 4. BM25 Retrieval (Cold scan vs Persisted Index)
    bench_query = "sacred primes loss of innocence"
    def bench_bm25():
        ask.bm25_retrieve(bench_query, k=5)

    results["bm25_retrieval"] = time_callable(bench_bm25, iterations=15)

    # 5. ChromaDB Vector Query (if active)
    if not skip_vector:
        try:
            coll = ask.get_collection()
            if coll and coll.count() > 0:
                def bench_vector():
                    ask.retrieve(coll, bench_query, k=5)
                results["vector_retrieval"] = time_callable(bench_vector, iterations=10)
            else:
                results["vector_retrieval"] = {"p50_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0, "skipped": True}
        except Exception as e:
            results["vector_retrieval"] = {"p50_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0, "error": str(e)}
    else:
        results["vector_retrieval"] = {"p50_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0, "skipped": True}

    # 6. Micro-benchmark: Pair-table build (Phase 0)
    sample_indices = [i % 29 for i in range(120)]
    def bench_pair_table():
        taxonomy.compute_t_table(sample_indices, period=8)
    results["pair_table_build"] = time_callable(bench_pair_table, iterations=30)

    # 7. Micro-benchmark: Sliding-window entropy on >= 1 MB buffer (Phase 0)
    large_1mb_buffer = (sample_rune_page * 35000)[:1_000_000]
    if len(large_1mb_buffer) < 1_000_000:
        large_1mb_buffer = ("ABCDEF" * 170000)[:1_000_000]
    def bench_sliding_1mb():
        entropy.sliding_window_entropy(large_1mb_buffer, window_size=256, step=64)
    results["entropy_sliding_1mb"] = time_callable(bench_sliding_1mb, iterations=5, warmup=1)

    # 8. Micro-benchmark: BM25 Cold load vs Warm retrieval (Phase 0)
    def bench_bm25_cold():
        ask.load_persisted_bm25(corpus_dir=ask.CORPUS_DIR)
    results["bm25_cold_load"] = time_callable(bench_bm25_cold, iterations=15)

    # 9. Micro-benchmark: RAG Cache Hit vs Miss (Phase 0)
    test_key_hit = ask.rag_cache_key("benchmark_hit_query", "test_digest", "ollama", "spark", False)
    ask.store_rag_cache(test_key_hit, "benchmark_hit_query", "test_digest", "ollama", "spark", False, "v1", "bm25", "Answer hit", [])
    test_key_miss = "non_existent_cache_key_miss_12345"
    def bench_cache_hit():
        ask.lookup_rag_cache(test_key_hit)
    def bench_cache_miss():
        ask.lookup_rag_cache(test_key_miss)
    results["rag_cache_hit"] = time_callable(bench_cache_hit, iterations=40)
    results["rag_cache_miss"] = time_callable(bench_cache_miss, iterations=40)

    return results


def save_history_entry(results: Dict[str, Any]):
    """Append benchmark run to vectordb/bench_history.jsonl."""
    entry = {
        "timestamp": time.time(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "results": results,
    }
    with open(HISTORY_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def load_baselines(baselines_file: str = BASELINES_FILE) -> Dict[str, Any]:
    if os.path.exists(baselines_file):
        try:
            with open(baselines_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_baseline(name: str, results: Dict[str, Any], baselines_file: str = BASELINES_FILE):
    baselines = load_baselines(baselines_file=baselines_file)
    baselines[name] = {
        "timestamp": time.time(),
        "results": results,
    }
    with open(baselines_file, "w", encoding="utf-8") as f:
        json.dump(baselines, f, indent=2)


def print_telemetry_table(results: Dict[str, Any], baseline_results: Optional[Dict[str, Any]] = None, baseline_name: Optional[str] = None):
    """Print formatted terminal comparison table."""
    print("\n+--- [TRITHEMIUS PERFORMANCE BENCHMARK] ---------------------------------------------+")
    print(f"| {'Benchmark Component':<36} | {'p50 (ms)':<9} | {'Min (ms)':<9} | {'Max (ms)':<9} |" + (f" {'Delta':<10} |" if baseline_results else ""))
    print("+--------------------------------------+-----------+-----------+-----------+" + ("------------+" if baseline_results else ""))

    for key, data in results.items():
        if data.get("skipped"):
            val_str = f"| {key:<36} | {'SKIPPED':<9} | {'-':<9} | {'-':<9} |"
            if baseline_results:
                val_str += f" {'-':<10} |"
            print(val_str)
            continue

        p50 = data["p50_ms"]
        min_v = data["min_ms"]
        max_v = data["max_ms"]

        delta_str = ""
        if baseline_results and key in baseline_results and not baseline_results[key].get("skipped"):
            base_p50 = baseline_results[key]["p50_ms"]
            if base_p50 > 0:
                pct = ((p50 - base_p50) / base_p50) * 100.0
                sign = "+" if pct > 0 else ""
                delta_str = f" {sign}{pct:5.1f}%    |"

        row = f"| {key:<36} | {p50:9.4f} | {min_v:9.4f} | {max_v:9.4f} |" + delta_str
        print(row)

    print("+--------------------------------------+-----------+-----------+-----------+" + ("------------+" if baseline_results else ""))
    if baseline_name:
        print(f"  * Compared against baseline: '{baseline_name}' (negative delta = faster)")
    print("")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Trithemius Benchmarking & Profiling Harness")
    parser.add_argument("--profile", action="store_true", help="Run cProfile hotspot profiling")
    parser.add_argument("--save-baseline", type=str, default=None, help="Save run as tagged baseline name")
    parser.add_argument("--compare", type=str, default=None, help="Compare results against a saved baseline")
    parser.add_argument("--skip-vector", action="store_true", help="Skip ChromaDB vector query benchmark")
    parser.add_argument("--llm", action="store_true", help="Include LLM time-to-first-token benchmark")
    args = parser.parse_args()

    if args.profile:
        print("[*] Running cProfile instrumentation pass...")
        pr = cProfile.Profile()
        pr.enable()
        run_benchmark(skip_vector=args.skip_vector, include_llm=args.llm)
        pr.disable()
        pr.dump_stats(PROFILE_PSTATS)
        print(f"[+] Saved cProfile stats to: {PROFILE_PSTATS}")
        print("\n=== Top 20 Hotspots by Cumulative Time ===")
        ps = pstats.Stats(pr).sort_stats(pstats.SortKey.CUMULATIVE)
        ps.print_stats(20)
        return

    print("[*] Running microsecond-precision component benchmarks...")
    results = run_benchmark(skip_vector=args.skip_vector, include_llm=args.llm)
    save_history_entry(results)

    baseline_data = None
    if args.compare:
        baselines = load_baselines()
        if args.compare in baselines:
            baseline_data = baselines[args.compare]["results"]
        else:
            print(f"[!] Warning: baseline '{args.compare}' not found in {BASELINES_FILE}.")

    print_telemetry_table(results, baseline_results=baseline_data, baseline_name=args.compare)

    if args.save_baseline:
        save_baseline(args.save_baseline, results)
        print(f"[+] Saved baseline '{args.save_baseline}' to {BASELINES_FILE}")


if __name__ == "__main__":
    main()
