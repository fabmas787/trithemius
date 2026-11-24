"""
Benchmark and profiling harness for Trithemius Cryptanalytic Workstation.
Measures execution latencies with nanosecond accuracy using time.perf_counter_ns,
peak memory via tracemalloc, sample standard deviation and 95% confidence intervals,
isolating cold vs warm paths, providing mandatory accelerated vs pure-Python baselines,
and exporting raw per-trial CSV and summary JSON.
"""

import os
import sys
import gc
import csv
import json
import time
import math
import cProfile
import pstats
import platform
import tracemalloc
from typing import Dict, Any, List, Optional, Tuple, Callable, Sequence

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

BENCH_DIR = os.environ.get("TRITHEMIUS_BENCH_DIR", os.path.join(BASE_DIR, "vectordb"))
DB_DIR = os.path.join(BASE_DIR, "vectordb")
HISTORY_FILE = os.path.join(BENCH_DIR, "bench_history.jsonl")
BASELINES_FILE = os.path.join(BENCH_DIR, "bench_baselines.json")
PROFILE_PSTATS = os.path.join(BENCH_DIR, "benchmark_profile.pstats")


def time_callable(
    fn: Callable,
    *args,
    iterations: Optional[int] = None,
    trials: int = 100,
    warmup: int = 3,
    clear_cache_fn: Optional[Callable] = None,
    record_raw: bool = False,
    component_name: str = "callable"
) -> Dict[str, Any]:
    """
    Execute a callable with warmup, optional cache clearing per iteration,
    guaranteed GC restoration, nanosecond latency tracking, peak memory via tracemalloc,
    and 95% confidence interval estimation.
    """
    n_trials = iterations if iterations is not None else trials
    if n_trials < 1:
        n_trials = 1

    # Warmup pass
    for _ in range(warmup):
        if clear_cache_fn:
            clear_cache_fn()
        fn(*args)

    durations_ns: List[int] = []
    raw_trials: List[Dict[str, Any]] = []

    gc_was_enabled = gc.isenabled()
    tracemalloc_was_tracing = tracemalloc.is_tracing()
    if not tracemalloc_was_tracing:
        tracemalloc.start()
    tracemalloc.reset_peak()

    try:
        for trial_idx in range(n_trials):
            if clear_cache_fn:
                clear_cache_fn()
            gc.collect()
            gc.disable()
            try:
                t0 = time.perf_counter_ns()
                fn(*args)
                t1 = time.perf_counter_ns()
                dur_ns = t1 - t0
                durations_ns.append(dur_ns)
                if record_raw:
                    raw_trials.append({
                        "component": component_name,
                        "trial": trial_idx,
                        "duration_ns": dur_ns,
                        "duration_ms": dur_ns / 1_000_000.0,
                    })
            finally:
                if gc_was_enabled:
                    gc.enable()
    finally:
        _, peak_mem_bytes = tracemalloc.get_traced_memory()
        if not tracemalloc_was_tracing:
            tracemalloc.stop()
        if gc_was_enabled and not gc.isenabled():
            gc.enable()

    n = len(durations_ns)
    if not durations_ns or n == 0:
        return {
            "p50_ms": 0.0,
            "p95_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
            "mean_ms": 0.0,
            "mean_ns": 0.0,
            "sample_stdev_ms": 0.0,
            "sample_stdev": 0.0,
            "stdev": 0.0,
            "ci_95": (0.0, 0.0),
            "ci_margin_ms": 0.0,
            "iterations": 0,
            "trials": 0,
            "underpowered": True,
            "peak_memory_bytes": peak_mem_bytes,
        }

    durations_ms = [d / 1_000_000.0 for d in durations_ns]
    durations_ms_sorted = sorted(durations_ms)

    mean_ns = sum(durations_ns) / n
    mean_ms = sum(durations_ms) / n

    if n > 1:
        sample_stdev_ms = math.sqrt(sum((x - mean_ms) ** 2 for x in durations_ms) / (n - 1))
        sample_stdev_ns = math.sqrt(sum((x - mean_ns) ** 2 for x in durations_ns) / (n - 1))
    else:
        sample_stdev_ms = 0.0
        sample_stdev_ns = 0.0

    ci_margin_ms = 1.96 * sample_stdev_ms / math.sqrt(n) if n > 0 else 0.0
    ci_95 = (mean_ms - ci_margin_ms, mean_ms + ci_margin_ms)

    p50 = durations_ms_sorted[n // 2]
    p95_idx = min(n - 1, int(round(0.95 * (n - 1))))
    p95 = durations_ms_sorted[p95_idx]
    min_t = durations_ms_sorted[0]
    max_t = durations_ms_sorted[-1]

    underpowered = (n < 100)

    result = {
        "p50_ms": p50,
        "p95_ms": p95,
        "min_ms": min_t,
        "max_ms": max_t,
        "mean_ms": mean_ms,
        "mean_ns": mean_ns,
        "sample_stdev_ms": sample_stdev_ms,
        "sample_stdev": sample_stdev_ms,
        "stdev": sample_stdev_ms,
        "ci_95": ci_95,
        "ci_margin_ms": ci_margin_ms,
        "iterations": n,
        "trials": n,
        "underpowered": underpowered,
        "peak_memory_bytes": peak_mem_bytes,
    }
    if record_raw:
        result["raw_trials"] = raw_trials
    return result


def clear_agrippa_caches():
    from ciphers import agrippa
    agrippa.is_prime.cache_clear()
    agrippa.prime_factors.cache_clear()


def pure_python_reference_key_scoring(
    t_table: Sequence[Sequence[float]],
    keys: Sequence[Sequence[int]],
    period: int
) -> List[float]:
    """Pure-Python CPU reference implementation of multi-key periodic scoring."""
    scores: List[float] = []
    for k in keys:
        k_len = len(k)
        if k_len == 0:
            scores.append(0.0)
            continue
        total = sum(t_table[i][k[i % k_len] % 29] for i in range(period))
        scores.append(round(total / period, 4))
    return scores


def accelerated_key_scoring(
    t_table: Sequence[Sequence[float]],
    keys: Sequence[Sequence[int]],
    period: int
) -> List[float]:
    """Accelerated key scoring using Apple Metal GPU / ANE when available, with pure-Python fallback."""
    try:
        from ciphers import metal_accel
        if metal_accel.is_metal_available():
            return metal_accel.metal_score_keys_batch(t_table, keys, period)
    except Exception:
        pass
    return pure_python_reference_key_scoring(t_table, keys, period)


def run_baseline_comparison(
    trials: int = 100,
    record_raw: bool = False
) -> Dict[str, Any]:
    """
    Mandatory baseline comparison between hardware-accelerated and pure-Python reference implementation.
    """
    period = 7
    t_table = [[float((i * 3 + j * 5) % 29) for j in range(29)] for i in range(period)]
    keys = [
        [(i + j * 3) % 29 for j in range(period)]
        for i in range(50)
    ]

    ref_res = time_callable(
        pure_python_reference_key_scoring,
        t_table,
        keys,
        period,
        trials=trials,
        record_raw=record_raw,
        component_name="baseline_pure_python_reference"
    )

    acc_res = time_callable(
        accelerated_key_scoring,
        t_table,
        keys,
        period,
        trials=trials,
        record_raw=record_raw,
        component_name="baseline_accelerated"
    )

    ref_mean = ref_res["mean_ms"]
    acc_mean = acc_res["mean_ms"]
    speedup = ref_mean / max(1e-9, acc_mean)

    metal_available = False
    try:
        from ciphers import metal_accel
        metal_available = bool(metal_accel.is_metal_available())
    except Exception:
        metal_available = False

    return {
        "pure_python_reference": ref_res,
        "accelerated": acc_res,
        "speedup": round(speedup, 4),
        "accelerator_type": "metal_gpu" if metal_available else "pure_python_fallback",
        "accelerator_available": metal_available,
        "trials": trials,
        "underpowered": (trials < 100),
    }


def export_raw_trials_csv(raw_records: List[Dict[str, Any]], filepath: str) -> str:
    """Export raw per-trial benchmark records to CSV."""
    dir_name = os.path.dirname(os.path.abspath(filepath))
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    fieldnames = ["component", "trial", "duration_ns", "duration_ms"]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for rec in raw_records:
            writer.writerow(rec)
    return filepath


def export_summary_json(results: Dict[str, Any], filepath: str) -> str:
    """Export benchmark summary metrics to JSON."""
    dir_name = os.path.dirname(os.path.abspath(filepath))
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    summary_data = {k: v for k, v in results.items() if k != "raw_trials"}
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2, default=str)
    return filepath


def run_benchmark(
    skip_vector: bool = False,
    include_llm: bool = False,
    trials: int = 100,
    export_csv: Optional[str] = None,
    export_json: Optional[str] = None,
    record_raw: bool = False
) -> Dict[str, Any]:
    """Run all benchmark components, baseline comparisons, and return structured metrics."""
    os.makedirs(DB_DIR, exist_ok=True)
    from ciphers import agrippa, kasiski, entropy, taxonomy
    try:
        from scripts import ask
    except Exception:
        ask = None
    sample_rune_page = "ᛋᚩᛗᛖ᛫ᚹᛁᛋᛞᚩᛗ᛫ᚦᛖ᛫ᛈᚱᛁᛗᛖᛋ᛫ᚪᚱᛖ᛫ᛋᚪᚳᚱᛖᛞ"
    sample_key = "DIVINITY"
    sample_num = 3301

    should_record_raw = record_raw or (export_csv is not None)
    all_raw_records: List[Dict[str, Any]] = []

    def _collect(name: str, res: Dict[str, Any]):
        if should_record_raw and "raw_trials" in res:
            all_raw_records.extend(res["raw_trials"])

    results: Dict[str, Any] = {}
    underpowered_flag = (trials < 100)

    # 1. Modulo-29 Runic Vigenère Decryption
    def bench_vigenere():
        kasiski.rune_vigenere_decode(sample_rune_page, sample_key)

    res_vig = time_callable(
        bench_vigenere,
        trials=trials,
        record_raw=should_record_raw,
        component_name="vigenere_mod29_warm"
    )
    _collect("vigenere_mod29_warm", res_vig)
    results["vigenere_mod29_warm"] = res_vig

    # 2. Gematria Primus Arithmetic & Totient
    def bench_gematria():
        s = agrippa.gematria_prime_sum(sample_rune_page)
        agrippa.euler_totient(sample_num)
        agrippa.is_prime(sample_num)
        agrippa.prime_factors(sample_num)
        return s

    res_gem_cold = time_callable(
        bench_gematria,
        trials=trials,
        clear_cache_fn=clear_agrippa_caches,
        record_raw=should_record_raw,
        component_name="gematria_sacred_math_cold"
    )
    _collect("gematria_sacred_math_cold", res_gem_cold)
    results["gematria_sacred_math_cold"] = res_gem_cold

    res_gem_warm = time_callable(
        bench_gematria,
        trials=trials,
        record_raw=should_record_raw,
        component_name="gematria_sacred_math_warm"
    )
    _collect("gematria_sacred_math_warm", res_gem_warm)
    results["gematria_sacred_math_warm"] = res_gem_warm

    # 3. Shannon Entropy & Signal Features
    sample_text = sample_rune_page * 10
    def bench_entropy():
        entropy.extract_signal_features(sample_text)

    res_ent = time_callable(
        bench_entropy,
        trials=trials,
        record_raw=should_record_raw,
        component_name="entropy_features"
    )
    _collect("entropy_features", res_ent)
    results["entropy_features"] = res_ent

    # 4. BM25 Retrieval
    bench_query = "sacred primes loss of innocence"
    if ask is not None:
        def bench_bm25():
            ask.bm25_retrieve(bench_query, k=5)
        res_bm25 = time_callable(bench_bm25, trials=min(trials, 25), record_raw=should_record_raw, component_name="bm25_retrieval")
        _collect("bm25_retrieval", res_bm25)
        results["bm25_retrieval"] = res_bm25
    else:
        results["bm25_retrieval"] = {"p50_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0, "mean_ms": 0.0, "sample_stdev_ms": 0.0, "skipped": True}

    # 5. ChromaDB Vector Query (if active)
    if not skip_vector and ask is not None:
        try:
            coll = ask.get_collection()
            if coll and coll.count() > 0:
                def bench_vector():
                    ask.retrieve(coll, bench_query, k=5)
                res_vec = time_callable(bench_vector, trials=min(trials, 15), record_raw=should_record_raw, component_name="vector_retrieval")
                _collect("vector_retrieval", res_vec)
                results["vector_retrieval"] = res_vec
            else:
                results["vector_retrieval"] = {"p50_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0, "mean_ms": 0.0, "sample_stdev_ms": 0.0, "skipped": True}
        except Exception as e:
            results["vector_retrieval"] = {"p50_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0, "mean_ms": 0.0, "sample_stdev_ms": 0.0, "error": str(e)}
    else:
        results["vector_retrieval"] = {"p50_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0, "mean_ms": 0.0, "sample_stdev_ms": 0.0, "skipped": True}

    # 6. Micro-benchmark: Pair-table build
    sample_indices = [i % 29 for i in range(120)]
    def bench_pair_table():
        taxonomy.compute_t_table(sample_indices, period=8)
    res_pair = time_callable(bench_pair_table, trials=trials, record_raw=should_record_raw, component_name="pair_table_build")
    _collect("pair_table_build", res_pair)
    results["pair_table_build"] = res_pair

    # 7. Micro-benchmark: Sliding-window entropy
    large_buf = (sample_rune_page * 350)[:100_000]
    def bench_sliding():
        entropy.sliding_window_entropy(large_buf, window_size=256, step=64)
    res_sliding = time_callable(bench_sliding, trials=min(trials, 20), warmup=1, record_raw=should_record_raw, component_name="entropy_sliding_1mb")
    _collect("entropy_sliding_1mb", res_sliding)
    results["entropy_sliding_1mb"] = res_sliding

    # 8. Mandatory Baselines: Accelerated vs Pure-Python Reference
    baseline_comp = run_baseline_comparison(trials=trials, record_raw=should_record_raw)
    results["baseline_pure_python"] = baseline_comp["pure_python_reference"]
    results["baseline_accelerated"] = baseline_comp["accelerated"]
    results["baseline_comparison"] = baseline_comp
    if should_record_raw:
        if "raw_trials" in baseline_comp["pure_python_reference"]:
            all_raw_records.extend(baseline_comp["pure_python_reference"]["raw_trials"])
        if "raw_trials" in baseline_comp["accelerated"]:
            all_raw_records.extend(baseline_comp["accelerated"]["raw_trials"])

    # Attach global meta
    results["trials"] = trials
    results["underpowered"] = underpowered_flag
    if should_record_raw:
        results["raw_trials"] = all_raw_records

    if export_csv:
        export_raw_trials_csv(all_raw_records, export_csv)
    if export_json:
        export_summary_json(results, export_json)

    return results


def save_history_entry(results: Dict[str, Any]):
    """Append benchmark run to vectordb/bench_history.jsonl."""
    entry = {
        "timestamp": time.time(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "results": {k: v for k, v in results.items() if k != "raw_trials"},
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
        "results": {k: v for k, v in results.items() if k != "raw_trials"},
    }
    with open(baselines_file, "w", encoding="utf-8") as f:
        json.dump(baselines, f, indent=2)


def print_telemetry_table(
    results: Dict[str, Any],
    baseline_results: Optional[Dict[str, Any]] = None,
    baseline_name: Optional[str] = None
):
    """Print formatted terminal comparison table."""
    print("\n+--- [TRITHEMIUS PERFORMANCE BENCHMARK] ---------------------------------------------+")
    print(f"| {'Benchmark Component':<36} | {'Mean (ms)':<9} | {'p50 (ms)':<9} | {'95% CI (ms)':<16} |" + (f" {'Delta':<10} |" if baseline_results else ""))
    print("+--------------------------------------+-----------+-----------+------------------+" + ("------------+" if baseline_results else ""))

    for key, data in results.items():
        if not isinstance(data, dict):
            continue
        if data.get("skipped"):
            val_str = f"| {key:<36} | {'SKIPPED':<9} | {'-':<9} | {'-':<16} |"
            if baseline_results:
                val_str += f" {'-':<10} |"
            print(val_str)
            continue

        mean_v = data.get("mean_ms", 0.0)
        p50 = data.get("p50_ms", 0.0)
        ci = data.get("ci_95", (0.0, 0.0))
        ci_str = f"[{ci[0]:.2f}, {ci[1]:.2f}]"

        delta_str = ""
        if baseline_results and key in baseline_results and not baseline_results[key].get("skipped"):
            base_p50 = baseline_results[key].get("p50_ms", 0.0)
            if base_p50 > 0:
                pct = ((p50 - base_p50) / base_p50) * 100.0
                sign = "+" if pct > 0 else ""
                delta_str = f" {sign}{pct:5.1f}%    |"

        row = f"| {key:<36} | {mean_v:9.4f} | {p50:9.4f} | {ci_str:<16} |" + delta_str
        print(row)

    print("+--------------------------------------+-----------+-----------+------------------+" + ("------------+" if baseline_results else ""))
    if results.get("underpowered"):
        print("  [!] WARNING: Benchmark run is UNDERPOWERED (trials < 100). Minimum n>=100 required for statistical rigor.")
    if "baseline_comparison" in results:
        comp = results["baseline_comparison"]
        speedup = comp.get("speedup", 1.0)
        acc_type = comp.get("accelerator_type", "reference")
        print(f"  * Mandatory Baseline: pure-Python ref vs {acc_type} -> Speedup: {speedup:.2f}x")
    if baseline_name:
        print(f"  * Compared against baseline: '{baseline_name}' (negative delta = faster)")
    print("")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Trithemius Benchmarking & Profiling Harness")
    parser.add_argument("--trials", type=int, default=100, help="Number of trials per benchmark (default: 100)")
    parser.add_argument("--profile", action="store_true", help="Run cProfile hotspot profiling")
    parser.add_argument("--save-baseline", type=str, default=None, help="Save run as tagged baseline name")
    parser.add_argument("--compare", type=str, default=None, help="Compare results against a saved baseline")
    parser.add_argument("--skip-vector", action="store_true", help="Skip ChromaDB vector query benchmark")
    parser.add_argument("--llm", action="store_true", help="Include LLM time-to-first-token benchmark")
    parser.add_argument("--csv", type=str, default=None, help="Export raw per-trial metrics to CSV")
    parser.add_argument("--json", type=str, default=None, help="Export benchmark summary to JSON")
    args = parser.parse_args()

    if args.profile:
        print("[*] Running cProfile instrumentation pass...")
        pr = cProfile.Profile()
        pr.enable()
        run_benchmark(skip_vector=args.skip_vector, include_llm=args.llm, trials=args.trials)
        pr.disable()
        pr.dump_stats(PROFILE_PSTATS)
        print(f"[+] Saved cProfile stats to: {PROFILE_PSTATS}")
        print("\n=== Top 20 Hotspots by Cumulative Time ===")
        ps = pstats.Stats(pr).sort_stats(pstats.SortKey.CUMULATIVE)
        ps.print_stats(20)
        return

    print(f"[*] Running DEE-RSA compliant benchmark suite (trials={args.trials})...")
    results = run_benchmark(
        skip_vector=args.skip_vector,
        include_llm=args.llm,
        trials=args.trials,
        export_csv=args.csv,
        export_json=args.json
    )
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
