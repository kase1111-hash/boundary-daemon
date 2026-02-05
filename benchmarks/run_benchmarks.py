#!/usr/bin/env python3
"""
Boundary Daemon Performance Benchmark Runner

Runs all performance benchmarks and generates a report.

Usage:
    python -m benchmarks.run_benchmarks [options]

Options:
    --quick         Run with fewer iterations (faster but less accurate)
    --full          Run with more iterations (slower but more accurate)
    --json          Output results as JSON
    --component X   Only run benchmarks for component X (policy, eventlog, tripwire)
    --save FILE     Save results to FILE
"""

import argparse
import json
import sys
import platform
import time
from datetime import datetime
from typing import Dict, Any, List

from benchmarks.bench_policy_engine import PolicyEngineBenchmarks
from benchmarks.bench_event_logger import EventLoggerBenchmarks
from benchmarks.bench_tripwires import TripwireBenchmarks


def get_system_info() -> Dict[str, str]:
    """Gather system information for the report."""
    return {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "processor": platform.processor() or "unknown",
        "machine": platform.machine(),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def print_header():
    """Print benchmark suite header."""
    print("=" * 70)
    print("  Boundary Daemon Performance Benchmarks")
    print("=" * 70)
    print()
    info = get_system_info()
    print(f"  Platform:       {info['platform']}")
    print(f"  Python:         {info['python_version']}")
    print(f"  Processor:      {info['processor']}")
    print(f"  Timestamp:      {info['timestamp']}")
    print()


def print_summary(all_results: Dict[str, Dict[str, Dict[str, Any]]]):
    """Print a summary of all benchmark results."""
    print()
    print("=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print()

    # Collect all metrics
    metrics = []
    for component, results in all_results.items():
        for name, stats in results.items():
            metrics.append({
                "component": component,
                "benchmark": name,
                "mean_us": stats["mean_us"],
                "p99_us": stats["p99_us"],
                "ops_per_sec": stats["ops_per_sec"],
            })

    # Sort by mean latency
    metrics.sort(key=lambda x: x["mean_us"])

    # Print table
    print(f"{'Component':<15} {'Benchmark':<30} {'Mean (µs)':<12} {'P99 (µs)':<12} {'Ops/sec':<12}")
    print("-" * 85)

    for m in metrics:
        print(f"{m['component']:<15} {m['benchmark']:<30} "
              f"{m['mean_us']:<12.2f} {m['p99_us']:<12.2f} {m['ops_per_sec']:<12,.0f}")

    print()

    # Performance thresholds check
    print("-" * 70)
    print("  PERFORMANCE THRESHOLDS")
    print("-" * 70)

    thresholds = {
        "policy_eval_simple": {"max_us": 50, "min_ops": 20000},
        "policy_eval_complex": {"max_us": 100, "min_ops": 10000},
        "log_event_simple": {"max_us": 5000, "min_ops": 200},  # fsync() after each write
        "check_violations_clean": {"max_us": 100, "min_ops": 10000},
    }

    all_passed = True
    for m in metrics:
        if m["benchmark"] in thresholds:
            thresh = thresholds[m["benchmark"]]
            passed_latency = m["mean_us"] <= thresh["max_us"]
            passed_ops = m["ops_per_sec"] >= thresh["min_ops"]

            status = "PASS" if (passed_latency and passed_ops) else "FAIL"
            if status == "FAIL":
                all_passed = False

            print(f"  {m['benchmark']:<30} "
                  f"Latency: {'OK' if passed_latency else 'SLOW'} ({m['mean_us']:.1f}/{thresh['max_us']} µs)  "
                  f"Throughput: {'OK' if passed_ops else 'LOW'} ({m['ops_per_sec']:.0f}/{thresh['min_ops']} ops/s)  "
                  f"[{status}]")

    print()
    if all_passed:
        print("  All performance thresholds PASSED")
    else:
        print("  WARNING: Some performance thresholds FAILED")
    print()


def run_all_benchmarks(
    iterations: int = 10000,
    components: List[str] = None
) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Run all benchmark suites and return combined results."""
    all_results = {}

    if components is None or "policy" in components:
        policy_bench = PolicyEngineBenchmarks(iterations=iterations)
        all_results["policy"] = policy_bench.run_all()

    if components is None or "eventlog" in components:
        eventlog_bench = EventLoggerBenchmarks(iterations=iterations // 2)
        all_results["eventlog"] = eventlog_bench.run_all()

    if components is None or "tripwire" in components:
        tripwire_bench = TripwireBenchmarks(iterations=iterations)
        all_results["tripwire"] = tripwire_bench.run_all()

    return all_results


def main():
    parser = argparse.ArgumentParser(
        description="Run Boundary Daemon performance benchmarks"
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="Run with fewer iterations (faster)"
    )
    parser.add_argument(
        "--full", action="store_true",
        help="Run with more iterations (more accurate)"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON"
    )
    parser.add_argument(
        "--component", type=str, action="append",
        choices=["policy", "eventlog", "tripwire"],
        help="Only run benchmarks for specific component(s)"
    )
    parser.add_argument(
        "--save", type=str, metavar="FILE",
        help="Save results to a JSON file"
    )

    args = parser.parse_args()

    # Determine iteration count
    if args.quick:
        iterations = 1000
    elif args.full:
        iterations = 50000
    else:
        iterations = 10000

    # Run benchmarks
    if not args.json:
        print_header()

    start_time = time.time()
    results = run_all_benchmarks(
        iterations=iterations,
        components=args.component
    )
    elapsed = time.time() - start_time

    # Output results
    if args.json:
        output = {
            "system": get_system_info(),
            "config": {
                "iterations": iterations,
                "components": args.component or ["all"],
            },
            "elapsed_seconds": elapsed,
            "results": results,
        }
        print(json.dumps(output, indent=2))
    else:
        print_summary(results)
        print(f"  Total benchmark time: {elapsed:.1f}s")
        print()

    # Save to file if requested
    if args.save:
        output = {
            "system": get_system_info(),
            "config": {
                "iterations": iterations,
                "components": args.component or ["all"],
            },
            "elapsed_seconds": elapsed,
            "results": results,
        }
        with open(args.save, 'w') as f:
            json.dumps(output, f, indent=2)
        if not args.json:
            print(f"  Results saved to: {args.save}")
            print()


if __name__ == "__main__":
    main()
