"""
Event Logger Performance Benchmarks

Measures:
- Event logging throughput
- Hash chain computation overhead
- Log verification performance
- Concurrent logging behavior
"""

import os
import time
import tempfile
import shutil
import statistics
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

from daemon.event_logger import EventLogger, EventType


class EventLoggerBenchmarks:
    """Benchmarks for the EventLogger component."""

    def __init__(self, iterations: int = 5000):
        self.iterations = iterations
        self.results: Dict[str, Dict[str, Any]] = {}
        self._temp_dir = None

    def setup(self):
        """Create temporary directory for benchmark logs."""
        self._temp_dir = tempfile.mkdtemp(prefix="bench_eventlog_")

    def teardown(self):
        """Clean up temporary directory."""
        if self._temp_dir and os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)

    def _get_log_path(self, name: str) -> str:
        """Get a unique log file path for a benchmark."""
        return os.path.join(self._temp_dir, f"{name}_{time.time_ns()}.log")

    def bench_log_event_simple(self) -> Dict[str, Any]:
        """Benchmark simple event logging."""
        log_path = self._get_log_path("simple")
        logger = EventLogger(log_path, secure_permissions=False)

        times = []
        for i in range(self.iterations):
            start = time.perf_counter_ns()
            logger.log_event(
                EventType.INFO,
                f"Benchmark event {i}",
                {"iteration": i}
            )
            end = time.perf_counter_ns()
            times.append(end - start)

        return self._compute_stats("log_event_simple", times)

    def bench_log_event_complex_metadata(self) -> Dict[str, Any]:
        """Benchmark event logging with complex metadata."""
        log_path = self._get_log_path("complex")
        logger = EventLogger(log_path, secure_permissions=False)

        complex_metadata = {
            "user": "benchmark_user",
            "action": "policy_evaluation",
            "context": {
                "mode": "restricted",
                "network": "online",
                "hardware_trust": "medium"
            },
            "tags": ["benchmark", "performance", "test"],
            "metrics": {
                "cpu_percent": 45.2,
                "memory_mb": 512,
                "disk_io_ops": 1234
            }
        }

        times = []
        for i in range(self.iterations):
            metadata = {**complex_metadata, "iteration": i}
            start = time.perf_counter_ns()
            logger.log_event(
                EventType.POLICY_DECISION,
                "Complex policy decision with detailed context",
                metadata
            )
            end = time.perf_counter_ns()
            times.append(end - start)

        return self._compute_stats("log_event_complex", times)

    def bench_log_event_all_types(self) -> Dict[str, Any]:
        """Benchmark logging different event types."""
        log_path = self._get_log_path("alltypes")
        logger = EventLogger(log_path, secure_permissions=False)

        event_types = list(EventType)

        times = []
        for i in range(self.iterations):
            event_type = event_types[i % len(event_types)]
            start = time.perf_counter_ns()
            logger.log_event(
                event_type,
                f"Event of type {event_type.value}",
                {"iteration": i, "type": event_type.value}
            )
            end = time.perf_counter_ns()
            times.append(end - start)

        return self._compute_stats("log_event_all_types", times)

    def bench_hash_chain_verification(self) -> Dict[str, Any]:
        """Benchmark hash chain verification."""
        log_path = self._get_log_path("verify")
        logger = EventLogger(log_path, secure_permissions=False)

        # Create a log with events to verify
        for i in range(100):
            logger.log_event(EventType.INFO, f"Event {i}", {"i": i})

        times = []
        for _ in range(self.iterations // 10):  # Fewer iterations since verification is slower
            start = time.perf_counter_ns()
            logger.verify_chain()
            end = time.perf_counter_ns()
            times.append(end - start)

        return self._compute_stats("hash_chain_verify", times)

    def bench_concurrent_logging(self) -> Dict[str, Any]:
        """Benchmark concurrent event logging from multiple threads."""
        log_path = self._get_log_path("concurrent")
        logger = EventLogger(log_path, secure_permissions=False)

        def log_batch(batch_id: int, count: int) -> int:
            """Log a batch of events and return total time in ns."""
            total_time = 0
            for i in range(count):
                start = time.perf_counter_ns()
                logger.log_event(
                    EventType.INFO,
                    f"Concurrent event {batch_id}-{i}",
                    {"batch": batch_id, "item": i}
                )
                total_time += time.perf_counter_ns() - start
            return total_time

        num_threads = 8
        events_per_thread = self.iterations // num_threads

        times = []
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [
                executor.submit(log_batch, t, events_per_thread)
                for t in range(num_threads)
            ]
            # Collect total times per thread
            thread_times = [f.result() for f in futures]
            # Average time per event
            total_events = num_threads * events_per_thread
            avg_time = sum(thread_times) / total_events
            times = [avg_time] * total_events  # Approximate distribution

        return self._compute_stats("concurrent_logging", times)

    def bench_log_rotation_ready(self) -> Dict[str, Any]:
        """Benchmark checking if log rotation is needed."""
        log_path = self._get_log_path("rotation")
        logger = EventLogger(log_path, secure_permissions=False)

        # Add some events
        for i in range(100):
            logger.log_event(EventType.INFO, f"Event {i}", {})

        times = []
        for _ in range(self.iterations):
            start = time.perf_counter_ns()
            # Check file size (common rotation check)
            if os.path.exists(log_path):
                os.path.getsize(log_path)
            end = time.perf_counter_ns()
            times.append(end - start)

        return self._compute_stats("rotation_check", times)

    def bench_event_retrieval(self) -> Dict[str, Any]:
        """Benchmark retrieving recent events."""
        log_path = self._get_log_path("retrieve")
        logger = EventLogger(log_path, secure_permissions=False)

        # Populate with events
        for i in range(500):
            logger.log_event(EventType.INFO, f"Event {i}", {"i": i})

        times = []
        for _ in range(self.iterations // 10):
            start = time.perf_counter_ns()
            logger.get_recent_events(count=50)
            end = time.perf_counter_ns()
            times.append(end - start)

        return self._compute_stats("event_retrieval", times)

    def bench_throughput(self) -> Dict[str, Any]:
        """Measure maximum logging throughput (events/second)."""
        log_path = self._get_log_path("throughput")
        logger = EventLogger(log_path, secure_permissions=False)

        # Warm up
        for i in range(100):
            logger.log_event(EventType.INFO, f"Warmup {i}", {})

        # Measure throughput
        count = self.iterations
        start = time.perf_counter()
        for i in range(count):
            logger.log_event(EventType.INFO, f"Throughput event {i}", {"i": i})
        elapsed = time.perf_counter() - start

        throughput = count / elapsed

        result = {
            "name": "throughput",
            "iterations": count,
            "total_time_sec": elapsed,
            "events_per_sec": throughput,
            "mean_us": (elapsed / count) * 1_000_000,
            "median_us": 0,
            "stdev_us": 0,
            "min_us": 0,
            "max_us": 0,
            "p95_us": 0,
            "p99_us": 0,
            "ops_per_sec": throughput,
        }
        self.results["throughput"] = result
        return result

    def _compute_stats(self, name: str, times_ns: List[int]) -> Dict[str, Any]:
        """Compute statistics from timing measurements."""
        times_us = [t / 1000 for t in times_ns]  # Convert to microseconds

        stats = {
            "name": name,
            "iterations": len(times_us),
            "mean_us": statistics.mean(times_us),
            "median_us": statistics.median(times_us),
            "stdev_us": statistics.stdev(times_us) if len(times_us) > 1 else 0,
            "min_us": min(times_us),
            "max_us": max(times_us),
            "p95_us": sorted(times_us)[int(len(times_us) * 0.95)],
            "p99_us": sorted(times_us)[int(len(times_us) * 0.99)],
            "ops_per_sec": 1_000_000 / statistics.mean(times_us) if times_us else 0,
        }
        self.results[name] = stats
        return stats

    def run_all(self) -> Dict[str, Dict[str, Any]]:
        """Run all benchmarks and return results."""
        print(f"\nRunning Event Logger Benchmarks ({self.iterations} iterations each)...")
        print("-" * 60)

        self.setup()
        try:
            benchmarks = [
                ("Simple event logging", self.bench_log_event_simple),
                ("Complex metadata logging", self.bench_log_event_complex_metadata),
                ("All event types", self.bench_log_event_all_types),
                ("Hash chain verification", self.bench_hash_chain_verification),
                ("Concurrent logging", self.bench_concurrent_logging),
                ("Rotation check", self.bench_log_rotation_ready),
                ("Event retrieval", self.bench_event_retrieval),
                ("Throughput", self.bench_throughput),
            ]

            for desc, bench_func in benchmarks:
                print(f"  {desc}...", end=" ", flush=True)
                result = bench_func()
                if "events_per_sec" in result and result.get("total_time_sec"):
                    print(f"{result['events_per_sec']:.0f} events/sec")
                else:
                    print(f"{result['mean_us']:.2f} µs (p99: {result['p99_us']:.2f} µs)")

        finally:
            self.teardown()

        return self.results


if __name__ == "__main__":
    bench = EventLoggerBenchmarks(iterations=5000)
    bench.run_all()
