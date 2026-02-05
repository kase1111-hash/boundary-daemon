"""
Policy Engine Performance Benchmarks

Measures:
- Policy evaluation latency across different modes
- Mode transition overhead
- Callback dispatch performance
- Concurrent policy evaluation
"""

import time
import statistics
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Dict, Any

from daemon.policy_engine import (
    PolicyEngine, BoundaryMode, PolicyRequest, MemoryClass,
    PolicyDecision, Operator
)
from daemon.state_monitor import (
    NetworkState, NetworkType, HardwareTrust, EnvironmentState,
    SpecialtyNetworkStatus
)
from datetime import datetime


def create_test_env_state(network: NetworkState = NetworkState.OFFLINE) -> EnvironmentState:
    """Create a test environment state with all required fields."""
    return EnvironmentState(
        timestamp=datetime.utcnow().isoformat() + "Z",
        network=network,
        hardware_trust=HardwareTrust.MEDIUM,
        active_interfaces=[],
        interface_types={},
        has_internet=network == NetworkState.ONLINE,
        vpn_active=False,
        dns_available=True,
        specialty_networks=SpecialtyNetworkStatus(
            lora_devices=[],
            thread_devices=[],
            wimax_interfaces=[],
            irda_devices=[],
            ant_plus_devices=[],
            cellular_alerts=[]
        ),
        dns_security_alerts=[],
        arp_security_alerts=[],
        wifi_security_alerts=[],
        threat_intel_alerts=[],
        file_integrity_alerts=[],
        traffic_anomaly_alerts=[],
        process_security_alerts=[],
        usb_devices=set(),
        block_devices=set(),
        camera_available=False,
        mic_available=False,
        tpm_present=False,
        external_model_endpoints=[],
        suspicious_processes=[],
        shell_escapes_detected=0,
        keyboard_active=True,
        screen_unlocked=True,
        last_activity=None
    )


class PolicyEngineBenchmarks:
    """Benchmarks for the PolicyEngine component."""

    def __init__(self, iterations: int = 10000):
        self.iterations = iterations
        self.results: Dict[str, Dict[str, Any]] = {}

    def bench_policy_evaluation_simple(self) -> Dict[str, Any]:
        """Benchmark simple policy evaluation (memory recall)."""
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
        env_state = create_test_env_state()

        request = PolicyRequest(
            request_type='recall',
            memory_class=MemoryClass.PUBLIC,
            requires_network=False,
            requires_filesystem=False
        )

        times = []
        for _ in range(self.iterations):
            start = time.perf_counter_ns()
            engine.evaluate_policy(request, env_state)
            end = time.perf_counter_ns()
            times.append(end - start)

        engine.cleanup()
        return self._compute_stats("policy_eval_simple", times)

    def bench_policy_evaluation_complex(self) -> Dict[str, Any]:
        """Benchmark complex policy evaluation (tool with network)."""
        engine = PolicyEngine(initial_mode=BoundaryMode.RESTRICTED)
        env_state = create_test_env_state(NetworkState.ONLINE)

        request = PolicyRequest(
            request_type='tool',
            tool_name='shell_execute',
            requires_network=True,
            requires_filesystem=True,
            requires_usb=False
        )

        times = []
        for _ in range(self.iterations):
            start = time.perf_counter_ns()
            engine.evaluate_policy(request, env_state)
            end = time.perf_counter_ns()
            times.append(end - start)

        engine.cleanup()
        return self._compute_stats("policy_eval_complex", times)

    def bench_policy_evaluation_all_modes(self) -> Dict[str, Any]:
        """Benchmark policy evaluation across all boundary modes."""
        env_state = create_test_env_state()
        request = PolicyRequest(
            request_type='recall',
            memory_class=MemoryClass.CONFIDENTIAL,
            requires_network=False,
            requires_filesystem=True
        )

        all_times = []
        for mode in BoundaryMode:
            engine = PolicyEngine(initial_mode=mode)
            for _ in range(self.iterations // len(BoundaryMode)):
                start = time.perf_counter_ns()
                engine.evaluate_policy(request, env_state)
                end = time.perf_counter_ns()
                all_times.append(end - start)
            engine.cleanup()

        return self._compute_stats("policy_eval_all_modes", all_times)

    def bench_mode_transition(self) -> Dict[str, Any]:
        """Benchmark mode transitions."""
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)

        # Cycle through modes
        modes = [BoundaryMode.RESTRICTED, BoundaryMode.TRUSTED,
                 BoundaryMode.AIRGAP, BoundaryMode.COLDROOM,
                 BoundaryMode.OPEN]

        times = []
        for i in range(self.iterations):
            target_mode = modes[i % len(modes)]
            start = time.perf_counter_ns()
            engine.transition_mode(target_mode, Operator.SYSTEM, "benchmark")
            end = time.perf_counter_ns()
            times.append(end - start)

        engine.cleanup()
        return self._compute_stats("mode_transition", times)

    def bench_mode_transition_with_callbacks(self) -> Dict[str, Any]:
        """Benchmark mode transitions with registered callbacks."""
        engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)

        # Register 10 callbacks (realistic scenario)
        callback_ids = []
        for _ in range(10):
            def callback(old, new, op, reason):
                pass  # Minimal callback
            callback_ids.append(engine.register_transition_callback(callback))

        modes = [BoundaryMode.RESTRICTED, BoundaryMode.TRUSTED, BoundaryMode.OPEN]

        times = []
        for i in range(self.iterations):
            target_mode = modes[i % len(modes)]
            start = time.perf_counter_ns()
            engine.transition_mode(target_mode, Operator.SYSTEM, "benchmark")
            end = time.perf_counter_ns()
            times.append(end - start)

        # Cleanup
        for cid in callback_ids:
            engine.unregister_transition_callback(cid)
        engine.cleanup()

        return self._compute_stats("mode_transition_callbacks", times)

    def bench_concurrent_evaluation(self) -> Dict[str, Any]:
        """Benchmark concurrent policy evaluations."""
        engine = PolicyEngine(initial_mode=BoundaryMode.RESTRICTED)
        env_state = create_test_env_state()

        requests = [
            PolicyRequest(request_type='recall', memory_class=MemoryClass.PUBLIC),
            PolicyRequest(request_type='recall', memory_class=MemoryClass.CONFIDENTIAL),
            PolicyRequest(request_type='tool', tool_name='read', requires_filesystem=True),
            PolicyRequest(request_type='tool', tool_name='network', requires_network=True),
        ]

        def evaluate_batch():
            start = time.perf_counter_ns()
            for req in requests:
                engine.evaluate_policy(req, env_state)
            return time.perf_counter_ns() - start

        times = []
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(evaluate_batch)
                       for _ in range(self.iterations // 4)]
            times = [f.result() for f in futures]

        engine.cleanup()
        return self._compute_stats("concurrent_evaluation", times)

    def bench_state_retrieval(self) -> Dict[str, Any]:
        """Benchmark state retrieval operations."""
        engine = PolicyEngine(initial_mode=BoundaryMode.RESTRICTED)

        times = []
        for _ in range(self.iterations):
            start = time.perf_counter_ns()
            engine.get_current_state()
            engine.get_current_mode()
            end = time.perf_counter_ns()
            times.append(end - start)

        engine.cleanup()
        return self._compute_stats("state_retrieval", times)

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
        print(f"\nRunning Policy Engine Benchmarks ({self.iterations} iterations each)...")
        print("-" * 60)

        benchmarks = [
            ("Simple policy evaluation", self.bench_policy_evaluation_simple),
            ("Complex policy evaluation", self.bench_policy_evaluation_complex),
            ("Policy eval (all modes)", self.bench_policy_evaluation_all_modes),
            ("Mode transition", self.bench_mode_transition),
            ("Mode transition (with callbacks)", self.bench_mode_transition_with_callbacks),
            ("Concurrent evaluation", self.bench_concurrent_evaluation),
            ("State retrieval", self.bench_state_retrieval),
        ]

        for desc, bench_func in benchmarks:
            print(f"  {desc}...", end=" ", flush=True)
            result = bench_func()
            print(f"{result['mean_us']:.2f} µs (p99: {result['p99_us']:.2f} µs)")

        return self.results


if __name__ == "__main__":
    bench = PolicyEngineBenchmarks(iterations=10000)
    bench.run_all()
