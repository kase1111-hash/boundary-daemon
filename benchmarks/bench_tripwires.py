"""
Tripwire System Performance Benchmarks

Measures:
- Violation check latency
- Callback dispatch overhead
- Baseline comparison performance
- Concurrent violation detection
"""

import time
import statistics
import tempfile
import shutil
import os
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

from daemon.tripwires import TripwireSystem, ViolationType
from daemon.policy_engine import BoundaryMode
from daemon.state_monitor import (
    NetworkState, HardwareTrust, EnvironmentState,
    SpecialtyNetworkStatus
)
from daemon.event_logger import EventLogger
from datetime import datetime


def create_test_env_state(
    network: NetworkState = NetworkState.OFFLINE,
    usb_devices: set = None
) -> EnvironmentState:
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
        usb_devices=usb_devices or set(),
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


class TripwireBenchmarks:
    """Benchmarks for the TripwireSystem component."""

    def __init__(self, iterations: int = 10000):
        self.iterations = iterations
        self.results: Dict[str, Dict[str, Any]] = {}
        self._temp_dir = None
        # Suppress auth token log message during benchmarks
        import logging
        logging.getLogger('daemon.tripwires').setLevel(logging.CRITICAL)

    def setup(self):
        """Create temporary directory for event logs."""
        self._temp_dir = tempfile.mkdtemp(prefix="bench_tripwire_")

    def teardown(self):
        """Clean up temporary directory."""
        if self._temp_dir and os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)

    def _get_event_logger(self, name: str) -> EventLogger:
        """Get an event logger for benchmarks."""
        log_path = os.path.join(self._temp_dir, f"{name}_{time.time_ns()}.log")
        return EventLogger(log_path, secure_permissions=False)

    def bench_check_violations_clean(self) -> Dict[str, Any]:
        """Benchmark violation check with no violations."""
        tripwire = TripwireSystem()
        env_state = create_test_env_state(NetworkState.OFFLINE)
        current_mode = BoundaryMode.OPEN

        times = []
        for _ in range(self.iterations):
            start = time.perf_counter_ns()
            tripwire.check_violations(current_mode, env_state)
            end = time.perf_counter_ns()
            times.append(end - start)

        return self._compute_stats("check_violations_clean", times)

    def bench_check_violations_airgap(self) -> Dict[str, Any]:
        """Benchmark violation check in airgap mode."""
        tripwire = TripwireSystem()
        env_state = create_test_env_state(NetworkState.OFFLINE)
        current_mode = BoundaryMode.AIRGAP

        times = []
        for _ in range(self.iterations):
            start = time.perf_counter_ns()
            tripwire.check_violations(current_mode, env_state)
            end = time.perf_counter_ns()
            times.append(end - start)

        return self._compute_stats("check_violations_airgap", times)

    def bench_check_with_usb_devices(self) -> Dict[str, Any]:
        """Benchmark violation check with USB devices present."""
        tripwire = TripwireSystem()
        usb_devices = {
            "/dev/sda1", "/dev/sda2", "/dev/sdb1",
            "/dev/usb0", "/dev/usb1"
        }
        env_state = create_test_env_state(NetworkState.OFFLINE, usb_devices)
        current_mode = BoundaryMode.TRUSTED

        # Set baseline
        tripwire._baseline_usb_devices = usb_devices.copy()

        times = []
        for _ in range(self.iterations):
            start = time.perf_counter_ns()
            tripwire.check_violations(current_mode, env_state)
            end = time.perf_counter_ns()
            times.append(end - start)

        return self._compute_stats("check_violations_usb", times)

    def bench_callback_registration(self) -> Dict[str, Any]:
        """Benchmark callback registration and unregistration."""
        tripwire = TripwireSystem()

        def dummy_callback(violation):
            pass

        times = []
        for _ in range(self.iterations):
            start = time.perf_counter_ns()
            callback_id = tripwire.register_callback(dummy_callback)
            tripwire.unregister_callback(callback_id)
            end = time.perf_counter_ns()
            times.append(end - start)

        return self._compute_stats("callback_reg_unreg", times)

    def bench_get_violations(self) -> Dict[str, Any]:
        """Benchmark retrieving violations list."""
        tripwire = TripwireSystem()

        times = []
        for _ in range(self.iterations):
            start = time.perf_counter_ns()
            tripwire.get_violations()
            end = time.perf_counter_ns()
            times.append(end - start)

        return self._compute_stats("get_violations", times)

    def bench_get_violation_count(self) -> Dict[str, Any]:
        """Benchmark getting violation count."""
        tripwire = TripwireSystem()

        times = []
        for _ in range(self.iterations):
            start = time.perf_counter_ns()
            tripwire.get_violation_count()
            end = time.perf_counter_ns()
            times.append(end - start)

        return self._compute_stats("get_violation_count", times)

    def bench_concurrent_checks(self) -> Dict[str, Any]:
        """Benchmark concurrent violation checks."""
        tripwire = TripwireSystem()
        env_state = create_test_env_state()
        current_mode = BoundaryMode.RESTRICTED

        def check_batch(count: int) -> List[int]:
            times = []
            for _ in range(count):
                start = time.perf_counter_ns()
                tripwire.check_violations(current_mode, env_state)
                times.append(time.perf_counter_ns() - start)
            return times

        num_threads = 8
        checks_per_thread = self.iterations // num_threads

        all_times = []
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(check_batch, checks_per_thread)
                       for _ in range(num_threads)]
            for f in futures:
                all_times.extend(f.result())

        return self._compute_stats("concurrent_checks", all_times)

    def bench_baseline_comparison(self) -> Dict[str, Any]:
        """Benchmark USB device baseline comparison."""
        tripwire = TripwireSystem()

        # Set a baseline with devices
        baseline_devices = {f"/dev/usb{i}" for i in range(10)}
        tripwire._baseline_usb_devices = baseline_devices.copy()

        # Test environment with same devices
        env_state = create_test_env_state(NetworkState.OFFLINE, baseline_devices)

        times = []
        for _ in range(self.iterations):
            start = time.perf_counter_ns()
            # This is the comparison logic (simulated)
            current = env_state.usb_devices
            added = current - tripwire._baseline_usb_devices
            removed = tripwire._baseline_usb_devices - current
            end = time.perf_counter_ns()
            times.append(end - start)

        return self._compute_stats("baseline_compare", times)

    def bench_security_status(self) -> Dict[str, Any]:
        """Benchmark getting security status."""
        tripwire = TripwireSystem()

        times = []
        for _ in range(self.iterations):
            start = time.perf_counter_ns()
            tripwire.get_security_status()
            end = time.perf_counter_ns()
            times.append(end - start)

        return self._compute_stats("security_status", times)

    def bench_is_enabled_check(self) -> Dict[str, Any]:
        """Benchmark checking if tripwire is enabled."""
        tripwire = TripwireSystem()

        times = []
        for _ in range(self.iterations):
            start = time.perf_counter_ns()
            _ = tripwire._enabled
            end = time.perf_counter_ns()
            times.append(end - start)

        return self._compute_stats("is_enabled_check", times)

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
        print(f"\nRunning Tripwire Benchmarks ({self.iterations} iterations each)...")
        print("-" * 60)

        self.setup()
        try:
            benchmarks = [
                ("Violation check (clean)", self.bench_check_violations_clean),
                ("Violation check (airgap)", self.bench_check_violations_airgap),
                ("Violation check (USB)", self.bench_check_with_usb_devices),
                ("Callback registration", self.bench_callback_registration),
                ("Get violations", self.bench_get_violations),
                ("Get violation count", self.bench_get_violation_count),
                ("Concurrent checks", self.bench_concurrent_checks),
                ("Baseline comparison", self.bench_baseline_comparison),
                ("Security status", self.bench_security_status),
                ("Is-enabled check", self.bench_is_enabled_check),
            ]

            for desc, bench_func in benchmarks:
                print(f"  {desc}...", end=" ", flush=True)
                result = bench_func()
                print(f"{result['mean_us']:.2f} µs (p99: {result['p99_us']:.2f} µs)")

        finally:
            self.teardown()

        return self.results


if __name__ == "__main__":
    bench = TripwireBenchmarks(iterations=10000)
    bench.run_all()
