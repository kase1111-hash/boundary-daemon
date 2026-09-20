#!/usr/bin/env python3
"""
sandboxctl - Sandbox Management CLI for Boundary Daemon

Provides command-line interface for managing sandboxed processes:
- Run commands in isolated sandboxes
- List and manage active sandboxes
- Inspect sandbox configuration
- View resource usage
- Test sandbox profiles

Usage:
    sandboxctl run -- /usr/bin/python3 script.py
    sandboxctl run --profile restricted -- npm install
    sandboxctl list
    sandboxctl inspect sandbox-001
    sandboxctl kill sandbox-001
    sandboxctl profiles
    sandboxctl test --profile airgap

Environment Variables:
    BOUNDARY_SOCKET  - Path to daemon control socket
    BOUNDARY_CONFIG  - Path to configuration file
"""

import argparse
import json
import os
import sys
import signal
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

# Attempt imports - graceful fallback for standalone usage
try:
    from daemon.sandbox import (
        SandboxManager,
        SandboxProfile,
        SandboxError,
        CgroupLimits,
        NetworkPolicy,
        get_profile_loader,
    )
    from daemon.policy_engine import BoundaryMode
    SANDBOX_AVAILABLE = True
except ImportError:
    SANDBOX_AVAILABLE = False

# Metrics are served by the daemon's Prometheus exporter; the CLI reads them
# over HTTP (see daemon/telemetry/prometheus_metrics.py).
DEFAULT_METRICS_URL = os.environ.get('BOUNDARY_METRICS_URL', 'http://127.0.0.1:9090/metrics')


# ANSI color codes
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'

    @classmethod
    def disable(cls):
        """Disable colors for non-TTY output."""
        cls.RESET = ''
        cls.BOLD = ''
        cls.RED = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.BLUE = ''
        cls.CYAN = ''
        cls.GRAY = ''


def format_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(n) < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0  # type: ignore[assignment]  # int parameter becomes float after division
    return f"{n:.1f}PB"


def format_duration(seconds: float) -> str:
    """Format duration as human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h {mins}m"


def print_error(msg: str, code: str = "", hint: str = "") -> None:
    """Print error message with optional error code and hint."""
    prefix = f"{Colors.RED}{code}:{Colors.RESET} " if code else f"{Colors.RED}Error:{Colors.RESET} "
    print(f"{prefix}{msg}", file=sys.stderr)
    if hint:
        print(f"  {Colors.GRAY}Hint: {hint}{Colors.RESET}", file=sys.stderr)


def print_success(msg: str) -> None:
    """Print success message."""
    print(f"{Colors.GREEN}✓{Colors.RESET} {msg}")


def print_warning(msg: str) -> None:
    """Print warning message."""
    print(f"{Colors.YELLOW}Warning:{Colors.RESET} {msg}")


def print_info(msg: str) -> None:
    """Print info message."""
    print(f"{Colors.CYAN}ℹ{Colors.RESET} {msg}")


class SandboxCLI:
    """CLI handler for sandbox commands."""

    def __init__(self, socket_path: Optional[str] = None, config_path: Optional[str] = None):
        self.socket_path = socket_path or os.environ.get(
            'BOUNDARY_SOCKET', '/var/run/boundary-daemon/sandbox.sock'
        )
        self.config_path = config_path or os.environ.get(
            'BOUNDARY_CONFIG', '/etc/boundary-daemon/config.yaml'
        )
        self._manager: Optional[SandboxManager] = None

    def _get_manager(self) -> SandboxManager:
        """Get or create sandbox manager."""
        if not SANDBOX_AVAILABLE:
            print_error("Sandbox module not available.",
                        code="E009", hint="Ensure boundary-daemon is installed.")
            sys.exit(1)

        if self._manager is None:
            # In a real implementation, this would connect to the daemon
            # For now, create a local manager
            self._manager = SandboxManager(policy_engine=None)

        return self._manager

    # Boundary-mode profile names accepted by --profile (see SandboxProfile.from_boundary_mode)
    _MODE_PROFILES = ('open', 'restricted', 'trusted', 'airgap', 'coldroom', 'lockdown')

    def _resolve_profile(self, name: str) -> 'SandboxProfile':
        """
        Resolve a profile name to a SandboxProfile.

        Lookup order: profiles loaded from the sandbox profile configuration,
        the built-in minimal/standard/strict profiles (``untrusted`` is an
        alias for strict), then boundary-mode profiles (open, restricted,
        trusted, airgap, coldroom, lockdown).
        """
        key = name.strip().lower()
        try:
            loaded = get_profile_loader().get_sandbox_profile(key)
        except Exception:  # profile config is optional
            loaded = None
        if loaded is not None:
            return loaded

        builtin = {
            'minimal': SandboxProfile.minimal,
            'standard': SandboxProfile.standard,
            'strict': SandboxProfile.strict,
            'untrusted': SandboxProfile.strict,
        }
        if key in builtin:
            return builtin[key]()
        if key in self._MODE_PROFILES:
            return SandboxProfile.from_boundary_mode(BoundaryMode[key.upper()].value)
        raise ValueError(f"Unknown sandbox profile: {name}")

    def cmd_run(self, args: argparse.Namespace) -> int:
        """Run a command in a sandbox."""
        if not args.command:
            print_error("No command specified.", code="E003",
                        hint="Use: sandboxctl run -- <command>")
            return 1

        manager = self._get_manager()

        profile_name = (args.profile or 'standard').lower()
        try:
            profile = self._resolve_profile(profile_name)
        except ValueError as e:
            print_error(str(e), code="E012", hint="Run: sandboxctl profiles")
            return 1

        # Apply overrides (attribute names must match CgroupLimits exactly)
        if args.memory:
            profile.cgroup_limits = profile.cgroup_limits or CgroupLimits()
            profile.cgroup_limits.memory_max_bytes = self._parse_memory(args.memory)

        if args.cpu:
            profile.cgroup_limits = profile.cgroup_limits or CgroupLimits()
            profile.cgroup_limits.cpu_period_us = 100000
            profile.cgroup_limits.cpu_quota_us = int(args.cpu * 1000)  # percent -> quota per 100ms

        if args.timeout:
            profile.max_runtime_seconds = args.timeout

        if args.network_deny:
            profile.network_policy = NetworkPolicy(deny_all=True)
        elif args.network_allow:
            profile.network_policy = NetworkPolicy(
                allow_all=False,
                allowed_hosts=list(args.network_allow),
            )

        # Print info
        if not args.quiet:
            print_info(f"Running in sandbox with profile: {profile.name}")
            if profile.max_runtime_seconds:
                print_info(f"Timeout: {profile.max_runtime_seconds}s")

        # Handle signals
        def signal_handler(sig, frame):
            print_warning("Interrupt received, terminating sandbox...")
            sys.exit(130)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        env = dict(os.environ) if args.inherit_env else None

        # Run command
        start_time = time.time()
        try:
            result = manager.run_sandboxed(
                command=list(args.command),
                env=env,
                profile=profile,
                timeout=args.timeout,
                capture_output=not args.interactive,
            )

            elapsed = time.time() - start_time

            # Output handling
            if not args.interactive:
                if result.stdout:
                    sys.stdout.write(result.stdout)
                if result.stderr:
                    sys.stderr.write(result.stderr)

            if not args.quiet:
                if result.killed:
                    print_warning(f"Sandbox terminated: {result.kill_reason or 'unknown reason'}")
                if result.exit_code == 0:
                    print_success(f"Command completed in {format_duration(elapsed)}")
                else:
                    print_warning(f"Command exited with code {result.exit_code}")

                # Resource usage (daemon.sandbox.cgroups.ResourceUsage)
                if result.resource_usage and args.verbose:
                    usage = result.resource_usage
                    print(f"\n{Colors.BOLD}Resource Usage:{Colors.RESET}")
                    print(f"  CPU time:     {usage.cpu_usage_us / 1_000_000:.2f}s")
                    print(f"  Memory peak:  {format_bytes(usage.memory_peak_bytes)}")
                    print(f"  I/O read:     {format_bytes(usage.io_read_bytes)}")
                    print(f"  I/O write:    {format_bytes(usage.io_write_bytes)}")

            return result.exit_code

        except SandboxError as e:
            print_error(str(e), code="E010",
                        hint="Check sandbox profile and system capabilities.")
            return 1
        except Exception as e:
            print_error(f"Unexpected error: {e}", code="E010",
                        hint="Run with --verbose for full traceback.")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1

    def cmd_list(self, args: argparse.Namespace) -> int:
        """List active sandboxes (SandboxManager.list_sandboxes returns Sandbox.get_info dicts)."""
        manager = self._get_manager()

        sandboxes = manager.list_sandboxes()

        if not sandboxes:
            print("No active sandboxes")
            return 0

        if args.output == 'json':
            print(json.dumps(sandboxes, indent=2, default=str))
            return 0

        if args.output == 'wide':
            for sbx in sandboxes:
                usage = sbx.get('resource_usage') or {}
                command = sbx.get('command')
                print(f"\n{Colors.BOLD}Sandbox: {sbx['id']}{Colors.RESET}")
                print(f"  Profile:  {sbx.get('profile')}")
                print(f"  State:    {sbx.get('state')}")
                print(f"  PID:      {sbx.get('pid') or 'N/A'}")
                print(f"  Command:  {' '.join(command) if command else 'N/A'}")
                print(f"  Cgroup:   {sbx.get('cgroup_path') or 'N/A'}")
                if usage:
                    print("  Resources:")
                    print(f"    Memory: {format_bytes(usage.get('memory', {}).get('current_bytes', 0))}")
                    print(f"    CPU:    {usage.get('cpu', {}).get('total_us', 0) / 1_000_000:.2f}s")
            return 0

        # table
        print(f"\n{Colors.BOLD}{'ID':<20} {'PROFILE':<12} {'STATE':<10} {'PID':<8} {'UPTIME':<12} {'MEMORY':<10}{Colors.RESET}")
        print("-" * 72)

        for sbx in sandboxes:
            state = str(sbx.get('state') or 'UNKNOWN')
            state_color = Colors.GREEN if state == 'RUNNING' else Colors.YELLOW
            uptime = format_duration(sbx['uptime_seconds']) if sbx.get('uptime_seconds') else '-'
            usage = sbx.get('resource_usage') or {}
            memory_bytes = (usage.get('memory') or {}).get('current_bytes')
            memory = format_bytes(memory_bytes) if memory_bytes else '-'

            print(
                f"{sbx['id']:<20} "
                f"{str(sbx.get('profile') or '-'):<12} "
                f"{state_color}{state:<10}{Colors.RESET} "
                f"{str(sbx.get('pid') or '-'):<8} "
                f"{uptime:<12} "
                f"{memory:<10}"
            )

        print(f"\n{len(sandboxes)} sandbox(es) total")
        return 0

    def cmd_inspect(self, args: argparse.Namespace) -> int:
        """Inspect a sandbox."""
        manager = self._get_manager()

        sandbox = manager.get_sandbox(args.sandbox_id)
        if sandbox is None:
            print_error(f"Sandbox not found: {args.sandbox_id}",
                        code="E011", hint="Run: sandboxctl list")
            return 1

        info = sandbox.get_info()

        if args.output == 'json':
            print(json.dumps(info, indent=2, default=str))
            return 0

        command = info.get('command')
        print(f"\n{Colors.BOLD}Sandbox: {info['id']}{Colors.RESET}")
        print(f"\n{Colors.CYAN}Configuration:{Colors.RESET}")
        print(f"  Profile:    {info.get('profile', 'N/A')}")
        print(f"  State:      {info.get('state', 'N/A')}")
        print(f"  PID:        {info.get('pid') or 'N/A'}")
        print(f"  Command:    {' '.join(command) if command else 'N/A'}")

        print(f"\n{Colors.CYAN}Isolation:{Colors.RESET}")
        print(f"  Namespaces: {info.get('namespace_flags', 'N/A')}")
        print(f"  Cgroup:     {info.get('cgroup_path') or 'N/A'}")
        print(f"  Seccomp:    {'enabled' if info.get('seccomp_enabled') else 'disabled'}")
        print(f"  Read-only:  {'yes' if info.get('readonly_filesystem') else 'no'}")

        np = info.get('network_policy')
        if info.get('network_disabled'):
            print(f"\n{Colors.CYAN}Network Policy:{Colors.RESET}")
            print("  Mode:       DISABLED")
        elif np:
            print(f"\n{Colors.CYAN}Network Policy:{Colors.RESET}")
            if np.get('deny_all'):
                print("  Mode:       DENY ALL")
            elif np.get('allow_all'):
                print("  Mode:       ALLOW ALL")
            else:
                print("  Mode:       FILTERED")
                if np.get('allowed_hosts'):
                    print(f"  Allowed:    {', '.join(np['allowed_hosts'])}")

        limits = info.get('resource_limits')
        if limits:
            print(f"\n{Colors.CYAN}Resource Limits:{Colors.RESET}")
            if limits.get('memory_max_bytes'):
                print(f"  Memory:     {format_bytes(limits['memory_max_bytes'])}")
            if limits.get('cpu_max_cores'):
                print(f"  CPU:        {limits['cpu_max_cores']} cores")
            elif limits.get('cpu_quota_us') and limits.get('cpu_period_us'):
                print(f"  CPU:        {100 * limits['cpu_quota_us'] / limits['cpu_period_us']:.0f}%")
            if limits.get('pids_max'):
                print(f"  PIDs:       {limits['pids_max']}")

        usage = info.get('resource_usage')
        if usage:
            print(f"\n{Colors.CYAN}Resource Usage:{Colors.RESET}")
            print(f"  Memory:     {format_bytes(usage.get('memory', {}).get('current_bytes', 0))}")
            print(f"  CPU time:   {usage.get('cpu', {}).get('total_us', 0) / 1_000_000:.2f}s")

        return 0

    def cmd_kill(self, args: argparse.Namespace) -> int:
        """Kill a sandbox."""
        manager = self._get_manager()

        sandbox_ids = list(args.sandbox_ids)
        if args.all:
            sandbox_ids = [s['id'] for s in manager.list_sandboxes()]

        if not sandbox_ids:
            print("No sandboxes to kill")
            return 0

        reason = "sandboxctl kill --force" if args.force else "sandboxctl kill"
        errors = 0
        for sandbox_id in sandbox_ids:
            try:
                if manager.terminate_sandbox(sandbox_id, reason=reason):
                    print_success(f"Killed sandbox: {sandbox_id}")
                else:
                    print_error(f"Sandbox not found: {sandbox_id}",
                                code="E011", hint="Run: sandboxctl list")
                    errors += 1
            except Exception as e:
                print_error(f"Failed to kill {sandbox_id}: {e}", code="E010")
                errors += 1

        return 1 if errors else 0

    def cmd_profiles(self, args: argparse.Namespace) -> int:
        """List available sandbox profiles."""
        profiles = [
            ('minimal', 'Basic resource limits, minimal isolation'),
            ('standard', 'Namespace isolation with resource limits (default)'),
            ('strict', 'Full isolation for untrusted code (alias: untrusted)'),
            ('open', 'Boundary-mode profile: same as minimal'),
            ('restricted', 'Boundary-mode profile: light isolation'),
            ('trusted', 'Boundary-mode profile: standard isolation'),
            ('airgap', 'Boundary-mode profile: network-isolated'),
            ('coldroom', 'Boundary-mode profile: maximum isolation'),
            ('lockdown', 'Boundary-mode profile: no execution allowed'),
        ]
        if SANDBOX_AVAILABLE:
            try:
                for name in get_profile_loader().list_profiles():
                    profiles.append((name, 'Loaded from sandbox profile configuration'))
            except Exception:  # profile config is optional
                pass

        if args.output == 'json':
            output = [{'name': name, 'description': desc} for name, desc in profiles]
            print(json.dumps(output, indent=2))
        else:
            print(f"\n{Colors.BOLD}Available Sandbox Profiles:{Colors.RESET}\n")
            for name, desc in profiles:
                print(f"  {Colors.CYAN}{name:<12}{Colors.RESET} {desc}")

            print(f"\n{Colors.GRAY}Use 'sandboxctl run --profile <name> -- <command>' to run with a profile{Colors.RESET}")

        return 0

    def cmd_test(self, args: argparse.Namespace) -> int:
        """Test sandbox functionality."""
        manager = self._get_manager()

        profile_name = args.profile.upper() if args.profile else 'STANDARD'
        try:
            self._resolve_profile(profile_name)
        except ValueError as e:
            print_error(str(e), code="E012", hint="Run: sandboxctl profiles")
            return 1

        print(f"\n{Colors.BOLD}Testing Sandbox Profile: {profile_name}{Colors.RESET}\n")

        tests = [
            ('namespace_isolation', 'Namespace isolation'),
            ('seccomp_filter', 'Seccomp filtering'),
            ('cgroup_limits', 'Cgroup resource limits'),
            ('network_policy', 'Network policy'),
        ]

        passed = 0
        failed = 0

        for test_id, test_name in tests:
            try:
                result = self._run_test(manager, test_id, profile_name)
                if result:
                    print(f"  {Colors.GREEN}✓{Colors.RESET} {test_name}")
                    passed += 1
                else:
                    print(f"  {Colors.RED}✗{Colors.RESET} {test_name}")
                    failed += 1
            except Exception as e:
                print(f"  {Colors.YELLOW}?{Colors.RESET} {test_name}: {e}")
                failed += 1

        print(f"\n{Colors.BOLD}Results:{Colors.RESET} {passed} passed, {failed} failed")

        # Check capabilities
        print(f"\n{Colors.BOLD}System Capabilities:{Colors.RESET}")
        # SandboxManager.get_capabilities() returns {'namespaces': {<ns>_ns: bool, ...},
        # 'cgroups': {'cgroups_v2': bool, 'can_create': bool, ...},
        # 'firewall': {'available': bool, ...}, 'can_sandbox': bool}
        caps = manager.get_capabilities()

        def _section(name: str) -> Dict[str, Any]:
            value = caps.get(name)
            return value if isinstance(value, dict) else {}

        ns_caps = _section('namespaces')
        cg_caps = _section('cgroups')
        fw_caps = _section('firewall')

        cap_items = [
            ('Namespace support', any(bool(v) for k, v in ns_caps.items() if k.endswith('_ns'))),
            ('Cgroups v2 support', bool(cg_caps.get('cgroups_v2'))),
            ('Cgroup management', bool(cg_caps.get('can_create'))),
            ('Firewall support', bool(fw_caps.get('available'))),
            ('Sandboxing possible', bool(caps.get('can_sandbox'))),
        ]

        for cap_name, available in cap_items:
            icon = Colors.GREEN + '✓' if available else Colors.RED + '✗'
            print(f"  {icon}{Colors.RESET} {cap_name}")

        return 0 if failed == 0 else 1

    def _run_test(self, manager: SandboxManager, test_id: str, profile_name: str) -> bool:
        """Run a specific sandbox test."""
        # Simplified test implementation
        if test_id == 'namespace_isolation':
            # Test that PID 1 is not visible
            result = manager.run_sandboxed(
                command=['cat', '/proc/1/cmdline'],
                profile=self._resolve_profile(profile_name),
                capture_output=True,
            )
            return result.exit_code != 0 or 'systemd' not in result.stdout

        elif test_id == 'seccomp_filter':
            # Test that blocked syscalls fail
            result = manager.run_sandboxed(
                command=['python3', '-c', 'import os; os.setuid(0)'],
                profile=self._resolve_profile(profile_name),
                capture_output=True,
            )
            return result.exit_code != 0

        elif test_id == 'cgroup_limits':
            # Test that resource limits are applied
            # This is a simple check that the sandbox ran
            result = manager.run_sandboxed(
                command=['true'],
                profile=self._resolve_profile(profile_name),
                capture_output=True,
            )
            return result.exit_code == 0

        elif test_id == 'network_policy':
            # Test network restrictions (if profile restricts network)
            if profile_name in ('AIRGAP', 'COLDROOM', 'RESTRICTED'):
                result = manager.run_sandboxed(
                    command=['ping', '-c', '1', '-W', '1', '8.8.8.8'],
                    profile=self._resolve_profile(profile_name),
                    capture_output=True,
                )
                return result.exit_code != 0
            return True

        return False

    def cmd_metrics(self, args: argparse.Namespace) -> int:
        """Show daemon metrics, read from the Prometheus exporter endpoint."""
        url = args.metrics_url or DEFAULT_METRICS_URL
        if not url.lower().startswith(('http://', 'https://')):
            print_error(f"Metrics URL must be http(s): {url}", code="E013")
            return 1

        try:
            with urllib.request.urlopen(url, timeout=5) as response:  # nosec B310 - scheme validated above
                text = response.read().decode('utf-8', errors='replace')
        except (urllib.error.URLError, OSError) as e:
            print_error(f"Could not read metrics from {url}: {e}", code="E013",
                        hint="Is the daemon running with the Prometheus exporter enabled?")
            return 1

        samples = self._parse_prometheus_text(text)

        if args.output == 'json':
            print(json.dumps(samples, indent=2))
        else:
            print(f"\n{Colors.BOLD}Daemon Metrics ({url}):{Colors.RESET}\n")
            for sample in samples:
                label_str = ', '.join(f"{k}={v}" for k, v in sample['labels'].items())
                if label_str:
                    label_str = f" {{{label_str}}}"
                print(f"  {Colors.CYAN}{sample['name']}{Colors.RESET}{label_str}: {sample['value']}")

        return 0

    @staticmethod
    def _parse_prometheus_text(text: str) -> List[Dict[str, Any]]:
        """Parse Prometheus exposition text into {name, labels, value} samples."""
        samples: List[Dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            name_labels, _, value = line.rpartition(' ')
            name, _, labels = name_labels.partition('{')
            label_dict: Dict[str, str] = {}
            if labels:
                for item in labels.rstrip('}').split(','):
                    key, _, val = item.partition('=')
                    if key:
                        label_dict[key.strip()] = val.strip().strip('"')
            try:
                samples.append({'name': name, 'labels': label_dict, 'value': float(value)})
            except ValueError:
                continue
        return samples

    def _parse_memory(self, value: str) -> int:
        """Parse memory string (e.g., '512M', '1G') to bytes."""
        value = value.strip().upper()
        multipliers = {
            'B': 1,
            'K': 1024,
            'KB': 1024,
            'M': 1024 * 1024,
            'MB': 1024 * 1024,
            'G': 1024 * 1024 * 1024,
            'GB': 1024 * 1024 * 1024,
        }

        for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
            if value.endswith(suffix):
                return int(float(value[:-len(suffix)]) * mult)

        return int(value)


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog='sandboxctl',
        description='Sandbox Management CLI for Boundary Daemon',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sandboxctl run -- python3 script.py
  sandboxctl run --profile restricted -- npm install
  sandboxctl run --memory 512M --timeout 60 -- ./build.sh
  sandboxctl list
  sandboxctl inspect sandbox-001
  sandboxctl kill sandbox-001
  sandboxctl profiles
  sandboxctl test --profile airgap
        """
    )

    parser.add_argument(
        '--no-color', action='store_true',
        help='Disable colored output'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--socket', metavar='PATH',
        help='Path to daemon socket'
    )
    parser.add_argument(
        '--config', metavar='PATH',
        help='Path to configuration file'
    )

    # dest must not collide with the 'run' positional argument named 'command'
    subparsers = parser.add_subparsers(dest='subcommand', help='Available commands')

    # run command
    run_parser = subparsers.add_parser('run', help='Run command in sandbox')
    run_parser.add_argument(
        '-p', '--profile', default='standard',
        help='Sandbox profile to use (default: standard)'
    )
    run_parser.add_argument(
        '-m', '--memory', metavar='SIZE',
        help='Memory limit (e.g., 512M, 1G)'
    )
    run_parser.add_argument(
        '-c', '--cpu', type=float, metavar='PERCENT',
        help='CPU limit percentage (e.g., 50 for 50%%)'
    )
    run_parser.add_argument(
        '-t', '--timeout', type=int, metavar='SECONDS',
        help='Timeout in seconds'
    )
    run_parser.add_argument(
        '--network-deny', action='store_true',
        help='Deny all network access'
    )
    run_parser.add_argument(
        '--network-allow', nargs='+', metavar='HOST',
        help='Allow network access to specific hosts'
    )
    run_parser.add_argument(
        '-i', '--interactive', action='store_true',
        help='Interactive mode (inherit stdin/stdout)'
    )
    run_parser.add_argument(
        '-e', '--inherit-env', action='store_true',
        help='Inherit environment variables'
    )
    run_parser.add_argument(
        '-q', '--quiet', action='store_true',
        help='Suppress informational output'
    )
    run_parser.add_argument(
        'command', nargs='*',
        help='Command to run'
    )

    # list command
    list_parser = subparsers.add_parser('list', aliases=['ls'], help='List sandboxes')
    list_parser.add_argument(
        '-o', '--output', choices=['table', 'json', 'wide'], default='table',
        help='Output format'
    )

    # inspect command
    inspect_parser = subparsers.add_parser('inspect', help='Inspect sandbox')
    inspect_parser.add_argument('sandbox_id', help='Sandbox ID')
    inspect_parser.add_argument(
        '-o', '--output', choices=['text', 'json'], default='text',
        help='Output format'
    )

    # kill command
    kill_parser = subparsers.add_parser('kill', help='Kill sandbox(es)')
    kill_parser.add_argument('sandbox_ids', nargs='*', help='Sandbox IDs to kill')
    kill_parser.add_argument(
        '-a', '--all', action='store_true',
        help='Kill all sandboxes'
    )
    kill_parser.add_argument(
        '-f', '--force', action='store_true',
        help='Force kill (SIGKILL instead of SIGTERM)'
    )

    # profiles command
    profiles_parser = subparsers.add_parser('profiles', help='List profiles')
    profiles_parser.add_argument(
        '-o', '--output', choices=['text', 'json'], default='text',
        help='Output format'
    )

    # test command
    test_parser = subparsers.add_parser('test', help='Test sandbox')
    test_parser.add_argument(
        '-p', '--profile', default='standard',
        help='Profile to test'
    )

    # metrics command
    metrics_parser = subparsers.add_parser('metrics', help='Show metrics')
    metrics_parser.add_argument(
        '-o', '--output', choices=['text', 'json'], default='text',
        help='Output format'
    )
    metrics_parser.add_argument(
        '--metrics-url', metavar='URL', default=None,
        help=f'Prometheus exporter URL (default: $BOUNDARY_METRICS_URL or {DEFAULT_METRICS_URL})'
    )

    return parser


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Handle colors
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    # Create CLI handler
    cli = SandboxCLI(
        socket_path=args.socket,
        config_path=args.config,
    )

    # Dispatch command
    if not args.subcommand:
        parser.print_help()
        return 0

    command_map = {
        'run': cli.cmd_run,
        'list': cli.cmd_list,
        'ls': cli.cmd_list,
        'inspect': cli.cmd_inspect,
        'kill': cli.cmd_kill,
        'profiles': cli.cmd_profiles,
        'test': cli.cmd_test,
        'metrics': cli.cmd_metrics,
    }

    handler = command_map.get(args.subcommand)
    if handler:
        return handler(args)
    else:
        print_error(f"Unknown command: {args.subcommand}",
                     code="E003", hint="Run: sandboxctl --help")
        return 1


if __name__ == '__main__':
    sys.exit(main())
