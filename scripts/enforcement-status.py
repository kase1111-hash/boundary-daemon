#!/usr/bin/env python3
"""
Boundary Daemon - Enforcement Status Tool

Shows the current status of all enforcement modules.
Run with sudo for full information.

Usage:
    sudo python3 scripts/enforcement-status.py
    sudo python3 scripts/enforcement-status.py --json
    sudo python3 scripts/enforcement-status.py --check
"""

import os
import sys
import json
import subprocess
import argparse
from datetime import datetime
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ANSI colors
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    BOLD = '\033[1m'
    NC = '\033[0m'

    @classmethod
    def disable(cls):
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = cls.CYAN = cls.BOLD = cls.NC = ''


def check_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def run_command(cmd: list, timeout: int = 5) -> tuple:
    """Run a command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True
        )
        return result.returncode == 0, result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False, ""


def check_service_status(service: str) -> dict:
    """Check systemd service status."""
    status = {
        'name': service,
        'active': False,
        'enabled': False,
        'status': 'unknown'
    }

    success, output = run_command(['systemctl', 'is-active', service])
    status['active'] = success
    status['status'] = output if output else 'inactive'

    success, output = run_command(['systemctl', 'is-enabled', service])
    status['enabled'] = success

    return status


def check_network_enforcement() -> dict:
    """Check network enforcement status."""
    result = {
        'available': False,
        'backend': 'none',
        'active': False,
        'rules': [],
        'mode': None
    }

    # Check iptables
    success, output = run_command(['iptables', '-L', 'BOUNDARY_DAEMON', '-n'])
    if success and 'Chain BOUNDARY_DAEMON' in output:
        result['available'] = True
        result['backend'] = 'iptables'
        result['active'] = True
        # Parse rules
        lines = output.split('\n')[2:]  # Skip header lines
        result['rules'] = [l.strip() for l in lines if l.strip()]
        result['rule_count'] = len(result['rules'])

        # Detect mode from rules
        if 'DROP' in output and 'lo' not in output:
            result['mode'] = 'LOCKDOWN'
        elif 'DROP' in output:
            result['mode'] = 'AIRGAP/COLDROOM'
        elif 'LOG' in output and 'ACCEPT' in output:
            result['mode'] = 'RESTRICTED'
        elif 'ACCEPT' in output:
            result['mode'] = 'TRUSTED'

        return result

    # Check nftables
    success, output = run_command(['nft', 'list', 'table', 'inet', 'boundary_daemon'])
    if success and 'table inet boundary_daemon' in output:
        result['available'] = True
        result['backend'] = 'nftables'
        result['active'] = True
        result['rules'] = [output]
        return result

    # Check if tools are available
    iptables_available, _ = run_command(['which', 'iptables'])
    nft_available, _ = run_command(['which', 'nft'])

    if iptables_available or nft_available:
        result['available'] = True
        result['backend'] = 'nftables' if nft_available else 'iptables'
        result['note'] = 'No rules applied (rules are created on mode transition)'

    return result


def check_usb_enforcement() -> dict:
    """Check USB enforcement status."""
    result = {
        'available': False,
        'active': False,
        'rules_installed': False,
        'rule_path': '/etc/udev/rules.d/99-boundary-usb.rules',
        'mode': None
    }

    # Check if udevadm is available
    success, _ = run_command(['which', 'udevadm'])
    result['available'] = success

    # Check for rules file
    rule_path = Path(result['rule_path'])
    if rule_path.exists():
        result['rules_installed'] = True
        result['active'] = True

        # Read and analyze rules
        try:
            content = rule_path.read_text()
            if 'LOCKDOWN' in content:
                result['mode'] = 'LOCKDOWN'
            elif 'COLDROOM' in content:
                result['mode'] = 'COLDROOM'
            elif 'Block USB mass storage' in content:
                result['mode'] = 'TRUSTED/AIRGAP'
            elif 'Log all USB' in content:
                result['mode'] = 'RESTRICTED'
            result['rule_preview'] = content[:200]
        except OSError:
            pass
    else:
        result['note'] = 'No rules installed (rules are created on mode transition)'

    # Count connected USB devices
    usb_path = Path('/sys/bus/usb/devices')
    if usb_path.exists():
        devices = [d for d in usb_path.iterdir() if d.is_dir() and ':' not in d.name]
        result['connected_devices'] = len(devices)

    return result


def check_process_enforcement() -> dict:
    """Check process enforcement status."""
    result = {
        'available': False,
        'seccomp_supported': False,
        'container_runtime': 'none',
        'profiles': [],
        'profile_dir': '/etc/boundary-daemon/seccomp'
    }

    # Check seccomp support
    seccomp_path = Path('/proc/sys/kernel/seccomp/actions_avail')
    if seccomp_path.exists():
        result['seccomp_supported'] = True
        result['available'] = True
        try:
            result['seccomp_actions'] = seccomp_path.read_text().strip()
        except OSError:
            pass

    # Check container runtime
    for runtime in ['podman', 'docker']:
        success, version = run_command([runtime, '--version'])
        if success:
            result['container_runtime'] = runtime
            result['container_version'] = version.split('\n')[0]
            break

    # Check for seccomp profiles
    profile_dir = Path(result['profile_dir'])
    if profile_dir.exists():
        profiles = list(profile_dir.glob('*.json'))
        result['profiles'] = [p.name for p in profiles]
        result['profile_count'] = len(profiles)

    return result


def check_persistence() -> dict:
    """Check protection persistence status."""
    result = {
        'enabled': False,
        'state_file': '/var/lib/boundary-daemon/protection_state.json',
        'protections': []
    }

    state_path = Path(result['state_file'])
    if state_path.exists():
        result['enabled'] = True
        try:
            state = json.loads(state_path.read_text())
            result['protections'] = list(state.get('protections', {}).keys())
            result['last_updated'] = state.get('last_updated')
        except (json.JSONDecodeError, OSError):
            result['error'] = 'Failed to parse state file'

    return result


def check_lockdown_status() -> dict:
    """Check if system is in lockdown."""
    result = {
        'in_lockdown': False,
        'lockdown_file': '/var/run/boundary-daemon/LOCKDOWN'
    }

    lockdown_path = Path(result['lockdown_file'])
    if lockdown_path.exists():
        result['in_lockdown'] = True
        try:
            result['lockdown_reason'] = lockdown_path.read_text().strip()
        except OSError:
            pass

    return result


def get_full_status() -> dict:
    """Get complete enforcement status."""
    return {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'running_as_root': check_root(),
        'services': {
            'daemon': check_service_status('boundary-daemon.service'),
            'watchdog': check_service_status('boundary-watchdog.service')
        },
        'enforcement': {
            'network': check_network_enforcement(),
            'usb': check_usb_enforcement(),
            'process': check_process_enforcement()
        },
        'persistence': check_persistence(),
        'lockdown': check_lockdown_status()
    }


def print_status(status: dict):
    """Print status in human-readable format."""
    C = Colors

    print(f"\n{C.CYAN}{'='*60}{C.NC}")
    print(f"{C.BOLD}  BOUNDARY DAEMON - ENFORCEMENT STATUS{C.NC}")
    print(f"{C.CYAN}{'='*60}{C.NC}\n")

    # Root check
    if not status['running_as_root']:
        print(f"{C.YELLOW}[!] Not running as root - some information may be limited{C.NC}\n")

    # Lockdown status
    lockdown = status['lockdown']
    if lockdown['in_lockdown']:
        print(f"{C.RED}{C.BOLD}*** SYSTEM IS IN LOCKDOWN ***{C.NC}")
        if 'lockdown_reason' in lockdown:
            print(f"    Reason: {lockdown['lockdown_reason']}")
        print()

    # Services
    print(f"{C.BOLD}Services:{C.NC}")
    for name, svc in status['services'].items():
        if svc['active']:
            symbol = f"{C.GREEN}●{C.NC}"
        else:
            symbol = f"{C.YELLOW}○{C.NC}"
        enabled = "enabled" if svc['enabled'] else "disabled"
        print(f"  {symbol} {svc['name']}: {svc['status']} ({enabled})")
    print()

    # Network enforcement
    net = status['enforcement']['network']
    print(f"{C.BOLD}Network Enforcement:{C.NC}")
    if net['active']:
        print(f"  {C.GREEN}●{C.NC} Status: ACTIVE ({net['backend']})")
        if net.get('mode'):
            print(f"    Mode: {net['mode']}")
        if net.get('rule_count'):
            print(f"    Rules: {net['rule_count']}")
    elif net['available']:
        print(f"  {C.YELLOW}○{C.NC} Status: Available but no rules applied")
        if net.get('note'):
            print(f"    {net['note']}")
    else:
        print(f"  {C.RED}●{C.NC} Status: NOT AVAILABLE")
    print()

    # USB enforcement
    usb = status['enforcement']['usb']
    print(f"{C.BOLD}USB Enforcement:{C.NC}")
    if usb['active']:
        print(f"  {C.GREEN}●{C.NC} Status: ACTIVE")
        if usb.get('mode'):
            print(f"    Mode: {usb['mode']}")
    elif usb['available']:
        print(f"  {C.YELLOW}○{C.NC} Status: Available but no rules installed")
        if usb.get('note'):
            print(f"    {usb['note']}")
    else:
        print(f"  {C.RED}●{C.NC} Status: NOT AVAILABLE")
    if usb.get('connected_devices'):
        print(f"    Connected devices: {usb['connected_devices']}")
    print()

    # Process enforcement
    proc = status['enforcement']['process']
    print(f"{C.BOLD}Process Enforcement:{C.NC}")
    if proc['seccomp_supported']:
        print(f"  {C.GREEN}●{C.NC} seccomp: supported")
    else:
        print(f"  {C.RED}●{C.NC} seccomp: not supported")

    if proc['container_runtime'] != 'none':
        print(f"  {C.GREEN}●{C.NC} Container runtime: {proc['container_runtime']}")
    else:
        print(f"  {C.YELLOW}○{C.NC} Container runtime: none")

    if proc.get('profile_count', 0) > 0:
        print(f"    Profiles installed: {proc['profile_count']}")
    print()

    # Persistence
    pers = status['persistence']
    print(f"{C.BOLD}Protection Persistence:{C.NC}")
    if pers['enabled']:
        print(f"  {C.GREEN}●{C.NC} Status: ENABLED")
        if pers['protections']:
            print(f"    Active protections: {', '.join(pers['protections'])}")
    else:
        print(f"  {C.YELLOW}○{C.NC} Status: No persisted state")
    print()

    # Summary
    print(f"{C.CYAN}{'─'*60}{C.NC}")
    all_active = (
        status['services']['daemon']['active'] and
        net['available'] and
        usb['available'] and
        proc['available']
    )

    if all_active:
        print(f"{C.GREEN}{C.BOLD}Phase 1 Enforcement: READY{C.NC}")
        print(f"  Run 'boundaryctl mode airgap' to apply enforcement rules")
    else:
        print(f"{C.YELLOW}{C.BOLD}Phase 1 Enforcement: PARTIALLY READY{C.NC}")
        print(f"  Some components need attention")

    print()


def check_enforcement_health() -> int:
    """Check if enforcement is healthy, return exit code."""
    status = get_full_status()

    issues = []

    # Check daemon
    if not status['services']['daemon']['active']:
        issues.append("Daemon service not running")

    # Check network
    if not status['enforcement']['network']['available']:
        issues.append("Network enforcement not available")

    # Check USB
    if not status['enforcement']['usb']['available']:
        issues.append("USB enforcement not available")

    # Check process
    if not status['enforcement']['process']['available']:
        issues.append("Process enforcement not available")

    # Check lockdown
    if status['lockdown']['in_lockdown']:
        issues.append("System is in LOCKDOWN")

    if issues:
        for issue in issues:
            print(f"CRITICAL: {issue}", file=sys.stderr)
        return 1

    print("OK: All enforcement modules available")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description='Boundary Daemon Enforcement Status'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output as JSON'
    )
    parser.add_argument(
        '--check',
        action='store_true',
        help='Check health and exit with code (for monitoring)'
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    if args.check:
        sys.exit(check_enforcement_health())

    status = get_full_status()

    if args.json:
        print(json.dumps(status, indent=2, default=str))
    else:
        print_status(status)


if __name__ == '__main__':
    main()
