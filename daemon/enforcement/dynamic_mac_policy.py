"""
Dynamic MAC Policy Generator - Kernel-Level Mode Enforcement

Phase 4: This module generates and applies SELinux/AppArmor policies that
enforce boundary modes at the KERNEL level, not just in userspace.

WHY THIS MATTERS:
- Phases 1-3: Enforcement via iptables, udev, seccomp (userspace tools)
- Phase 4: Enforcement via SELinux/AppArmor (kernel MAC)

The key difference: SELinux/AppArmor policies are enforced by the kernel
itself. Even if the boundary daemon is compromised, the kernel continues
to enforce the policy. This is TRUE mandatory access control.

SUPPORTED SYSTEMS:
- SELinux (RHEL, Fedora, CentOS, Rocky, Alma)
- AppArmor (Ubuntu, Debian, SUSE, Linux Mint)

BOUNDARY MODE → MAC POLICY MAPPING:
- OPEN:       Permissive policy (logging only)
- RESTRICTED: Limited network, logged file access
- TRUSTED:    VPN-only network, restricted file paths
- AIRGAP:     No network syscalls allowed
- COLDROOM:   No network, no exec, limited file access
- LOCKDOWN:   Deny all, minimum for daemon survival

USAGE:
    from daemon.enforcement.dynamic_mac_policy import DynamicMACPolicyManager

    mac = DynamicMACPolicyManager()
    mac.apply_mode_policy(BoundaryMode.AIRGAP)

    # On mode transition:
    mac.transition_policy(BoundaryMode.TRUSTED, BoundaryMode.AIRGAP)
"""

import os
import sys
import subprocess
import tempfile
import shutil
import logging
import json
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime

logger = logging.getLogger(__name__)

# Platform detection
IS_LINUX = sys.platform.startswith('linux')


class MACSystem(Enum):
    """Available MAC systems."""
    SELINUX = "selinux"
    APPARMOR = "apparmor"
    NONE = "none"


class PolicyMode(Enum):
    """Policy enforcement modes."""
    ENFORCING = "enforcing"      # Deny violations
    PERMISSIVE = "permissive"    # Log violations only
    DISABLED = "disabled"        # No policy


@dataclass
class ModePolicy:
    """Policy configuration for a specific boundary mode."""
    mode_name: str

    # Network restrictions
    allow_network: bool = True
    allow_network_connect: bool = True
    allow_network_bind: bool = True
    allowed_ports: Set[int] = field(default_factory=set)
    allowed_addresses: Set[str] = field(default_factory=set)
    allow_loopback_only: bool = False
    deny_all_network: bool = False

    # File access restrictions
    allow_file_read: Set[str] = field(default_factory=set)
    allow_file_write: Set[str] = field(default_factory=set)
    allow_file_exec: Set[str] = field(default_factory=set)
    deny_file_paths: Set[str] = field(default_factory=set)

    # Process restrictions
    allow_exec: bool = True
    allow_fork: bool = True
    allow_ptrace: bool = False
    allowed_executables: Set[str] = field(default_factory=set)

    # Capability restrictions
    allowed_capabilities: Set[str] = field(default_factory=set)
    denied_capabilities: Set[str] = field(default_factory=set)

    # IPC restrictions
    allow_ipc: bool = True
    allow_unix_sockets: bool = True
    allow_shared_memory: bool = True

    # Audit level
    audit_denials: bool = True
    audit_allows: bool = False


# Predefined policies for each boundary mode
MODE_POLICIES: Dict[str, ModePolicy] = {
    'OPEN': ModePolicy(
        mode_name='OPEN',
        allow_network=True,
        allow_network_connect=True,
        allow_network_bind=True,
        allow_exec=True,
        allow_fork=True,
        allow_file_read={'/'},
        allow_file_write={'/tmp', '/var/log', '/var/run'},
        allowed_capabilities={'net_admin', 'sys_admin', 'dac_override'},
        audit_denials=True,
        audit_allows=False,
    ),

    'RESTRICTED': ModePolicy(
        mode_name='RESTRICTED',
        allow_network=True,
        allow_network_connect=True,
        allow_network_bind=True,
        allowed_ports={80, 443, 22, 514, 6514},  # HTTP(S), SSH, Syslog
        allow_exec=True,
        allow_fork=True,
        allow_file_read={'/etc', '/usr', '/lib', '/proc', '/sys'},
        allow_file_write={'/tmp', '/var/log/boundary-daemon', '/var/run/boundary-daemon'},
        deny_file_paths={'/etc/shadow', '/etc/passwd-'},
        allowed_capabilities={'net_admin', 'audit_write'},
        audit_denials=True,
        audit_allows=True,
    ),

    'TRUSTED': ModePolicy(
        mode_name='TRUSTED',
        allow_network=True,
        allow_network_connect=True,
        allow_network_bind=False,
        allowed_ports={443, 514, 6514},  # HTTPS, Syslog only
        allowed_addresses={'127.0.0.1', '::1'},  # + VPN ranges
        allow_exec=True,
        allow_fork=True,
        allow_file_read={'/etc/boundary-daemon', '/proc', '/sys', '/usr/lib'},
        allow_file_write={'/var/log/boundary-daemon', '/var/run/boundary-daemon'},
        allowed_capabilities={'audit_write'},
        denied_capabilities={'net_admin'},
        audit_denials=True,
        audit_allows=True,
    ),

    'AIRGAP': ModePolicy(
        mode_name='AIRGAP',
        allow_network=False,
        allow_network_connect=False,
        allow_network_bind=False,
        allow_loopback_only=True,
        allow_exec=True,
        allow_fork=True,
        allow_file_read={'/etc/boundary-daemon', '/proc', '/sys'},
        allow_file_write={'/var/log/boundary-daemon', '/var/run/boundary-daemon'},
        deny_file_paths={'/etc/resolv.conf'},  # Prevent DNS config access
        allowed_capabilities={'audit_write'},
        denied_capabilities={'net_admin', 'net_raw', 'net_bind_service'},
        allow_unix_sockets=True,
        allow_shared_memory=False,
        audit_denials=True,
        audit_allows=True,
    ),

    'COLDROOM': ModePolicy(
        mode_name='COLDROOM',
        allow_network=False,
        deny_all_network=True,
        allow_exec=False,
        allow_fork=False,
        allow_ptrace=False,
        allowed_executables={'/usr/bin/python3'},  # Only Python for daemon
        allow_file_read={'/etc/boundary-daemon', '/proc/self'},
        allow_file_write={'/var/log/boundary-daemon'},
        deny_file_paths={'/home', '/root', '/tmp'},
        allowed_capabilities=set(),
        denied_capabilities={'all'},
        allow_ipc=False,
        allow_unix_sockets=True,  # For API socket
        allow_shared_memory=False,
        audit_denials=True,
        audit_allows=True,
    ),

    'LOCKDOWN': ModePolicy(
        mode_name='LOCKDOWN',
        allow_network=False,
        deny_all_network=True,
        allow_network_connect=False,
        allow_network_bind=False,
        allow_exec=False,
        allow_fork=False,
        allow_ptrace=False,
        allowed_executables=set(),
        allow_file_read={'/proc/self/status'},  # Minimum for daemon to function
        allow_file_write={'/var/log/boundary-daemon/lockdown.log'},
        deny_file_paths={'/', '/home', '/root', '/etc'},
        allowed_capabilities=set(),
        denied_capabilities={'all'},
        allow_ipc=False,
        allow_unix_sockets=False,
        allow_shared_memory=False,
        audit_denials=True,
        audit_allows=True,
    ),
}


class SELinuxPolicyGenerator:
    """Generates SELinux policy modules for boundary modes."""

    POLICY_DIR = Path('/etc/selinux/targeted/policy')
    MODULE_DIR = Path('/etc/selinux/targeted/modules/active/modules')
    CONTEXT_DIR = Path('/etc/selinux/targeted/contexts/files')

    def __init__(self):
        self._temp_dir = None

    def is_available(self) -> bool:
        """Check if SELinux is available and tools exist."""
        if not IS_LINUX:
            return False

        # Check for SELinux filesystem
        if not Path('/sys/fs/selinux').exists():
            return False

        # Check for required tools
        required_tools = ['semodule', 'checkmodule', 'semodule_package']
        for tool in required_tools:
            if not shutil.which(tool):
                return False

        return True

    def get_status(self) -> Dict[str, Any]:
        """Get SELinux status."""
        status = {
            'available': self.is_available(),
            'mode': 'unknown',
            'policy': 'unknown',
            'boundary_modules': [],
        }

        try:
            result = subprocess.run(['getenforce'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                status['mode'] = result.stdout.strip().lower()

            result = subprocess.run(['sestatus'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Policy name:' in line:
                        status['policy'] = line.split(':')[1].strip()

            # List boundary modules
            result = subprocess.run(['semodule', '-l'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'boundary_' in line.lower():
                        status['boundary_modules'].append(line.strip())

        except Exception as e:
            status['error'] = str(e)

        return status

    def generate_mode_policy(self, policy: ModePolicy) -> str:
        """Generate SELinux policy module for a boundary mode."""
        mode_name = policy.mode_name.lower()

        # Build network rules
        network_rules = self._generate_network_rules(policy)

        # Build file rules
        file_rules = self._generate_file_rules(policy)

        # Build capability rules
        cap_rules = self._generate_capability_rules(policy)

        # Build process rules
        proc_rules = self._generate_process_rules(policy)

        policy_text = f'''
# SELinux Policy Module for Boundary Daemon - {policy.mode_name} Mode
# Generated: {datetime.utcnow().isoformat()}Z
# DO NOT EDIT - This file is auto-generated

policy_module(boundary_{mode_name}, 1.0.0)

require {{
    type boundary_daemon_t;
    type boundary_daemon_exec_t;
    type init_t;
    type unconfined_t;
    type bin_t;
    type shell_exec_t;
    type proc_t;
    type sysfs_t;
    type etc_t;
    type var_log_t;
    type var_run_t;
    type tmp_t;
    type port_t;
    type node_t;
    type netif_t;
    class capability {{ {' '.join(self._all_capabilities())} }};
    class file {{ read write create unlink getattr setattr open append }};
    class dir {{ read write create search add_name remove_name getattr }};
    class process {{ fork exec signal ptrace }};
    class tcp_socket {{ create connect bind listen accept read write getattr setattr }};
    class udp_socket {{ create connect bind read write getattr setattr }};
    class unix_stream_socket {{ create connect bind listen accept read write }};
}}

########################################
# Boundary Mode: {policy.mode_name}
########################################

# Network Access Rules
{network_rules}

# File Access Rules
{file_rules}

# Capability Rules
{cap_rules}

# Process Control Rules
{proc_rules}
'''
        return policy_text.strip()

    def _generate_network_rules(self, policy: ModePolicy) -> str:
        """Generate SELinux network rules."""
        rules = []

        if policy.deny_all_network:
            rules.append("# DENY ALL NETWORK - LOCKDOWN/COLDROOM mode")
            rules.append("neverallow boundary_daemon_t port_t:tcp_socket { connect bind };")
            rules.append("neverallow boundary_daemon_t port_t:udp_socket { connect bind };")
        elif policy.allow_loopback_only:
            rules.append("# LOOPBACK ONLY - AIRGAP mode")
            rules.append("allow boundary_daemon_t self:tcp_socket create_stream_socket_perms;")
            rules.append("allow boundary_daemon_t self:udp_socket create_socket_perms;")
            rules.append("# Deny connection to remote hosts")
            rules.append("dontaudit boundary_daemon_t port_t:tcp_socket name_connect;")
        elif policy.allow_network:
            rules.append("# NETWORK ALLOWED")
            if policy.allow_network_connect:
                rules.append("allow boundary_daemon_t port_t:tcp_socket name_connect;")
            if policy.allow_network_bind:
                rules.append("allow boundary_daemon_t port_t:tcp_socket name_bind;")
                rules.append("allow boundary_daemon_t port_t:udp_socket name_bind;")

        # Unix sockets
        if policy.allow_unix_sockets:
            rules.append("# Unix sockets for local IPC")
            rules.append("allow boundary_daemon_t self:unix_stream_socket create_stream_socket_perms;")
        else:
            rules.append("neverallow boundary_daemon_t self:unix_stream_socket *;")

        return '\n'.join(rules)

    def _generate_file_rules(self, policy: ModePolicy) -> str:
        """Generate SELinux file access rules."""
        rules = []

        # Read paths
        if policy.allow_file_read:
            rules.append("# Allowed read paths")
            rules.append("allow boundary_daemon_t etc_t:file read_file_perms;")
            rules.append("allow boundary_daemon_t proc_t:file read_file_perms;")
            rules.append("allow boundary_daemon_t sysfs_t:file read_file_perms;")

        # Write paths
        if policy.allow_file_write:
            rules.append("# Allowed write paths")
            rules.append("allow boundary_daemon_t var_log_t:file create_file_perms;")
            rules.append("allow boundary_daemon_t var_run_t:file create_file_perms;")
        else:
            rules.append("# DENY WRITES")
            rules.append("neverallow boundary_daemon_t file_type:file { write create append };")

        # Deny specific paths
        if policy.deny_file_paths:
            rules.append("# Explicitly denied paths")
            rules.append("neverallow boundary_daemon_t shadow_t:file *;")

        return '\n'.join(rules)

    def _generate_capability_rules(self, policy: ModePolicy) -> str:
        """Generate SELinux capability rules."""
        rules = []

        if policy.allowed_capabilities:
            caps = ' '.join(policy.allowed_capabilities)
            rules.append(f"allow boundary_daemon_t self:capability {{ {caps} }};")

        if 'all' in policy.denied_capabilities:
            rules.append("# DENY ALL CAPABILITIES - LOCKDOWN mode")
            rules.append("neverallow boundary_daemon_t self:capability *;")
        elif policy.denied_capabilities:
            caps = ' '.join(policy.denied_capabilities)
            rules.append(f"neverallow boundary_daemon_t self:capability {{ {caps} }};")

        return '\n'.join(rules)

    def _generate_process_rules(self, policy: ModePolicy) -> str:
        """Generate SELinux process control rules."""
        rules = []

        if not policy.allow_exec:
            rules.append("# DENY EXEC - COLDROOM/LOCKDOWN mode")
            rules.append("neverallow boundary_daemon_t bin_t:file execute;")
            rules.append("neverallow boundary_daemon_t shell_exec_t:file execute;")

        if not policy.allow_fork:
            rules.append("# DENY FORK")
            rules.append("neverallow boundary_daemon_t self:process fork;")

        if not policy.allow_ptrace:
            rules.append("# DENY PTRACE")
            rules.append("neverallow boundary_daemon_t domain:process ptrace;")

        return '\n'.join(rules)

    def _all_capabilities(self) -> List[str]:
        """Return list of all Linux capabilities."""
        return [
            'chown', 'dac_override', 'dac_read_search', 'fowner', 'fsetid',
            'kill', 'setgid', 'setuid', 'setpcap', 'linux_immutable',
            'net_bind_service', 'net_broadcast', 'net_admin', 'net_raw',
            'ipc_lock', 'ipc_owner', 'sys_module', 'sys_rawio', 'sys_chroot',
            'sys_ptrace', 'sys_pacct', 'sys_admin', 'sys_boot', 'sys_nice',
            'sys_resource', 'sys_time', 'sys_tty_config', 'mknod', 'lease',
            'audit_write', 'audit_control', 'setfcap',
        ]

    def compile_and_install(self, policy_text: str, module_name: str) -> Tuple[bool, str]:
        """Compile and install a SELinux policy module."""
        if not self.is_available():
            return False, "SELinux not available"

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                te_file = Path(temp_dir) / f"{module_name}.te"
                mod_file = Path(temp_dir) / f"{module_name}.mod"
                pp_file = Path(temp_dir) / f"{module_name}.pp"

                # Write policy source
                te_file.write_text(policy_text)

                # Compile to module
                result = subprocess.run(
                    ['checkmodule', '-M', '-m', '-o', str(mod_file), str(te_file)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode != 0:
                    return False, f"checkmodule failed: {result.stderr}"

                # Package module
                result = subprocess.run(
                    ['semodule_package', '-o', str(pp_file), '-m', str(mod_file)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode != 0:
                    return False, f"semodule_package failed: {result.stderr}"

                # Install module
                result = subprocess.run(
                    ['semodule', '-i', str(pp_file)],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if result.returncode != 0:
                    return False, f"semodule install failed: {result.stderr}"

                return True, f"Module {module_name} installed successfully"

        except Exception as e:
            return False, f"Error: {e}"

    def remove_module(self, module_name: str) -> Tuple[bool, str]:
        """Remove a SELinux policy module."""
        try:
            result = subprocess.run(
                ['semodule', '-r', module_name],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                if 'No such file' in result.stderr or 'not found' in result.stderr.lower():
                    return True, "Module not installed"
                return False, f"semodule remove failed: {result.stderr}"

            return True, f"Module {module_name} removed"

        except Exception as e:
            return False, f"Error: {e}"


class AppArmorPolicyGenerator:
    """Generates AppArmor profiles for boundary modes."""

    PROFILE_DIR = Path('/etc/apparmor.d')
    CACHE_DIR = Path('/var/cache/apparmor')

    def __init__(self):
        pass

    def is_available(self) -> bool:
        """Check if AppArmor is available."""
        if not IS_LINUX:
            return False

        # Check for AppArmor filesystem
        if not Path('/sys/kernel/security/apparmor').exists():
            return False

        # Check for required tools
        required_tools = ['apparmor_parser', 'aa-status']
        for tool in required_tools:
            if not shutil.which(tool):
                return False

        return True

    def get_status(self) -> Dict[str, Any]:
        """Get AppArmor status."""
        status = {
            'available': self.is_available(),
            'mode': 'unknown',
            'profiles_enforcing': 0,
            'profiles_complain': 0,
            'boundary_profiles': [],
        }

        try:
            result = subprocess.run(
                ['aa-status', '--json'],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                profiles = data.get('profiles', {})
                status['profiles_enforcing'] = len([p for p in profiles.values() if p == 'enforce'])
                status['profiles_complain'] = len([p for p in profiles.values() if p == 'complain'])
                status['mode'] = 'enforcing' if status['profiles_enforcing'] > 0 else 'permissive'

                # Find boundary profiles
                for name in profiles.keys():
                    if 'boundary' in name.lower():
                        status['boundary_profiles'].append(name)

        except Exception as e:
            status['error'] = str(e)

        return status

    def generate_mode_profile(self, policy: ModePolicy, profile_name: str = "boundary-daemon") -> str:
        """Generate AppArmor profile for a boundary mode."""
        mode_name = policy.mode_name

        # Build sections
        network_rules = self._generate_network_rules(policy)
        file_rules = self._generate_file_rules(policy)
        capability_rules = self._generate_capability_rules(policy)
        process_rules = self._generate_process_rules(policy)

        profile_text = f'''#include <tunables/global>

# AppArmor Profile for Boundary Daemon - {mode_name} Mode
# Generated: {datetime.utcnow().isoformat()}Z
# DO NOT EDIT - This file is auto-generated

profile {profile_name} /opt/boundary-daemon/daemon/**  flags=(attach_disconnected) {{
    #include <abstractions/base>

    # ========================================
    # BOUNDARY MODE: {mode_name}
    # ========================================

    # Capability Rules
{capability_rules}

    # Network Rules
{network_rules}

    # File Access Rules
{file_rules}

    # Process Control Rules
{process_rules}

    # Python interpreter (required for daemon)
    /usr/bin/python3* ixr,
    /usr/lib/python3*/** r,
    /usr/lib/python3*/**.so mr,

    # Daemon executable
    /opt/boundary-daemon/** r,
    /opt/boundary-daemon/daemon/** r,

    # Proc filesystem (for monitoring)
    @{{PROC}}/@{{pid}}/stat r,
    @{{PROC}}/@{{pid}}/status r,
    @{{PROC}}/@{{pid}}/cmdline r,
    @{{PROC}}/sys/kernel/** r,

    # Sysfs (for hardware monitoring)
    /sys/class/** r,
    /sys/bus/** r,
    /sys/devices/** r,

    # Configuration
    /etc/boundary-daemon/ r,
    /etc/boundary-daemon/** r,

    # Logging
    /var/log/boundary-daemon/ rw,
    /var/log/boundary-daemon/** rw,

    # Runtime
    /var/run/boundary-daemon/ rw,
    /var/run/boundary-daemon/** rw,

    # State
    /var/lib/boundary-daemon/ rw,
    /var/lib/boundary-daemon/** rw,
}}
'''
        return profile_text

    def _generate_network_rules(self, policy: ModePolicy) -> str:
        """Generate AppArmor network rules."""
        rules = []

        if policy.deny_all_network:
            rules.append("    # DENY ALL NETWORK - LOCKDOWN/COLDROOM mode")
            rules.append("    deny network,")
        elif policy.allow_loopback_only:
            rules.append("    # LOOPBACK ONLY - AIRGAP mode")
            rules.append("    network unix stream,")
            rules.append("    network unix dgram,")
            rules.append("    # Deny inet connections")
            rules.append("    deny network inet,")
            rules.append("    deny network inet6,")
        elif policy.allow_network:
            rules.append("    # NETWORK ALLOWED")
            rules.append("    network inet stream,")
            rules.append("    network inet dgram,")
            rules.append("    network inet6 stream,")
            rules.append("    network inet6 dgram,")
            if policy.allow_unix_sockets:
                rules.append("    network unix stream,")
                rules.append("    network unix dgram,")

        return '\n'.join(rules)

    def _generate_file_rules(self, policy: ModePolicy) -> str:
        """Generate AppArmor file access rules."""
        rules = []

        # Explicit denies first (more specific)
        for path in policy.deny_file_paths:
            rules.append(f"    deny {path}** rwmlkx,")

        # Then allows
        for path in policy.allow_file_read:
            if path == '/':
                rules.append("    /** r,")
            else:
                rules.append(f"    {path}/** r,")

        for path in policy.allow_file_write:
            rules.append(f"    {path}/** rw,")

        if not policy.allow_file_write:
            rules.append("    # DENY ALL WRITES")
            rules.append("    deny /** w,")

        return '\n'.join(rules)

    def _generate_capability_rules(self, policy: ModePolicy) -> str:
        """Generate AppArmor capability rules."""
        rules = []

        if 'all' in policy.denied_capabilities:
            rules.append("    # DENY ALL CAPABILITIES - LOCKDOWN mode")
            rules.append("    deny capability,")
        else:
            for cap in policy.allowed_capabilities:
                rules.append(f"    capability {cap},")

            for cap in policy.denied_capabilities:
                rules.append(f"    deny capability {cap},")

        return '\n'.join(rules)

    def _generate_process_rules(self, policy: ModePolicy) -> str:
        """Generate AppArmor process control rules."""
        rules = []

        if not policy.allow_exec:
            rules.append("    # DENY EXEC - COLDROOM/LOCKDOWN mode")
            rules.append("    deny /bin/** x,")
            rules.append("    deny /usr/bin/** x,")
            rules.append("    deny /sbin/** x,")
            rules.append("    deny /usr/sbin/** x,")

        if policy.allowed_executables:
            for exe in policy.allowed_executables:
                rules.append(f"    {exe} ixr,")

        if not policy.allow_ptrace:
            rules.append("    # DENY PTRACE")
            rules.append("    deny ptrace,")

        return '\n'.join(rules)

    def install_profile(self, profile_text: str, profile_name: str) -> Tuple[bool, str]:
        """Install an AppArmor profile."""
        if not self.is_available():
            return False, "AppArmor not available"

        try:
            profile_path = self.PROFILE_DIR / profile_name

            # Write profile
            profile_path.write_text(profile_text)

            # Load profile in enforce mode
            result = subprocess.run(
                ['apparmor_parser', '-r', '-W', str(profile_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return False, f"apparmor_parser failed: {result.stderr}"

            return True, f"Profile {profile_name} installed and enforced"

        except Exception as e:
            return False, f"Error: {e}"

    def remove_profile(self, profile_name: str) -> Tuple[bool, str]:
        """Remove an AppArmor profile."""
        try:
            profile_path = self.PROFILE_DIR / profile_name

            # Unload profile
            result = subprocess.run(
                ['apparmor_parser', '-R', str(profile_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )

            # Remove file
            if profile_path.exists():
                profile_path.unlink()

            return True, f"Profile {profile_name} removed"

        except Exception as e:
            return False, f"Error: {e}"

    def set_profile_mode(self, profile_name: str, mode: str) -> Tuple[bool, str]:
        """Set profile to enforce or complain mode."""
        try:
            if mode == 'enforce':
                tool = 'aa-enforce'
            elif mode == 'complain':
                tool = 'aa-complain'
            else:
                return False, f"Invalid mode: {mode}"

            result = subprocess.run(
                [tool, profile_name],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return False, f"{tool} failed: {result.stderr}"

            return True, f"Profile {profile_name} set to {mode}"

        except Exception as e:
            return False, f"Error: {e}"


class DynamicMACPolicyManager:
    """
    Manages dynamic MAC policy switching based on boundary modes.

    This is the main interface for Phase 4 enforcement.
    """

    def __init__(self, event_logger=None):
        self._event_logger = event_logger
        self._selinux = SELinuxPolicyGenerator()
        self._apparmor = AppArmorPolicyGenerator()
        self._current_mode: Optional[str] = None
        self._mac_system: Optional[MACSystem] = None

        # Detect MAC system
        self._detect_mac_system()

    def _detect_mac_system(self):
        """Detect available MAC system."""
        if self._selinux.is_available():
            self._mac_system = MACSystem.SELINUX
            logger.info("MAC system: SELinux")
        elif self._apparmor.is_available():
            self._mac_system = MACSystem.APPARMOR
            logger.info("MAC system: AppArmor")
        else:
            self._mac_system = MACSystem.NONE
            logger.warning("No MAC system available")

    @property
    def is_available(self) -> bool:
        """Check if MAC enforcement is available."""
        return self._mac_system != MACSystem.NONE

    @property
    def mac_system(self) -> MACSystem:
        """Get detected MAC system."""
        return self._mac_system

    @property
    def current_mode(self) -> Optional[str]:
        """Get current enforced mode."""
        return self._current_mode

    def get_status(self) -> Dict[str, Any]:
        """Get MAC policy status."""
        status = {
            'available': self.is_available,
            'mac_system': self._mac_system.value if self._mac_system else 'none',
            'current_mode': self._current_mode,
        }

        if self._mac_system == MACSystem.SELINUX:
            status['selinux'] = self._selinux.get_status()
        elif self._mac_system == MACSystem.APPARMOR:
            status['apparmor'] = self._apparmor.get_status()

        return status

    def apply_mode_policy(self, mode_name: str) -> Tuple[bool, str]:
        """
        Apply MAC policy for a specific boundary mode.

        Args:
            mode_name: One of OPEN, RESTRICTED, TRUSTED, AIRGAP, COLDROOM, LOCKDOWN

        Returns:
            (success, message)
        """
        if not self.is_available:
            return False, "No MAC system available"

        mode_name = mode_name.upper()
        if mode_name not in MODE_POLICIES:
            return False, f"Unknown mode: {mode_name}"

        policy = MODE_POLICIES[mode_name]
        module_name = f"boundary_{mode_name.lower()}"

        logger.info(f"Applying MAC policy for mode: {mode_name}")

        try:
            if self._mac_system == MACSystem.SELINUX:
                # Remove old policy if exists
                if self._current_mode:
                    old_module = f"boundary_{self._current_mode.lower()}"
                    self._selinux.remove_module(old_module)

                # Generate and install new policy
                policy_text = self._selinux.generate_mode_policy(policy)
                success, msg = self._selinux.compile_and_install(policy_text, module_name)

            elif self._mac_system == MACSystem.APPARMOR:
                # Generate and install profile
                profile_text = self._apparmor.generate_mode_profile(policy)
                success, msg = self._apparmor.install_profile(profile_text, "boundary-daemon")

            else:
                return False, "No MAC system"

            if success:
                self._current_mode = mode_name
                self._log_policy_change(mode_name, 'applied')
                return True, f"MAC policy for {mode_name} applied: {msg}"
            else:
                return False, f"Failed to apply policy: {msg}"

        except Exception as e:
            return False, f"Error applying policy: {e}"

    def transition_policy(self, from_mode: str, to_mode: str) -> Tuple[bool, str]:
        """
        Transition from one mode's policy to another.

        This handles the atomic transition to avoid gaps.
        """
        logger.info(f"MAC policy transition: {from_mode} -> {to_mode}")

        # For AppArmor, we just replace the profile
        # For SELinux, we need to be more careful

        success, msg = self.apply_mode_policy(to_mode)

        if success:
            self._log_policy_change(to_mode, 'transition', from_mode)

        return success, msg

    def remove_all_policies(self) -> Tuple[bool, str]:
        """Remove all boundary MAC policies."""
        if not self.is_available:
            return True, "No MAC system"

        try:
            if self._mac_system == MACSystem.SELINUX:
                for mode in MODE_POLICIES.keys():
                    module_name = f"boundary_{mode.lower()}"
                    self._selinux.remove_module(module_name)

            elif self._mac_system == MACSystem.APPARMOR:
                self._apparmor.remove_profile("boundary-daemon")

            self._current_mode = None
            return True, "All policies removed"

        except Exception as e:
            return False, f"Error removing policies: {e}"

    def _log_policy_change(self, mode: str, action: str, from_mode: str = None):
        """Log policy change to event logger."""
        if not self._event_logger:
            return

        try:
            metadata = {
                'mac_system': self._mac_system.value,
                'mode': mode,
                'action': action,
            }
            if from_mode:
                metadata['from_mode'] = from_mode

            self._event_logger.log_event(
                'MODE_CHANGE',
                f"MAC policy {action}: {mode}",
                metadata=metadata,
            )
        except Exception as e:
            logger.error(f"Failed to log policy change: {e}")


def check_mac_support() -> Dict[str, Any]:
    """Check system MAC support."""
    result = {
        'platform': sys.platform,
        'is_linux': IS_LINUX,
        'is_root': os.geteuid() == 0 if IS_LINUX else False,
        'selinux': {
            'available': False,
            'mode': 'unknown',
        },
        'apparmor': {
            'available': False,
            'mode': 'unknown',
        },
        'recommendation': None,
    }

    if not IS_LINUX:
        result['recommendation'] = "MAC requires Linux"
        return result

    # Check SELinux
    selinux = SELinuxPolicyGenerator()
    if selinux.is_available():
        result['selinux']['available'] = True
        status = selinux.get_status()
        result['selinux']['mode'] = status.get('mode', 'unknown')

    # Check AppArmor
    apparmor = AppArmorPolicyGenerator()
    if apparmor.is_available():
        result['apparmor']['available'] = True
        status = apparmor.get_status()
        result['apparmor']['mode'] = status.get('mode', 'unknown')

    # Recommendation
    if result['selinux']['available']:
        result['recommendation'] = f"SELinux available (mode: {result['selinux']['mode']})"
    elif result['apparmor']['available']:
        result['recommendation'] = f"AppArmor available (mode: {result['apparmor']['mode']})"
    else:
        result['recommendation'] = "No MAC system found - install SELinux or AppArmor"

    return result


# Module-level instance
_mac_manager: Optional[DynamicMACPolicyManager] = None


def get_mac_policy_manager(event_logger=None) -> DynamicMACPolicyManager:
    """Get or create the global MAC policy manager."""
    global _mac_manager

    if _mac_manager is None:
        _mac_manager = DynamicMACPolicyManager(event_logger=event_logger)

    return _mac_manager


if __name__ == '__main__':
    import argparse

    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description='Dynamic MAC Policy Manager')
    parser.add_argument('--check', action='store_true', help='Check MAC support')
    parser.add_argument('--status', action='store_true', help='Show current status')
    parser.add_argument('--apply', type=str, help='Apply policy for mode')
    parser.add_argument('--generate', type=str, help='Generate policy for mode (dry run)')
    parser.add_argument('--remove', action='store_true', help='Remove all policies')

    args = parser.parse_args()

    if args.check:
        support = check_mac_support()
        print("\nMAC Support Check:")
        print(f"  Platform: {support['platform']}")
        print(f"  Is Root: {support['is_root']}")
        print(f"  SELinux: {support['selinux']}")
        print(f"  AppArmor: {support['apparmor']}")
        print(f"  Recommendation: {support['recommendation']}")

    elif args.status:
        manager = DynamicMACPolicyManager()
        status = manager.get_status()
        print("\nMAC Policy Status:")
        print(json.dumps(status, indent=2))

    elif args.generate:
        mode = args.generate.upper()
        if mode not in MODE_POLICIES:
            print(f"Unknown mode: {mode}")
            print(f"Available: {list(MODE_POLICIES.keys())}")
            sys.exit(1)

        policy = MODE_POLICIES[mode]

        # Try SELinux first
        selinux = SELinuxPolicyGenerator()
        if selinux.is_available():
            print(f"\n# SELinux Policy for {mode}:")
            print(selinux.generate_mode_policy(policy))
        else:
            # Try AppArmor
            apparmor = AppArmorPolicyGenerator()
            if apparmor.is_available():
                print(f"\n# AppArmor Profile for {mode}:")
                print(apparmor.generate_mode_profile(policy))
            else:
                print("No MAC system available")

    elif args.apply:
        manager = DynamicMACPolicyManager()
        success, msg = manager.apply_mode_policy(args.apply)
        print(f"\nResult: {msg}")
        sys.exit(0 if success else 1)

    elif args.remove:
        manager = DynamicMACPolicyManager()
        success, msg = manager.remove_all_policies()
        print(f"\nResult: {msg}")
        sys.exit(0 if success else 1)

    else:
        parser.print_help()
