"""
Tests for nftables script generation in enforcement modules.

Regression tests for a bug where _run_nft collapsed ALL whitespace
(including newlines) in multi-statement nft scripts, merging every
statement onto one unparseable line. Since nft separates statements by
newline, this made the entire nftables backend fail: boundary modes
(AIRGAP, LOCKDOWN, ...) could not apply firewall rules, and sandbox
network policies were silently unenforced (the cgroup jump rule was
added with ignore_errors=True).

Also covers:
- rule statements must carry the 'inet' family (a bare
  'add rule <table> ...' targets the 'ip' family, where the table
  does not exist)
- nft set elements (VPN interfaces) must be comma-separated
"""

import sys
import os
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.enforcement.network_enforcer import NetworkEnforcer, FirewallBackend
from daemon.policy_engine import BoundaryMode


def _make_nft_enforcer():
    """Build a NetworkEnforcer forced onto the nftables backend."""
    enforcer = NetworkEnforcer.__new__(NetworkEnforcer)
    enforcer.daemon = None
    enforcer.event_logger = None
    enforcer.persistence_manager = None
    import threading
    enforcer._lock = threading.Lock()
    enforcer._backend = FirewallBackend.NFTABLES
    enforcer._has_root = True
    enforcer._rules_applied = False
    enforcer._current_mode = None
    enforcer._vpn_interfaces = ['tun0', 'wg0']
    return enforcer


def _completed(returncode=0):
    result = MagicMock()
    result.returncode = returncode
    result.stderr = b''
    result.stdout = b''
    return result


@pytest.mark.security
class TestRunNftScriptFormatting:
    """_run_nft must preserve statement boundaries (newlines)."""

    def test_multiline_script_keeps_newlines(self):
        enforcer = _make_nft_enforcer()
        captured = {}

        def fake_run(cmd, **kwargs):
            captured['input'] = kwargs.get('input', b'').decode()
            return _completed()

        with patch('daemon.enforcement.network_enforcer.subprocess.run', side_effect=fake_run):
            enforcer._run_nft('''
                add table inet t
                add chain inet t c { type filter hook output priority 0; policy accept; }
            ''')

        lines = captured['input'].splitlines()
        assert len(lines) == 2, f"statements must stay on separate lines: {captured['input']!r}"
        assert lines[0] == 'add table inet t'
        assert lines[1].startswith('add chain inet t c')

    def test_indentation_collapsed_within_lines(self):
        enforcer = _make_nft_enforcer()
        captured = {}

        def fake_run(cmd, **kwargs):
            captured['input'] = kwargs.get('input', b'').decode()
            return _completed()

        with patch('daemon.enforcement.network_enforcer.subprocess.run', side_effect=fake_run):
            enforcer._run_nft('   add   table   inet   t   ')

        assert captured['input'] == 'add table inet t'


@pytest.mark.security
class TestNftModeRules:
    """Generated mode rules must be valid for the inet table."""

    def _collect_nft_input(self, enforcer, mode):
        scripts = []

        def fake_run(cmd, **kwargs):
            if cmd[:2] == ['nft', '-f']:
                scripts.append(kwargs.get('input', b'').decode())
            return _completed()

        with patch('daemon.enforcement.network_enforcer.subprocess.run', side_effect=fake_run):
            apply_fn = {
                BoundaryMode.RESTRICTED: enforcer._apply_restricted_mode,
                BoundaryMode.TRUSTED: enforcer._apply_trusted_mode,
                BoundaryMode.AIRGAP: enforcer._apply_airgap_mode,
                BoundaryMode.LOCKDOWN: enforcer._apply_lockdown_mode,
            }[mode]
            apply_fn()
        return '\n'.join(scripts)

    @pytest.mark.parametrize('mode', [
        BoundaryMode.RESTRICTED,
        BoundaryMode.TRUSTED,
        BoundaryMode.AIRGAP,
        BoundaryMode.LOCKDOWN,
    ])
    def test_rule_statements_use_inet_family(self, mode):
        enforcer = _make_nft_enforcer()
        script = self._collect_nft_input(enforcer, mode)
        for line in script.splitlines():
            if line.startswith('add rule'):
                assert line.startswith(f'add rule inet {enforcer.NFT_TABLE}'), (
                    f"rule missing inet family (would target 'ip' table): {line!r}"
                )

    def test_trusted_mode_vpn_set_is_comma_separated(self):
        enforcer = _make_nft_enforcer()
        script = self._collect_nft_input(enforcer, BoundaryMode.TRUSTED)
        assert '{ "tun0", "wg0" }' in script

    def test_trusted_mode_empty_vpn_list_emits_no_empty_set(self):
        enforcer = _make_nft_enforcer()
        enforcer._vpn_interfaces = []
        script = self._collect_nft_input(enforcer, BoundaryMode.TRUSTED)
        assert '{ }' not in script and '{}' not in script


@pytest.mark.security
class TestSandboxFirewallNft:
    """Sandbox firewall nft handling must not silently fail open."""

    def _make_firewall(self):
        from daemon.sandbox.network_policy import SandboxFirewall, FirewallBackend as SbxBackend
        import threading
        fw = SandboxFirewall.__new__(SandboxFirewall)
        fw._lock = threading.Lock()
        fw._backend = SbxBackend.NFTABLES
        fw._has_root = True
        fw._has_cgroup_match = True
        fw._active_sandboxes = {}
        return fw

    def test_run_nft_keeps_newlines(self):
        fw = self._make_firewall()
        captured = {}

        def fake_run(cmd, **kwargs):
            captured['input'] = kwargs.get('input', b'').decode()
            return _completed()

        with patch('daemon.sandbox.network_policy.subprocess.run', side_effect=fake_run):
            fw._run_nft('''
                add table inet t
                add chain inet t c
            ''')

        assert captured['input'].splitlines() == ['add table inet t', 'add chain inet t c']

    def test_jump_rule_failure_raises(self):
        """A failed cgroup jump rule must raise, not be silently ignored:
        without the jump rule the sandbox policy is unenforced."""
        from pathlib import Path
        from daemon.sandbox.network_policy import NetworkPolicy

        fw = self._make_firewall()

        def fake_run(cmd, **kwargs):
            script = kwargs.get('input', b'').decode()
            if 'jump' in script:
                result = _completed(returncode=1)
                result.stderr = b'Error: syntax error'
                return result
            return _completed()

        with patch('daemon.sandbox.network_policy.subprocess.run', side_effect=fake_run):
            policy = NetworkPolicy(deny_all=True)
            with pytest.raises(RuntimeError):
                fw._setup_nftables_rules('sbx', Path('/sys/fs/cgroup/test'), policy)
