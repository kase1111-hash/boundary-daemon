#!/usr/bin/env python3
"""
Enforcement Module Integration Tests

Tests the kernel-level enforcement capabilities on Linux systems.
These tests require root privileges and are designed to run in Docker
or other isolated environments.

Run with Docker:
    docker run --privileged -v $(pwd):/app python:3.11 \
        bash -c "cd /app && pip install -r requirements.txt && pytest tests/integration/test_enforcement_integration.py -v"

Run locally (requires root):
    sudo pytest tests/integration/test_enforcement_integration.py -v

Skip enforcement tests:
    pytest tests/integration/test_enforcement_integration.py -v -k "not requires_root"
"""

import os
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import pytest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

# Platform detection
IS_LINUX = sys.platform.startswith('linux')
IS_ROOT = os.geteuid() == 0 if IS_LINUX else False
HAS_IPTABLES = IS_LINUX and os.path.exists('/sbin/iptables')
HAS_SECCOMP = IS_LINUX and os.path.exists('/proc/sys/kernel/seccomp')

# Import feature detection
try:
    from daemon.features import FEATURES, is_enforcement_available
    FEATURES_AVAILABLE = True
except ImportError:
    FEATURES_AVAILABLE = False
    is_enforcement_available = lambda: False


def requires_root(func):
    """Decorator to skip tests that require root privileges."""
    return pytest.mark.skipif(
        not IS_ROOT,
        reason="Test requires root privileges"
    )(func)


def requires_linux(func):
    """Decorator to skip tests that require Linux."""
    return pytest.mark.skipif(
        not IS_LINUX,
        reason="Test requires Linux"
    )(func)


def requires_iptables(func):
    """Decorator to skip tests that require iptables."""
    return pytest.mark.skipif(
        not HAS_IPTABLES,
        reason="Test requires iptables"
    )(func)


class TestFeatureDetection(unittest.TestCase):
    """Test the feature detection system."""

    def test_feature_module_loads(self):
        """Feature detection module should load without errors."""
        self.assertTrue(FEATURES_AVAILABLE, "features.py should be importable")

    @requires_linux
    def test_linux_features_detected(self):
        """On Linux, platform-specific features should be detected."""
        if FEATURES_AVAILABLE:
            # Features are accessed via get_info/get_all, not as direct attributes
            all_features = FEATURES.get_all()
            self.assertIsInstance(all_features, dict)
            self.assertGreater(len(all_features), 0)

    def test_feature_status_report(self):
        """Feature status report should be generatable."""
        if FEATURES_AVAILABLE:
            from daemon.features import get_feature_status
            status = get_feature_status()
            self.assertIsInstance(status, dict)
            self.assertGreater(len(status), 0)


@pytest.mark.integration
class TestNetworkEnforcement(unittest.TestCase):
    """Test network enforcement capabilities."""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures."""
        cls.skip_enforcement = not is_enforcement_available()
        if cls.skip_enforcement:
            return

        try:
            from daemon.enforcement import NetworkEnforcer
            cls.NetworkEnforcer = NetworkEnforcer
        except ImportError:
            cls.skip_enforcement = True

    def setUp(self):
        if self.skip_enforcement:
            self.skipTest("Network enforcement not available")

    @requires_root
    @requires_linux
    @requires_iptables
    def test_network_enforcer_initialization(self):
        """NetworkEnforcer should initialize on Linux with root."""
        enforcer = self.NetworkEnforcer()
        self.assertIsNotNone(enforcer)

    @requires_root
    @requires_linux
    @requires_iptables
    def test_enforce_airgap_mode_creates_rules(self):
        """Enforcing AIRGAP mode should create iptables rules."""
        from daemon.policy_engine import BoundaryMode

        enforcer = self.NetworkEnforcer()

        if not enforcer.is_available:
            self.skipTest("Network enforcement not available (no working firewall backend)")

        try:
            # Enforce AIRGAP mode (blocks all network except loopback)
            success, msg = enforcer.enforce_mode(BoundaryMode.AIRGAP, reason="test")
            self.assertTrue(success, f"enforce_mode should succeed: {msg}")

            # Verify rules were applied
            status = enforcer.get_status()
            self.assertTrue(status['rules_applied'], "Rules should be applied")
            self.assertEqual(status['current_mode'], 'AIRGAP')

        finally:
            # Clean up
            try:
                enforcer.cleanup(force=True)
            except Exception:
                pass

    @requires_root
    @requires_linux
    @requires_iptables
    def test_enforce_lockdown_mode_creates_rules(self):
        """Enforcing LOCKDOWN mode should create iptables rules that block all traffic."""
        from daemon.policy_engine import BoundaryMode

        enforcer = self.NetworkEnforcer()

        if not enforcer.is_available:
            self.skipTest("Network enforcement not available (no working firewall backend)")

        try:
            success, msg = enforcer.enforce_mode(BoundaryMode.LOCKDOWN, reason="test")
            self.assertTrue(success, f"enforce_mode should succeed: {msg}")

            # Verify rules were applied
            status = enforcer.get_status()
            self.assertTrue(status['rules_applied'], "Rules should be applied")
            self.assertEqual(status['current_mode'], 'LOCKDOWN')

        finally:
            try:
                enforcer.cleanup(force=True)
            except Exception:
                pass

    @requires_linux
    def test_network_enforcer_graceful_degradation(self):
        """NetworkEnforcer should degrade gracefully without root."""
        if IS_ROOT:
            self.skipTest("Test requires non-root user")

        try:
            from daemon.enforcement import NetworkEnforcer
            enforcer = NetworkEnforcer()
            # Should not raise, but enforcement may be disabled
            self.assertIsNotNone(enforcer)
        except PermissionError:
            # This is acceptable - clear failure on permission issues
            pass


@pytest.mark.integration
class TestUSBEnforcement(unittest.TestCase):
    """Test USB enforcement capabilities."""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures."""
        cls.skip_enforcement = not is_enforcement_available()
        if cls.skip_enforcement:
            return

        try:
            from daemon.enforcement import USBEnforcer
            cls.USBEnforcer = USBEnforcer
        except ImportError:
            cls.skip_enforcement = True

    def setUp(self):
        if self.skip_enforcement:
            self.skipTest("USB enforcement not available")

    @requires_root
    @requires_linux
    def test_usb_enforcer_initialization(self):
        """USBEnforcer should initialize on Linux with root."""
        enforcer = self.USBEnforcer()
        self.assertIsNotNone(enforcer)

    @requires_linux
    def test_usb_device_listing(self):
        """Should be able to list USB devices."""
        if not IS_LINUX:
            self.skipTest("USB listing requires Linux")

        try:
            from daemon.enforcement import USBEnforcer
            enforcer = USBEnforcer()
            devices = enforcer.get_connected_devices()
            self.assertIsInstance(devices, list)
        except (ImportError, PermissionError):
            # Acceptable - may not have permission to list
            pass


@pytest.mark.integration
class TestProcessEnforcement(unittest.TestCase):
    """Test process enforcement capabilities."""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures."""
        cls.skip_enforcement = not is_enforcement_available()
        if cls.skip_enforcement:
            return

        try:
            from daemon.enforcement import ProcessEnforcer
            cls.ProcessEnforcer = ProcessEnforcer
        except ImportError:
            cls.skip_enforcement = True

    def setUp(self):
        if self.skip_enforcement:
            self.skipTest("Process enforcement not available")

    @requires_root
    @requires_linux
    def test_process_enforcer_initialization(self):
        """ProcessEnforcer should initialize on Linux with root."""
        enforcer = self.ProcessEnforcer()
        self.assertIsNotNone(enforcer)

    @requires_linux
    def test_seccomp_availability_check(self):
        """Should correctly detect seccomp availability."""
        if not IS_LINUX:
            self.skipTest("seccomp requires Linux")

        try:
            from daemon.enforcement import ProcessEnforcer
            enforcer = ProcessEnforcer()
            # is_available property checks seccomp and container runtime
            is_avail = enforcer.is_available
            self.assertIsInstance(is_avail, bool)
            # get_status returns detailed enforcement status
            status = enforcer.get_status()
            self.assertIsInstance(status, dict)
        except ImportError:
            pass


@pytest.mark.integration
class TestPrivilegeManager(unittest.TestCase):
    """Test privilege manager integration."""

    def test_privilege_manager_loads(self):
        """PrivilegeManager should be importable."""
        try:
            from daemon.privilege_manager import PrivilegeManager
            self.assertIsNotNone(PrivilegeManager)
        except ImportError:
            self.skipTest("PrivilegeManager not available")

    @requires_linux
    def test_privilege_check_on_linux(self):
        """Privilege checks should work on Linux."""
        try:
            from daemon.privilege_manager import PrivilegeManager, EnforcementModule
            pm = PrivilegeManager()

            # Register network module and check overall status
            pm.register_module(EnforcementModule.NETWORK, is_available=True, reason="test")
            status = pm.get_status()
            self.assertIsNotNone(status)
            self.assertIsInstance(status.modules_available, dict)
            self.assertIn('network', status.modules_available)

        except ImportError:
            self.skipTest("PrivilegeManager not available")


@pytest.mark.integration
class TestEnforcementEndToEnd(unittest.TestCase):
    """End-to-end enforcement tests."""

    @requires_root
    @requires_linux
    @requires_iptables
    def test_mode_based_network_enforcement(self):
        """Network enforcement should activate based on boundary mode."""
        if not is_enforcement_available():
            self.skipTest("Enforcement not available")

        try:
            from daemon.enforcement import NetworkEnforcer
            from daemon.policy_engine import BoundaryMode

            enforcer = NetworkEnforcer()

            if not enforcer.is_available:
                self.skipTest("Network enforcement not available (no working firewall backend)")

            # In AIRGAP mode, network should be restricted
            # This test verifies the enforcer responds to mode changes
            success, msg = enforcer.enforce_mode(BoundaryMode.AIRGAP, reason="test")
            self.assertTrue(success, f"enforce_mode should succeed: {msg}")

            # Verify some network restriction is in place
            status = enforcer.get_status()
            self.assertIsNotNone(status)
            self.assertEqual(status['current_mode'], 'AIRGAP')

            # Cleanup
            enforcer.cleanup(force=True)

        except ImportError as e:
            self.skipTest(f"Required modules not available: {e}")

    @requires_root
    @requires_linux
    def test_enforcement_persistence(self):
        """Enforcement rules should persist until explicitly cleared."""
        if not is_enforcement_available():
            self.skipTest("Enforcement not available")

        try:
            from daemon.enforcement import ProtectionPersistenceManager
            from daemon.enforcement.protection_persistence import (
                ProtectionType, PersistenceReason
            )

            with tempfile.TemporaryDirectory() as tmpdir:
                persistence = ProtectionPersistenceManager(state_dir=tmpdir)

                # Persist a protection
                success, msg = persistence.persist_protection(
                    protection_type=ProtectionType.NETWORK_FIREWALL,
                    mode='AIRGAP',
                    reason=PersistenceReason.MODE_CHANGE,
                )
                self.assertTrue(success, f"persist_protection should succeed: {msg}")

                # Load it back via should_reapply_protection
                protection = persistence.should_reapply_protection(
                    ProtectionType.NETWORK_FIREWALL
                )
                self.assertIsNotNone(protection, "Protection should be reapplyable")
                self.assertEqual(protection.mode, 'AIRGAP')

        except ImportError as e:
            self.skipTest(f"ProtectionPersistenceManager not available: {e}")


class TestEnforcementMocking(unittest.TestCase):
    """Tests using mocks for non-root environments."""

    def test_network_enforcer_with_mock_iptables(self):
        """Test NetworkEnforcer logic with mocked iptables."""
        if not IS_LINUX:
            self.skipTest("Requires Linux for mock testing")

        try:
            from daemon.enforcement.network_enforcer import (
                NetworkEnforcer, FirewallBackend
            )
            from daemon.policy_engine import BoundaryMode

            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(returncode=0)

                enforcer = NetworkEnforcer()
                enforcer._backend = FirewallBackend.IPTABLES
                enforcer._has_root = True
                enforcer._enforcement_degraded = False

                # enforce_mode should call iptables via subprocess
                enforcer.enforce_mode(BoundaryMode.AIRGAP, reason="test")

                # Verify subprocess was called (for iptables commands)
                self.assertTrue(mock_run.called)

        except ImportError:
            self.skipTest("NetworkEnforcer not available")

    def test_enforcement_disabled_without_privileges(self):
        """Enforcement should clearly indicate when disabled."""
        if not IS_LINUX:
            self.skipTest("Requires Linux")

        try:
            from daemon.enforcement.network_enforcer import NetworkEnforcer

            with patch('os.geteuid', return_value=65534):
                enforcer = NetworkEnforcer()
                # Should indicate enforcement is not active
                self.assertFalse(enforcer._has_root)
                # is_available should also be False
                self.assertFalse(enforcer.is_available)

        except ImportError:
            self.skipTest("NetworkEnforcer not available")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
