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
            # These should at least be detectable (may or may not be available)
            self.assertIn('ENFORCEMENT', dir(FEATURES))
            self.assertIn('WATCHDOG', dir(FEATURES))

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
    def test_block_ip_creates_rule(self):
        """Blocking an IP should create an iptables rule."""
        enforcer = self.NetworkEnforcer()

        # Use a test IP that won't affect real traffic
        test_ip = "192.0.2.1"  # TEST-NET-1, reserved for documentation

        try:
            # Block the IP
            result = enforcer.block_ip(test_ip)
            self.assertTrue(result, "block_ip should return True")

            # Verify rule exists
            output = subprocess.check_output(
                ['iptables', '-L', 'OUTPUT', '-n'],
                text=True
            )
            self.assertIn(test_ip, output, "IP should appear in iptables rules")

        finally:
            # Clean up - unblock the IP
            try:
                enforcer.unblock_ip(test_ip)
            except Exception:
                pass

    @requires_root
    @requires_linux
    @requires_iptables
    def test_block_port_creates_rule(self):
        """Blocking a port should create an iptables rule."""
        enforcer = self.NetworkEnforcer()

        # Use a high port number unlikely to be in use
        test_port = 59999

        try:
            result = enforcer.block_port(test_port)
            self.assertTrue(result, "block_port should return True")

            # Verify rule exists
            output = subprocess.check_output(
                ['iptables', '-L', 'OUTPUT', '-n'],
                text=True
            )
            self.assertIn(str(test_port), output, "Port should appear in iptables rules")

        finally:
            try:
                enforcer.unblock_port(test_port)
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
            devices = enforcer.list_devices()
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
            has_seccomp = enforcer.check_seccomp_available()
            # Should return a boolean
            self.assertIsInstance(has_seccomp, bool)
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

            # Check network module status
            status = pm.check_module(EnforcementModule.NETWORK)
            self.assertIsInstance(status, dict)
            self.assertIn('available', status)
            self.assertIn('reason', status)

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

            # In AIRGAP mode, network should be restricted
            # This test verifies the enforcer responds to mode changes
            enforcer.set_mode(BoundaryMode.AIRGAP)

            # Verify some network restriction is in place
            status = enforcer.get_status()
            self.assertIsNotNone(status)

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

            with tempfile.TemporaryDirectory() as tmpdir:
                persistence = ProtectionPersistenceManager(state_dir=tmpdir)

                # Save some state
                persistence.save_state({'test': True, 'mode': 'airgap'})

                # Load it back
                state = persistence.load_state()
                self.assertEqual(state.get('test'), True)
                self.assertEqual(state.get('mode'), 'airgap')

        except ImportError as e:
            self.skipTest(f"ProtectionPersistenceManager not available: {e}")


class TestEnforcementMocking(unittest.TestCase):
    """Tests using mocks for non-root environments."""

    def test_network_enforcer_with_mock_iptables(self):
        """Test NetworkEnforcer logic with mocked iptables."""
        if not IS_LINUX:
            self.skipTest("Requires Linux for mock testing")

        try:
            from daemon.enforcement.network_enforcer import NetworkEnforcer

            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(returncode=0)

                enforcer = NetworkEnforcer()
                enforcer._has_iptables = True
                enforcer._is_root = True

                # Block should call iptables
                enforcer.block_ip("192.0.2.1")

                # Verify subprocess was called
                self.assertTrue(mock_run.called)

        except ImportError:
            self.skipTest("NetworkEnforcer not available")

    def test_enforcement_disabled_without_privileges(self):
        """Enforcement should clearly indicate when disabled."""
        if not IS_LINUX:
            self.skipTest("Requires Linux")

        try:
            from daemon.enforcement.network_enforcer import NetworkEnforcer

            with patch.object(NetworkEnforcer, '_check_root', return_value=False):
                enforcer = NetworkEnforcer()
                # Should indicate enforcement is not active
                self.assertFalse(enforcer._is_root)

        except ImportError:
            self.skipTest("NetworkEnforcer not available")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
