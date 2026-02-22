"""
Tests for the State Monitor module.

Tests environment sensing, network detection, and state tracking.
"""

import os
import sys
import threading
import time
from datetime import datetime
from unittest.mock import MagicMock

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.state_monitor import (
    StateMonitor,
    MonitoringConfig,
    EnvironmentState,
    SpecialtyNetworkStatus,
    NetworkState,
    NetworkType,
    CellularSecurityAlert,
    HardwareTrust,
)


# ===========================================================================
# Enum Tests
# ===========================================================================

class TestNetworkState:
    def test_network_state_values(self):
        assert NetworkState.OFFLINE.value == "offline"
        assert NetworkState.ONLINE.value == "online"

    def test_network_state_members(self):
        assert len(NetworkState) == 2


class TestNetworkType:
    def test_network_type_common_values(self):
        assert NetworkType.ETHERNET.value == "ethernet"
        assert NetworkType.WIFI.value == "wifi"
        assert NetworkType.VPN.value == "vpn"
        assert NetworkType.CELLULAR_4G.value == "cellular_4g"
        assert NetworkType.CELLULAR_5G.value == "cellular_5g"

    def test_network_type_iot_values(self):
        assert NetworkType.LORA.value == "lora"
        assert NetworkType.THREAD.value == "thread"
        assert NetworkType.ANT_PLUS.value == "ant_plus"

    def test_network_type_unknown(self):
        assert NetworkType.UNKNOWN.value == "unknown"


class TestCellularSecurityAlert:
    """Tests for CellularSecurityAlert enum."""

    def test_cellular_alert_values(self):
        """CellularSecurityAlert should have expected values."""
        assert CellularSecurityAlert.NONE.value == "none"
        assert CellularSecurityAlert.TOWER_CHANGE.value == "tower_change"
        assert CellularSecurityAlert.WEAK_ENCRYPTION.value == "weak_encryption"
        assert CellularSecurityAlert.SIGNAL_ANOMALY.value == "signal_anomaly"
        assert CellularSecurityAlert.IMSI_CATCHER.value == "imsi_catcher"
        assert CellularSecurityAlert.DOWNGRADE_ATTACK.value == "downgrade_attack"


class TestHardwareTrust:
    def test_hardware_trust_values(self):
        assert HardwareTrust.LOW.value == "low"
        assert HardwareTrust.MEDIUM.value == "medium"
        assert HardwareTrust.HIGH.value == "high"


# ===========================================================================
# MonitoringConfig Tests
# ===========================================================================

class TestMonitoringConfig:
    def test_default_config(self):
        config = MonitoringConfig()
        assert config.monitor_lora is True
        assert config.monitor_thread is True
        assert config.monitor_cellular_security is True
        assert config.monitor_wimax is False  # Disabled by default (obsolete)
        assert config.monitor_irda is False   # Disabled by default (legacy)
        assert config.monitor_ant_plus is True

    def test_security_monitoring_defaults(self):
        """Security monitoring should be enabled by default."""
        config = MonitoringConfig()
        assert config.monitor_dns_security is True
        assert config.monitor_arp_security is True
        assert config.monitor_wifi_security is True
        assert config.monitor_threat_intel is True
        assert config.monitor_file_integrity is True
        assert config.monitor_traffic_anomaly is True
        assert config.monitor_process_security is True

    def test_custom_config(self):
        config = MonitoringConfig(
            monitor_lora=False,
            monitor_wimax=True,
            monitor_dns_security=False,
        )
        assert config.monitor_lora is False
        assert config.monitor_wimax is True
        assert config.monitor_dns_security is False

    def test_to_dict(self):
        config = MonitoringConfig()
        d = config.to_dict()
        assert 'monitor_lora' in d
        assert 'monitor_thread' in d
        assert 'monitor_cellular_security' in d
        assert 'monitor_dns_security' in d
        assert isinstance(d['monitor_lora'], bool)


# ===========================================================================
# SpecialtyNetworkStatus Tests
# ===========================================================================

class TestSpecialtyNetworkStatus:
    def test_creation(self):
        status = SpecialtyNetworkStatus(
            lora_devices=['lora0'],
            thread_devices=[],
            wimax_interfaces=[],
            irda_devices=[],
            ant_plus_devices=['ant0'],
            cellular_alerts=['tower_change'],
        )
        assert status.lora_devices == ['lora0']
        assert status.ant_plus_devices == ['ant0']
        assert status.cellular_alerts == ['tower_change']

    def test_to_dict(self):
        status = SpecialtyNetworkStatus(
            lora_devices=[],
            thread_devices=['thread0'],
            wimax_interfaces=[],
            irda_devices=[],
            ant_plus_devices=[],
            cellular_alerts=[],
        )
        d = status.to_dict()
        assert 'lora_devices' in d
        assert 'thread_devices' in d
        assert d['thread_devices'] == ['thread0']


# ===========================================================================
# EnvironmentState Tests
# ===========================================================================

class TestEnvironmentState:
    @pytest.fixture
    def sample_specialty_networks(self):
        return SpecialtyNetworkStatus(
            lora_devices=[],
            thread_devices=[],
            wimax_interfaces=[],
            irda_devices=[],
            ant_plus_devices=[],
            cellular_alerts=[],
        )

    @pytest.fixture
    def sample_environment_state(self, sample_specialty_networks):
        return EnvironmentState(
            timestamp=datetime.utcnow().isoformat() + "Z",
            network=NetworkState.OFFLINE,
            hardware_trust=HardwareTrust.HIGH,
            active_interfaces=['lo'],
            interface_types={'lo': NetworkType.UNKNOWN},
            has_internet=False,
            vpn_active=False,
            dns_available=False,
            specialty_networks=sample_specialty_networks,
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
            tpm_present=True,
            external_model_endpoints=[],
            suspicious_processes=[],
            shell_escapes_detected=0,
            keyboard_active=True,
            screen_unlocked=True,
            last_activity=None,
        )

    def test_environment_state_creation(self, sample_environment_state):
        assert sample_environment_state.network == NetworkState.OFFLINE
        assert sample_environment_state.hardware_trust == HardwareTrust.HIGH
        assert sample_environment_state.tpm_present is True

    def test_environment_state_to_dict(self, sample_environment_state):
        d = sample_environment_state.to_dict()
        assert d['network'] == 'offline'
        assert d['hardware_trust'] == 'high'
        assert 'active_interfaces' in d
        assert 'usb_devices' in d
        assert isinstance(d['usb_devices'], list)


# ===========================================================================
# StateMonitor Initialization Tests
# ===========================================================================

class TestStateMonitorInit:
    def test_init_default(self):
        monitor = StateMonitor()
        assert monitor.poll_interval == 1.0
        assert monitor._running is False
        assert monitor._current_state is None

    def test_init_custom_interval(self):
        monitor = StateMonitor(poll_interval=0.5)
        assert monitor.poll_interval == 0.5

    def test_init_with_config(self):
        config = MonitoringConfig(monitor_lora=False)
        monitor = StateMonitor(monitoring_config=config)
        assert monitor.monitoring_config.monitor_lora is False

    def test_default_monitoring_config(self):
        monitor = StateMonitor()
        assert isinstance(monitor.monitoring_config, MonitoringConfig)


# ===========================================================================
# StateMonitor Configuration Tests
# ===========================================================================

class TestStateMonitorConfig:
    def test_get_monitoring_config(self):
        config = MonitoringConfig(monitor_lora=False)
        monitor = StateMonitor(monitoring_config=config)
        assert monitor.get_monitoring_config() == config

    def test_set_monitoring_config(self):
        monitor = StateMonitor()
        new_config = MonitoringConfig(monitor_lora=False)
        monitor.set_monitoring_config(new_config)
        assert monitor.monitoring_config.monitor_lora is False

    def test_set_monitor_lora(self):
        monitor = StateMonitor()
        monitor.set_monitor_lora(False)
        assert monitor.monitoring_config.monitor_lora is False
        monitor.set_monitor_lora(True)
        assert monitor.monitoring_config.monitor_lora is True

    def test_set_monitor_thread(self):
        monitor = StateMonitor()
        monitor.set_monitor_thread(False)
        assert monitor.monitoring_config.monitor_thread is False

    def test_set_monitor_cellular_security(self):
        """set_monitor_cellular_security should update cellular monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_cellular_security(False)
        assert monitor.monitoring_config.monitor_cellular_security is False

    def test_set_monitor_wimax(self):
        monitor = StateMonitor()
        monitor.set_monitor_wimax(True)
        assert monitor.monitoring_config.monitor_wimax is True

    def test_set_monitor_irda(self):
        monitor = StateMonitor()
        monitor.set_monitor_irda(True)
        assert monitor.monitoring_config.monitor_irda is True

    def test_set_monitor_ant_plus(self):
        """set_monitor_ant_plus should update ANT+ monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_ant_plus(False)
        assert monitor.monitoring_config.monitor_ant_plus is False

    def test_set_monitor_dns_security(self):
        """set_monitor_dns_security should update DNS security monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_dns_security(False)
        assert monitor.monitoring_config.monitor_dns_security is False

    def test_set_monitor_arp_security(self):
        """set_monitor_arp_security should update ARP security monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_arp_security(False)
        assert monitor.monitoring_config.monitor_arp_security is False

    def test_set_monitor_wifi_security(self):
        """set_monitor_wifi_security should update WiFi security monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_wifi_security(False)
        assert monitor.monitoring_config.monitor_wifi_security is False

    def test_set_monitor_threat_intel(self):
        monitor = StateMonitor()
        monitor.set_monitor_threat_intel(False)
        assert monitor.monitoring_config.monitor_threat_intel is False

    def test_set_monitor_file_integrity(self):
        monitor = StateMonitor()
        monitor.set_monitor_file_integrity(False)
        assert monitor.monitoring_config.monitor_file_integrity is False

    def test_set_monitor_traffic_anomaly(self):
        monitor = StateMonitor()
        monitor.set_monitor_traffic_anomaly(False)
        assert monitor.monitoring_config.monitor_traffic_anomaly is False

    def test_set_monitor_process_security(self):
        """set_monitor_process_security should update process security monitoring."""
        monitor = StateMonitor()
        monitor.set_monitor_process_security(False)
        assert monitor.monitoring_config.monitor_process_security is False


# ===========================================================================
# StateMonitor Callback Tests
# ===========================================================================

class TestStateMonitorCallbacks:
    def test_register_callback(self):
        monitor = StateMonitor()
        callback = MagicMock()
        monitor.register_callback(callback)
        assert callback in monitor._callbacks.values()

    def test_register_multiple_callbacks(self):
        """Multiple callbacks can be registered."""
        monitor = StateMonitor()
        callback1 = MagicMock()
        callback2 = MagicMock()
        monitor.register_callback(callback1)
        monitor.register_callback(callback2)
        assert len(monitor._callbacks) == 2


# ===========================================================================
# StateMonitor Start/Stop Tests
# ===========================================================================

class TestStateMonitorLifecycle:
    def test_start_sets_running(self):
        monitor = StateMonitor(poll_interval=10.0)  # Long interval to avoid rapid polling
        try:
            monitor.start()
            assert monitor._running is True
        finally:
            monitor.stop()

    def test_start_creates_thread(self):
        monitor = StateMonitor(poll_interval=10.0)
        try:
            monitor.start()
            assert monitor._thread is not None
            assert monitor._thread.is_alive()
        finally:
            monitor.stop()

    def test_start_idempotent(self):
        monitor = StateMonitor(poll_interval=10.0)
        try:
            monitor.start()
            first_thread = monitor._thread
            monitor.start()  # Second call
            assert monitor._thread is first_thread
        finally:
            monitor.stop()

    def test_stop_sets_not_running(self):
        monitor = StateMonitor(poll_interval=10.0)
        monitor.start()
        monitor.stop()
        assert monitor._running is False

    def test_stop_without_start(self):
        monitor = StateMonitor()
        monitor.stop()  # Should not raise


# ===========================================================================
# StateMonitor State Access Tests
# ===========================================================================

class TestStateMonitorStateAccess:
    def test_get_current_state_initially_none(self):
        monitor = StateMonitor()
        assert monitor.get_current_state() is None

    def test_get_current_state_thread_safe(self):
        monitor = StateMonitor()

        # Start monitor briefly
        monitor.start()
        time.sleep(0.1)  # Give it time to sample

        # Access state from multiple threads
        results = []
        def access_state():
            for _ in range(10):
                state = monitor.get_current_state()
                results.append(state)

        threads = [threading.Thread(target=access_state) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        monitor.stop()

        # Should have 30 results (10 per thread)
        assert len(results) == 30


# ===========================================================================
# StateMonitor Lazy Initialization Tests
# ===========================================================================

class TestStateMonitorLazyInit:
    """Tests for lazy initialization of security monitors."""

    def test_dns_security_monitor_lazy_init(self):
        """DNS security monitor should be lazily initialized."""
        monitor = StateMonitor()
        assert monitor._dns_security_monitor is None
        # Calling the getter should initialize it (or return None if import fails)
        result = monitor._get_dns_security_monitor()
        # After call, it should either be set or still None (if import fails)
        assert monitor._dns_security_monitor is result

    def test_arp_security_monitor_lazy_init(self):
        """ARP security monitor should be lazily initialized."""
        monitor = StateMonitor()
        assert monitor._arp_security_monitor is None

    def test_wifi_security_monitor_lazy_init(self):
        """WiFi security monitor should be lazily initialized."""
        monitor = StateMonitor()
        assert monitor._wifi_security_monitor is None

    def test_threat_intel_monitor_lazy_init(self):
        monitor = StateMonitor()
        assert monitor._threat_intel_monitor is None

    def test_file_integrity_monitor_lazy_init(self):
        monitor = StateMonitor()
        assert monitor._file_integrity_monitor is None

    def test_traffic_anomaly_monitor_lazy_init(self):
        monitor = StateMonitor()
        assert monitor._traffic_anomaly_monitor is None

    def test_process_security_monitor_lazy_init(self):
        """Process security monitor should be lazily initialized."""
        monitor = StateMonitor()
        assert monitor._process_security_monitor is None


# ===========================================================================
# StateMonitor Baseline Tracking Tests
# ===========================================================================

class TestStateMonitorBaseline:
    def test_baseline_usb_initially_none(self):
        monitor = StateMonitor()
        assert monitor._baseline_usb is None

    def test_baseline_block_devices_initially_none(self):
        monitor = StateMonitor()
        assert monitor._baseline_block_devices is None

    def test_last_network_state_initially_none(self):
        monitor = StateMonitor()
        assert monitor._last_network_state is None

    def test_cellular_security_tracking(self):
        """Cellular security tracking should be initialized."""
        monitor = StateMonitor()
        assert monitor._last_cell_tower is None
        assert len(monitor._cell_tower_history) == 0  # May be deque or list
        assert len(monitor._signal_strength_history) == 0  # May be deque or list


# ===========================================================================
# Integration Tests
# ===========================================================================

class TestStateMonitorIntegration:
    def test_full_lifecycle(self):
        callback_called = []
        def on_state_change(old, new):
            callback_called.append((old, new))

        monitor = StateMonitor(poll_interval=0.1)
        monitor.register_callback(on_state_change)

        # Start monitoring
        monitor.start()
        assert monitor._running is True

        # Wait for at least one sample
        time.sleep(0.3)

        # Should have a current state
        state = monitor.get_current_state()
        # State might be None in some test environments
        # but the monitor should have run without errors

        # Stop monitoring
        monitor.stop()
        assert monitor._running is False

    def test_config_changes_during_monitoring(self):
        """Configuration can be changed during monitoring."""
        monitor = StateMonitor(poll_interval=0.1)
        monitor.start()

        # Change config while running
        monitor.set_monitor_lora(False)
        assert monitor.monitoring_config.monitor_lora is False

        monitor.set_monitor_dns_security(False)
        assert monitor.monitoring_config.monitor_dns_security is False

        monitor.stop()


# ===========================================================================
# Edge Cases
# ===========================================================================

class TestStateMonitorEdgeCases:
    def test_zero_poll_interval(self):
        monitor = StateMonitor(poll_interval=0.01)
        monitor.start()
        time.sleep(0.1)
        monitor.stop()
        # Should not crash

    def test_callback_error_handling(self):
        def bad_callback(old, new):
            raise ValueError("Intentional error")

        monitor = StateMonitor(poll_interval=0.1)
        monitor.register_callback(bad_callback)
        monitor.start()
        time.sleep(0.3)
        monitor.stop()
        # Should not crash despite callback error

    def test_multiple_start_stop_cycles(self):
        monitor = StateMonitor(poll_interval=0.1)

        for _ in range(3):
            monitor.start()
            time.sleep(0.1)
            monitor.stop()
            time.sleep(0.05)

        # Should not crash or leak threads
        assert monitor._running is False


# ===========================================================================
# Hardware Trust Calculation Tests
# ===========================================================================

class TestHardwareTrustCalculation:
    """Tests for _calculate_hardware_trust logic.

    Trust rules:
    - NEW USB devices since baseline → LOW
    - NEW block devices since baseline → LOW
    - TPM present and no new devices → HIGH
    - No TPM, no new devices → MEDIUM
    """

    def _make_monitor(self):
        monitor = StateMonitor()
        return monitor

    def test_new_usb_device_gives_low_trust(self):
        monitor = self._make_monitor()
        monitor._baseline_usb = {'device-a', 'device-b'}
        monitor._baseline_block_devices = set()

        hardware_info = {
            'usb_devices': {'device-a', 'device-b', 'device-c'},  # device-c is new
            'block_devices': set(),
            'camera': False,
            'mic': False,
            'tpm': True,
        }
        trust = monitor._calculate_hardware_trust(hardware_info)
        assert trust == HardwareTrust.LOW

    def test_removed_usb_device_not_low_trust(self):
        monitor = self._make_monitor()
        monitor._baseline_usb = {'device-a', 'device-b'}
        monitor._baseline_block_devices = set()

        hardware_info = {
            'usb_devices': {'device-a'},  # device-b removed
            'block_devices': set(),
            'camera': False,
            'mic': False,
            'tpm': True,
        }
        trust = monitor._calculate_hardware_trust(hardware_info)
        # No NEW devices, just removed → should not be LOW
        assert trust == HardwareTrust.HIGH  # TPM present

    def test_new_block_device_gives_low_trust(self):
        monitor = self._make_monitor()
        monitor._baseline_usb = set()
        monitor._baseline_block_devices = {'/dev/sda'}

        hardware_info = {
            'usb_devices': set(),
            'block_devices': {'/dev/sda', '/dev/sdb'},  # sdb is new
            'camera': False,
            'mic': False,
            'tpm': True,
        }
        trust = monitor._calculate_hardware_trust(hardware_info)
        assert trust == HardwareTrust.LOW

    def test_tpm_present_no_new_devices_gives_high(self):
        monitor = self._make_monitor()
        monitor._baseline_usb = {'device-a'}
        monitor._baseline_block_devices = {'/dev/sda'}

        hardware_info = {
            'usb_devices': {'device-a'},
            'block_devices': {'/dev/sda'},
            'camera': False,
            'mic': False,
            'tpm': True,
        }
        trust = monitor._calculate_hardware_trust(hardware_info)
        assert trust == HardwareTrust.HIGH

    def test_no_tpm_no_new_devices_gives_medium(self):
        monitor = self._make_monitor()
        monitor._baseline_usb = {'device-a'}
        monitor._baseline_block_devices = {'/dev/sda'}

        hardware_info = {
            'usb_devices': {'device-a'},
            'block_devices': {'/dev/sda'},
            'camera': False,
            'mic': False,
            'tpm': False,
        }
        trust = monitor._calculate_hardware_trust(hardware_info)
        assert trust == HardwareTrust.MEDIUM

    def test_baseline_not_set_with_tpm_gives_high(self):
        """When baseline is None (first sample), USB check is skipped → TPM → HIGH."""
        monitor = self._make_monitor()
        # Baselines are None by default

        hardware_info = {
            'usb_devices': {'device-a'},
            'block_devices': {'/dev/sda'},
            'camera': False,
            'mic': False,
            'tpm': True,
        }
        trust = monitor._calculate_hardware_trust(hardware_info)
        assert trust == HardwareTrust.HIGH

    def test_baseline_not_set_without_tpm_gives_medium(self):
        """When baseline is None and no TPM → MEDIUM."""
        monitor = self._make_monitor()

        hardware_info = {
            'usb_devices': {'device-a'},
            'block_devices': {'/dev/sda'},
            'camera': False,
            'mic': False,
            'tpm': False,
        }
        trust = monitor._calculate_hardware_trust(hardware_info)
        assert trust == HardwareTrust.MEDIUM

    def test_empty_baseline_new_usb_gives_low(self):
        monitor = self._make_monitor()
        monitor._baseline_usb = set()
        monitor._baseline_block_devices = set()

        hardware_info = {
            'usb_devices': {'new-device'},
            'block_devices': set(),
            'camera': False,
            'mic': False,
            'tpm': True,
        }
        trust = monitor._calculate_hardware_trust(hardware_info)
        assert trust == HardwareTrust.LOW

    def test_usb_checked_before_block_devices(self):
        monitor = self._make_monitor()
        monitor._baseline_usb = set()
        monitor._baseline_block_devices = set()

        hardware_info = {
            'usb_devices': {'new-usb'},
            'block_devices': {'new-block'},
            'camera': False,
            'mic': False,
            'tpm': True,
        }
        # Both are new, but result should still be LOW
        trust = monitor._calculate_hardware_trust(hardware_info)
        assert trust == HardwareTrust.LOW


# ===========================================================================
# Interface Type Detection Tests
# ===========================================================================

class TestInterfaceTypeDetection:
    def test_ethernet_interfaces(self):
        monitor = StateMonitor()
        for iface in ['eth0', 'enp0s3', 'eno1', 'ens160', 'em1']:
            result = monitor._detect_interface_type(iface)
            assert result == NetworkType.ETHERNET, f"{iface} should be ETHERNET"

    def test_wifi_interfaces(self):
        monitor = StateMonitor()
        for iface in ['wlan0', 'wlp3s0', 'wlx001122334455']:
            result = monitor._detect_interface_type(iface)
            assert result == NetworkType.WIFI, f"{iface} should be WIFI"

    def test_vpn_interfaces(self):
        monitor = StateMonitor()
        for iface in ['tun0', 'tap0', 'wg0']:
            result = monitor._detect_interface_type(iface)
            assert result == NetworkType.VPN, f"{iface} should be VPN"

    def test_bluetooth_interfaces(self):
        monitor = StateMonitor()
        for iface in ['bnep0']:
            result = monitor._detect_interface_type(iface)
            assert result == NetworkType.BLUETOOTH, f"{iface} should be BLUETOOTH"

    def test_bridge_interfaces(self):
        monitor = StateMonitor()
        for iface in ['br0', 'docker0', 'virbr0', 'veth12345']:
            result = monitor._detect_interface_type(iface)
            assert result == NetworkType.BRIDGE, f"{iface} should be BRIDGE"

    def test_ppp_interfaces(self):
        monitor = StateMonitor()
        result = monitor._detect_interface_type('ppp0')
        assert result == NetworkType.CELLULAR_4G


# ===========================================================================
# Callback Unregister Tests
# ===========================================================================

class TestStateMonitorUnregister:
    def test_unregister_callback_returns_true(self):
        monitor = StateMonitor()
        cb_id = monitor.register_callback(lambda old, new: None)
        assert monitor.unregister_callback(cb_id) is True

    def test_unregister_callback_removes_it(self):
        monitor = StateMonitor()
        cb_id = monitor.register_callback(lambda old, new: None)
        monitor.unregister_callback(cb_id)
        assert cb_id not in monitor._callbacks

    def test_unregister_nonexistent_returns_false(self):
        monitor = StateMonitor()
        assert monitor.unregister_callback(9999) is False

    def test_stop_clears_callbacks(self):
        monitor = StateMonitor()
        monitor.register_callback(lambda old, new: None)
        monitor.register_callback(lambda old, new: None)
        monitor.stop()
        assert len(monitor._callbacks) == 0


# ===========================================================================
# get_usb_changes Tests
# ===========================================================================

class TestGetUsbChanges:
    def test_get_usb_changes_before_baseline_returns_empty(self):
        monitor = StateMonitor()
        added, removed = monitor.get_usb_changes()
        assert added == set()
        assert removed == set()

    def test_get_usb_changes_no_state_returns_empty(self):
        monitor = StateMonitor()
        monitor._baseline_usb = {'device-a'}
        # No current state sampled
        added, removed = monitor.get_usb_changes()
        assert added == set()
        assert removed == set()


# ===========================================================================
# SECURITY INVARIANT: Interface Type Detection Completeness
# ===========================================================================

class TestInterfaceTypeUnknown:
    """Tests that unknown interface names safely return UNKNOWN type."""

    def test_unknown_interface_name(self):
        monitor = StateMonitor()
        result = monitor._detect_interface_type('foo0')
        assert result == NetworkType.UNKNOWN

    def test_numeric_interface_name(self):
        monitor = StateMonitor()
        result = monitor._detect_interface_type('12345')
        assert result == NetworkType.UNKNOWN

    def test_empty_interface_name(self):
        monitor = StateMonitor()
        result = monitor._detect_interface_type('')
        assert result == NetworkType.UNKNOWN


# ===========================================================================
# Error-Path Tests
# ===========================================================================

class TestStateMonitorErrorPaths:
    """Error-path tests for StateMonitor using pytest.raises."""

    def test_network_state_invalid_value_raises(self):
        with pytest.raises(ValueError):
            NetworkState("invalid_state")

    def test_network_type_invalid_value_raises(self):
        with pytest.raises(ValueError):
            NetworkType("invalid_type")

    def test_hardware_trust_invalid_value_raises(self):
        with pytest.raises(ValueError):
            HardwareTrust("invalid_trust")

    def test_cellular_security_alert_invalid_value_raises(self):
        """Creating a CellularSecurityAlert with invalid value should raise ValueError."""
        with pytest.raises(ValueError):
            CellularSecurityAlert("invalid_alert")

    def test_specialty_network_status_missing_fields_raises(self):
        with pytest.raises(TypeError):
            SpecialtyNetworkStatus(lora_devices=[])

    def test_environment_state_missing_fields_raises(self):
        with pytest.raises(TypeError):
            EnvironmentState(timestamp="test")

    def test_unregister_nonexistent_callback_returns_false(self):
        monitor = StateMonitor()
        result = monitor.unregister_callback(99999)
        assert result is False

    def test_monitoring_config_unexpected_kwarg_raises(self):
        with pytest.raises(TypeError):
            MonitoringConfig(nonexistent_option=True)

    def test_hardware_trust_calculation_missing_key_raises(self):
        monitor = StateMonitor()
        monitor._baseline_usb = set()
        monitor._baseline_block_devices = set()

        with pytest.raises(KeyError):
            monitor._calculate_hardware_trust({})

    def test_start_when_already_running_is_idempotent(self):
        monitor = StateMonitor(poll_interval=0.1)
        monitor.start()
        try:
            # Second start should not raise
            monitor.start()
        finally:
            monitor.stop()

    def test_stop_when_not_running_is_safe(self):
        monitor = StateMonitor()
        # Should not raise
        monitor.stop()
