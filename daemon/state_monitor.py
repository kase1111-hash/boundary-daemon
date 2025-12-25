"""
State Monitor - Environment Sensing Component
Continuously monitors network, hardware, software, and human presence signals.
"""

import os
import psutil
import socket
import threading
import time
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Set
from enum import Enum
from datetime import datetime


class NetworkState(Enum):
    """Network connectivity state"""
    OFFLINE = "offline"
    ONLINE = "online"


class NetworkType(Enum):
    """Network interface type classification"""
    ETHERNET = "ethernet"      # eth*, en*, eno*, enp* interfaces
    WIFI = "wifi"              # wlan*, wlp*, wifi*, ath* interfaces
    CELLULAR_4G = "cellular_4g"  # wwan*, wwp*, ppp* with LTE/4G
    CELLULAR_5G = "cellular_5g"  # wwan* with 5G capability
    VPN = "vpn"                # tun*, vpn*, wg*, tap* interfaces
    BLUETOOTH = "bluetooth"    # bt*, bnep* interfaces
    BRIDGE = "bridge"          # br*, virbr*, docker* interfaces
    UNKNOWN = "unknown"        # Unclassified interfaces


class HardwareTrust(Enum):
    """Hardware trust level based on detected conditions"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class EnvironmentState:
    """Complete environment state snapshot"""
    timestamp: str
    network: NetworkState
    hardware_trust: HardwareTrust

    # Network details
    active_interfaces: List[str]
    interface_types: Dict[str, NetworkType]  # Map of interface name to type
    has_internet: bool
    vpn_active: bool
    dns_available: bool

    # Hardware details
    usb_devices: Set[str]
    block_devices: Set[str]
    camera_available: bool
    mic_available: bool
    tpm_present: bool

    # Software details
    external_model_endpoints: List[str]
    suspicious_processes: List[str]
    shell_escapes_detected: int

    # Human presence
    keyboard_active: bool
    screen_unlocked: bool
    last_activity: Optional[str]

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        result = asdict(self)
        result['network'] = self.network.value
        result['hardware_trust'] = self.hardware_trust.value
        result['interface_types'] = {k: v.value for k, v in self.interface_types.items()}
        result['usb_devices'] = list(self.usb_devices)
        result['block_devices'] = list(self.block_devices)
        return result


class StateMonitor:
    """
    Continuous environment monitoring service.
    Detects network state, hardware changes, software anomalies, and human presence.
    """

    def __init__(self, poll_interval: float = 1.0):
        """
        Initialize state monitor.

        Args:
            poll_interval: How frequently to poll environment (seconds)
        """
        self.poll_interval = poll_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._current_state: Optional[EnvironmentState] = None
        self._state_lock = threading.Lock()
        self._callbacks: List[callable] = []

        # Baseline state for detecting changes
        self._baseline_usb: Optional[Set[str]] = None
        self._baseline_block_devices: Optional[Set[str]] = None
        self._last_network_state: Optional[NetworkState] = None

    def register_callback(self, callback: callable):
        """
        Register a callback to be notified of state changes.

        Args:
            callback: Function accepting (old_state, new_state)
        """
        self._callbacks.append(callback)

    def start(self):
        """Start continuous monitoring"""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop monitoring"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)

    def get_current_state(self) -> Optional[EnvironmentState]:
        """Get the most recent environment state"""
        with self._state_lock:
            return self._current_state

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                new_state = self._sample_environment()

                with self._state_lock:
                    old_state = self._current_state
                    self._current_state = new_state

                # Notify callbacks of state change
                if old_state != new_state:
                    for callback in self._callbacks:
                        try:
                            callback(old_state, new_state)
                        except Exception as e:
                            print(f"Error in state change callback: {e}")

                time.sleep(self.poll_interval)
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(self.poll_interval)

    def _sample_environment(self) -> EnvironmentState:
        """Sample all environment sensors"""
        timestamp = datetime.utcnow().isoformat() + "Z"

        # Network sensing
        network_info = self._check_network()

        # Hardware sensing
        hardware_info = self._check_hardware()

        # Software sensing
        software_info = self._check_software()

        # Human presence sensing
        presence_info = self._check_human_presence()

        # Determine overall hardware trust level
        hardware_trust = self._calculate_hardware_trust(hardware_info)

        # Detect network state changes for tripwire detection
        current_network = network_info['state']
        if self._last_network_state != current_network:
            self._last_network_state = current_network

        return EnvironmentState(
            timestamp=timestamp,
            network=network_info['state'],
            hardware_trust=hardware_trust,
            active_interfaces=network_info['interfaces'],
            interface_types=network_info['interface_types'],
            has_internet=network_info['has_internet'],
            vpn_active=network_info['vpn_active'],
            dns_available=network_info['dns_available'],
            usb_devices=hardware_info['usb_devices'],
            block_devices=hardware_info['block_devices'],
            camera_available=hardware_info['camera'],
            mic_available=hardware_info['mic'],
            tpm_present=hardware_info['tpm'],
            external_model_endpoints=software_info['external_endpoints'],
            suspicious_processes=software_info['suspicious_processes'],
            shell_escapes_detected=software_info['shell_escapes'],
            keyboard_active=presence_info['keyboard_active'],
            screen_unlocked=presence_info['screen_unlocked'],
            last_activity=presence_info['last_activity']
        )

    def _detect_interface_type(self, iface: str) -> NetworkType:
        """
        Detect the type of a network interface based on its name and system info.

        Args:
            iface: Interface name (e.g., 'eth0', 'wlan0', 'wg0')

        Returns:
            NetworkType enum value
        """
        iface_lower = iface.lower()

        # VPN interfaces (check first as they may overlay other types)
        if any(pattern in iface_lower for pattern in ['tun', 'tap', 'vpn', 'wg']):
            return NetworkType.VPN

        # WiFi/WLAN interfaces
        if any(pattern in iface_lower for pattern in ['wlan', 'wlp', 'wifi', 'ath', 'wlx']):
            return NetworkType.WIFI

        # Cellular interfaces - try to detect 5G vs 4G
        if any(pattern in iface_lower for pattern in ['wwan', 'wwp', 'rmnet', 'usb']):
            # Check for 5G capability via sysfs if available
            if self._is_5g_capable(iface):
                return NetworkType.CELLULAR_5G
            return NetworkType.CELLULAR_4G

        # PPP interfaces (often used for cellular/dial-up)
        if iface_lower.startswith('ppp'):
            return NetworkType.CELLULAR_4G

        # Bluetooth interfaces
        if any(pattern in iface_lower for pattern in ['bt', 'bnep', 'pan']):
            return NetworkType.BLUETOOTH

        # Bridge interfaces
        if any(pattern in iface_lower for pattern in ['br', 'virbr', 'docker', 'veth', 'cni']):
            return NetworkType.BRIDGE

        # Ethernet interfaces (most common patterns)
        if any(pattern in iface_lower for pattern in ['eth', 'enp', 'eno', 'ens', 'em']):
            return NetworkType.ETHERNET

        # Try to detect type from sysfs as a fallback
        sys_type = self._get_interface_type_from_sysfs(iface)
        if sys_type:
            return sys_type

        return NetworkType.UNKNOWN

    def _is_5g_capable(self, iface: str) -> bool:
        """
        Check if a cellular interface supports 5G.

        Args:
            iface: Interface name

        Returns:
            True if 5G capable, False otherwise
        """
        # Check modem capabilities via sysfs/dbus if available
        try:
            # Check for 5G modem indicators in sysfs
            modem_paths = [
                f'/sys/class/net/{iface}/device/capabilities',
                f'/sys/class/net/{iface}/device/uevent'
            ]
            for path in modem_paths:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        content = f.read().lower()
                        if '5g' in content or 'nr' in content:
                            return True

            # Check ModemManager info if available
            mm_path = f'/sys/class/net/{iface}/device/driver'
            if os.path.exists(mm_path):
                driver = os.readlink(mm_path)
                # Common 5G modem drivers
                if any(d in driver.lower() for d in ['qmi', 'mbim', 'option']):
                    # Additional check would need ModemManager D-Bus API
                    pass
        except Exception:
            pass

        return False

    def _get_interface_type_from_sysfs(self, iface: str) -> Optional[NetworkType]:
        """
        Get interface type from sysfs as a fallback.

        Args:
            iface: Interface name

        Returns:
            NetworkType if detected, None otherwise
        """
        try:
            # Check the interface type from sysfs
            type_path = f'/sys/class/net/{iface}/type'
            if os.path.exists(type_path):
                with open(type_path, 'r') as f:
                    iface_type = int(f.read().strip())
                    # Linux ARPHRD types
                    if iface_type == 1:  # ARPHRD_ETHER - could be ethernet or wifi
                        # Check for wireless directory
                        if os.path.exists(f'/sys/class/net/{iface}/wireless'):
                            return NetworkType.WIFI
                        return NetworkType.ETHERNET
                    elif iface_type == 772:  # ARPHRD_LOOPBACK
                        return None  # Skip loopback
                    elif iface_type == 65534:  # ARPHRD_NONE (tunnel)
                        return NetworkType.VPN

            # Check for wireless interface
            if os.path.exists(f'/sys/class/net/{iface}/wireless'):
                return NetworkType.WIFI

            # Check device driver for clues
            driver_path = f'/sys/class/net/{iface}/device/driver'
            if os.path.exists(driver_path):
                driver = os.path.basename(os.readlink(driver_path))
                if driver in ['iwlwifi', 'ath9k', 'ath10k', 'rtlwifi', 'brcmfmac']:
                    return NetworkType.WIFI
                if driver in ['e1000', 'e1000e', 'igb', 'ixgbe', 'r8169']:
                    return NetworkType.ETHERNET
        except Exception:
            pass

        return None

    def _check_network(self) -> Dict:
        """Check network state"""
        interfaces = []
        interface_types: Dict[str, NetworkType] = {}
        has_internet = False
        vpn_active = False
        dns_available = False

        # Get active network interfaces
        try:
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()

            for iface, addrs in net_if_addrs.items():
                if iface in net_if_stats and net_if_stats[iface].isup:
                    # Skip loopback
                    if iface != 'lo' and not iface.startswith('lo'):
                        interfaces.append(iface)

                        # Detect interface type
                        iface_type = self._detect_interface_type(iface)
                        interface_types[iface] = iface_type

                        # Check for VPN interfaces using the detected type
                        if iface_type == NetworkType.VPN:
                            vpn_active = True
        except Exception as e:
            print(f"Error checking network interfaces: {e}")

        # Test for internet connectivity
        try:
            # Try to resolve a common domain
            # Note: socket.getaddrinfo doesn't accept timeout parameter
            # Use setdefaulttimeout temporarily for DNS lookup timeout
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(2.0)
            try:
                socket.getaddrinfo('google.com', 80)
                dns_available = True
                has_internet = True
            finally:
                socket.setdefaulttimeout(old_timeout)
        except (socket.gaierror, socket.timeout, OSError):
            pass

        # Determine overall network state
        state = NetworkState.ONLINE if (interfaces or has_internet) else NetworkState.OFFLINE

        return {
            'state': state,
            'interfaces': interfaces,
            'interface_types': interface_types,
            'has_internet': has_internet,
            'vpn_active': vpn_active,
            'dns_available': dns_available
        }

    def _check_hardware(self) -> Dict:
        """Check hardware state"""
        usb_devices = set()
        block_devices = set()
        camera = False
        mic = False
        tpm = False

        # Check USB devices via /sys/bus/usb/devices
        try:
            if os.path.exists('/sys/bus/usb/devices'):
                for device in os.listdir('/sys/bus/usb/devices'):
                    if device.startswith('usb'):
                        continue
                    usb_devices.add(device)
        except Exception as e:
            print(f"Error checking USB devices: {e}")

        # Check block devices
        try:
            for partition in psutil.disk_partitions(all=True):
                block_devices.add(partition.device)
        except Exception as e:
            print(f"Error checking block devices: {e}")

        # Check for camera devices
        try:
            if os.path.exists('/dev'):
                video_devs = [d for d in os.listdir('/dev') if d.startswith('video')]
                camera = len(video_devs) > 0
        except Exception:
            pass

        # Check for audio input devices
        try:
            if os.path.exists('/proc/asound'):
                cards = os.listdir('/proc/asound')
                mic = any(c.startswith('card') for c in cards)
        except Exception:
            pass

        # Check for TPM
        try:
            tpm = os.path.exists('/dev/tpm0') or os.path.exists('/sys/class/tpm')
        except Exception:
            pass

        # Store baseline on first check
        if self._baseline_usb is None:
            self._baseline_usb = usb_devices.copy()
        if self._baseline_block_devices is None:
            self._baseline_block_devices = block_devices.copy()

        return {
            'usb_devices': usb_devices,
            'block_devices': block_devices,
            'camera': camera,
            'mic': mic,
            'tpm': tpm
        }

    def _check_software(self) -> Dict:
        """Check software state for anomalies"""
        external_endpoints = []
        suspicious_processes = []
        shell_escapes = 0

        # Check for processes that might indicate external model usage
        try:
            for proc in psutil.process_iter(['name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info['cmdline'] or [])

                    # Look for OpenAI, Anthropic, or other API endpoints
                    if any(endpoint in cmdline.lower() for endpoint in
                           ['openai', 'anthropic', 'api.claude', 'api.openai']):
                        external_endpoints.append(proc.info['name'])

                    # Look for suspicious shell activity
                    if any(cmd in cmdline.lower() for cmd in
                           ['bash -c', 'sh -c', 'eval', 'exec']):
                        shell_escapes += 1

                    # Look for privilege escalation attempts
                    if proc.info['name'] in ['sudo', 'su', 'pkexec']:
                        suspicious_processes.append(f"{proc.info['name']} (PID: {proc.pid})")

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"Error checking processes: {e}")

        return {
            'external_endpoints': external_endpoints,
            'suspicious_processes': suspicious_processes,
            'shell_escapes': shell_escapes
        }

    def _check_human_presence(self) -> Dict:
        """Check for human presence signals"""
        keyboard_active = False
        screen_unlocked = True  # Assume unlocked if we can't detect
        last_activity = None

        # Check for recent keyboard/mouse activity via idle time
        try:
            # Try to get idle time from X11 (if available)
            if os.environ.get('DISPLAY'):
                # This would require xprintidle or similar, skip for now
                pass

            # Check last user login
            users = psutil.users()
            if users:
                last_activity = datetime.fromtimestamp(users[0].started).isoformat()
                keyboard_active = True
        except Exception as e:
            print(f"Error checking human presence: {e}")

        return {
            'keyboard_active': keyboard_active,
            'screen_unlocked': screen_unlocked,
            'last_activity': last_activity
        }

    def _calculate_hardware_trust(self, hardware_info: Dict) -> HardwareTrust:
        """
        Calculate hardware trust level based on detected conditions.

        LOW: Untrusted hardware detected, unknown USB devices
        MEDIUM: Some trusted hardware, controlled environment
        HIGH: Fully trusted hardware, TPM present, no unknown devices
        """
        # Check for new USB devices since baseline
        if self._baseline_usb is not None:
            new_usb = hardware_info['usb_devices'] - self._baseline_usb
            if new_usb:
                return HardwareTrust.LOW

        # Check for new block devices
        if self._baseline_block_devices is not None:
            new_blocks = hardware_info['block_devices'] - self._baseline_block_devices
            if new_blocks:
                return HardwareTrust.LOW

        # HIGH trust: TPM present and no new devices
        if hardware_info['tpm']:
            return HardwareTrust.HIGH

        # MEDIUM: Stable hardware but no TPM
        return HardwareTrust.MEDIUM

    def get_usb_changes(self) -> tuple[Set[str], Set[str]]:
        """
        Get USB device changes since baseline.

        Returns:
            (added_devices, removed_devices)
        """
        current_state = self.get_current_state()
        if not current_state or self._baseline_usb is None:
            return (set(), set())

        added = current_state.usb_devices - self._baseline_usb
        removed = self._baseline_usb - current_state.usb_devices
        return (added, removed)

    def get_network_change_detected(self) -> bool:
        """Check if network state has changed since last check"""
        current = self.get_current_state()
        if not current:
            return False
        return current.network != self._last_network_state


if __name__ == '__main__':
    # Test the state monitor
    print("Starting State Monitor test...")
    monitor = StateMonitor(poll_interval=2.0)

    def on_state_change(old_state, new_state):
        print(f"\n=== State Change Detected ===")
        if old_state:
            print(f"Old network: {old_state.network.value}")
        print(f"New network: {new_state.network.value}")
        print(f"Hardware trust: {new_state.hardware_trust.value}")
        print(f"Active interfaces: {new_state.active_interfaces}")
        print(f"Interface types: {{{', '.join(f'{k}: {v.value}' for k, v in new_state.interface_types.items())}}}")
        print(f"USB devices: {len(new_state.usb_devices)}")
        print(f"Internet: {new_state.has_internet}")

    monitor.register_callback(on_state_change)
    monitor.start()

    try:
        print("Monitoring environment. Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        monitor.stop()
        print("Monitor stopped.")
