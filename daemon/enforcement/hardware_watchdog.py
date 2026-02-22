"""
Hardware Watchdog Integration - Kernel-Level System Protection

This module provides comprehensive hardware watchdog support for Phase 3,
ensuring system protection even if the boundary daemon is killed.

WHAT THIS DOES:
When enabled, the hardware watchdog timer will reset the system if the
daemon stops pinging it. This provides ultimate fail-closed protection:
- Daemon killed → no pings → system resets → daemon restarts in LOCKDOWN

HARDWARE WATCHDOG TYPES SUPPORTED:
- Intel TCO watchdog (/dev/watchdog)
- Software watchdog (softdog)
- IPMI watchdog
- Various embedded watchdogs

REQUIREMENTS:
- Linux kernel with watchdog support
- Root privileges
- Hardware watchdog or softdog module loaded

USAGE:
    from daemon.enforcement.hardware_watchdog import HardwareWatchdogManager

    hwdog = HardwareWatchdogManager(timeout=60, pretimeout=10)
    hwdog.enable()

    # In main loop:
    hwdog.ping()

    # On clean shutdown:
    hwdog.disable()

SECURITY NOTES:
- Hardware watchdog CANNOT be disabled by killing the daemon
- System WILL reset if pings stop (even with SIGKILL)
- Use with caution - can cause data loss on reset
- Configure BIOS/UEFI to boot into lockdown mode after reset
"""

import os
import sys
import fcntl
import struct
import ctypes
import logging
import threading
import time
from dataclasses import dataclass
from enum import Enum, IntFlag
from typing import Optional, Dict, Any, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

# Platform detection
IS_LINUX = sys.platform.startswith('linux')


# Watchdog ioctl constants (from linux/watchdog.h)
WATCHDOG_IOCTL_BASE = ord('W')

# Read/write ioctls
WDIOC_GETSUPPORT = 0x80285700      # Get watchdog_info struct
WDIOC_GETSTATUS = 0x80045701       # Get status flags
WDIOC_GETBOOTSTATUS = 0x80045702   # Get boot status
WDIOC_GETTEMP = 0x80045703         # Get temperature (if supported)
WDIOC_SETOPTIONS = 0x80045704      # Set options
WDIOC_KEEPALIVE = 0x80045705       # Ping the watchdog
WDIOC_SETTIMEOUT = 0xC0045706      # Set timeout (read-modify-write)
WDIOC_GETTIMEOUT = 0x80045707      # Get current timeout
WDIOC_SETPRETIMEOUT = 0xC0045708   # Set pre-timeout
WDIOC_GETPRETIMEOUT = 0x80045709   # Get pre-timeout
WDIOC_GETTIMELEFT = 0x8004570A     # Get time left before reset

# Watchdog options for WDIOC_SETOPTIONS
WDIOS_DISABLECARD = 0x0001
WDIOS_ENABLECARD = 0x0002
WDIOS_TEMPPANIC = 0x0004


class WatchdogCapability(IntFlag):
    """Watchdog capability flags from watchdog_info.options"""
    WDIOF_OVERHEAT = 0x0001         # Reset due to CPU overheat
    WDIOF_FANFAULT = 0x0002         # Reset due to fan failure
    WDIOF_EXTERN1 = 0x0004          # External relay 1
    WDIOF_EXTERN2 = 0x0008          # External relay 2
    WDIOF_POWERUNDER = 0x0010       # Power bad/power fault
    WDIOF_CARDRESET = 0x0020        # Card previously reset the CPU
    WDIOF_POWEROVER = 0x0040        # Power over voltage
    WDIOF_SETTIMEOUT = 0x0080       # Set timeout (in seconds)
    WDIOF_MAGICCLOSE = 0x0100       # Supports magic close character
    WDIOF_PRETIMEOUT = 0x0200       # Pretimeout (in seconds)
    WDIOF_ALARMONLY = 0x0400        # Watchdog triggers external alarm
    WDIOF_KEEPALIVEPING = 0x8000    # Keep alive ping supported


@dataclass
class WatchdogInfo:
    """Information about the hardware watchdog"""
    options: int                     # Capability flags
    firmware_version: int            # Firmware version
    identity: str                    # Watchdog identity string

    @property
    def capabilities(self) -> WatchdogCapability:
        return WatchdogCapability(self.options)

    @property
    def supports_settimeout(self) -> bool:
        return bool(self.options & WatchdogCapability.WDIOF_SETTIMEOUT)

    @property
    def supports_pretimeout(self) -> bool:
        return bool(self.options & WatchdogCapability.WDIOF_PRETIMEOUT)

    @property
    def supports_magicclose(self) -> bool:
        return bool(self.options & WatchdogCapability.WDIOF_MAGICCLOSE)


class HardwareWatchdogError(Exception):
    """Raised when hardware watchdog operations fail"""
    pass


class HardwareWatchdogManager:
    """
    Comprehensive hardware watchdog manager.

    Provides:
    - Automatic detection of watchdog device
    - Timeout configuration via ioctl
    - Pre-timeout support (warning before reset)
    - Status monitoring
    - Automatic ping thread option
    - Safe enable/disable
    """

    WATCHDOG_DEVICES = [
        '/dev/watchdog',
        '/dev/watchdog0',
        '/dev/watchdog1',
    ]

    SOFTDOG_MODULE = 'softdog'

    def __init__(
        self,
        timeout: int = 60,
        pretimeout: int = 10,
        auto_ping: bool = False,
        ping_interval: Optional[float] = None,
        on_pretimeout: Optional[callable] = None,
        device_path: Optional[str] = None,
    ):
        """
        Initialize hardware watchdog manager.

        Args:
            timeout: Seconds before reset if not pinged (default: 60)
            pretimeout: Seconds before timeout to trigger warning (default: 10)
            auto_ping: If True, start automatic ping thread
            ping_interval: Seconds between auto pings (default: timeout/3)
            on_pretimeout: Callback when pretimeout occurs
            device_path: Specific device to use (auto-detect if None)
        """
        self._timeout = timeout
        self._pretimeout = pretimeout
        self._auto_ping = auto_ping
        self._ping_interval = ping_interval or (timeout / 3)
        self._on_pretimeout = on_pretimeout
        self._device_path = device_path

        self._fd: Optional[int] = None
        self._enabled = False
        self._info: Optional[WatchdogInfo] = None

        # Auto-ping thread
        self._ping_thread: Optional[threading.Thread] = None
        self._ping_stop = threading.Event()

        # Statistics
        self._stats = {
            'pings': 0,
            'last_ping': 0.0,
            'enabled_at': 0.0,
            'errors': 0,
        }

    @property
    def is_available(self) -> bool:
        """Check if hardware watchdog is available."""
        if not IS_LINUX:
            return False

        for device in self.WATCHDOG_DEVICES:
            if os.path.exists(device) and os.access(device, os.W_OK):
                return True

        return False

    @property
    def is_enabled(self) -> bool:
        """Check if watchdog is currently enabled."""
        return self._enabled and self._fd is not None

    @property
    def info(self) -> Optional[WatchdogInfo]:
        """Get watchdog info (available after enable)."""
        return self._info

    def _find_device(self) -> Optional[str]:
        """Find available watchdog device."""
        if self._device_path:
            if os.path.exists(self._device_path):
                return self._device_path
            return None

        for device in self.WATCHDOG_DEVICES:
            if os.path.exists(device) and os.access(device, os.W_OK):
                return device

        return None

    def _get_watchdog_info(self) -> Optional[WatchdogInfo]:
        """Get watchdog capabilities via ioctl."""
        if self._fd is None:
            return None

        try:
            # struct watchdog_info { u32 options; u32 firmware; u8 identity[32]; }
            buf = bytearray(40)
            fcntl.ioctl(self._fd, WDIOC_GETSUPPORT, buf)

            options, firmware = struct.unpack_from('II', buf, 0)
            identity = buf[8:40].rstrip(b'\x00').decode('utf-8', errors='replace')

            return WatchdogInfo(
                options=options,
                firmware_version=firmware,
                identity=identity,
            )
        except (OSError, struct.error) as e:
            logger.debug(f"Could not get watchdog info: {e}")
            return None

    def _set_timeout(self, timeout: int) -> bool:
        """Set watchdog timeout via ioctl."""
        if self._fd is None:
            return False

        try:
            # WDIOC_SETTIMEOUT is a read-modify-write ioctl
            buf = struct.pack('i', timeout)
            result = fcntl.ioctl(self._fd, WDIOC_SETTIMEOUT, buf)
            actual_timeout = struct.unpack('i', result)[0]

            if actual_timeout != timeout:
                logger.warning(
                    f"Requested timeout {timeout}s, got {actual_timeout}s "
                    "(driver may have limits)"
                )
                self._timeout = actual_timeout

            return True
        except (OSError, struct.error) as e:
            logger.warning(f"Could not set watchdog timeout: {e}")
            return False

    def _set_pretimeout(self, pretimeout: int) -> bool:
        """Set watchdog pre-timeout via ioctl."""
        if self._fd is None:
            return False

        if self._info and not self._info.supports_pretimeout:
            logger.debug("Watchdog does not support pre-timeout")
            return False

        try:
            buf = struct.pack('i', pretimeout)
            result = fcntl.ioctl(self._fd, WDIOC_SETPRETIMEOUT, buf)
            actual = struct.unpack('i', result)[0]

            if actual != pretimeout:
                logger.warning(f"Requested pretimeout {pretimeout}s, got {actual}s")
                self._pretimeout = actual

            return True
        except (OSError, struct.error) as e:
            logger.debug(f"Could not set pretimeout: {e}")
            return False

    def _get_timeleft(self) -> Optional[int]:
        """Get seconds left before reset."""
        if self._fd is None:
            return None

        try:
            buf = struct.pack('i', 0)
            result = fcntl.ioctl(self._fd, WDIOC_GETTIMELEFT, buf)
            return struct.unpack('i', result)[0]
        except OSError:
            return None

    def load_softdog(self) -> bool:
        """Load the software watchdog kernel module."""
        if not IS_LINUX:
            return False

        try:
            import subprocess
            result = subprocess.run(
                ['modprobe', self.SOFTDOG_MODULE],
                capture_output=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.info("Loaded softdog kernel module")
                time.sleep(0.5)  # Wait for device to appear
                return True
            else:
                logger.warning(f"Failed to load softdog: {result.stderr.decode()}")
                return False
        except (subprocess.SubprocessError, OSError) as e:
            logger.warning(f"Could not load softdog: {e}")
            return False

    def enable(self, load_softdog_if_needed: bool = True) -> Tuple[bool, str]:
        """
        Enable the hardware watchdog.

        Args:
            load_softdog_if_needed: Load softdog module if no hardware watchdog

        Returns:
            (success, message)

        WARNING: Once enabled, the system WILL reset if ping() is not called
        regularly. There is no way to disable without the magic close character.
        """
        if self._enabled:
            return True, "Already enabled"

        # Find device
        device = self._find_device()

        if not device and load_softdog_if_needed:
            logger.info("No hardware watchdog found, loading softdog...")
            if self.load_softdog():
                device = self._find_device()

        if not device:
            return False, "No watchdog device available"

        try:
            # Open watchdog device
            # WARNING: Opening the device STARTS the watchdog timer!
            self._fd = os.open(device, os.O_WRONLY)
            logger.info(f"Opened watchdog device: {device}")

            # Get device info
            self._info = self._get_watchdog_info()
            if self._info:
                logger.info(
                    f"Watchdog: {self._info.identity} "
                    f"(caps: {self._info.capabilities!r})"
                )

            # Set timeout
            if not self._set_timeout(self._timeout):
                logger.warning("Using default watchdog timeout")

            # Set pre-timeout if supported
            if self._pretimeout > 0:
                self._set_pretimeout(self._pretimeout)

            self._enabled = True
            self._stats['enabled_at'] = time.time()

            # Initial ping
            self.ping()

            # Start auto-ping thread if requested
            if self._auto_ping:
                self._start_auto_ping()

            return True, f"Hardware watchdog enabled (timeout: {self._timeout}s)"

        except PermissionError:
            return False, "Permission denied - run as root"
        except FileNotFoundError:
            return False, f"Watchdog device not found: {device}"
        except OSError as e:
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except OSError:
                    pass
                self._fd = None
            return False, f"Failed to enable watchdog: {e}"

    def disable(self) -> Tuple[bool, str]:
        """
        Disable the hardware watchdog.

        This only works if the watchdog supports magic close (most do).
        If magic close is not supported, the watchdog cannot be disabled
        and the system will reset when the process exits!

        Returns:
            (success, message)
        """
        if not self._enabled or self._fd is None:
            return True, "Not enabled"

        # Stop auto-ping thread
        self._stop_auto_ping()

        try:
            # Write magic close character 'V' to disable
            # This is a safety feature - normal close doesn't stop the timer
            os.write(self._fd, b'V')
            os.close(self._fd)
            self._fd = None
            self._enabled = False
            logger.info("Hardware watchdog disabled (magic close)")
            return True, "Watchdog disabled"

        except OSError as e:
            logger.error(f"Failed to disable watchdog: {e}")
            # Try to close anyway
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
            self._enabled = False
            return False, f"Disable failed (system may reset!): {e}"

    def ping(self) -> bool:
        """
        Ping the watchdog to prevent reset.

        Must be called regularly (at least every timeout/2 seconds).

        Returns:
            True if ping succeeded
        """
        if not self._enabled or self._fd is None:
            return False

        try:
            # Write any character to ping (except 'V' which disables)
            os.write(self._fd, b'\x00')
            self._stats['pings'] += 1
            self._stats['last_ping'] = time.time()
            return True
        except OSError as e:
            logger.error(f"Watchdog ping failed: {e}")
            self._stats['errors'] += 1
            return False

    def _start_auto_ping(self):
        """Start automatic ping thread."""
        if self._ping_thread is not None:
            return

        self._ping_stop.clear()
        self._ping_thread = threading.Thread(
            target=self._auto_ping_loop,
            name="HWWatchdog-Ping",
            daemon=True,
        )
        self._ping_thread.start()
        logger.info(f"Started auto-ping thread (interval: {self._ping_interval}s)")

    def _stop_auto_ping(self):
        """Stop automatic ping thread."""
        if self._ping_thread is None:
            return

        self._ping_stop.set()
        self._ping_thread.join(timeout=2.0)
        self._ping_thread = None

    def _auto_ping_loop(self):
        """Auto-ping thread main loop."""
        while not self._ping_stop.is_set():
            self.ping()
            self._ping_stop.wait(self._ping_interval)

    def get_status(self) -> Dict[str, Any]:
        """Get current watchdog status."""
        status = {
            'available': self.is_available,
            'enabled': self.is_enabled,
            'timeout': self._timeout,
            'pretimeout': self._pretimeout,
            'auto_ping': self._auto_ping,
            'ping_interval': self._ping_interval,
            'stats': self._stats.copy(),
        }

        if self._info:
            status['info'] = {
                'identity': self._info.identity,
                'firmware_version': self._info.firmware_version,
                'supports_settimeout': self._info.supports_settimeout,
                'supports_pretimeout': self._info.supports_pretimeout,
                'supports_magicclose': self._info.supports_magicclose,
            }

        if self.is_enabled:
            timeleft = self._get_timeleft()
            if timeleft is not None:
                status['time_left'] = timeleft

        return status

    def __enter__(self):
        """Context manager entry."""
        self.enable()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - disable watchdog."""
        self.disable()
        return False


class WatchdogLockdownManager:
    """
    Manages automatic lockdown mode after watchdog-triggered reset.

    When the system resets due to watchdog timeout:
    1. Bootloader starts normally
    2. Systemd starts boundary-daemon
    3. Daemon checks for watchdog reset flag
    4. If flag present → start in LOCKDOWN mode

    The flag is persisted to disk before enabling watchdog.
    """

    LOCKDOWN_FLAG_FILE = '/var/lib/boundary-daemon/watchdog_lockdown_pending'
    RESET_MARKER_FILE = '/var/lib/boundary-daemon/last_watchdog_reset'

    def __init__(self):
        self._lockdown_pending = False

    def set_lockdown_pending(self):
        """
        Set flag indicating next boot should be in lockdown.

        Called before enabling hardware watchdog.
        """
        try:
            flag_path = Path(self.LOCKDOWN_FLAG_FILE)
            flag_path.parent.mkdir(parents=True, exist_ok=True)
            flag_path.write_text(f"pending:{time.time()}\n")
            self._lockdown_pending = True
            logger.info("Set watchdog lockdown pending flag")
        except OSError as e:
            logger.error(f"Failed to set lockdown flag: {e}")

    def clear_lockdown_pending(self):
        """
        Clear lockdown pending flag.

        Called when watchdog is cleanly disabled.
        """
        try:
            flag_path = Path(self.LOCKDOWN_FLAG_FILE)
            if flag_path.exists():
                flag_path.unlink()
            self._lockdown_pending = False
            logger.info("Cleared watchdog lockdown pending flag")
        except OSError as e:
            logger.warning(f"Failed to clear lockdown flag: {e}")

    def check_watchdog_reset(self) -> bool:
        """
        Check if system was reset by watchdog.

        Called on daemon startup.

        Returns:
            True if watchdog reset occurred and lockdown should be enforced
        """
        flag_path = Path(self.LOCKDOWN_FLAG_FILE)

        if not flag_path.exists():
            return False

        try:
            content = flag_path.read_text().strip()
            if content.startswith('pending:'):
                # Lockdown was pending when we crashed/reset
                logger.warning("WATCHDOG RESET DETECTED - entering lockdown mode")

                # Record the reset
                marker_path = Path(self.RESET_MARKER_FILE)
                marker_path.write_text(
                    f"reset_detected:{time.time()}\n"
                    f"original_flag:{content}\n"
                )

                # Clear the pending flag
                flag_path.unlink()

                return True

        except OSError as e:
            logger.error(f"Error checking watchdog reset: {e}")

        return False

    def get_last_reset_info(self) -> Optional[Dict[str, Any]]:
        """Get information about the last watchdog reset."""
        marker_path = Path(self.RESET_MARKER_FILE)

        if not marker_path.exists():
            return None

        try:
            content = marker_path.read_text()
            lines = content.strip().split('\n')
            info = {}
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    info[key] = value
            return info
        except (OSError, ValueError):
            return None


def check_watchdog_support() -> Dict[str, Any]:
    """
    Check system watchdog support.

    Returns dict with support information.
    """
    result = {
        'platform': sys.platform,
        'is_linux': IS_LINUX,
        'is_root': os.geteuid() == 0 if IS_LINUX else False,
        'devices': [],
        'softdog_loaded': False,
        'recommendation': None,
    }

    if not IS_LINUX:
        result['recommendation'] = "Hardware watchdog only supported on Linux"
        return result

    # Check for watchdog devices
    for device in HardwareWatchdogManager.WATCHDOG_DEVICES:
        if os.path.exists(device):
            writable = os.access(device, os.W_OK)
            result['devices'].append({
                'path': device,
                'exists': True,
                'writable': writable,
            })

    # Check if softdog is loaded
    try:
        with open('/proc/modules', 'r') as f:
            modules = f.read()
            result['softdog_loaded'] = 'softdog' in modules
    except OSError:
        pass

    # Determine recommendation
    if not result['is_root']:
        result['recommendation'] = "Run as root for hardware watchdog access"
    elif result['devices']:
        writable_devices = [d for d in result['devices'] if d['writable']]
        if writable_devices:
            result['recommendation'] = f"Hardware watchdog available: {writable_devices[0]['path']}"
        else:
            result['recommendation'] = "Watchdog devices exist but not writable - check permissions"
    elif result['softdog_loaded']:
        result['recommendation'] = "Software watchdog (softdog) is loaded but no device found"
    else:
        result['recommendation'] = "No watchdog found - run 'modprobe softdog' to enable software watchdog"

    return result


# Module-level instance
_hw_watchdog: Optional[HardwareWatchdogManager] = None


def get_hardware_watchdog(
    timeout: int = 60,
    pretimeout: int = 10,
    **kwargs
) -> HardwareWatchdogManager:
    """Get or create the global hardware watchdog manager."""
    global _hw_watchdog

    if _hw_watchdog is None:
        _hw_watchdog = HardwareWatchdogManager(
            timeout=timeout,
            pretimeout=pretimeout,
            **kwargs
        )

    return _hw_watchdog


if __name__ == '__main__':
    # Test the hardware watchdog
    import argparse

    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description='Hardware Watchdog Test')
    parser.add_argument('--check', action='store_true', help='Check watchdog support')
    parser.add_argument('--enable', action='store_true', help='Enable watchdog (DANGEROUS)')
    parser.add_argument('--timeout', type=int, default=60, help='Timeout in seconds')
    parser.add_argument('--test-seconds', type=int, default=30, help='Test duration')

    args = parser.parse_args()

    if args.check:
        support = check_watchdog_support()
        print("\nWatchdog Support Check:")
        print(f"  Platform: {support['platform']}")
        print(f"  Is Linux: {support['is_linux']}")
        print(f"  Is Root: {support['is_root']}")
        print(f"  Devices: {support['devices']}")
        print(f"  Softdog Loaded: {support['softdog_loaded']}")
        print(f"  Recommendation: {support['recommendation']}")
        sys.exit(0)

    if args.enable:
        print("\n" + "="*60)
        print("WARNING: This will enable the hardware watchdog!")
        print("If the test fails, your system WILL RESET!")
        print("="*60)
        response = input("\nType 'yes' to continue: ")
        if response.lower() != 'yes':
            print("Aborted.")
            sys.exit(1)

        hwdog = HardwareWatchdogManager(timeout=args.timeout, auto_ping=True)
        success, msg = hwdog.enable(load_softdog_if_needed=True)
        print(f"\nEnable result: {msg}")

        if success:
            print(f"\nWatchdog enabled. Running for {args.test_seconds} seconds...")
            print("Status:", hwdog.get_status())

            try:
                for i in range(args.test_seconds):
                    time.sleep(1)
                    status = hwdog.get_status()
                    timeleft = status.get('time_left', '?')
                    pings = status['stats']['pings']
                    print(f"  [{i+1}/{args.test_seconds}] Pings: {pings}, Time left: {timeleft}s")
            except KeyboardInterrupt:
                print("\nInterrupted.")

            print("\nDisabling watchdog...")
            success, msg = hwdog.disable()
            print(f"Disable result: {msg}")
