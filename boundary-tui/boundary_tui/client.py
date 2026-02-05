"""
TUI Dashboard Client - API client for daemon communication.

Implements the DaemonProtocol interface for socket/TCP communication
with the Boundary Daemon.
"""

import json
import logging
import os
import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .models import DashboardEvent, DashboardAlert, SandboxStatus
from .protocol import DaemonProtocol

logger = logging.getLogger(__name__)


class DashboardClient(DaemonProtocol):
    """
    Client for communicating with Boundary Daemon via socket API.

    Implements DaemonProtocol for use with the TUI Dashboard.
    Supports both Unix domain sockets and TCP connections.
    """

    # Windows TCP fallback
    WINDOWS_HOST = '127.0.0.1'
    WINDOWS_PORT = 19847

    def __init__(self, socket_path: Optional[str] = None):
        self.socket_path = socket_path
        self._connected = False
        self._use_tcp = False  # Flag for Windows TCP mode
        self._log_file_path = None  # Path to daemon log file for offline mode
        self._connection_debug_log = []  # Store debug messages

        # Set up debug log file
        self._debug_log_path = self._setup_debug_log()

        self._log_debug("=" * 60)
        self._log_debug(f"TUI Connection Debug - {datetime.now().isoformat()}")
        self._log_debug(f"Platform: {sys.platform}")
        self._log_debug(f"Python version: {sys.version}")
        self._log_debug("=" * 60)

        # Build dynamic socket paths based on where daemon might create them
        self._socket_paths = self._build_socket_paths()
        self._log_debug(f"Socket paths to try: {self._socket_paths}")

        # Find log file for reading real events when offline
        self._log_file_path = self._find_log_file()
        self._log_debug(f"Daemon log file: {self._log_file_path}")

        # Try to find working socket
        if not self.socket_path:
            self.socket_path = self._find_socket()
        self._log_debug(f"Selected socket path: {self.socket_path}")

        # Resolve token after finding socket (token might be near socket)
        self._token = self._resolve_token()
        self._log_debug(f"API token found: {'Yes' if self._token else 'No'}")

        # On Windows, try TCP first (more reliable than Unix sockets)
        if sys.platform == 'win32':
            self._log_debug("Windows detected - trying TCP connection first")
            self._log_debug(f"Attempting TCP connection to {self.WINDOWS_HOST}:{self.WINDOWS_PORT}")

            if self._try_tcp_connection():
                self._connected = True
                self._use_tcp = True
                self._log_debug("SUCCESS: Connected via TCP")
                logger.info(f"Connected to daemon via TCP on port {self.WINDOWS_PORT}")
            else:
                self._log_debug("TCP connection failed, trying Unix socket fallback")
                # Fallback to socket test (unlikely to work on Windows)
                self._connected = self._test_connection()
                self._log_debug(f"Unix socket fallback result: {self._connected}")
        else:
            self._log_debug("Unix platform - trying socket connection first")
            # On Unix, try socket first, then TCP as fallback
            self._connected = self._test_connection()
            self._log_debug(f"Unix socket connection result: {self._connected}")

            if not self._connected:
                self._log_debug(f"Socket failed, trying TCP fallback to {self.WINDOWS_HOST}:{self.WINDOWS_PORT}")
                if self._try_tcp_connection():
                    self._connected = True
                    self._use_tcp = True
                    self._log_debug("SUCCESS: Connected via TCP fallback")
                    logger.info(f"Connected to daemon via TCP on port {self.WINDOWS_PORT}")

        if not self._connected:
            self._log_debug("FAILED: Could not connect to daemon")
            self._log_debug("Checking for offline log file...")
            if self._log_file_path and os.path.exists(self._log_file_path):
                self._log_debug(f"Found log file for offline mode: {self._log_file_path}")
                logger.info(f"Daemon not connected, reading events from {self._log_file_path}")
            else:
                self._log_debug("No log file found - running in demo mode")
                logger.info("Daemon not available, no log file found")

            # Additional diagnostics
            self._run_connection_diagnostics()
        else:
            self._log_debug(f"SUCCESS: Connected (use_tcp={self._use_tcp})")

        # Write all debug info to log file
        self._flush_debug_log()

    def _setup_debug_log(self) -> str:
        """Set up debug log file path."""
        # Try several locations
        log_locations = [
            Path(__file__).parent.parent.parent / 'logs' / 'tui_connection_debug.log',
            Path.home() / '.boundary-daemon' / 'logs' / 'tui_connection_debug.log',
            Path('./tui_connection_debug.log'),
        ]

        for log_path in log_locations:
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                # Test we can write to it
                with open(log_path, 'a') as f:
                    f.write('')
                return str(log_path)
            except (OSError, PermissionError):
                continue

        # Fallback to current directory
        return './tui_connection_debug.log'

    def _log_debug(self, message: str):
        """Add a debug message to the log buffer."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        self._connection_debug_log.append(f"[{timestamp}] {message}")
        # Limit debug log buffer to prevent memory growth (flushed to file periodically)
        if len(self._connection_debug_log) > 500:
            self._connection_debug_log = self._connection_debug_log[-500:]

    def _flush_debug_log(self):
        """Write all buffered debug messages to log file."""
        try:
            with open(self._debug_log_path, 'a') as f:
                f.write('\n'.join(self._connection_debug_log) + '\n\n')
            self._connection_debug_log = []
        except Exception as e:
            logger.warning(f"Could not write debug log to {self._debug_log_path}: {e}")

    def _run_connection_diagnostics(self):
        """Run detailed connection diagnostics."""
        self._log_debug("\n--- Connection Diagnostics ---")

        # Check if port 19847 is in use
        self._log_debug(f"Checking if port {self.WINDOWS_PORT} is listening...")
        try:
            import psutil
            listening = False
            for conn in psutil.net_connections(kind='tcp'):
                if conn.laddr.port == self.WINDOWS_PORT:
                    self._log_debug(f"  Port {self.WINDOWS_PORT}: status={conn.status}, pid={conn.pid}")
                    if conn.status == 'LISTEN':
                        listening = True
                        try:
                            proc = psutil.Process(conn.pid)
                            self._log_debug(f"  Listening process: {proc.name()} (PID {conn.pid})")
                            self._log_debug(f"  Process cmdline: {' '.join(proc.cmdline())}")
                        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                            self._log_debug(f"  Could not get process info: {e}")
            if not listening:
                self._log_debug(f"  Port {self.WINDOWS_PORT} is NOT listening - daemon may not be running")
        except ImportError:
            self._log_debug("  psutil not available - cannot check port status")
        except Exception as e:
            self._log_debug(f"  Error checking port: {e}")

        # Check socket file existence
        self._log_debug("\nChecking socket paths:")
        for path in self._socket_paths:
            exists = os.path.exists(path)
            self._log_debug(f"  {path}: {'EXISTS' if exists else 'not found'}")

        # Check for daemon process
        self._log_debug("\nSearching for daemon process:")
        try:
            import psutil
            found_daemon = False
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    name = (proc.info.get('name') or '').lower()
                    cmdline = ' '.join(proc.info.get('cmdline') or []).lower()
                    if 'boundary' in name or 'boundary' in cmdline:
                        found_daemon = True
                        self._log_debug(f"  Found: PID={proc.info['pid']} name={proc.info['name']}")
                        self._log_debug(f"    cmdline: {cmdline[:100]}...")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            if not found_daemon:
                self._log_debug("  No daemon process found - daemon is probably not running")
        except ImportError:
            self._log_debug("  psutil not available")
        except Exception as e:
            self._log_debug(f"  Error: {e}")

        # Try direct TCP connection with detailed error
        self._log_debug(f"\nTrying direct TCP connection to {self.WINDOWS_HOST}:{self.WINDOWS_PORT}:")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect((self.WINDOWS_HOST, self.WINDOWS_PORT))
            self._log_debug("  TCP connect succeeded!")
            sock.close()
        except ConnectionRefusedError:
            self._log_debug("  ConnectionRefusedError - daemon not listening on this port")
        except socket.timeout:
            self._log_debug("  Timeout - no response from daemon")
        except OSError as e:
            self._log_debug(f"  OSError: {e}")
        except Exception as e:
            self._log_debug(f"  Error: {type(e).__name__}: {e}")

        self._log_debug("\n--- End Diagnostics ---\n")

    def _find_log_file(self) -> Optional[str]:
        """Find the daemon log file for reading real events offline."""
        package_root = Path(__file__).parent.parent.parent

        # Check possible log file locations
        log_paths = [
            package_root / 'logs' / 'boundary_chain.log',
            package_root / 'boundary_chain.log',
            Path('/var/log/boundary-daemon/boundary_chain.log'),
            Path.home() / '.boundary-daemon' / 'logs' / 'boundary_chain.log',
        ]

        for log_path in log_paths:
            if log_path.exists():
                return str(log_path)

        return None

    def _read_events_from_log(self, limit: int = 20) -> List[DashboardEvent]:
        """Read real events from daemon log file."""
        events = []

        if not self._log_file_path or not os.path.exists(self._log_file_path):
            return events

        try:
            with open(self._log_file_path, 'r') as f:
                lines = f.readlines()

            # Read last N lines (most recent events)
            for line in reversed(lines[-limit*2:]):  # Read more to filter
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                    # Map log entry to DashboardEvent
                    event_type = entry.get('event_type', 'UNKNOWN').upper()
                    details = entry.get('details', '')
                    timestamp = entry.get('timestamp', datetime.utcnow().isoformat())

                    # Map severity from metadata
                    metadata = entry.get('metadata', {})
                    alert_level = metadata.get('alert_level', 'info')
                    severity_map = {
                        'critical': 'ERROR',
                        'error': 'ERROR',
                        'warning': 'WARN',
                        'warn': 'WARN',
                        'info': 'INFO',
                    }
                    severity = severity_map.get(alert_level.lower(), 'INFO')

                    events.append(DashboardEvent(
                        timestamp=timestamp,
                        event_type=event_type,
                        details=details,
                        severity=severity,
                        metadata=metadata,
                    ))

                    if len(events) >= limit:
                        break

                except (json.JSONDecodeError, KeyError):
                    continue

        except Exception as e:
            logger.warning(f"Error reading log file: {e}")

        return events

    def _read_status_from_log(self) -> Dict:
        """Read status from the most recent log entries."""
        status = {
            'mode': 'UNKNOWN',
            'mode_since': datetime.utcnow().isoformat(),
            'uptime': 0,
            'events_today': 0,
            'violations': 0,
            'tripwire_enabled': True,
            'clock_monitor_enabled': True,
            'network_attestation_enabled': True,
            'is_frozen': False,
        }

        if not self._log_file_path or not os.path.exists(self._log_file_path):
            return status

        try:
            with open(self._log_file_path, 'r') as f:
                lines = f.readlines()

            event_count = len(lines)
            violation_count = 0

            # Scan recent entries for mode and violations
            for line in reversed(lines[-100:]):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                    event_type = entry.get('event_type', '')

                    if event_type == 'mode_change':
                        metadata = entry.get('metadata', {})
                        if 'new_mode' in metadata:
                            # Map mode number to name
                            mode_map = {0: 'OPEN', 1: 'TRUSTED', 2: 'RESTRICTED', 3: 'AIRGAP'}
                            status['mode'] = mode_map.get(metadata['new_mode'], 'UNKNOWN')
                        status['mode_since'] = entry.get('timestamp', status['mode_since'])

                    elif event_type == 'daemon_start':
                        metadata = entry.get('metadata', {})
                        status['mode'] = metadata.get('initial_mode', status['mode'])

                    elif event_type == 'violation':
                        violation_count += 1

                except (json.JSONDecodeError, KeyError):
                    continue

            status['events_today'] = event_count
            status['violations'] = violation_count

        except Exception as e:
            logger.warning(f"Error reading status from log: {e}")

        return status

    def _build_socket_paths(self) -> List[str]:
        """Build list of possible socket paths based on daemon behavior."""
        paths = []

        # Get package root directory (where boundary-daemon- is installed)
        package_root = Path(__file__).parent.parent.parent

        # 1. Check for running daemon process and get its working directory
        daemon_cwd = self._find_daemon_working_dir()
        if daemon_cwd:
            paths.append(os.path.join(daemon_cwd, 'api', 'boundary.sock'))

        # 2. Relative to package root (most common for development)
        paths.append(str(package_root / 'api' / 'boundary.sock'))

        # 2b. Sibling to logs directory (daemon creates socket relative to log_dir parent)
        # If log file is at /path/logs/boundary_chain.log, socket is at /path/api/boundary.sock
        if self._log_file_path:
            log_parent = Path(self._log_file_path).parent.parent
            paths.append(str(log_parent / 'api' / 'boundary.sock'))

        # 3. Standard system locations
        paths.append('/var/run/boundary-daemon/boundary.sock')

        # 4. User home directory locations
        paths.append(os.path.expanduser('~/.boundary-daemon/api/boundary.sock'))
        paths.append(os.path.expanduser('~/.agent-os/api/boundary.sock'))

        # 5. Current working directory
        paths.append('./api/boundary.sock')

        # 6. Check PID file for daemon location hints
        pid_socket = self._find_socket_from_pid_file()
        if pid_socket:
            paths.insert(0, pid_socket)

        # Remove duplicates while preserving order
        seen = set()
        unique_paths = []
        for p in paths:
            normalized = os.path.normpath(os.path.abspath(p))
            if normalized not in seen:
                seen.add(normalized)
                unique_paths.append(p)

        return unique_paths

    def _find_daemon_working_dir(self) -> Optional[str]:
        """Find working directory of running daemon process."""
        try:
            import psutil

            # First try: Find by process name/cmdline matching
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cwd', 'exe']):
                try:
                    # Check process name (works for .exe files)
                    name = (proc.info.get('name') or '').lower()
                    exe = (proc.info.get('exe') or '').lower()
                    cmdline = proc.info.get('cmdline') or []
                    cmdline_str = ' '.join(cmdline).lower()

                    # Look for boundary daemon process by various methods
                    is_daemon = False

                    # Method 1: Process name contains 'boundary'
                    if 'boundary' in name:
                        is_daemon = True
                    # Method 2: Exe path contains 'boundary'
                    elif 'boundary' in exe:
                        is_daemon = True
                    # Method 3: Command line contains both 'boundary' and 'daemon'
                    elif 'boundary' in cmdline_str and 'daemon' in cmdline_str:
                        is_daemon = True
                    # Method 4: Running boundary_daemon module
                    elif 'boundary_daemon' in cmdline_str:
                        is_daemon = True
                    # Method 5: Command line contains boundary-daemon- (directory name)
                    elif 'boundary-daemon-' in cmdline_str:
                        is_daemon = True

                    if is_daemon:
                        cwd = proc.info.get('cwd')
                        if cwd:
                            logger.debug(f"Found daemon process {proc.info['pid']} ({name}) at {cwd}")
                            return cwd
                        # If no cwd, try exe directory
                        if exe:
                            exe_dir = os.path.dirname(exe)
                            if exe_dir:
                                logger.debug(f"Found daemon exe {proc.info['pid']} at {exe_dir}")
                                return exe_dir
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            # Second try: Find process listening on port 19847 (TCP mode)
            for conn in psutil.net_connections(kind='tcp'):
                if conn.laddr.port == self.WINDOWS_PORT and conn.status == 'LISTEN':
                    try:
                        proc = psutil.Process(conn.pid)
                        cwd = proc.cwd()
                        if cwd:
                            logger.debug(f"Found daemon on port {self.WINDOWS_PORT}, pid {conn.pid}, cwd: {cwd}")
                            return cwd
                        exe_path = proc.exe()
                        if exe_path:
                            exe_dir = os.path.dirname(exe_path)
                            logger.debug(f"Found daemon on port {self.WINDOWS_PORT}, pid {conn.pid}, exe: {exe_dir}")
                            return exe_dir
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue

        except ImportError:
            logger.debug("psutil not available for process detection")
        except Exception as e:
            logger.debug(f"Error finding daemon process: {e}")
        return None

    def _find_socket_from_pid_file(self) -> Optional[str]:
        """Find socket path from daemon PID file."""
        pid_file_locations = [
            '/var/run/boundary-daemon/boundary.pid',
            os.path.expanduser('~/.boundary-daemon/boundary.pid'),
            './boundary.pid',
        ]
        # Add Windows-specific locations
        if sys.platform == 'win32':
            appdata = os.environ.get('APPDATA', '')
            localappdata = os.environ.get('LOCALAPPDATA', '')
            if appdata:
                pid_file_locations.append(os.path.join(appdata, 'boundary-daemon', 'boundary.pid'))
            if localappdata:
                pid_file_locations.append(os.path.join(localappdata, 'boundary-daemon', 'boundary.pid'))

        for pid_file in pid_file_locations:
            if os.path.exists(pid_file):
                # Socket is usually in api/ subdirectory relative to PID file
                pid_dir = os.path.dirname(pid_file)
                socket_path = os.path.join(pid_dir, 'api', 'boundary.sock')
                if os.path.exists(socket_path):
                    return socket_path
                # Or in parent directory's api folder
                parent_api = os.path.join(os.path.dirname(pid_dir), 'api', 'boundary.sock')
                if os.path.exists(parent_api):
                    return parent_api
        return None

    def _resolve_token(self) -> Optional[str]:
        """Resolve API token from environment, file, or bootstrap token."""
        self._log_debug("Resolving API token...")

        # 1. Environment variable (highest priority)
        token = os.environ.get('BOUNDARY_API_TOKEN')
        if token:
            self._log_debug("Found token in BOUNDARY_API_TOKEN environment variable")
            return token.strip()

        # Build paths to check
        token_paths = []
        bootstrap_paths = []

        # If we found a socket, look for token near it
        if self.socket_path:
            socket_dir = os.path.dirname(self.socket_path)
            parent_dir = os.path.dirname(socket_dir)
            token_paths.append(os.path.join(parent_dir, 'config', 'api_tokens.json'))
            token_paths.append(os.path.join(socket_dir, 'api_tokens.json'))
            # Bootstrap token locations
            bootstrap_paths.append(os.path.join(parent_dir, 'config', 'bootstrap_token.txt'))
            bootstrap_paths.append(os.path.join(parent_dir, 'config', 'tui_token.txt'))

        # Package root config
        package_root = Path(__file__).parent.parent.parent
        token_paths.append(str(package_root / 'config' / 'api_tokens.json'))
        bootstrap_paths.append(str(package_root / 'config' / 'bootstrap_token.txt'))
        bootstrap_paths.append(str(package_root / 'config' / 'tui_token.txt'))

        # Standard locations
        token_paths.extend([
            './config/api_tokens.json',
            os.path.expanduser('~/.boundary-daemon/config/api_tokens.json'),
            os.path.expanduser('~/.agent-os/api_token'),
            '/etc/boundary-daemon/api_token',
        ])
        bootstrap_paths.extend([
            './config/bootstrap_token.txt',
            './config/tui_token.txt',
            os.path.expanduser('~/.boundary-daemon/config/bootstrap_token.txt'),
            os.path.expanduser('~/.boundary-daemon/config/tui_token.txt'),
        ])

        # 2. Check for bootstrap/TUI token files (plaintext token)
        for path in bootstrap_paths:
            if os.path.exists(path):
                self._log_debug(f"Checking bootstrap/TUI token file: {path}")
                try:
                    with open(path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            # Skip comments and empty lines
                            if line and not line.startswith('#'):
                                self._log_debug(f"Found token in {path}")
                                return line
                except IOError as e:
                    self._log_debug(f"Failed to read {path}: {e}")

        # 3. Check JSON token files
        for path in token_paths:
            if os.path.exists(path):
                self._log_debug(f"Checking JSON token file: {path}")
                try:
                    with open(path, 'r') as f:
                        content = f.read().strip()
                        if path.endswith('.json'):
                            data = json.loads(content)
                            # Token file format: {"tokens": [{"token": "...", ...}]}
                            if isinstance(data, dict):
                                if 'token' in data:
                                    self._log_debug(f"Found token in {path}")
                                    return data['token']
                                if 'tokens' in data and data['tokens']:
                                    # Get first non-expired token with raw token value
                                    for tok in data['tokens']:
                                        if isinstance(tok, dict) and 'token' in tok:
                                            self._log_debug(f"Found token in {path}")
                                            return tok['token']
                            elif isinstance(data, list) and data:
                                if 'token' in data[0]:
                                    self._log_debug(f"Found token in {path}")
                                    return data[0].get('token')
                        else:
                            self._log_debug(f"Found token in {path}")
                            return content
                except (IOError, json.JSONDecodeError) as e:
                    self._log_debug(f"Failed to read token from {path}: {e}")

        # 4. Try to create a TUI token via daemon API (if connected without auth)
        token = self._request_tui_token()
        if token:
            return token

        self._log_debug("No API token found")
        return None

    def _request_tui_token(self) -> Optional[str]:
        """Request a TUI-specific token from the daemon."""
        self._log_debug("Attempting to request TUI token from daemon...")
        try:
            # Try TCP connection to request token
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect((self.WINDOWS_HOST, self.WINDOWS_PORT))

            # Request a TUI token (this would need daemon support)
            request = {
                'command': 'create_tui_token',
                'params': {'name': 'tui-dashboard', 'client': 'dashboard'}
            }
            sock.sendall(json.dumps(request).encode('utf-8'))
            data = sock.recv(65536)
            sock.close()

            response = json.loads(data.decode('utf-8'))
            if response.get('success') and response.get('token'):
                token = response['token']
                self._log_debug("Received TUI token from daemon")
                # Save token for future use
                self._save_tui_token(token)
                return token
            else:
                self._log_debug(f"Token request failed: {response.get('error', 'unknown')}")

        except Exception as e:
            self._log_debug(f"Failed to request TUI token: {e}")

        return None

    def _save_tui_token(self, token: str):
        """Save TUI token to file for future use."""
        try:
            # Try to save in config directory
            save_paths = [
                Path(__file__).parent.parent.parent / 'config' / 'tui_token.txt',
                Path.home() / '.boundary-daemon' / 'config' / 'tui_token.txt',
            ]

            for path in save_paths:
                try:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with open(path, 'w') as f:
                        f.write(f"# TUI Dashboard Token - Auto-generated\n")
                        f.write(f"# Created: {datetime.now().isoformat()}\n")
                        f.write(f"{token}\n")
                    self._log_debug(f"Saved TUI token to {path}")
                    return
                except (OSError, PermissionError):
                    continue
        except Exception as e:
            self._log_debug(f"Failed to save TUI token: {e}")
        return None

    def _find_socket(self) -> str:
        """Find available socket path by testing each candidate."""
        for path in self._socket_paths:
            if os.path.exists(path):
                logger.debug(f"Found socket at {path}")
                return path

        # No socket found - return first path as default
        logger.debug(f"No socket found, using default: {self._socket_paths[0] if self._socket_paths else './api/boundary.sock'}")
        return self._socket_paths[0] if self._socket_paths else './api/boundary.sock'

    def _test_connection(self) -> bool:
        """Test if daemon is reachable."""
        try:
            response = self._send_request('status')
            if response.get('success'):
                logger.debug("Connection test successful")
                return True
            elif 'error' in response:
                logger.debug(f"Connection test failed: {response.get('error')}")
                # If auth error, we're connected but need token - that's still "connected"
                if 'auth' in response.get('error', '').lower() or 'token' in response.get('error', '').lower():
                    logger.debug("Connection works but auth failed - daemon is running")
                    return True
            return False
        except Exception as e:
            logger.debug(f"Connection test failed: {e}")
            return False

    def _try_tcp_connection(self) -> bool:
        """Try direct TCP connection to daemon (Windows primary, Unix fallback)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((self.WINDOWS_HOST, self.WINDOWS_PORT))

            # Send a status request
            request = {'command': 'status'}
            if self._token:
                request['token'] = self._token
            sock.sendall(json.dumps(request).encode('utf-8'))

            # Try to receive response
            data = sock.recv(65536)
            sock.close()

            if data:
                response = json.loads(data.decode('utf-8'))
                if response.get('success') or 'error' in response:
                    logger.debug(f"TCP connection successful on port {self.WINDOWS_PORT}")
                    return True
        except Exception as e:
            logger.debug(f"TCP connection failed: {e}")
        return False

    def _send_request(self, command: str, params: Optional[Dict] = None) -> Dict:
        """Send request to daemon API."""
        request = {
            'command': command,
            'params': params or {},
        }
        if self._token:
            request['token'] = self._token

        try:
            # Use TCP if we're in TCP mode or on Windows
            if self._use_tcp or sys.platform == 'win32':
                return self._send_tcp(request)
            else:
                return self._send_unix(request)
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return {'success': False, 'error': str(e)}

    def _send_unix(self, request: Dict) -> Dict:
        """Send request via Unix socket."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
            sock.connect(self.socket_path)
            sock.sendall(json.dumps(request).encode('utf-8'))
            data = sock.recv(65536)
            return json.loads(data.decode('utf-8'))
        finally:
            sock.close()

    def _send_tcp(self, request: Dict) -> Dict:
        """Send request via TCP (Windows)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
            sock.connect((self.WINDOWS_HOST, self.WINDOWS_PORT))
            sock.sendall(json.dumps(request).encode('utf-8'))
            data = sock.recv(65536)
            return json.loads(data.decode('utf-8'))
        finally:
            sock.close()

    def connect(self) -> bool:
        """Test connection to daemon."""
        self._connected = self._test_connection()
        return self._connected

    def reconnect(self) -> bool:
        """Try to reconnect to daemon by refreshing socket paths."""
        # Rebuild socket paths (daemon might have started since last check)
        self._socket_paths = self._build_socket_paths()

        # Refresh token
        self._token = self._resolve_token()

        # Try each socket path (Unix sockets)
        if sys.platform != 'win32':
            for path in self._socket_paths:
                if os.path.exists(path):
                    old_path = self.socket_path
                    self.socket_path = path
                    self._use_tcp = False
                    if self._test_connection():
                        self._connected = True
                        logger.info(f"Connected to daemon at {path}")
                        return True
                    self.socket_path = old_path

        # Try TCP connection (Windows primary, Unix fallback)
        if self._try_tcp_connection():
            self._connected = True
            self._use_tcp = True
            logger.info(f"Connected to daemon via TCP {self.WINDOWS_HOST}:{self.WINDOWS_PORT}")
            return True

        return False

    def is_demo_mode(self) -> bool:
        """Check if running in demo mode (not connected to live daemon)."""
        return not self._connected

    def get_status(self) -> Dict:
        """Get daemon status from connection or log file."""
        # Try live connection first
        if self._connected:
            response = self._send_request('status')
            if response.get('success'):
                status = response.get('status', {})
                # Extract nested boundary_state (daemon returns mode inside boundary_state)
                boundary_state = status.get('boundary_state', {})
                lockdown = status.get('lockdown', {})
                environment = status.get('environment', {})
                # Map API response to dashboard format
                # Uptime can come from health monitor, clock monitor, or environment
                health = status.get('health', {})
                clock = status.get('clock', {})
                uptime = health.get('uptime_seconds') or clock.get('uptime_seconds') or 0
                return {
                    'mode': boundary_state.get('mode', 'unknown').upper(),
                    'mode_since': boundary_state.get('last_transition', datetime.utcnow().isoformat()),
                    'uptime': uptime,
                    'events_today': status.get('event_count', 0),
                    'violations': status.get('tripwire_violations', 0),
                    'tripwire_enabled': True,
                    'clock_monitor_enabled': status.get('running', False),
                    'network_attestation_enabled': boundary_state.get('network', 'isolated') != 'isolated',
                    'is_frozen': lockdown.get('active', False) if lockdown else False,
                }

        # Fall back to reading from log file
        if self._log_file_path:
            return self._read_status_from_log()

        # No connection and no log file - return empty status
        return {
            'mode': 'OFFLINE',
            'mode_since': datetime.utcnow().isoformat(),
            'uptime': 0,
            'events_today': 0,
            'violations': 0,
            'tripwire_enabled': False,
            'clock_monitor_enabled': False,
            'network_attestation_enabled': False,
            'is_frozen': False,
        }

    def get_events(self, limit: int = 20) -> List[DashboardEvent]:
        """Get recent events from connection or log file."""
        # Try live connection first
        if self._connected:
            response = self._send_request('get_events', {'count': limit})
            if response.get('success'):
                events = []
                for e in response.get('events', []):
                    events.append(DashboardEvent(
                        timestamp=e.get('timestamp', datetime.utcnow().isoformat()),
                        event_type=e.get('event_type', 'UNKNOWN'),
                        details=e.get('details', ''),
                        severity=e.get('severity', 'INFO'),
                        metadata=e.get('metadata', {}),
                    ))
                return events

        # Fall back to reading from log file
        if self._log_file_path:
            return self._read_events_from_log(limit)

        # No connection and no log file - return empty list
        return []

    def get_alerts(self) -> List[DashboardAlert]:
        """Get active alerts from daemon."""
        # Try to get alerts from daemon
        response = self._send_request('get_alerts')
        if response.get('success'):
            alerts = []
            for a in response.get('alerts', []):
                alerts.append(DashboardAlert(
                    alert_id=a.get('alert_id', ''),
                    timestamp=a.get('timestamp', datetime.utcnow().isoformat()),
                    severity=a.get('severity', 'MEDIUM'),
                    message=a.get('message', ''),
                    status=a.get('status', 'NEW'),
                    source=a.get('source', ''),
                ))
            return alerts
        return []

    def get_sandboxes(self) -> List[SandboxStatus]:
        """Get active sandboxes."""
        response = self._send_request('get_sandboxes')
        if response.get('success'):
            sandboxes = []
            for s in response.get('sandboxes', []):
                sandboxes.append(SandboxStatus(
                    sandbox_id=s.get('sandbox_id', ''),
                    profile=s.get('profile', 'standard'),
                    status=s.get('status', 'unknown'),
                    memory_used=s.get('memory_used', 0),
                    memory_limit=s.get('memory_limit', 0),
                    cpu_percent=s.get('cpu_percent', 0),
                    uptime=s.get('uptime', 0),
                ))
            return sandboxes
        return []

    def get_siem_status(self) -> Tuple[Dict, Dict]:
        """Get SIEM shipping and ingestion status.

        Returns:
            (siem_status, ingestion_status) - Both shipping and ingestion stats
        """
        response = self._send_request('get_siem_status')
        if response.get('success'):
            siem = response.get('siem_status', {})
            ingestion = response.get('ingestion', {})
            return siem, ingestion
        return (
            {'events_shipped_today': 0, 'last_ship_time': None, 'queue_size': 0},
            {'active': False, 'events_served_today': 0, 'requests_today': 0}
        )

    def set_mode(self, mode: str, reason: str = '') -> Tuple[bool, str]:
        """Request mode change."""
        if not self._connected:
            return False, "Daemon not connected"

        response = self._send_request('set_mode', {
            'mode': mode.lower(),
            'operator': 'human',
            'reason': reason,
        })
        if response.get('success'):
            return True, response.get('message', 'Mode changed')
        return False, response.get('error', 'Mode change failed')

    def acknowledge_alert(self, alert_id: str) -> Tuple[bool, str]:
        """Acknowledge an alert."""
        if not self._connected:
            return False, "Daemon not connected"

        response = self._send_request('acknowledge_alert', {'alert_id': alert_id})
        if response.get('success'):
            return True, response.get('message', 'Alert acknowledged')
        return False, response.get('error', 'Failed to acknowledge alert')

    def export_events(self, start_time: Optional[str] = None,
                      end_time: Optional[str] = None) -> List[Dict]:
        """Export events for a time range."""
        if self._log_file_path:
            events = self._read_events_from_log(100)
            return [e.__dict__ for e in events]

        params = {}
        if start_time:
            params['start_time'] = start_time
        if end_time:
            params['end_time'] = end_time
        params['count'] = 1000

        response = self._send_request('get_events', params)
        if response.get('success'):
            return response.get('events', [])
        return []

    def toggle_memory_debug(self) -> Tuple[bool, str]:
        """Toggle memory debug mode (tracemalloc) for leak detection.

        Returns:
            (success, message) - Whether toggle succeeded and status message
        """
        if not self._connected:
            return False, "Daemon not connected"

        response = self._send_request('toggle_memory_debug')
        if response.get('success'):
            enabled = response.get('debug_enabled', False)
            status = "enabled" if enabled else "disabled"
            return True, f"Memory debug mode {status}"
        return False, response.get('error', 'Failed to toggle memory debug')

