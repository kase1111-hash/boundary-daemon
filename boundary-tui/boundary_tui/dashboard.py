"""
Boundary TUI Dashboard - Cyberpunk Terminal Interface

A standalone terminal user interface featuring animated cityscapes,
weather effects, and real-time system monitoring.

Features:
- Real-time mode and status display
- Event stream with filtering
- Alert management (acknowledge, resolve)
- Sandbox monitoring
- SIEM shipping status
- Keyboard shortcuts for common operations
- Animated cyberpunk cityscape with weather effects

Usage:
    boundary-tui
    boundary-tui --refresh 1
    boundary-tui --matrix

Keyboard Shortcuts:
    [m] Mode change ceremony
    [a] Acknowledge alert
    [e] Export event range
    [r] Refresh
    [q] Quit
    [/] Search events
    [?] Help
    [w] Cycle weather modes
"""

import json
import logging
import os
import random
import signal
import sys
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, TYPE_CHECKING

# Handle curses import for Windows compatibility
try:
    import curses
    CURSES_AVAILABLE = True
except ImportError:
    curses = None
    CURSES_AVAILABLE = False

# Optional: Ollama client for AI chat (install with: pip install boundary-tui[ai])
try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    ollama = None

logger = logging.getLogger(__name__)

# Optional: Audio/TTS support (install with: pip install boundary-tui[audio])
try:
    import pyttsx3
    AUDIO_ENGINE_AVAILABLE = True
except ImportError:
    AUDIO_ENGINE_AVAILABLE = False
    pyttsx3 = None

# TUI modules
from .models import PanelType, DashboardEvent, DashboardAlert, SandboxStatus
from .colors import Colors
from .weather import WeatherMode, MatrixRain
from .backdrop import TunnelBackdrop
from .creatures import LightningBolt, AlleyRat, LurkingShadow
from .client import DashboardClient
from .scene import AlleyScene
from .protocol import DaemonProtocol, DemoProtocol

class Dashboard:
    """
    Terminal-based dashboard for Boundary Daemon.

    Displays:
    - Current mode and status
    - Recent events
    - Active alerts
    - Sandbox status
    - SIEM shipping status
    """

    def __init__(self, refresh_interval: float = 2.0, socket_path: Optional[str] = None,
                 matrix_mode: bool = False, client: Optional['DashboardClient'] = None):
        self.refresh_interval = refresh_interval
        # Use pre-created client if provided, otherwise create new one
        self.client = client or DashboardClient(socket_path)
        self.running = False
        self.screen = None
        self.selected_panel = PanelType.STATUS
        self.event_filter = ""
        self.scroll_offset = 0
        self.show_help = False
        self.matrix_mode = matrix_mode
        self.matrix_rain: Optional[MatrixRain] = None
        self.alley_scene: Optional[AlleyScene] = None

        # Data caches
        self.status: Dict = {}
        self.events: List[DashboardEvent] = []
        self.alerts: List[DashboardAlert] = []
        self.sandboxes: List[SandboxStatus] = []
        self.siem_status: Dict = {}
        self.ingestion_status: Dict = {}  # SIEM clients pulling events

        # Layout
        self.height = 0
        self.width = 0

        # Lightning effect state (for matrix mode)
        self._lightning_next_time = 0.0  # When to trigger next lightning
        self._lightning_active = False
        self._lightning_bolt: Optional[LightningBolt] = None
        self._lightning_flickers_remaining = 0
        self._lightning_flash_phase = 0

        # Creature state (for matrix mode)
        self.alley_rat: Optional[AlleyRat] = None
        self.lurking_shadow: Optional[LurkingShadow] = None
        self._has_warnings = False
        self._has_threats = False

        # Weather mode (for matrix mode)
        self._current_weather: WeatherMode = WeatherMode.MATRIX

        # Framerate options (for matrix mode)
        self._framerate_options = [100, 50, 25, 15, 10]  # ms
        self._framerate_index = 1  # Start at 50ms
        self._qte_enabled = False  # QTE (meteor game) toggle state - off by default
        self._qte_pending_activation = False  # Waiting for delayed QTE activation
        self._qte_activation_time = 0.0  # When to activate QTE
        self._audio_muted = False  # Audio mute toggle state
        self._tunnel_enabled = True  # 3D tunnel backdrop toggle state - on by default
        self._memory_debug_enabled = False  # Memory debug mode (tracemalloc) for leak tracking

        # TTS Engine for sound effects and LLM response speech
        self._tts_manager = None
        self._tts_enabled = True  # Enable TTS for LLM responses
        if AUDIO_ENGINE_AVAILABLE and pyttsx3 is not None:
            try:
                self._tts_manager = pyttsx3.init()
            except Exception as e:
                logger.debug(f"TTS initialization error: {e}")
                self._tts_manager = None

        # CLI mode state (bounded to prevent memory leaks)
        self._cli_history: deque = deque(maxlen=100)  # Command history limited to 100 entries
        self._cli_history_index = 0
        self._cli_results: List[str] = []  # Results display (trimmed on extend)
        self._cli_results_scroll = 0
        self._cli_last_activity = 0.0  # Last activity timestamp
        self._cli_timeout = 300.0  # 5 minutes inactivity timeout
        self._cli_chat_history: deque = deque(maxlen=50)  # Ollama chat history limited to 50 exchanges

        # Ollama client for CLI chat
        self._ollama_client = ollama if OLLAMA_AVAILABLE else None
        self._self_knowledge = ""  # Self-knowledge context for AI
        if self._ollama_client:
            try:
                # Load self-knowledge document for AI context
                self._self_knowledge = self._load_self_knowledge()
            except Exception:
                pass  # Ollama not available

        # Moon state (arcs across sky every 15 minutes)
        self._moon_active = False
        self._moon_x = 0.0
        self._moon_start_time = 0.0
        self._moon_next_time = 0.0  # When to start next moon arc
        self._moon_duration = 900.0  # 15 minutes (900 seconds) to cross screen

    def _speak_text(self, text: str, speed: float = 1.0, pitch: float = 0.0) -> bool:
        """Speak text using TTS engine in background thread. Returns True if started."""
        if self._audio_muted or not self._tts_manager:
            return False

        def _tts_worker():
            try:
                # Use pyttsx3 directly
                engine = self._tts_manager
                # Adjust rate based on speed (default is ~200 wpm)
                engine.setProperty('rate', int(200 * speed))
                engine.say(text)
                engine.runAndWait()
                logger.debug(f"TTS spoke: {text[:50]}...")
            except Exception as e:
                logger.debug(f"TTS error: {e}")

        try:
            # Run TTS in background thread to avoid blocking UI
            import threading
            tts_thread = threading.Thread(target=_tts_worker, daemon=True)
            tts_thread.start()
            return True
        except Exception as e:
            logger.debug(f"TTS thread error: {e}")
        return False

    def run(self):
        """Run the dashboard."""
        if not CURSES_AVAILABLE:
            if sys.platform == 'win32':
                # Try to auto-launch with Python 3.12 if available
                if self._try_relaunch_with_py312():
                    return  # Successfully relaunched
                print("Error: curses library not available on Windows.")
                print("")
                print("Try: pip install windows-curses")
                print("")
                print("If that fails (e.g., Python 3.14+), install Python 3.12:")
                print("  1. Download from https://www.python.org/downloads/release/python-3120/")
                print("  2. Run: py -3.12 -m pip install windows-curses")
                print("  3. Re-run this command (it will auto-detect Python 3.12)")
            else:
                print("Error: curses library not available.")
            sys.exit(1)
        curses.wrapper(self._main_loop)

    def _try_relaunch_with_py312(self) -> bool:
        """Try to relaunch the dashboard with Python 3.12 on Windows."""
        import subprocess

        # Check if we're already being relaunched (prevent infinite loop)
        if os.environ.get('_BOUNDARY_PY312_RELAUNCH'):
            return False

        # Try to find Python 3.12
        try:
            result = subprocess.run(
                ['py', '-3.12', '--version'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return False
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

        # Check if windows-curses is installed for Python 3.12
        try:
            result = subprocess.run(
                ['py', '-3.12', '-c', 'import curses'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                # Try to install windows-curses automatically
                print("Found Python 3.12, installing windows-curses...")
                install_result = subprocess.run(
                    ['py', '-3.12', '-m', 'pip', 'install', '-q', 'windows-curses'],
                    capture_output=True, text=True, timeout=60
                )
                if install_result.returncode != 0:
                    print("Failed to install windows-curses for Python 3.12")
                    return False
                print("Successfully installed windows-curses!")
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

        # Install project dependencies for Python 3.12
        # Find the project root (where requirements.txt should be)
        project_root = Path(__file__).parent.parent.parent
        requirements_file = project_root / 'requirements.txt'

        if requirements_file.exists():
            print("Installing project dependencies for Python 3.12...")
            try:
                install_result = subprocess.run(
                    ['py', '-3.12', '-m', 'pip', 'install', '-q', '-r', str(requirements_file)],
                    capture_output=True, text=True, timeout=300
                )
                if install_result.returncode != 0:
                    # Try installing just the essential packages
                    print("Full install failed, trying essential packages...")
                    subprocess.run(
                        ['py', '-3.12', '-m', 'pip', 'install', '-q', 'psutil'],
                        capture_output=True, text=True, timeout=60
                    )
            except subprocess.SubprocessError:
                pass  # Continue anyway, might still work
        else:
            # No requirements.txt, just install psutil
            try:
                subprocess.run(
                    ['py', '-3.12', '-m', 'pip', 'install', '-q', 'psutil'],
                    capture_output=True, text=True, timeout=60
                )
            except subprocess.SubprocessError:
                pass

        # Relaunch with Python 3.12
        print("Relaunching with Python 3.12...")
        env = os.environ.copy()
        env['_BOUNDARY_PY312_RELAUNCH'] = '1'

        # Rebuild the command line arguments
        args = ['py', '-3.12', '-m', 'daemon.tui.dashboard']
        if self.matrix_mode:
            args.append('--matrix')
        if self.refresh_interval != 2.0:
            args.extend(['--refresh', str(self.refresh_interval)])

        try:
            result = subprocess.run(args, env=env)
            sys.exit(result.returncode)
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

        return True

    def _main_loop(self, screen):
        """Main curses loop."""
        self.screen = screen
        self.running = True

        # Setup curses
        curses.curs_set(0)  # Hide cursor
        Colors.init_colors(self.matrix_mode)

        # Matrix mode: faster refresh for smooth animation, black background
        if self.matrix_mode:
            screen.timeout(self._framerate_options[self._framerate_index])  # Use selected framerate
            screen.bkgd(' ', curses.color_pair(Colors.MATRIX_DIM))
            self._update_dimensions()
            self.alley_scene = AlleyScene(self.width, self.height)
            self.matrix_rain = MatrixRain(self.width, self.height)
            self.tunnel_backdrop = TunnelBackdrop(self.width, self.height)
            # Connect snow filter so snow only collects on roofs/sills, not building faces
            self.matrix_rain.set_snow_filter(self.alley_scene.is_valid_snow_position)
            # Connect roof/sill checker so snow on roofs/sills lasts 10x longer
            self.matrix_rain.set_roof_sill_checker(self.alley_scene.is_roof_or_sill)
            # Connect street light glow positions so snow melts faster in warm light
            self.matrix_rain.set_glow_positions(self.alley_scene._street_light_positions)
            # Set quick-melt zones (sidewalk, mailbox, street, traffic light) so snow melts very fast there
            sidewalk_y = self.height - 4  # curb_y
            street_y = self.height - 3
            mailbox_bounds = (self.alley_scene.mailbox_x, self.alley_scene.mailbox_y,
                              len(self.alley_scene.MAILBOX[0]), len(self.alley_scene.MAILBOX))
            # Traffic light bounds
            traffic_light_x = min(self.width - 10, self.alley_scene.box_x + len(self.alley_scene.BOX[0]) + 100)
            traffic_light_y = self.height - len(self.alley_scene.TRAFFIC_LIGHT_TEMPLATE) - 1
            traffic_light_bounds = (traffic_light_x, traffic_light_y,
                                    len(self.alley_scene.TRAFFIC_LIGHT_TEMPLATE[0]),
                                    len(self.alley_scene.TRAFFIC_LIGHT_TEMPLATE))
            # Cafe bounds (snow melts on building but not on turtle shell roof)
            cafe_bounds = (self.alley_scene.cafe_x, self.alley_scene.cafe_y,
                          len(self.alley_scene.CAFE[0]), len(self.alley_scene.CAFE), 7)  # 7 rows for turtle shell
            self.matrix_rain.set_quick_melt_zones(sidewalk_y, mailbox_bounds, street_y, traffic_light_bounds, cafe_bounds)
            # Initialize creatures
            self.alley_rat = AlleyRat(self.width, self.height)
            self.alley_rat.set_hiding_spots(self.alley_scene)
            self.lurking_shadow = LurkingShadow(self.width, self.height)
            # Schedule first lightning strike (5-30 minutes from now)
            self._lightning_next_time = time.time() + random.uniform(300, 1800)
            # Schedule first moon arc (start immediately, then every 15 minutes)
            self._moon_next_time = time.time() + 5.0  # Start in 5 seconds
        else:
            screen.timeout(int(self.refresh_interval * 1000))

        # Handle terminal resize (Unix only - Windows doesn't have SIGWINCH)
        if hasattr(signal, 'SIGWINCH'):
            signal.signal(signal.SIGWINCH, lambda *_: self._handle_resize())

        # Initial data fetch
        self._refresh_data()

        while self.running:
            try:
                old_width, old_height = self.width, self.height
                self._update_dimensions()

                # Sync matrix rain dimensions if window resized
                if self.matrix_mode and self.matrix_rain:
                    if self.width != old_width or self.height != old_height:
                        if self.alley_scene:
                            self.alley_scene.resize(self.width, self.height)
                            # Update glow positions for snow melting
                            self.matrix_rain.set_glow_positions(self.alley_scene._street_light_positions)
                            # Update quick-melt zones
                            sidewalk_y = self.height - 4
                            street_y = self.height - 3
                            mailbox_bounds = (self.alley_scene.mailbox_x, self.alley_scene.mailbox_y,
                                              len(self.alley_scene.MAILBOX[0]), len(self.alley_scene.MAILBOX))
                            traffic_light_x = min(self.width - 10, self.alley_scene.box_x + len(self.alley_scene.BOX[0]) + 100)
                            traffic_light_y = self.height - len(self.alley_scene.TRAFFIC_LIGHT_TEMPLATE) - 1
                            traffic_light_bounds = (traffic_light_x, traffic_light_y,
                                                    len(self.alley_scene.TRAFFIC_LIGHT_TEMPLATE[0]),
                                                    len(self.alley_scene.TRAFFIC_LIGHT_TEMPLATE))
                            # Cafe bounds (snow melts on building but not on shell roof)
                            cafe_bounds = (self.alley_scene.cafe_x, self.alley_scene.cafe_y,
                                          len(self.alley_scene.CAFE[0]), len(self.alley_scene.CAFE), 8)
                            self.matrix_rain.set_quick_melt_zones(sidewalk_y, mailbox_bounds, street_y, traffic_light_bounds, cafe_bounds)
                        self.matrix_rain.resize(self.width, self.height)
                        if hasattr(self, 'tunnel_backdrop') and self.tunnel_backdrop:
                            self.tunnel_backdrop.resize(self.width, self.height)
                        if self.alley_rat:
                            self.alley_rat.resize(self.width, self.height)
                            self.alley_rat.set_hiding_spots(self.alley_scene)
                        if self.lurking_shadow:
                            self.lurking_shadow.resize(self.width, self.height)
                    self.matrix_rain.update()

                    # Update tunnel backdrop animation
                    if hasattr(self, 'tunnel_backdrop') and self.tunnel_backdrop:
                        self.tunnel_backdrop.update()

                    # Update alley scene (traffic light)
                    if self.alley_scene:
                        self.alley_scene.update()
                        # Check for new daemon events to spawn warning trucks
                        self._check_daemon_events_for_trucks()
                        # Check for pending QTE activation
                        if self._qte_pending_activation and time.time() >= self._qte_activation_time:
                            self._qte_pending_activation = False
                            self._qte_enabled = True
                            self.alley_scene._qte_enabled = True

                    # Update creatures based on alert state
                    self._update_creatures()

                    # Check for lightning strike
                    self._update_lightning()

                    # Update moon arc
                    self._update_moon()

                self._draw()

                # Wait for input with timeout
                key = screen.getch()
                self._handle_input(key)

                # Refresh data on timeout (less frequently in matrix mode)
                if key == -1:  # Timeout
                    if not self.matrix_mode or random.random() < 0.1:
                        self._refresh_data()

            except KeyboardInterrupt:
                self.running = False
            except curses.error:
                pass

    def _handle_resize(self):
        """Handle terminal resize."""
        self._update_dimensions()
        if self.matrix_mode:
            if self.alley_scene:
                self.alley_scene.resize(self.width, self.height)
            if self.matrix_rain:
                self.matrix_rain.resize(self.width, self.height)
                # Update glow positions for snow melting
                if self.alley_scene:
                    self.matrix_rain.set_glow_positions(self.alley_scene._street_light_positions)
            if hasattr(self, 'tunnel_backdrop') and self.tunnel_backdrop:
                self.tunnel_backdrop.resize(self.width, self.height)
            if self.alley_rat:
                self.alley_rat.resize(self.width, self.height)
                self.alley_rat.set_hiding_spots(self.alley_scene)
            if self.lurking_shadow:
                self.lurking_shadow.resize(self.width, self.height)
        self.screen.clear()

    def _update_dimensions(self):
        """Update terminal dimensions."""
        self.height, self.width = self.screen.getmaxyx()

    def _check_daemon_events_for_trucks(self):
        """Check for new daemon events and spawn warning trucks for critical/important ones.

        Only spawns warning trucks for REAL daemon events, not demo events.
        Tracks seen event IDs to avoid duplicate trucks.
        """
        if not self.alley_scene:
            return

        # Rate limit: only check every ~2 seconds (120 frames at 60fps)
        self.alley_scene._last_event_check += 1
        if self.alley_scene._last_event_check < 120:
            return
        self.alley_scene._last_event_check = 0

        # Skip if in demo mode (no real events)
        if self.client.is_demo_mode():
            return

        try:
            # Get recent alerts (high priority events)
            alerts = self.client.get_alerts()
            for alert in alerts:
                # Create unique ID from alert properties
                alert_id = f"alert_{alert.severity}_{alert.message[:20]}_{alert.timestamp}"
                if alert_id in self.alley_scene._known_event_ids:
                    continue

                # Mark as seen
                self.alley_scene._known_event_ids.add(alert_id)

                # Create warning message for truck
                prefix = random.choice(self.alley_scene.SEMI_WARNING_PREFIXES)
                message = f"{prefix}{alert.message[:40]}"

                # Spawn warning truck
                self.alley_scene._spawn_car(warning_message=message)

            # Get recent events (check for critical ones)
            events = self.client.get_events(10)
            for event in events:
                # Only spawn trucks for critical/warning events
                if event.severity not in ['critical', 'high', 'warning']:
                    continue

                # Create unique ID
                event_id = f"event_{event.type}_{event.timestamp}"
                if event_id in self.alley_scene._known_event_ids:
                    continue

                # Mark as seen
                self.alley_scene._known_event_ids.add(event_id)

                # Create warning message for truck
                prefix = random.choice(self.alley_scene.SEMI_WARNING_PREFIXES)
                message = f"{prefix}{event.type}: {event.details.get('message', '')[:30]}"

                # Spawn warning truck
                self.alley_scene._spawn_car(warning_message=message)

            # Limit the size of known events set (keep last 1000)
            if len(self.alley_scene._known_event_ids) > 1000:
                # Remove oldest half
                known_list = list(self.alley_scene._known_event_ids)
                self.alley_scene._known_event_ids = set(known_list[500:])

        except Exception as e:
            # Silently ignore errors (daemon might be unavailable)
            pass

    def _update_lightning(self):
        """Check and update lightning strike state."""
        current_time = time.time()

        # Check if it's time for a lightning strike
        if not self._lightning_active and current_time >= self._lightning_next_time:
            # Start lightning strike!
            self._lightning_active = True
            self._lightning_bolt = LightningBolt(self.width, self.height)
            self._lightning_flickers_remaining = random.randint(3, 5)
            self._lightning_flash_phase = 0
            # Check if lightning knocked out any pedestrians
            if self._lightning_bolt.path and self.alley_scene:
                lightning_x = self._lightning_bolt.path[0][1]  # Get x from first point
                self.alley_scene.check_lightning_knockout(lightning_x)

        # Update active lightning
        if self._lightning_active:
            self._lightning_flash_phase += 1

            # Each flicker cycle: bright(2) -> dim(1) -> off(1) = 4 frames per flicker
            # At 100ms per frame, 4 frames = 400ms, so 3-5 flickers = 1.2-2 seconds total
            # But we want 3-5 flickers in ~0.5 second, so faster: 2 frames per flicker
            cycle_length = 2
            cycles_done = self._lightning_flash_phase // cycle_length

            if cycles_done >= self._lightning_flickers_remaining:
                # Lightning is done
                self._lightning_active = False
                self._lightning_bolt = None
                # Schedule next lightning (5-30 minutes from now)
                self._lightning_next_time = current_time + random.uniform(300, 1800)

    def _update_moon(self):
        """Update moon arc across the sky (15 minute cycle)."""
        current_time = time.time()

        # Check if it's time to start a new moon arc
        if not self._moon_active and current_time >= self._moon_next_time:
            self._moon_active = True
            self._moon_start_time = current_time
            self._moon_x = 0.0

        # Update active moon
        if self._moon_active:
            elapsed = current_time - self._moon_start_time
            progress = elapsed / self._moon_duration  # 0.0 to 1.0

            if progress >= 1.0:
                # Moon has crossed the sky
                self._moon_active = False
                # Schedule next moon arc (15 minutes from now)
                self._moon_next_time = current_time + 900.0  # 15 minutes
            else:
                # Update moon x position
                self._moon_x = progress * self.width

    def _render_moon(self, screen):
        """Render the moon in a high arc across the sky."""
        if not self._moon_active:
            return

        # Calculate moon position in arc
        progress = (self._moon_x / self.width) if self.width > 0 else 0

        # High arc: y = height at edges, low (near top) in middle
        # Using parabola: y = a * (x - 0.5)^2 + min_y
        # At edges (x=0 or 1): y = a * 0.25 + min_y = max_y
        # At center (x=0.5): y = min_y
        min_y = 2  # Highest point (near top of screen)
        max_y = self.height // 3  # Lowest point of arc (at edges)
        arc_height = max_y - min_y

        # Parabola centered at 0.5
        x_centered = progress - 0.5
        moon_y = int(min_y + arc_height * 4 * (x_centered ** 2))
        moon_x = int(self._moon_x)

        # Moon ASCII art (filled moon)
        moon_chars = [
            " @@@ ",
            "@@@@@",
            "@@@@@",
            "@@@@@",
            " @@@ ",
        ]

        # Render moon
        for row_idx, row in enumerate(moon_chars):
            for col_idx, char in enumerate(row):
                px = moon_x + col_idx - 2  # Center the moon
                py = moon_y + row_idx - 2
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    try:
                        attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_BOLD
                        screen.attron(attr)
                        screen.addstr(py, px, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

    def _update_creatures(self):
        """Update creature state based on alerts."""
        # Check for warnings (MEDIUM severity or WARN events)
        has_warnings = False
        has_threats = False

        for alert in self.alerts:
            if alert.severity in ('MEDIUM', 'LOW'):
                has_warnings = True
            if alert.severity in ('HIGH', 'CRITICAL'):
                has_threats = True

        # Also check recent events for warnings
        for event in self.events[:5]:  # Check last 5 events
            if event.severity == 'WARN':
                has_warnings = True
            if event.severity == 'ERROR':
                has_threats = True

        # Update rat state (for warnings)
        if self.alley_rat:
            if has_warnings and not self._has_warnings:
                # New warning appeared - activate rat
                self.alley_rat.activate()
            elif not has_warnings and self._has_warnings:
                # Warnings cleared - deactivate rat
                self.alley_rat.deactivate()
            self.alley_rat.update()

        # Update shadow state (for threats)
        if self.lurking_shadow:
            if has_threats and not self._has_threats:
                # New threat detected - activate shadow
                self.lurking_shadow.activate()
            elif not has_threats and self._has_threats:
                # Threats cleared - deactivate shadow
                self.lurking_shadow.deactivate()
            self.lurking_shadow.update()

        self._has_warnings = has_warnings
        self._has_threats = has_threats

    def _render_lightning(self):
        """Render the lightning bolt with flicker effect."""
        if not self._lightning_bolt:
            return

        # Calculate flash intensity based on phase
        # Alternate between bright and dim for flicker effect
        cycle_pos = self._lightning_flash_phase % 2
        if cycle_pos == 0:
            # Bright flash
            LightningBolt.flash_screen(self.screen, self.width, self.height)
            self._lightning_bolt.render(self.screen, 1.0)
        else:
            # Dim phase - just show the bolt, no full screen flash
            self._lightning_bolt.render(self.screen, 0.5)

    def _refresh_data(self):
        """Refresh all data from daemon."""
        # If in demo mode, periodically try to reconnect to real daemon
        if self.client.is_demo_mode():
            if self.client.reconnect():
                logger.info("Reconnected to daemon!")

        try:
            self.status = self.client.get_status()
            # Only refresh events if not manually cleared
            if not getattr(self, '_events_cleared', False):
                self.events = self.client.get_events(20)
            self.alerts = self.client.get_alerts()
            self.sandboxes = self.client.get_sandboxes()
            self.siem_status, self.ingestion_status = self.client.get_siem_status()
        except Exception as e:
            logger.error(f"Failed to refresh data: {e}")

    def _handle_input(self, key: int):
        """Handle keyboard input."""
        if key == ord('q') or key == ord('Q'):
            self.running = False
        elif key == ord('r') or key == ord('R'):
            self._refresh_data()
        elif key == ord('?'):
            self.show_help = not self.show_help
        elif key == ord('m') or key == ord('M'):
            self._show_mode_ceremony()
        elif key == ord('a') or key == ord('A'):
            self._acknowledge_alert()
        elif key == ord('e') or key == ord('E'):
            self._export_events()
        elif key == ord('c') or key == ord('C'):
            # Clear events display (stays cleared until manual reload)
            self.events = []
            self.scroll_offset = 0
            self._events_cleared = True  # Prevent auto-refresh from refetching
        elif key == ord('l') or key == ord('L'):
            # Recall/reload events from daemon (also resets cleared flag)
            try:
                self._events_cleared = False  # Allow auto-refresh again
                self.events = self.client.get_events(50)  # Get more events
                self.scroll_offset = 0
            except Exception:
                pass
        elif key == ord('/'):
            self._start_search()
        elif key == 27:  # ESC - clear search filter
            self.event_filter = ""
        elif key == curses.KEY_UP:
            self.scroll_offset = max(0, self.scroll_offset - 1)
        elif key == curses.KEY_DOWN:
            self.scroll_offset += 1
        elif key == ord('1'):
            self.selected_panel = PanelType.STATUS
        elif key == ord('2'):
            self.selected_panel = PanelType.EVENTS
        elif key == ord('3'):
            self.selected_panel = PanelType.ALERTS
        elif key == ord('4'):
            self.selected_panel = PanelType.SANDBOXES
        elif key == ord('w') or key == ord('W'):
            # Cycle weather mode (only in matrix mode)
            if self.matrix_mode and self.matrix_rain:
                new_mode = self.matrix_rain.cycle_weather()
                # Store for header display
                self._current_weather = new_mode
                # Sync calm mode and full weather mode to alley scene
                if self.alley_scene:
                    self.alley_scene.set_calm_mode(new_mode == WeatherMode.CALM)
                    self.alley_scene.set_weather_mode(new_mode)
                    # Announce weather change via prop plane
                    weather_names = {
                        WeatherMode.MATRIX: "MATRIX MODE",
                        WeatherMode.RAIN: "RAIN STORM",
                        WeatherMode.SNOW: "SNOW FALL",
                        WeatherMode.SAND: "SAND STORM",
                        WeatherMode.CALM: "CALM WEATHER",
                    }
                    self.alley_scene.queue_plane_announcement(
                        f"★ WEATHER: {weather_names.get(new_mode, 'UNKNOWN')} ★"
                    )
                # Sync weather mode to tunnel backdrop
                if hasattr(self, 'tunnel_backdrop') and self.tunnel_backdrop:
                    self.tunnel_backdrop.set_weather_mode(new_mode)
        elif key == ord('t') or key == ord('T'):
            # Toggle tunnel backdrop effect (only in matrix mode)
            if self.matrix_mode and hasattr(self, 'tunnel_backdrop') and self.tunnel_backdrop:
                self._tunnel_enabled = not getattr(self, '_tunnel_enabled', True)
                self.tunnel_backdrop.set_enabled(self._tunnel_enabled)
        elif key == ord('f') or key == ord('F'):
            # Cycle framerate (only in matrix mode)
            if self.matrix_mode:
                self._framerate_index = (self._framerate_index + 1) % len(self._framerate_options)
                # Apply new framerate immediately
                if self.screen:
                    self.screen.timeout(self._framerate_options[self._framerate_index])
        elif key == ord('g') or key == ord('G'):
            # Toggle QTE (meteor game) on/off
            if self.matrix_mode and self.alley_scene:
                enabled = self.alley_scene.toggle_qte()
                self._qte_enabled = enabled  # Store for header display
        elif key == ord('u') or key == ord('U'):
            # Toggle audio mute on/off
            if self.matrix_mode and self.alley_scene:
                muted = self.alley_scene.toggle_mute()
                self._audio_muted = muted  # Store for header display
        elif key == ord('d') or key == ord('D'):
            # Toggle memory debug mode (tracemalloc) for leak tracking
            success, message = self.client.toggle_memory_debug()
            if success:
                self._memory_debug_enabled = not self._memory_debug_enabled
        # QTE keys (6, 7, 8, 9, 0) for meteor game
        elif key in [ord('6'), ord('7'), ord('8'), ord('9'), ord('0')]:
            if self.matrix_mode and self.alley_scene:
                if self._qte_enabled:
                    # QTE is on - pass key to game
                    self.alley_scene.handle_qte_key(chr(key))
                elif not self._qte_pending_activation:
                    # QTE is off - start delayed activation (30-90 seconds)
                    self._qte_pending_activation = True
                    self._qte_activation_time = time.time() + random.uniform(30, 90)
        # CLI mode (: or ;)
        elif key == ord(':') or key == ord(';'):
            self._start_cli()

    def _draw(self):
        """Draw the dashboard."""
        self.screen.clear()

        # Render 3D tunnel backdrop first (absolute furthest back - cosmic sky effect)
        if self.matrix_mode and hasattr(self, 'tunnel_backdrop') and self.tunnel_backdrop:
            self.tunnel_backdrop.render(self.screen)

        # Render moon (behind everything except tunnel)
        if self.matrix_mode and self.matrix_rain:
            self._render_moon(self.screen)

        # Render alley scene (behind rain but in front of moon)
        if self.matrix_mode and self.alley_scene:
            self.alley_scene.render(self.screen)

        # Render matrix rain on top of alley
        if self.matrix_mode and self.matrix_rain:
            self.matrix_rain.render(self.screen)

            # Render creatures (between rain and UI)
            if self.alley_rat:
                self.alley_rat.render(self.screen)
            if self.lurking_shadow:
                self.lurking_shadow.render(self.screen)

            # Render lightning bolt if active
            if self._lightning_active and self._lightning_bolt:
                self._render_lightning()

        if self.show_help:
            self._draw_help()
        else:
            self._draw_header()
            self._draw_panels()

        self.screen.refresh()

    def _draw_header(self):
        """Draw the header bar."""
        header = " BOUNDARY DAEMON"
        if self.client.is_demo_mode():
            header += " [DEMO]"
        # Show weather mode and framerate in matrix mode
        if self.matrix_mode:
            header += f" [{self._current_weather.display_name}]"
            header += f" [{self._framerate_options[self._framerate_index]}ms]"
            if not self._tunnel_enabled:
                header += " [TUNNEL OFF]"
            if not self._qte_enabled:
                header += " [QTE OFF]"
            if self._audio_muted:
                header += " [MUTED]"
        if self._memory_debug_enabled:
            header += " [DEBUG]"
        header += f"  │  Mode: {self.status.get('mode', 'UNKNOWN')}  │  "
        if self.status.get('is_frozen'):
            header += "⚠ MODE FROZEN  │  "
        # SIEM connection status indicator
        siem_connected = self.siem_status.get('connected', False) if self.siem_status else False
        ingestion_connected = bool(self.ingestion_status.get('active_clients', 0)) if self.ingestion_status else False
        if siem_connected and ingestion_connected:
            header += "[SIEM: CONNECTED]  │  "
        elif siem_connected or ingestion_connected:
            header += "[SIEM: PARTIAL]  │  "
        else:
            header += "[SIEM: UNDETECTED]  │  "
        header += f"Uptime: {self._format_duration(self.status.get('uptime', 0))}"
        if self.event_filter:
            header += f"  │  Filter: {self.event_filter}"

        # Pad to full width
        header = header.ljust(self.width - 1)

        # Use weather-blended color for header
        header_color = self._get_weather_text_color(Colors.HEADER)
        self.screen.attron(curses.color_pair(header_color) | curses.A_BOLD)
        self.screen.addstr(0, 0, header[:self.width-1])
        self.screen.attroff(curses.color_pair(header_color) | curses.A_BOLD)

    def _draw_panels(self):
        """Draw the main panels in a 2x2 grid."""
        # Calculate panel dimensions for 2x2 grid
        # Leave 1 row for header at top, boxes extend to bottom of screen
        available_height = self.height - 1
        available_width = self.width - 1  # Avoid last column curses error

        # Each panel gets half the width and half the height
        panel_width = available_width // 2
        panel_height = available_height // 2

        # Adjust for odd dimensions
        right_width = available_width - panel_width
        bottom_height = available_height - panel_height

        # Top row starts at y=1 (after header)
        # Bottom row starts at y=1+panel_height
        top_y = 1
        bottom_y = 1 + panel_height

        # Draw 2x2 grid: STATUS | ALERTS
        #                EVENTS | SIEM
        self._draw_status_panel(top_y, 0, panel_width, panel_height)
        self._draw_alerts_panel(top_y, panel_width, right_width, panel_height)
        self._draw_events_panel(bottom_y, 0, panel_width, bottom_height)
        self._draw_siem_panel(bottom_y, panel_width, right_width, bottom_height)

    def _draw_status_panel(self, y: int, x: int, width: int, height: int):
        """Draw the status panel with spaced out lines."""
        self._draw_box(y, x, width, height, "STATUS")

        row = y + 1
        col = x + 2

        # Connection status
        if self.client.is_demo_mode():
            self._addstr(row, col, "Connection: ", Colors.MUTED)
            self._addstr(row, col + 12, "DEMO MODE", Colors.STATUS_ERROR, bold=True)
            row += 2  # Extra space
            self._addstr(row, col, "(No daemon)", Colors.MUTED)
            row += 2  # Extra space
        else:
            self._addstr(row, col, "Connection: ", Colors.MUTED)
            if self.client._use_tcp:
                conn_text = f"TCP:{self.client.WINDOWS_PORT}"
            else:
                conn_text = "Socket"
            self._addstr(row, col + 12, conn_text, Colors.STATUS_OK)
            row += 2  # Extra space

        # Mode
        mode = self.status.get('mode', 'UNKNOWN')
        mode_color = Colors.STATUS_OK if mode in ('TRUSTED', 'AIRGAP', 'COLDROOM') else Colors.STATUS_WARN
        self._addstr(row, col, f"Mode: ", Colors.MUTED)
        self._addstr(row, col + 6, mode, mode_color, bold=True)
        row += 2  # Extra space

        # Tripwires
        tw_enabled = self.status.get('tripwire_enabled', False)
        tw_text = "✓ Enabled" if tw_enabled else "✗ Disabled"
        tw_color = Colors.STATUS_OK if tw_enabled else Colors.STATUS_ERROR
        self._addstr(row, col, "Tripwires: ", Colors.MUTED)
        self._addstr(row, col + 11, tw_text, tw_color)
        row += 2  # Extra space

        # Clock Monitor
        cm_enabled = self.status.get('clock_monitor_enabled', False)
        cm_text = "✓ Active" if cm_enabled else "✗ Inactive"
        cm_color = Colors.STATUS_OK if cm_enabled else Colors.STATUS_WARN
        self._addstr(row, col, "Clock: ", Colors.MUTED)
        self._addstr(row, col + 7, cm_text, cm_color)
        row += 2  # Extra space

        # Network Attestation
        na_enabled = self.status.get('network_attestation_enabled', False)
        na_text = "✓ Active" if na_enabled else "○ Inactive"
        na_color = Colors.STATUS_OK if na_enabled else Colors.MUTED
        self._addstr(row, col, "Network: ", Colors.MUTED)
        self._addstr(row, col + 9, na_text, na_color)
        row += 2  # Extra space

        # Events today
        events_count = self.status.get('events_today', 0)
        self._addstr(row, col, f"Events: {events_count:,}", Colors.MUTED)
        row += 2  # Extra space

        # Violations
        violations = self.status.get('violations', 0)
        v_color = Colors.STATUS_ERROR if violations > 0 else Colors.STATUS_OK
        self._addstr(row, col, f"Violations: {violations}", v_color)

    def _draw_events_panel(self, y: int, x: int, width: int, height: int):
        """Draw the events panel with footer shortcuts at bottom."""
        self._draw_box(y, x, width, height, f"EVENTS (last {len(self.events)})")

        row = y + 1
        col = x + 2
        # Reserve 1 row for shortcuts at bottom (inside the box)
        max_rows = height - 3
        display_width = width - 4

        for i, event in enumerate(self.events[:max_rows]):
            if row >= y + height - 2:  # Leave room for shortcuts
                break

            # Time
            time_str = event.time_short
            self._addstr(row, col, time_str, Colors.MUTED)

            # Type
            type_col = col + 10
            type_color = Colors.ACCENT if event.event_type in ('VIOLATION', 'TRIPWIRE') else Colors.NORMAL
            event_type = event.event_type[:15]
            self._addstr(row, type_col, event_type, type_color)

            # Details (truncated)
            detail_col = type_col + 16
            max_detail = display_width - (detail_col - col)
            details = event.details[:max_detail] if len(event.details) > max_detail else event.details
            self._addstr(row, detail_col, details, Colors.NORMAL)

            row += 1

        # Draw shortcuts at bottom of events panel (inside the box)
        shortcut_row = y + height - 2
        if self.matrix_mode:
            shortcuts = "[:]CLI [w]Weather [t]Tunnel [f]FPS [g]Game [u]Mute [a]Ack [d]Debug [?]Help [q]Quit"
        else:
            shortcuts = "[m]Mode [a]Ack [c]Clear [l]Load [e]Export [r]Refresh [/]Search [d]Debug [?]Help [q]Quit"

        # Center the shortcuts
        shortcuts = shortcuts[:display_width]
        self._addstr(shortcut_row, col, shortcuts, Colors.MUTED)

    def _draw_alerts_panel(self, y: int, x: int, width: int, height: int):
        """Draw the alerts panel."""
        unack_count = sum(1 for a in self.alerts if a.status == "NEW")
        title = f"ALERTS ({unack_count} unacknowledged)" if unack_count else "ALERTS"
        title_color = Colors.STATUS_ERROR if unack_count else Colors.HEADER
        self._draw_box(y, x, width, height, title, title_color)

        row = y + 1
        col = x + 2
        display_width = width - 4

        if not self.alerts:
            self._addstr(row, col, "No active alerts", Colors.STATUS_OK)
        else:
            for alert in self.alerts[:height-2]:
                if row >= y + height - 1:
                    break

                # Status icon
                if alert.status == "NEW":
                    icon = "⚠"
                    icon_color = Colors.STATUS_WARN if alert.severity == "MEDIUM" else Colors.STATUS_ERROR
                elif alert.status == "ACKNOWLEDGED":
                    icon = "○"
                    icon_color = Colors.MUTED
                else:
                    icon = "✓"
                    icon_color = Colors.STATUS_OK

                self._addstr(row, col, icon, icon_color)
                self._addstr(row, col + 2, alert.severity[:4], icon_color)

                # Message (truncated)
                msg_col = col + 8
                max_msg = display_width - 10
                message = alert.message[:max_msg] if len(alert.message) > max_msg else alert.message
                self._addstr(row, msg_col, message, Colors.NORMAL)

                row += 1

    def _draw_sandbox_panel(self, y: int, x: int, width: int, height: int):
        """Draw the sandbox panel."""
        active_count = len([s for s in self.sandboxes if s.status == "running"])
        self._draw_box(y, x, width, height, f"SANDBOXES ({active_count} active)")

        row = y + 1
        col = x + 2
        display_width = width - 4

        if not self.sandboxes:
            self._addstr(row, col, "No active sandboxes", Colors.MUTED)
        else:
            for sb in self.sandboxes[:height-2]:
                if row >= y + height - 1:
                    break

                # ID and profile
                id_str = f"{sb.sandbox_id[:12]} ({sb.profile})"
                status_color = Colors.STATUS_OK if sb.status == "running" else Colors.MUTED
                self._addstr(row, col, id_str, status_color)

                # Memory
                mem_pct = (sb.memory_used / sb.memory_limit * 100) if sb.memory_limit else 0
                mem_color = Colors.STATUS_OK if mem_pct < 80 else Colors.STATUS_WARN
                mem_str = f"{self._format_bytes(sb.memory_used)}/{self._format_bytes(sb.memory_limit)}"
                self._addstr(row, col + 28, mem_str, mem_color)

                # CPU
                cpu_color = Colors.STATUS_OK if sb.cpu_percent < 80 else Colors.STATUS_WARN
                cpu_str = f"{sb.cpu_percent:.0f}%"
                self._addstr(row, col + 45, cpu_str, cpu_color)

                row += 1

    def _draw_siem_panel(self, y: int, x: int, width: int, height: int):
        """Draw the SIEM status panel with shipping and ingestion stats."""
        connected = self.siem_status.get('connected', False)
        ingestion_connected = self.ingestion_status.get('connected', False)
        ingestion_was_connected = self.ingestion_status.get('was_connected', False)
        ingestion_active = self.ingestion_status.get('active', False)

        # Determine panel status color based on connection state
        # Warning (yellow) if SIEM was connected but is now disconnected
        if ingestion_was_connected and not ingestion_connected:
            title_color = Colors.STATUS_WARNING  # Disconnected warning
        elif connected or ingestion_connected:
            title_color = Colors.STATUS_OK
        else:
            title_color = Colors.MUTED

        # Draw box with empty title, then add right-aligned title manually
        self._draw_box(y, x, width, height, "")
        # Right-align the title
        title_str = " SIEM "
        title_x = x + width - len(title_str) - 1
        try:
            self.screen.attron(curses.color_pair(title_color) | curses.A_BOLD)
            self.screen.addstr(y, title_x, title_str)
            self.screen.attroff(curses.color_pair(title_color) | curses.A_BOLD)
        except curses.error:
            pass

        row = y + 1
        # Right-align text within the box (2 char padding from right edge)
        right_edge = x + width - 2

        # --- Ingestion stats (SIEM pulling from daemon) ---
        if ingestion_connected:
            ingestion_text = "✓ Connected"
            ingestion_color = Colors.STATUS_OK
        elif ingestion_was_connected:
            ingestion_text = "⚠ Disconnected"
            ingestion_color = Colors.STATUS_WARNING
        elif ingestion_active:
            ingestion_text = "○ Idle"
            ingestion_color = Colors.MUTED
        else:
            ingestion_text = "○ No client"
            ingestion_color = Colors.MUTED
        line = f"Ingestion: {ingestion_text}"
        self._addstr(row, right_edge - len(line), line, ingestion_color)
        row += 1

        # Events served to SIEM clients
        served = self.ingestion_status.get('events_served_today', 0)
        requests = self.ingestion_status.get('requests_today', 0)
        line = f"Served: {served:,} ({requests} req)"
        self._addstr(row, right_edge - len(line), line, Colors.MUTED)
        row += 1

        # Show last client info if disconnected
        if ingestion_was_connected and not ingestion_connected:
            last_client = self.ingestion_status.get('last_client', '')
            if last_client:
                # Truncate client info to fit
                max_len = width - 4
                if len(last_client) > max_len:
                    last_client = last_client[:max_len-2] + ".."
                line = f"Last: {last_client}"
                self._addstr(row, right_edge - len(line), line, Colors.STATUS_WARNING)
                row += 1

        # --- Shipping stats (daemon pushing to SIEM) ---
        status_text = "✓ Shipping" if connected else "○ Not configured"
        status_color = Colors.STATUS_OK if connected else Colors.MUTED
        line = f"Shipping: {status_text}"
        self._addstr(row, right_edge - len(line), line, status_color)
        row += 1

        # Events shipped (only show if connected)
        if connected:
            shipped = self.siem_status.get('events_shipped_today', 0)
            queue = self.siem_status.get('queue_depth', 0)
            line = f"Shipped: {shipped:,} (Q:{queue})"
            self._addstr(row, right_edge - len(line), line, Colors.MUTED)

    def _draw_footer(self):
        """Draw the footer bar."""
        # Add weather shortcut in matrix mode
        if self.matrix_mode:
            shortcuts = "[:]CLI [w]Weather [t]Tunnel [f]FPS [g]Game [u]Mute [a]Ack [d]Debug [?]Help [q]Quit"
        else:
            shortcuts = "[m]Mode [a]Ack [c]Clear [l]Load [e]Export [r]Refresh [/]Search [d]Debug [?]Help [q]Quit"

        # In demo mode, show connection hint
        if self.client.is_demo_mode():
            if sys.platform == 'win32':
                hint = " | Demo: Start daemon or check port 19847"
            else:
                hint = " | Demo: Start daemon (./api/boundary.sock)"
            footer = f" {shortcuts}{hint} ".ljust(self.width - 1)
        else:
            footer = f" {shortcuts} ".ljust(self.width - 1)

        row = self.height - 1
        self.screen.attron(curses.color_pair(Colors.MUTED))
        try:
            self.screen.addstr(row, 0, footer[:self.width-1])
        except curses.error:
            pass
        self.screen.attroff(curses.color_pair(Colors.MUTED))

    def _draw_help(self):
        """Draw help overlay."""
        help_text = [
            "KEYBOARD SHORTCUTS",
            "",
            "  m    Start mode change ceremony",
            "  a    Acknowledge selected alert",
            "  c    Clear events display",
            "  l    Load/recall events from daemon",
            "  e    Export events to file",
            "  r    Refresh data",
            "  /    Filter events",
            "  d    Toggle memory leak trace debug",
            "",
            "  1    Focus status panel",
            "  2    Focus events panel",
            "  3    Focus alerts panel",
            "  4    Focus sandboxes panel",
            "",
            "  ↑↓   Scroll current panel",
            "  q    Quit dashboard",
            "  ?    Toggle this help",
            "",
        ]

        # Add weather info if in matrix mode
        if self.matrix_mode:
            help_text.insert(8, "  w    Cycle weather (Matrix/Rain/Snow/Sand/Fog)")
            help_text.insert(9, "  t    Toggle 3D tunnel sky backdrop")
            help_text.insert(10, "  f    Cycle framerate (100/50/25/15/10ms)")
            help_text.insert(11, "  g    Toggle meteor defense game (QTE)")
            help_text.insert(12, "  u    Toggle audio mute")
            help_text.insert(13, "")

        help_text.append("Press any key to close")

        # Calculate centered position
        box_width = max(len(line) for line in help_text) + 4
        box_height = len(help_text) + 2
        start_y = (self.height - box_height) // 2
        start_x = (self.width - box_width) // 2

        # Draw box
        self._draw_box(start_y, start_x, box_width, box_height, "HELP")

        # Draw help text
        for i, line in enumerate(help_text):
            self._addstr(start_y + 1 + i, start_x + 2, line, Colors.NORMAL)

    def _get_weather_box_colors(self) -> Tuple[int, int, int, bool]:
        """Get box border colors based on current weather mode.

        Returns:
            (top_color, side_color, bottom_color, is_transparent)
        """
        if not self.matrix_mode:
            return (Colors.HEADER, Colors.HEADER, Colors.HEADER, False)

        weather = self._current_weather
        if weather == WeatherMode.CALM or weather == WeatherMode.MATRIX:
            # Transparent in calm/matrix mode - don't draw borders
            return (Colors.MATRIX_FADE3, Colors.MATRIX_FADE3, Colors.MATRIX_FADE3, True)
        elif weather == WeatherMode.SAND:
            # Grey in sand mode
            return (Colors.BOX_GREY, Colors.BOX_GREY, Colors.BOX_GREY, False)
        elif weather == WeatherMode.SNOW:
            # Brown on top and sides, white on bottom
            return (Colors.BOX_BROWN, Colors.BOX_BROWN, Colors.BOX_WHITE, False)
        elif weather == WeatherMode.RAIN:
            # Dark brown in rain mode
            return (Colors.BOX_DARK_BROWN, Colors.BOX_DARK_BROWN, Colors.BOX_DARK_BROWN, False)
        else:
            return (Colors.HEADER, Colors.HEADER, Colors.HEADER, False)

    def _draw_box(self, y: int, x: int, width: int, height: int, title: str, title_color: Optional[int] = None):
        """Draw a box with title, using weather-based colors."""
        if title_color is None:
            title_color = Colors.HEADER

        # Blend title color with weather
        title_color = self._get_weather_text_color(title_color)

        # Get weather-based box colors
        top_color, side_color, bottom_color, is_transparent = self._get_weather_box_colors()

        # Skip drawing borders if transparent (calm/matrix mode)
        if is_transparent:
            # Just draw title if present
            if title:
                try:
                    title_str = f" {title} "
                    self.screen.attron(curses.color_pair(title_color) | curses.A_BOLD)
                    self.screen.addstr(y, x + 2, title_str[:width-4])
                    self.screen.attroff(curses.color_pair(title_color) | curses.A_BOLD)
                except curses.error:
                    pass
            return

        try:
            # Top border with weather color
            top_attr = curses.color_pair(top_color)
            if top_color == Colors.BOX_GREY:
                top_attr |= curses.A_DIM  # Make grey dimmer
            self.screen.attron(top_attr)
            self.screen.addch(y, x, curses.ACS_ULCORNER)
            self.screen.addch(y, x + width - 1, curses.ACS_URCORNER)
            for i in range(1, width - 1):
                self.screen.addch(y, x + i, curses.ACS_HLINE)
            self.screen.attroff(top_attr)

            # Title
            if title:
                title_str = f" {title} "
                self.screen.attron(curses.color_pair(title_color) | curses.A_BOLD)
                self.screen.addstr(y, x + 2, title_str[:width-4])
                self.screen.attroff(curses.color_pair(title_color) | curses.A_BOLD)

            # Side borders with weather color
            side_attr = curses.color_pair(side_color)
            if side_color == Colors.BOX_GREY:
                side_attr |= curses.A_DIM
            self.screen.attron(side_attr)
            for i in range(1, height - 1):
                self.screen.addch(y + i, x, curses.ACS_VLINE)
                self.screen.addch(y + i, x + width - 1, curses.ACS_VLINE)
            self.screen.attroff(side_attr)

            # Bottom border with weather color (may be different in snow)
            bottom_attr = curses.color_pair(bottom_color)
            if bottom_color == Colors.BOX_GREY:
                bottom_attr |= curses.A_DIM
            elif bottom_color == Colors.BOX_WHITE:
                bottom_attr |= curses.A_BOLD  # Make white brighter
            self.screen.attron(bottom_attr)
            self.screen.addch(y + height - 1, x, curses.ACS_LLCORNER)
            self.screen.addch(y + height - 1, x + width - 1, curses.ACS_LRCORNER)
            for i in range(1, width - 1):
                self.screen.addch(y + height - 1, x + i, curses.ACS_HLINE)
            self.screen.attroff(bottom_attr)
        except curses.error:
            pass

    def _get_weather_text_color(self, base_color: int) -> int:
        """Get weather-blended text color.

        Blends the base color with weather-appropriate tint for better
        visual coherence with the current weather mode scene.
        """
        if not self.matrix_mode:
            return base_color

        weather = self._current_weather
        # For certain base colors, blend with weather
        # Keep status colors (OK, WARN, ERROR) as-is for visibility
        if base_color in (Colors.STATUS_OK, Colors.STATUS_WARN, Colors.STATUS_ERROR):
            return base_color

        # Colors that should be blended with weather theme
        blendable_colors = (Colors.NORMAL, Colors.MUTED, Colors.HEADER, Colors.ACCENT)

        # Blend text with weather-appropriate colors
        if weather == WeatherMode.RAIN:
            if base_color in blendable_colors:
                return Colors.TEXT_RAIN  # Cyan/blue tint
        elif weather == WeatherMode.SNOW:
            if base_color in blendable_colors:
                return Colors.TEXT_SNOW  # White/bright
        elif weather == WeatherMode.SAND:
            if base_color in blendable_colors:
                return Colors.TEXT_SAND  # Yellow/tan tint
        # Matrix and Calm stay green (default)
        return base_color

    def _addstr(self, y: int, x: int, text: str, color: int = Colors.NORMAL, bold: bool = False):
        """Add string with color and bounds checking, blending with weather."""
        if y >= self.height or x >= self.width:
            return

        max_len = self.width - x - 1
        if max_len <= 0:
            return

        text = text[:max_len]

        # Apply weather-based color blending
        blended_color = self._get_weather_text_color(color)

        try:
            attr = curses.color_pair(blended_color)
            if bold:
                attr |= curses.A_BOLD
            self.screen.attron(attr)
            self.screen.addstr(y, x, text)
            self.screen.attroff(attr)
        except curses.error:
            pass

    def _show_mode_ceremony(self):
        """Show mode change dialog and allow mode selection."""
        modes = ['OPEN', 'RESTRICTED', 'TRUSTED', 'AIRGAP', 'COLDROOM', 'LOCKDOWN']
        current_mode = self.status.get('mode', 'UNKNOWN')
        selected = 0

        # Find current mode index
        for i, m in enumerate(modes):
            if m == current_mode:
                selected = i
                break

        while True:
            self.screen.clear()

            # Draw mode selection dialog
            box_width = 40
            box_height = len(modes) + 6
            start_y = (self.height - box_height) // 2
            start_x = (self.width - box_width) // 2

            self._draw_box(start_y, start_x, box_width, box_height, "MODE CHANGE")

            # Instructions
            self._addstr(start_y + 1, start_x + 2, "Select mode (↑↓) Enter to confirm", Colors.MUTED)
            self._addstr(start_y + 2, start_x + 2, "Press ESC to cancel", Colors.MUTED)

            # Mode options
            for i, mode in enumerate(modes):
                row = start_y + 4 + i
                if i == selected:
                    self._addstr(row, start_x + 2, f"> {mode}", Colors.SELECTED, bold=True)
                else:
                    color = Colors.STATUS_OK if mode == current_mode else Colors.NORMAL
                    self._addstr(row, start_x + 4, mode, color)

            # Render alley and matrix rain if in matrix mode
            if self.matrix_mode:
                if self.alley_scene:
                    self.alley_scene.render(self.screen)
                if self.matrix_rain:
                    self.matrix_rain.render(self.screen)

            self.screen.refresh()

            key = self.screen.getch()
            if key == 27:  # ESC
                return
            elif key == curses.KEY_UP:
                selected = (selected - 1) % len(modes)
            elif key == curses.KEY_DOWN:
                selected = (selected + 1) % len(modes)
            elif key in (curses.KEY_ENTER, 10, 13):
                new_mode = modes[selected]
                if new_mode != current_mode:
                    success, message = self.client.set_mode(new_mode)
                    self._show_message(message, Colors.STATUS_OK if success else Colors.STATUS_ERROR)
                    if success:
                        self._refresh_data()
                        # Announce mode change via prop plane
                        if self.alley_scene:
                            self.alley_scene.queue_plane_announcement(
                                f"★ MODE CHANGED: {new_mode} ★"
                            )
                return

    def _acknowledge_alert(self):
        """Acknowledge the first unacknowledged alert."""
        for alert in self.alerts:
            if alert.status == "NEW":
                success, message = self.client.acknowledge_alert(alert.alert_id)
                if success:
                    alert.status = "ACKNOWLEDGED"
                    self._show_message(f"Alert {alert.alert_id} acknowledged", Colors.STATUS_OK)
                else:
                    self._show_message(message, Colors.STATUS_ERROR)
                return
        self._show_message("No unacknowledged alerts", Colors.MUTED)

    def _export_events(self):
        """Export events to a JSON file."""
        export_path = f"boundary_events_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            events = self.client.export_events()
            with open(export_path, 'w') as f:
                json.dump(events, f, indent=2, default=str)
            self._show_message(f"Exported {len(events)} events to {export_path}", Colors.STATUS_OK)
        except Exception as e:
            self._show_message(f"Export failed: {e}", Colors.STATUS_ERROR)

    # Boundary Daemon tool definitions with help
    DAEMON_TOOLS = {
        # CLI Commands
        'query': {
            'desc': 'Query events from log',
            'usage': 'query <filter> [--last 24h] [--limit N]',
            'help': [
                "QUERY - Event Query Tool",
                "=" * 50,
                "",
                "Query events from the daemon's hash-chain log.",
                "",
                "USAGE:",
                "  query <filter>",
                "  query type:VIOLATION --last 24h",
                "  query contains:unauthorized",
                "",
                "FILTERS:",
                "  type:<TYPE>       - Event type (VIOLATION, TRIPWIRE, MODE_CHANGE, etc)",
                "  severity:>=HIGH   - Minimum severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)",
                "  contains:<text>   - Full text search in details",
                "  actor:<pattern>   - Filter by actor/agent",
                "  --last <time>     - Time range (1h, 24h, 7d)",
                "",
                "EXAMPLES:",
                "  query type:VIOLATION",
                "  query severity:>=HIGH --last 24h",
                "  query contains:passwd",
                "  query actor:agent-*",
            ],
            'subcommands': [],
        },
        'trace': {
            'desc': 'Trace and search events with details',
            'usage': 'trace <search_term>',
            'help': [
                "TRACE - Event Tracing Tool",
                "=" * 50,
                "",
                "Search and display detailed event information.",
                "",
                "USAGE:",
                "  trace <search_term>",
                "",
                "Searches event types and details, displays results",
                "in detailed box format with timestamps.",
                "",
                "EXAMPLES:",
                "  trace unauthorized",
                "  trace VIOLATION",
                "  trace sandbox",
            ],
            'subcommands': [],
        },
        'status': {
            'desc': 'Show daemon status',
            'usage': 'status',
            'help': [
                "STATUS - Daemon Status",
                "=" * 50,
                "",
                "Display current daemon status including:",
                "  - Current security mode",
                "  - Mode frozen state",
                "  - Uptime",
                "  - Event count",
                "  - Violation count",
                "  - Connection info",
            ],
            'subcommands': [],
        },
        'alerts': {
            'desc': 'Show all alerts',
            'usage': 'alerts',
            'help': [
                "ALERTS - Alert Management",
                "=" * 50,
                "",
                "Display all current security alerts.",
                "",
                "Shows:",
                "  - Alert severity (HIGH, MEDIUM, LOW)",
                "  - Alert message",
                "  - Acknowledgment status",
                "  - Timestamp",
            ],
            'subcommands': [],
        },
        'violations': {
            'desc': 'Show recent violations',
            'usage': 'violations',
            'help': [
                "VIOLATIONS - Security Violations",
                "=" * 50,
                "",
                "Display recent security violations including:",
                "  - Unauthorized tool access attempts",
                "  - Policy violations",
                "  - PII detection events",
                "  - Command injection attempts",
                "",
                "For full history, use: query type:VIOLATION --last 24h",
            ],
            'subcommands': [],
        },
        'mode': {
            'desc': 'Show or change security mode',
            'usage': 'mode [MODE]',
            'help': [
                "MODE - Security Mode Management",
                "=" * 50,
                "",
                "Show current mode or initiate mode change.",
                "",
                "AVAILABLE MODES:",
                "  OPEN       - Minimal restrictions, full tool access",
                "  RESTRICTED - Limited tool access, monitoring active",
                "  TRUSTED    - Verified tools only, enhanced logging",
                "  AIRGAP     - No network, local tools only",
                "  COLDROOM   - Read-only, no modifications allowed",
                "  LOCKDOWN   - Emergency mode, all actions blocked",
                "",
                "Mode changes require ceremony confirmation.",
            ],
            'subcommands': ['open', 'restricted', 'trusted', 'airgap', 'coldroom', 'lockdown'],
        },
        'sandbox': {
            'desc': 'Sandbox management',
            'usage': 'sandbox <command>',
            'help': [
                "SANDBOX - Sandbox Management",
                "=" * 50,
                "",
                "Manage isolated execution environments.",
                "",
                "SUBCOMMANDS:",
                "  sandbox list      - List active sandboxes",
                "  sandbox run       - Run command in sandbox",
                "  sandbox inspect   - Inspect sandbox details",
                "  sandbox kill      - Terminate sandbox",
                "  sandbox profiles  - List available profiles",
                "  sandbox metrics   - Show sandbox metrics",
                "",
                "Sandboxes provide isolation for untrusted code execution.",
            ],
            'subcommands': ['list', 'run', 'inspect', 'kill', 'profiles', 'metrics', 'test'],
        },
        'config': {
            'desc': 'Configuration management',
            'usage': 'config <command>',
            'help': [
                "CONFIG - Configuration Management",
                "=" * 50,
                "",
                "Manage daemon configuration.",
                "",
                "SUBCOMMANDS:",
                "  config show     - Display current configuration",
                "  config lint     - Check configuration for errors",
                "  config validate - Validate configuration",
                "",
                "Config file: /etc/boundary-daemon/boundary.conf",
                "Or set BOUNDARY_CONFIG environment variable.",
            ],
            'subcommands': ['show', 'lint', 'validate'],
        },
        'case': {
            'desc': 'Security case management',
            'usage': 'case <command>',
            'help': [
                "CASE - Security Case Management",
                "=" * 50,
                "",
                "Manage security investigation cases.",
                "",
                "SUBCOMMANDS:",
                "  case list       - List all cases",
                "  case show <id>  - Show case details",
                "  case create     - Create new case",
                "  case update     - Update case status",
                "  case close      - Close a case",
                "",
                "Cases track security incidents and investigations.",
            ],
            'subcommands': ['list', 'show', 'create', 'update', 'close'],
        },
        'tripwire': {
            'desc': 'Tripwire file monitoring',
            'usage': 'tripwire <command>',
            'help': [
                "TRIPWIRE - File Integrity Monitoring",
                "=" * 50,
                "",
                "Monitor critical files for unauthorized changes.",
                "",
                "SUBCOMMANDS:",
                "  tripwire status  - Show tripwire status",
                "  tripwire list    - List monitored files",
                "  tripwire check   - Run integrity check",
                "  tripwire add     - Add file to monitoring",
                "  tripwire remove  - Remove file from monitoring",
                "",
                "Tripwires detect modifications to sensitive files",
                "like /etc/passwd, config files, and binaries.",
            ],
            'subcommands': ['status', 'list', 'check', 'add', 'remove'],
        },
        'network': {
            'desc': 'Network security status',
            'usage': 'network',
            'help': [
                "NETWORK - Network Security",
                "=" * 50,
                "",
                "Display network security status including:",
                "  - Network trust level",
                "  - VPN status",
                "  - DNS security status",
                "  - ARP monitoring status",
                "  - Traffic anomaly detection",
                "",
                "Network restrictions vary by security mode.",
            ],
            'subcommands': ['status', 'trust', 'dns', 'arp'],
        },
        'pii': {
            'desc': 'PII detection status',
            'usage': 'pii',
            'help': [
                "PII - Personal Information Detection",
                "=" * 50,
                "",
                "Monitor PII detection and filtering.",
                "",
                "Shows:",
                "  - PII detections in agent output",
                "  - Redaction statistics",
                "  - Sensitive data patterns matched",
                "",
                "PII types: SSN, credit cards, emails, phone numbers,",
                "API keys, passwords, and other credentials.",
            ],
            'subcommands': ['status', 'stats', 'patterns'],
        },
        'ceremony': {
            'desc': 'Security ceremonies',
            'usage': 'ceremony <type>',
            'help': [
                "CEREMONY - Security Ceremonies",
                "=" * 50,
                "",
                "Initiate security ceremonies for sensitive operations.",
                "",
                "CEREMONY TYPES:",
                "  ceremony mode     - Mode change ceremony",
                "  ceremony verify   - Identity verification",
                "  ceremony unlock   - Unlock frozen mode",
                "",
                "Ceremonies require human confirmation for",
                "security-critical operations.",
            ],
            'subcommands': ['mode', 'verify', 'unlock'],
        },
        'export': {
            'desc': 'Export events to file',
            'usage': 'export <filename>',
            'help': [
                "EXPORT - Export Events",
                "=" * 50,
                "",
                "Export events to JSON file for analysis.",
                "",
                "USAGE:",
                "  export events.json",
                "  export /path/to/output.json",
                "",
                "Exports include:",
                "  - Timestamp",
                "  - Event type",
                "  - Event details",
            ],
            'subcommands': [],
        },
        'checklogs': {
            'desc': 'AI analysis of daemon logs',
            'usage': 'checklogs [--last N]',
            'help': [
                "CHECKLOGS - AI-Powered Log Analysis",
                "=" * 50,
                "",
                "Sends daemon logs to Ollama for intelligent analysis.",
                "Identifies issues, security concerns, and recommendations.",
                "",
                "USAGE:",
                "  checklogs           - Analyze last 50 events",
                "  checklogs --last N  - Analyze last N events",
                "",
                "ANALYSIS INCLUDES:",
                "  - Security violations and threats",
                "  - Mode changes and ceremonies",
                "  - Rate limiting events",
                "  - PII detection incidents",
                "  - System health issues",
                "  - Recommended actions",
                "",
                "REQUIRES:",
                "  - Ollama running locally (ollama serve)",
                "  - llama3.2 or compatible model",
            ],
            'subcommands': [],
        },
        'clear': {
            'desc': 'Clear CLI results',
            'usage': 'clear',
            'help': ["Clears the results display area."],
            'subcommands': [],
        },
        'help': {
            'desc': 'Show help',
            'usage': 'help [command]',
            'help': [
                "HELP - Command Help",
                "=" * 50,
                "",
                "Show help for commands.",
                "",
                "USAGE:",
                "  help           - Show all commands",
                "  help <command> - Show help for specific command",
                "",
                "EXAMPLES:",
                "  help query",
                "  help sandbox",
                "  help mode",
            ],
            'subcommands': [],
        },
    }

    def _gather_command_data(self, commands: List[str]) -> Dict[str, Any]:
        """Execute commands and gather their results for Ollama analysis."""
        results = {}

        for cmd in commands:
            cmd = cmd.strip().lower()
            try:
                if cmd == 'status':
                    status = self.client.get_status()
                    results['status'] = {
                        'mode': status.get('mode', 'UNKNOWN'),
                        'frozen': status.get('is_frozen', False),
                        'uptime': self._format_duration(status.get('uptime', 0)),
                        'events': status.get('total_events', 0),
                        'violations': status.get('violations', 0),
                        'demo_mode': self.client.is_demo_mode(),
                    }
                elif cmd == 'alerts':
                    alerts = self.client.get_alerts()
                    results['alerts'] = [
                        {'severity': a.severity, 'message': a.message, 'time': a.time_str, 'acked': a.acknowledged}
                        for a in alerts
                    ]
                elif cmd == 'violations':
                    violations = [e for e in self.events if 'VIOLATION' in e.event_type.upper()]
                    results['violations'] = [
                        {'time': v.time_short, 'type': v.event_type, 'details': v.details[:100]}
                        for v in violations[:20]
                    ]
                elif cmd == 'events':
                    events = self.client.get_events(limit=30)
                    results['events'] = [
                        {'time': e.time_short, 'type': e.event_type, 'details': e.details[:80]}
                        for e in events
                    ]
                elif cmd == 'mode':
                    status = self.client.get_status()
                    results['mode'] = {
                        'current': status.get('mode', 'UNKNOWN'),
                        'frozen': status.get('is_frozen', False),
                    }
                elif cmd == 'sandbox' or cmd == 'sandboxes':
                    results['sandboxes'] = [
                        {'id': s.id[:8], 'name': s.name, 'status': s.status, 'uptime': s.uptime_str}
                        for s in self.sandboxes
                    ]
            except Exception as e:
                results[cmd] = {'error': str(e)}

        return results

    def _load_self_knowledge(self) -> str:
        """Load self-knowledge document for AI context."""
        import os
        # Try multiple locations for the self-knowledge document
        possible_paths = [
            os.path.join(os.path.dirname(__file__), '..', '..', 'docs', 'SELF_KNOWLEDGE.md'),
            os.path.join(os.path.dirname(__file__), '..', '..', '..', 'docs', 'SELF_KNOWLEDGE.md'),
            '/home/user/boundary-daemon-/docs/SELF_KNOWLEDGE.md',
            os.path.expanduser('~/.agent-os/boundary-daemon/docs/SELF_KNOWLEDGE.md'),
        ]

        for path in possible_paths:
            try:
                abs_path = os.path.abspath(path)
                if os.path.exists(abs_path):
                    with open(abs_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # Truncate to reasonable size for context (first 8000 chars)
                        if len(content) > 8000:
                            content = content[:8000] + "\n\n[... truncated for context length ...]"
                        return content
            except Exception:
                continue

        # Fallback: minimal self-knowledge
        return """# Boundary Daemon Self-Knowledge
I am the Boundary Daemon (Agent Smith), a security policy and audit system for Agent OS.
I make allow/deny decisions for AI operations and maintain immutable audit logs.
Boundary Modes: OPEN, RESTRICTED, TRUSTED, AIRGAP, COLDROOM, LOCKDOWN.
I operate on fail-closed principles - when uncertain, I DENY.
For detailed information, ask about specific features or run 'help' command."""

    def _get_system_context(self) -> str:
        """Get current system state for AI context."""
        context_parts = []

        # Current mode
        try:
            mode = self.daemon_status.get('mode', 'UNKNOWN') if self.daemon_status else 'UNKNOWN'
            context_parts.append(f"Current Mode: {mode}")
        except Exception:
            pass

        # Uptime
        try:
            uptime = self.daemon_status.get('uptime', 'unknown') if self.daemon_status else 'unknown'
            context_parts.append(f"Uptime: {uptime}")
        except Exception:
            pass

        # SIEM status
        try:
            siem_connected = self.siem_status.get('connected', False) if self.siem_status else False
            ingestion_connected = self.ingestion_status.get('connected', False) if hasattr(self, 'ingestion_status') and self.ingestion_status else False
            context_parts.append(f"SIEM Shipping: {'connected' if siem_connected else 'not configured'}")
            context_parts.append(f"SIEM Ingestion: {'connected' if ingestion_connected else 'disconnected'}")
        except Exception:
            pass

        # Active alerts
        try:
            alert_count = len(self.alerts) if self.alerts else 0
            context_parts.append(f"Active Alerts: {alert_count}")
        except Exception:
            pass

        # Recent events count
        try:
            event_count = len(self.events) if self.events else 0
            context_parts.append(f"Recent Events: {event_count}")
        except Exception:
            pass

        return "\n".join(context_parts)

    def _send_to_ollama(self, message: str) -> List[str]:
        """Send a message to Ollama with automatic command execution."""
        if not self._ollama_client:
            return ["ERROR: Ollama not available. Start with: ollama serve"]

        if not self._ollama_client.is_available():
            return ["ERROR: Ollama not running. Start with: ollama serve"]

        lines = ["", f"You: {message}", ""]

        # Step 1: Ask Ollama if commands are needed
        command_detection_prompt = f"""User request: "{message}"

You are an assistant for the Boundary Daemon security system. Determine if the user's request requires running system commands to answer.

AVAILABLE COMMANDS:
- status: Get daemon status (mode, uptime, event count, violations)
- alerts: Get active security alerts
- violations: Get recent security violations
- events: Get recent system events
- mode: Get current security mode
- sandboxes: Get active sandbox information

If the user is asking about system health, security status, problems, alerts, or wants to check/diagnose their system, you MUST specify which commands to run.

RESPOND WITH ONLY ONE OF THESE FORMATS:
1. If commands needed: COMMANDS: status, alerts, violations
2. If no commands needed: NONE

Examples:
- "what's wrong with my computer" -> COMMANDS: status, alerts, violations, events
- "check my system" -> COMMANDS: status, alerts, violations
- "any security issues?" -> COMMANDS: alerts, violations
- "hello" -> NONE
- "what is a sandbox?" -> NONE

Your response (COMMANDS: ... or NONE):"""

        try:
            # Detect if commands are needed
            detection_response = self._ollama_client.generate(command_detection_prompt, system="You are a command router. Respond only with COMMANDS: list or NONE.")

            commands_to_run = []
            if detection_response and 'COMMANDS:' in detection_response.upper():
                # Parse commands from response
                cmd_part = detection_response.upper().split('COMMANDS:')[1].strip()
                cmd_part = cmd_part.split('\n')[0]  # Take first line only
                commands_to_run = [c.strip().lower() for c in cmd_part.split(',') if c.strip()]

            # Step 2: Execute commands if needed
            command_results = {}
            if commands_to_run:
                lines.append("  [Gathering system information...]")
                command_results = self._gather_command_data(commands_to_run)

            # Step 3: Generate natural language response
            # Build conversation context (convert deque to list for slicing)
            chat_context = ""
            chat_history_list = list(self._cli_chat_history)
            for entry in chat_history_list[-5:]:
                chat_context += f"User: {entry['user']}\nAssistant: {entry['assistant']}\n\n"

            # Get current system state
            system_state = self._get_system_context()

            # Base system prompt with self-knowledge
            base_knowledge = f"""You are the Boundary Daemon's built-in AI assistant (codenamed "Agent Smith").
You are integrated directly into the security monitoring system and have full knowledge of its capabilities.

IMPORTANT: Always consult your internal knowledge first before making assumptions.
You ARE the daemon's voice - speak with authority about the system you're part of.

=== YOUR SELF-KNOWLEDGE ===
{self._self_knowledge[:4000] if self._self_knowledge else "Self-knowledge document not loaded."}

=== CURRENT SYSTEM STATE ===
{system_state}
"""

            if command_results:
                # Build response with command data
                system_prompt = base_knowledge + """
You have just gathered real system data. Analyze it to answer the user's question.
Be conversational but informative. Highlight any issues or concerns.
Keep responses concise (3-6 sentences) for the terminal interface.
If there are problems, explain what they mean and suggest actions.
Reference specific values from the data to support your analysis."""

                data_summary = json.dumps(command_results, indent=2, default=str)
                prompt = f"""{chat_context}User: {message}

LIVE SYSTEM DATA:
{data_summary}

Analyze this data and provide a helpful response. Be specific about what you found."""

            else:
                # Regular chat without command data
                system_prompt = base_knowledge + """
Help users understand the Boundary Daemon, its security features, and operations.
Keep responses concise (2-4 sentences) since this is a terminal interface.
If the user asks about system state, offer to check it for them.
Speak with confidence about the system's capabilities - you know this system inside and out."""

                prompt = f"{chat_context}User: {message}\nAssistant:"

            response = self._ollama_client.generate(prompt, system=system_prompt)

            if response:
                # Store in chat history (deque auto-trims to maxlen=50)
                self._cli_chat_history.append({'user': message, 'assistant': response})

                # Speak the LLM response using TTS (if enabled and not muted)
                if self._tts_enabled and not self._audio_muted:
                    self._speak_text(response, speed=1.1)

                # Word wrap response
                for paragraph in response.split('\n'):
                    if not paragraph.strip():
                        lines.append("")
                        continue
                    words = paragraph.split()
                    current_line = "  "
                    for word in words:
                        if len(current_line) + len(word) + 1 > self.width - 4:
                            lines.append(current_line)
                            current_line = "  " + word
                        else:
                            current_line += (" " if len(current_line) > 2 else "") + word
                    if current_line.strip():
                        lines.append(current_line)
                lines.append("")
                return lines
            else:
                return lines + ["ERROR: No response from Ollama"]
        except Exception as e:
            return lines + [f"ERROR: Ollama error: {e}"]

    def _analyze_logs_with_ollama(self, num_events: int = 50) -> List[str]:
        """Analyze daemon logs using Ollama and return analysis lines."""
        if not self._ollama_client:
            return ["ERROR: Ollama not available. Start with: ollama serve"]

        if not self._ollama_client.is_available():
            return ["ERROR: Ollama not running. Start with: ollama serve"]

        lines = ["", "ANALYZING LOGS WITH OLLAMA...", "=" * 50, ""]

        # Gather system information
        try:
            status = self.client.get_status()
            events = self.client.get_events(limit=num_events)
            alerts = self.client.get_alerts()
        except Exception as e:
            return [f"ERROR: Failed to fetch daemon data: {e}"]

        # Build comprehensive log data for Ollama
        log_data = []

        # Add daemon status
        log_data.append("=== DAEMON STATUS ===")
        log_data.append(f"Mode: {status.get('mode', 'unknown')}")
        log_data.append(f"State: {status.get('state', 'unknown')}")
        log_data.append(f"Uptime: {status.get('uptime', 'unknown')}")
        log_data.append(f"Active Sandboxes: {status.get('sandboxes', {}).get('active', 0)}")
        log_data.append("")

        # Add active alerts
        log_data.append("=== ACTIVE ALERTS ===")
        if alerts:
            for alert in alerts:
                log_data.append(f"[{alert.severity}] {alert.message}")
                log_data.append(f"  Time: {alert.time_str}")
        else:
            log_data.append("No active alerts")
        log_data.append("")

        # Add recent events with full details
        log_data.append(f"=== RECENT EVENTS (last {len(events)}) ===")
        event_type_counts = {}
        for event in events:
            event_type_counts[event.event_type] = event_type_counts.get(event.event_type, 0) + 1
            log_data.append(f"[{event.time_short}] {event.event_type}: {event.details[:100]}")

        log_data.append("")
        log_data.append("=== EVENT TYPE SUMMARY ===")
        for etype, count in sorted(event_type_counts.items(), key=lambda x: -x[1]):
            log_data.append(f"  {etype}: {count}")

        # Comprehensive system prompt for log analysis with self-knowledge
        self_knowledge_excerpt = self._self_knowledge[:2000] if self._self_knowledge else ""
        system_prompt = f"""You are the Boundary Daemon's built-in security analyst (Agent Smith).
You are analyzing your OWN system's logs - speak with authority about what you find.

=== YOUR KNOWLEDGE BASE ===
{self_knowledge_excerpt}

=== CURRENT SYSTEM STATE ===
{self._get_system_context()}

EVENT TYPES TO WATCH FOR:
- VIOLATION: Security policy violations - HIGH PRIORITY
- MODE_CHANGE: Operation mode transitions - important for security posture
- RATE_LIMIT_*: Rate limiting events - may indicate abuse or attacks
- PII_DETECTED/BLOCKED/REDACTED: Privacy incidents
- CLOCK_JUMP/DRIFT: Time manipulation (potential tampering)
- ALERT: System alerts requiring attention
- SECURITY_SCAN: Antivirus/malware scan results
- SIEM_DISCONNECTED: SIEM ingestion client lost connection
- TRIPWIRE_*: Security tripwire triggers (auto-LOCKDOWN)

SEVERITY ASSESSMENT:
- CRITICAL: Immediate action required (violations, lockdowns, tampering)
- HIGH: Security concern requiring investigation
- MEDIUM: Notable event to monitor
- LOW: Informational

Analyze the logs and provide:
1. SUMMARY: Overall system health assessment (1-2 sentences)
2. ISSUES FOUND: List specific problems with severity
3. SECURITY CONCERNS: Any security-related findings
4. RECOMMENDATIONS: Actionable next steps

Keep response concise and terminal-friendly (max 20 lines)."""

        prompt = f"""Analyze these Boundary Daemon security logs and tell me if there are any issues with my system:

{chr(10).join(log_data)}

Provide a clear, actionable analysis."""

        try:
            lines.append("Sending to Ollama for analysis...")
            lines.append("")

            response = self._ollama_client.generate(prompt, system=system_prompt)

            if response:
                lines.append("ANALYSIS RESULTS:")
                lines.append("-" * 40)

                # Speak the analysis response using TTS (if enabled and not muted)
                if self._tts_enabled and not self._audio_muted:
                    self._speak_text(response, speed=1.1)

                # Word wrap response for terminal
                for paragraph in response.split('\n'):
                    if not paragraph.strip():
                        lines.append("")
                        continue
                    words = paragraph.split()
                    current_line = ""
                    for word in words:
                        if len(current_line) + len(word) + 1 > self.width - 4:
                            lines.append(current_line)
                            current_line = word
                        else:
                            current_line += (" " if current_line else "") + word
                    if current_line:
                        lines.append(current_line)
                lines.append("")
                lines.append("-" * 40)
                lines.append(f"Analyzed {len(events)} events, {len(alerts)} alerts")
            else:
                lines.append("ERROR: No response from Ollama")
        except Exception as e:
            lines.append(f"ERROR: Analysis failed: {e}")

        return lines

    def _start_cli(self):
        """Start CLI mode for running commands and chatting with Ollama."""
        curses.curs_set(1)  # Show cursor
        cmd_text = ""
        cursor_pos = 0
        show_help_popup = False
        help_popup_tool = None

        # Initialize activity timer
        self._cli_last_activity = time.time()

        # Build autocomplete list from DAEMON_TOOLS (with / prefix)
        all_completions = ["/" + cmd for cmd in self.DAEMON_TOOLS.keys()]

        # Check Ollama status
        ollama_status = "connected" if (self._ollama_client and self._ollama_client.is_available()) else "offline"

        # Available commands help
        cli_help = [
            "BOUNDARY DAEMON CLI + OLLAMA CHAT",
            "=" * 60,
            "",
            f"  Ollama: {ollama_status}",
            "",
            "  Type a message to chat with Ollama",
            "  Use /command for daemon commands (e.g., /help, /status)",
            "",
            "COMMANDS (prefix with /):",
        ]
        for cmd, info in self.DAEMON_TOOLS.items():
            cli_help.append(f"  /{cmd:11} - {info['desc']}")
        cli_help.extend([
            "",
            "EXAMPLES:",
            "  What is a security violation?     (chat with Ollama)",
            "  /alerts                           (show daemon alerts)",
            "  /query type:VIOLATION --last 24h  (search events)",
            "",
            "Auto-hides after 5 minutes of inactivity",
        ])

        while True:
            # Check for inactivity timeout
            if time.time() - self._cli_last_activity > self._cli_timeout:
                # Clear results and exit
                self._cli_results = []
                self._cli_chat_history = []
                break

            # Render the scene as background (if in matrix mode)
            if self.matrix_mode:
                # Update scene animations
                if self.matrix_rain:
                    self.matrix_rain.update()
                if hasattr(self, 'tunnel_backdrop') and self.tunnel_backdrop:
                    self.tunnel_backdrop.update()
                if self.alley_scene:
                    self.alley_scene.update()

                # Render scene
                self.screen.clear()
                if hasattr(self, 'tunnel_backdrop') and self.tunnel_backdrop:
                    self.tunnel_backdrop.render(self.screen)
                if self.alley_scene:
                    self.alley_scene.render(self.screen)
                if self.matrix_rain:
                    self.matrix_rain.render(self.screen)
            else:
                self.screen.clear()

            # Draw semi-transparent CLI overlay panel
            cli_panel_height = min(self.height - 2, 20)  # Max 20 rows for CLI panel
            cli_panel_y = self.height - cli_panel_height - 2  # Position at bottom

            # Draw CLI panel background (semi-transparent effect with dim chars)
            for row in range(cli_panel_y, self.height):
                for col in range(self.width - 1):
                    try:
                        self.screen.addch(row, col, ' ', curses.color_pair(Colors.MATRIX_DIM))
                    except curses.error:
                        pass

            # Draw CLI border
            border_attr = curses.color_pair(Colors.HEADER)
            for col in range(self.width - 1):
                try:
                    self.screen.addch(cli_panel_y, col, '─', border_attr)
                except curses.error:
                    pass

            # Draw CLI header with Ollama status
            self._addstr(cli_panel_y, 0, " BOUNDARY CLI ", Colors.HEADER)
            ollama_indicator = f" [Ollama: {ollama_status}] "
            self._addstr(cli_panel_y, 15, ollama_indicator, Colors.STATUS_OK if ollama_status == "connected" else Colors.STATUS_WARN)

            # Draw results area (scrollable) - within the CLI panel
            results_start_y = cli_panel_y + 1  # Start after header
            results_height = cli_panel_height - 3  # Leave room for prompt and shortcuts
            if self._cli_results:
                for i, line in enumerate(self._cli_results[self._cli_results_scroll:]):
                    row = results_start_y + i
                    if i >= results_height:
                        break
                    # Color code based on content
                    if line.startswith("ERROR:") or "VIOLATION" in line or "CRITICAL" in line:
                        color = Colors.STATUS_ERROR
                    elif line.startswith("OK:") or "SUCCESS" in line:
                        color = Colors.STATUS_OK
                    elif line.startswith("You:"):
                        color = Colors.ACCENT
                    elif line.startswith("  ") or line.startswith("│"):
                        color = Colors.MUTED
                    elif "HIGH" in line:
                        color = Colors.STATUS_WARN
                    else:
                        color = Colors.NORMAL
                    self._addstr(row, 1, line[:self.width-3], color)

                # Scroll indicator
                if len(self._cli_results) > results_height:
                    scroll_info = f"[{self._cli_results_scroll+1}-{min(self._cli_results_scroll+results_height, len(self._cli_results))}/{len(self._cli_results)}]"
                    self._addstr(cli_panel_y, self.width - len(scroll_info) - 2, scroll_info, Colors.MUTED)
            else:
                # Show help if no results
                for i, line in enumerate(cli_help):
                    row = results_start_y + i
                    if i >= results_height:
                        break
                    self._addstr(row, 2, line, Colors.MUTED)

            # Draw command line at bottom of panel
            prompt_y = self.height - 2
            prompt_char = ">" if not cmd_text.startswith("/") else ":"
            self._addstr(prompt_y, 0, prompt_char + cmd_text + " ", Colors.HEADER)
            self._addstr(prompt_y, len(cmd_text) + 1, "_", Colors.ACCENT)

            # Draw shortcuts with timeout indicator
            remaining = max(0, int(self._cli_timeout - (time.time() - self._cli_last_activity)))
            timeout_str = f" [{remaining//60}:{remaining%60:02d}]"
            shortcuts = f"[Enter] Send  [Tab] Complete  [F1] Help  [ESC] Exit{timeout_str}"
            self._addstr(self.height - 1, 0, shortcuts[:self.width-1], Colors.MUTED)

            self.screen.refresh()

            # Use timeout to allow checking inactivity
            self.screen.timeout(1000)  # 1 second timeout
            key = self.screen.getch()

            if key == -1:  # Timeout, no key pressed
                continue

            # Key pressed - reset activity timer
            self._cli_last_activity = time.time()

            if key == 27:  # ESC
                break
            elif key in (curses.KEY_ENTER, 10, 13):
                if cmd_text.strip():
                    # Add to history
                    if not self._cli_history or self._cli_history[-1] != cmd_text:
                        self._cli_history.append(cmd_text)
                    self._cli_history_index = len(self._cli_history)

                    text = cmd_text.strip()
                    if text.startswith("/"):
                        # Execute as daemon command (strip the /)
                        self._execute_cli_command(text[1:])
                    else:
                        # Send to Ollama - clear old results first to show new response
                        self._cli_results = []
                        response_lines = self._send_to_ollama(text)
                        self._cli_results = response_lines
                        self._cli_results_scroll = 0  # Reset scroll to top of new response

                    cmd_text = ""
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                cmd_text = cmd_text[:-1]
            elif key == curses.KEY_UP:
                # History navigation
                if self._cli_history and self._cli_history_index > 0:
                    self._cli_history_index -= 1
                    cmd_text = self._cli_history[self._cli_history_index]
            elif key == curses.KEY_DOWN:
                if self._cli_history_index < len(self._cli_history) - 1:
                    self._cli_history_index += 1
                    cmd_text = self._cli_history[self._cli_history_index]
                else:
                    self._cli_history_index = len(self._cli_history)
                    cmd_text = ""
            elif key == curses.KEY_PPAGE:  # Page Up
                if show_help_popup:
                    # Scroll help popup
                    pass
                else:
                    self._cli_results_scroll = max(0, self._cli_results_scroll - 10)
            elif key == curses.KEY_NPAGE:  # Page Down
                if show_help_popup:
                    pass
                else:
                    max_scroll = max(0, len(self._cli_results) - (self.height - 6))
                    self._cli_results_scroll = min(max_scroll, self._cli_results_scroll + 10)
            elif key == curses.KEY_F1 or key == 265:  # F1 - show help for current command
                # Get the first word being typed (strip / for command lookup)
                first_word = cmd_text.split()[0].lstrip("/") if cmd_text.split() else ""
                if first_word in self.DAEMON_TOOLS:
                    help_popup_tool = first_word
                    show_help_popup = True
                else:
                    # Show general help
                    show_help_popup = True
                    help_popup_tool = None
            elif key == 9:  # Tab - smart autocomplete (only for /commands)
                if cmd_text.startswith("/"):
                    parts = cmd_text.split()
                    if len(parts) == 0 or (len(parts) == 1 and not cmd_text.endswith(' ')):
                        # Complete command name
                        prefix = parts[0] if parts else "/"
                        for comp in all_completions:
                            if comp.startswith(prefix):
                                cmd_text = comp + " "
                                break
                    elif len(parts) >= 1:
                        # Complete subcommand
                        base_cmd = parts[0].lstrip("/")
                        if base_cmd in self.DAEMON_TOOLS:
                            subcommands = self.DAEMON_TOOLS[base_cmd].get('subcommands', [])
                            if subcommands:
                                prefix = parts[1] if len(parts) > 1 else ""
                                for sub in subcommands:
                                    if sub.startswith(prefix):
                                        cmd_text = f"/{base_cmd} {sub} "
                                        break
            elif 32 <= key <= 126:  # Printable characters
                cmd_text += chr(key)

            # Draw help popup if active - blocks until F1/ESC/Enter pressed
            if show_help_popup:
                self._draw_help_popup(help_popup_tool)
                self.screen.refresh()
                # Set blocking mode while help is shown
                self.screen.timeout(-1)  # Block until key pressed
                popup_key = self.screen.getch()
                # Restore timeout for CLI
                self.screen.timeout(1000)
                if popup_key == 27 or popup_key == curses.KEY_F1 or popup_key == 265 or popup_key in (10, 13):
                    show_help_popup = False
                # Reset activity timer after help popup
                self._cli_last_activity = time.time()
                continue

        curses.curs_set(0)  # Hide cursor

        # Restore screen timeout for smooth animation after CLI exit
        if self.matrix_mode:
            self.screen.timeout(self._framerate_options[self._framerate_index])
        else:
            self.screen.timeout(int(self.refresh_interval * 1000))

    def _draw_help_popup(self, tool_name: Optional[str] = None):
        """Draw a help popup window for a tool."""
        # Calculate popup dimensions
        popup_width = min(60, self.width - 4)
        popup_height = min(25, self.height - 4)
        popup_x = (self.width - popup_width) // 2
        popup_y = (self.height - popup_height) // 2

        # Get help content
        if tool_name and tool_name in self.DAEMON_TOOLS:
            tool = self.DAEMON_TOOLS[tool_name]
            help_lines = tool['help']
            title = f" {tool_name.upper()} HELP "
        else:
            help_lines = [
                "BOUNDARY DAEMON CLI HELP",
                "=" * 40,
                "",
                "Available commands:",
                "",
            ]
            for cmd, info in self.DAEMON_TOOLS.items():
                help_lines.append(f"  {cmd:12} - {info['desc']}")
            help_lines.extend([
                "",
                "Type 'help <command>' for detailed help.",
                "Press F1 while typing a command for quick help.",
            ])
            title = " CLI HELP "

        # Draw popup border
        try:
            # Top border
            self._addstr(popup_y, popup_x, "┌" + "─" * (popup_width - 2) + "┐", Colors.HEADER)
            # Title
            title_x = popup_x + (popup_width - len(title)) // 2
            self._addstr(popup_y, title_x, title, Colors.ACCENT)

            # Content area
            for i in range(popup_height - 2):
                row = popup_y + 1 + i
                # Side borders
                self._addstr(row, popup_x, "│", Colors.HEADER)
                self._addstr(row, popup_x + popup_width - 1, "│", Colors.HEADER)
                # Content
                if i < len(help_lines):
                    line = help_lines[i][:popup_width - 4]
                    self._addstr(row, popup_x + 2, line, Colors.NORMAL)

            # Bottom border
            self._addstr(popup_y + popup_height - 1, popup_x, "└" + "─" * (popup_width - 2) + "┘", Colors.HEADER)

            # Close hint
            close_hint = " [ESC/Enter] Close "
            self._addstr(popup_y + popup_height - 1, popup_x + popup_width - len(close_hint) - 2, close_hint, Colors.MUTED)
        except curses.error:
            pass

    def _execute_cli_command(self, cmd: str):
        """Execute a CLI command and populate results."""
        parts = cmd.split(maxsplit=1)
        command = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        self._cli_results = []

        try:
            if command == 'help':
                if args and args in self.DAEMON_TOOLS:
                    # Show specific tool help
                    tool = self.DAEMON_TOOLS[args]
                    self._cli_results = tool['help'].copy()
                else:
                    # Show general help
                    self._cli_results = [
                        "BOUNDARY DAEMON CLI",
                        "=" * 50,
                        "",
                        "COMMANDS:",
                    ]
                    for cmd_name, info in self.DAEMON_TOOLS.items():
                        usage = info['usage']
                        self._cli_results.append(f"  {usage:24} - {info['desc']}")
                    self._cli_results.extend([
                        "",
                        "Type 'help <command>' for detailed help on any command.",
                        "Press F1 while typing for quick context help.",
                        "",
                        "EXAMPLES:",
                        "  query type:VIOLATION --last 24h",
                        "  trace unauthorized",
                        "  sandbox list",
                        "  tripwire status",
                    ])

            elif command == 'clear':
                self._cli_results = ["Results cleared."]

            elif command == 'checklogs':
                # Parse --last N argument
                num_events = 50  # Default
                if args:
                    parts = args.split()
                    for i, part in enumerate(parts):
                        if part == '--last' and i + 1 < len(parts):
                            try:
                                num_events = int(parts[i + 1])
                                num_events = min(max(num_events, 10), 200)  # Clamp 10-200
                            except ValueError:
                                pass
                self._cli_results = self._analyze_logs_with_ollama(num_events)

            elif command == 'status':
                status = self.client.get_status()
                self._cli_results = [
                    "DAEMON STATUS",
                    "=" * 40,
                    f"  Mode:       {status.get('mode', 'UNKNOWN')}",
                    f"  Frozen:     {status.get('is_frozen', False)}",
                    f"  Uptime:     {self._format_duration(status.get('uptime', 0))}",
                    f"  Events:     {status.get('total_events', 0)}",
                    f"  Violations: {status.get('violations', 0)}",
                    f"  Connection: {'TCP:19847' if self.client._use_tcp else self.client.socket_path}",
                    f"  Demo Mode:  {self.client.is_demo_mode()}",
                ]

            elif command == 'alerts':
                alerts = self.client.get_alerts()
                self._cli_results = [f"ALERTS ({len(alerts)} total)", "=" * 40]
                for alert in alerts:
                    ack = "✓" if alert.acknowledged else "○"
                    self._cli_results.append(f"  {ack} [{alert.severity}] {alert.message}")
                    self._cli_results.append(f"      Time: {alert.time_str}")
                if not alerts:
                    self._cli_results.append("  No alerts.")

            elif command == 'violations':
                # Query violations from events
                violations = [e for e in self.events if 'VIOLATION' in e.event_type.upper()]
                self._cli_results = [f"RECENT VIOLATIONS ({len(violations)})", "=" * 40]
                for v in violations[:20]:
                    self._cli_results.append(f"  [{v.time_short}] {v.event_type}")
                    self._cli_results.append(f"      {v.details[:60]}")
                if not violations:
                    self._cli_results.append("  No violations in recent events.")
                    self._cli_results.append("  Use 'query type:VIOLATION --last 24h' for full search.")

            elif command == 'query':
                self._cli_results = self._execute_query(args)

            elif command == 'trace':
                self._cli_results = self._execute_trace(args)

            elif command == 'mode':
                if args:
                    # Try to change mode (would need ceremony in real use)
                    self._cli_results = [
                        f"Mode change to '{args}' requires ceremony.",
                        "Use 'm' key from main dashboard to initiate mode change.",
                    ]
                else:
                    status = self.client.get_status()
                    self._cli_results = [
                        f"Current Mode: {status.get('mode', 'UNKNOWN')}",
                        f"Frozen: {status.get('is_frozen', False)}",
                    ]

            elif command == 'export':
                if not args:
                    self._cli_results = ["ERROR: Specify output file (e.g., export events.json)"]
                else:
                    try:
                        events = self.client.get_events(1000)
                        export_data = [{'time': e.time_str, 'type': e.event_type, 'details': e.details} for e in events]
                        with open(args, 'w') as f:
                            json.dump(export_data, f, indent=2)
                        self._cli_results = [f"OK: Exported {len(events)} events to {args}"]
                    except Exception as e:
                        self._cli_results = [f"ERROR: Export failed: {e}"]

            else:
                self._cli_results = [
                    f"ERROR: Unknown command '{command}'",
                    "Type 'help' for available commands.",
                ]

        except Exception as e:
            self._cli_results = [f"ERROR: {e}"]

    def _execute_query(self, query_str: str) -> List[str]:
        """Execute a query command."""
        results = ["QUERY RESULTS", "=" * 40]

        # Parse query parameters
        query_lower = query_str.lower()
        events = self.events

        # Filter by type
        if 'type:' in query_lower:
            import re
            type_match = re.search(r'type:(\w+)', query_lower)
            if type_match:
                event_type = type_match.group(1).upper()
                events = [e for e in events if event_type in e.event_type.upper()]

        # Filter by severity
        if 'severity:' in query_lower:
            severity_map = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            import re
            sev_match = re.search(r'severity:>=?(\w+)', query_lower)
            if sev_match:
                min_sev = severity_map.get(sev_match.group(1).lower(), 0)
                # Filter events with severity (would need actual severity field)
                events = [e for e in events if any(s in e.event_type.upper() for s in ['HIGH', 'CRITICAL', 'VIOLATION', 'ERROR'])]

        # Full text search
        if 'contains:' in query_lower:
            import re
            text_match = re.search(r'contains:(\S+)', query_lower)
            if text_match:
                search_text = text_match.group(1)
                events = [e for e in events if search_text.lower() in e.details.lower() or search_text.lower() in e.event_type.lower()]

        # Simple text search (no prefix)
        remaining = query_str
        for prefix in ['type:', 'severity:', 'contains:', '--last']:
            import re
            remaining = re.sub(rf'{prefix}\S*\s*', '', remaining, flags=re.IGNORECASE)
        remaining = remaining.strip()
        if remaining and not remaining.startswith('-'):
            events = [e for e in events if remaining.lower() in e.details.lower() or remaining.lower() in e.event_type.lower()]

        results.append(f"Found {len(events)} events matching: {query_str}")
        results.append("")

        for e in events[:30]:
            results.append(f"  [{e.time_short}] {e.event_type}")
            results.append(f"      {e.details[:70]}")

        if len(events) > 30:
            results.append(f"  ... and {len(events) - 30} more")

        if not events:
            results.append("  No matching events found.")
            results.append("  Try: query type:VIOLATION")
            results.append("       query contains:unauthorized")

        return results

    def _execute_trace(self, search_text: str) -> List[str]:
        """Trace/search for events with detailed output."""
        results = ["TRACE RESULTS", "=" * 40]

        if not search_text:
            results.append("Usage: trace <search_term>")
            results.append("Example: trace unauthorized")
            return results

        # Search through events
        matches = []
        for e in self.events:
            if search_text.lower() in e.event_type.lower() or search_text.lower() in e.details.lower():
                matches.append(e)

        results.append(f"Tracing '{search_text}': {len(matches)} matches")
        results.append("")

        for i, e in enumerate(matches[:15]):
            results.append(f"┌─ Event {i+1} ─────────────────────────")
            results.append(f"│ Time:    {e.time_str}")
            results.append(f"│ Type:    {e.event_type}")
            results.append(f"│ Details: {e.details[:50]}")
            if len(e.details) > 50:
                results.append(f"│          {e.details[50:100]}")
            results.append(f"└{'─' * 40}")
            results.append("")

        if len(matches) > 15:
            results.append(f"... and {len(matches) - 15} more matches")

        if not matches:
            results.append("No matches found.")
            results.append("Try a different search term.")

        return results

    def _start_search(self):
        """Start event search/filter with text input."""
        curses.curs_set(1)  # Show cursor
        search_text = ""

        while True:
            self.screen.clear()

            # Draw search bar at top
            self._addstr(0, 0, "Search: ", Colors.HEADER)
            self._addstr(0, 8, search_text + "_", Colors.NORMAL)
            self._addstr(0, self.width - 20, "[Enter] Apply [ESC] Cancel", Colors.MUTED)

            # Show filtered events preview
            filtered = [e for e in self.events if search_text.lower() in e.event_type.lower()
                       or search_text.lower() in e.details.lower()]
            self._addstr(2, 0, f"Matching events: {len(filtered)}", Colors.MUTED)

            for i, event in enumerate(filtered[:10]):
                row = 4 + i
                if row >= self.height - 1:
                    break
                self._addstr(row, 2, event.time_short, Colors.MUTED)
                self._addstr(row, 12, event.event_type[:15], Colors.ACCENT)
                self._addstr(row, 28, event.details[:self.width-30], Colors.NORMAL)

            self.screen.refresh()

            key = self.screen.getch()
            if key == 27:  # ESC
                self.event_filter = ""
                break
            elif key in (curses.KEY_ENTER, 10, 13):
                self.event_filter = search_text
                break
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                search_text = search_text[:-1]
            elif 32 <= key <= 126:  # Printable characters
                search_text += chr(key)

        curses.curs_set(0)  # Hide cursor

    def _show_message(self, message: str, color: int = Colors.NORMAL):
        """Show a temporary message overlay."""
        msg_width = min(len(message) + 4, self.width - 4)
        msg_x = (self.width - msg_width) // 2
        msg_y = self.height // 2

        self._draw_box(msg_y - 1, msg_x - 2, msg_width + 4, 3, "")
        self._addstr(msg_y, msg_x, message[:msg_width], color)
        self.screen.refresh()
        time.sleep(1.5)

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format duration as human-readable string."""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds // 60)}m {int(seconds % 60)}s"
        else:
            hours = int(seconds // 3600)
            mins = int((seconds % 3600) // 60)
            return f"{hours}h {mins}m"

    @staticmethod
    def _format_bytes(n: int) -> str:
        """Format bytes as human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if abs(n) < 1024.0:
                return f"{n:.0f}{unit}"
            n /= 1024.0
        return f"{n:.0f}TB"


def run_dashboard(refresh_interval: float = 2.0, socket_path: Optional[str] = None,
                  matrix_mode: bool = False):
    """
    Run the dashboard.

    Args:
        refresh_interval: How often to refresh data (seconds)
        socket_path: Path to daemon socket
        matrix_mode: Enable Matrix-style theme with digital rain
    """
    # Show connection status before entering curses mode
    print("Connecting to Boundary Daemon...")

    # Create client first to check connection
    client = DashboardClient(socket_path)

    if client.is_demo_mode():
        print("\n" + "=" * 60)
        print("WARNING: Could not connect to Boundary Daemon")
        print("=" * 60)
        print("\nSearched for daemon at:")
        for path in client._socket_paths[:5]:
            exists = "FOUND" if os.path.exists(path) else "not found"
            print(f"  - {path} [{exists}]")
        if sys.platform == 'win32':
            print(f"  - TCP 127.0.0.1:{client.WINDOWS_PORT} [not responding]")
        print("\nRunning in DEMO MODE with simulated data.")
        print("To connect to real daemon, start boundary-daemon.exe first.")
        print("=" * 60 + "\n")
        import time
        time.sleep(2)  # Give user time to read
    else:
        if client._use_tcp:
            print(f"Connected to daemon via TCP on port {client.WINDOWS_PORT}")
        else:
            print(f"Connected to daemon at {client.socket_path}")

    dashboard = Dashboard(refresh_interval=refresh_interval, socket_path=socket_path,
                         matrix_mode=matrix_mode, client=client)
    dashboard.run()


def main():
    """CLI entry point for boundary-tui command."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Boundary TUI - Cyberpunk Terminal Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    boundary-tui                    # Run with defaults
    boundary-tui --refresh 0.5      # Faster refresh rate
    boundary-tui --matrix           # Enable Matrix rain effect
    boundary-tui --socket /path/to/daemon.sock  # Custom socket path

Keyboard Shortcuts:
    q     Quit
    r     Refresh data
    w     Cycle weather modes
    m     Mode change ceremony
    a     Acknowledge alert
    /     Search events
    ?     Help
        """
    )
    parser.add_argument("--refresh", "-r", type=float, default=2.0,
                       help="Refresh interval in seconds (default: 2.0)")
    parser.add_argument("--socket", "-s", type=str,
                       help="Path to daemon socket")
    parser.add_argument("--matrix", action="store_true",
                       help="Enable Matrix rain effect")

    args = parser.parse_args()
    run_dashboard(refresh_interval=args.refresh, socket_path=args.socket,
                  matrix_mode=args.matrix)


if __name__ == "__main__":
    main()
