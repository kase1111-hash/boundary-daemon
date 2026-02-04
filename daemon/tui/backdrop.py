"""
TUI Backdrop Effects - 3D tunnel animation for sky backdrop.

Extracted from dashboard.py for maintainability.
"""

import math
from typing import Optional

# Handle curses import for Windows compatibility
try:
    import curses
    CURSES_AVAILABLE = True
except ImportError:
    curses = None
    CURSES_AVAILABLE = False

from .colors import Colors
from .weather import WeatherMode


class TunnelBackdrop:
    """
    Organic 3D tunnel effect for the sky backdrop - creates flowing, turbulent depth illusion.

    Uses layered noise functions to create organic, swirling patterns that flow toward
    a vanishing point, creating the illusion of flying through a cosmic tunnel/vortex.
    Characters range from sparse (.) to dense (@) based on computed depth values.

    Implements frame caching for performance - precomputes animation frames and cycles
    through them instead of computing every pixel every frame.
    """

    # Density character gradient from sparse to dense (organic ASCII tunnel style)
    DENSITY_CHARS = ' .,:;i1tfLCG0@#'

    # Weather-specific character sets (sparse to dense)
    WEATHER_CHARS = {
        WeatherMode.MATRIX: ' .,:;i1tfLCG0@#',
        WeatherMode.RAIN: ' .,~:;|/\\1tfL░▒▓',
        WeatherMode.SNOW: ' ·.,:*+o0O@#█',
        WeatherMode.SAND: ' .,:;~°^"oO0@',
        WeatherMode.CALM: ' .,:;=+*#@',
    }

    # Weather-specific color palettes (4 levels: far, mid, near, bright)
    WEATHER_COLORS = {
        WeatherMode.MATRIX: [Colors.TUNNEL_FAR, Colors.TUNNEL_MID, Colors.TUNNEL_NEAR, Colors.MATRIX_DIM],
        WeatherMode.RAIN: [Colors.RAIN_FADE2, Colors.RAIN_FADE1, Colors.RAIN_DIM, Colors.RAIN_BRIGHT],
        WeatherMode.SNOW: [Colors.SNOW_FADE, Colors.SNOW_DIM, Colors.SNOW_BRIGHT, Colors.SNOW_BRIGHT],
        WeatherMode.SAND: [Colors.SAND_FADE, Colors.SAND_DIM, Colors.SAND_BRIGHT, Colors.SAND_BRIGHT],
        WeatherMode.CALM: [Colors.TUNNEL_FAR, Colors.TUNNEL_MID, Colors.ALLEY_MID, Colors.ALLEY_LIGHT],
    }

    # Number of cached frames for animation loop (more = smoother)
    CACHE_FRAMES = 180

    def __init__(self, width: int, height: int, weather_mode: WeatherMode = WeatherMode.MATRIX):
        self.width = width
        self.height = height
        self.weather_mode = weather_mode
        self._enabled = True

        # Animation state
        self._frame_idx = 0
        self._speed = 1  # Single frame steps for smooth animation

        # Tunnel center (vanishing point)
        self._center_x = width // 2
        self._center_y = height // 3  # Higher up for taller effect

        # Precompute sine table for fast lookup
        self._sin_table = []
        for i in range(360):
            self._sin_table.append(math.sin(i * math.pi / 180))

        # Frame cache - list of frames, each frame is list of (y, x, char, color, bold) tuples
        self._frame_cache = []
        self._cache_valid = False
        self._cached_weather = weather_mode
        self._cached_width = width
        self._cached_height = height

    def _fast_sin(self, angle: float) -> float:
        """Fast sine lookup using precomputed table."""
        idx = int(angle * 57.2958) % 360
        return self._sin_table[idx]

    def _fast_cos(self, angle: float) -> float:
        """Fast cosine lookup using precomputed table."""
        idx = int((angle * 57.2958) + 90) % 360
        return self._sin_table[idx]

    def _noise(self, x: float, y: float, seed: float = 0) -> float:
        """Simple coherent noise function for organic patterns."""
        n = 0.0
        n += self._fast_sin(x * 0.1 + seed) * self._fast_cos(y * 0.15 + seed * 0.7)
        n += self._fast_sin(x * 0.23 + y * 0.17 + seed * 1.3) * 0.5
        n += self._fast_cos(x * 0.31 - y * 0.29 + seed * 0.9) * 0.25
        n += self._fast_sin((x + y) * 0.19 + seed * 2.1) * 0.125
        return n

    def _turbulence(self, x: float, y: float, t: float) -> float:
        """Create turbulent, organic flow patterns."""
        turb = 0.0
        turb += self._noise(x * 0.05 + t * 0.3, y * 0.08 + t * 0.2, t) * 0.5
        turb += self._noise(x * 0.12 + t * 0.5, y * 0.15 - t * 0.3, t * 1.7) * 0.3
        turb += self._noise(x * 0.25 - t * 0.4, y * 0.3 + t * 0.6, t * 2.3) * 0.2
        return turb

    def _build_cache(self):
        """Precompute all animation frames for the current size and weather."""
        self._frame_cache = []
        sky_height = self.height * 2 // 3  # Twice as tall

        chars = self.WEATHER_CHARS.get(self.weather_mode, self.DENSITY_CHARS)
        colors = self.WEATHER_COLORS.get(self.weather_mode,
                                         [Colors.TUNNEL_FAR, Colors.TUNNEL_MID,
                                          Colors.TUNNEL_NEAR, Colors.TUNNEL_BRIGHT])
        char_count = len(chars) - 1

        # Generate each frame
        for frame in range(self.CACHE_FRAMES):
            t = frame * 0.05  # Smaller time steps = smoother transitions
            frame_data = []

            for y in range(1, sky_height):
                for x in range(0, self.width - 1):
                    dx = x - self._center_x
                    dy = (y - self._center_y) * 2.0

                    dist = math.sqrt(dx * dx + dy * dy)
                    if dist < 1:
                        dist = 1

                    angle = math.atan2(dy, dx)
                    tunnel_depth = 50.0 / (dist + 5)
                    swirl = angle + t * 0.5 + tunnel_depth * 0.3

                    turb = self._turbulence(x + swirl * 3, y + t * 2, t)
                    density = tunnel_depth * 0.4 + turb * 0.4

                    wave = self._fast_sin(dist * 0.15 - t * 2) * 0.3
                    density += wave

                    spiral = self._fast_sin(angle * 3 + dist * 0.1 - t * 1.5) * 0.2
                    density += spiral

                    density = (density + 1) * 0.5
                    density = max(0, min(1, density))

                    char_idx = int(density * char_count)
                    char = chars[char_idx]

                    if char == ' ':
                        continue

                    color_idx = min(3, int(tunnel_depth * 0.8))
                    color = colors[color_idx]

                    # Store brightness level: 0=dim, 1=normal, 2=bold
                    if density > 0.7:
                        brightness = 2
                    elif density < 0.3:
                        brightness = 0
                    else:
                        brightness = 1

                    frame_data.append((y, x, char, color, brightness))

            self._frame_cache.append(frame_data)

        self._cache_valid = True
        self._cached_weather = self.weather_mode
        self._cached_width = self.width
        self._cached_height = self.height

    def set_weather_mode(self, mode: WeatherMode):
        """Change the weather mode."""
        if mode != self.weather_mode:
            self.weather_mode = mode
            self._cache_valid = False  # Invalidate cache

    def set_enabled(self, enabled: bool):
        """Enable or disable the tunnel effect."""
        self._enabled = enabled

    def resize(self, width: int, height: int):
        """Handle terminal resize."""
        if width != self.width or height != self.height:
            self.width = width
            self.height = height
            self._center_x = width // 2
            self._center_y = height // 3
            # Clear old cache immediately to free memory before rebuild
            self._frame_cache = []
            self._cache_valid = False  # Invalidate cache

    def update(self):
        """Update animation state."""
        if not self._enabled:
            return
        self._frame_idx = (self._frame_idx + self._speed) % self.CACHE_FRAMES

    def render(self, screen, sky_height: Optional[int] = None):
        """
        Render the organic tunnel backdrop effect using cached frames.

        Args:
            screen: Curses screen object
            sky_height: Ignored - uses cached height (2/3 of screen)
        """
        if not self._enabled or not CURSES_AVAILABLE or curses is None:
            return

        # Rebuild cache if needed
        if not self._cache_valid or self._cached_weather != self.weather_mode:
            self._build_cache()

        # Get current frame
        if not self._frame_cache:
            return

        frame_data = self._frame_cache[int(self._frame_idx)]

        # Render all pixels from cached frame
        for y, x, char, color, brightness in frame_data:
            if y >= self.height or x >= self.width - 1:
                continue

            try:
                attr = curses.color_pair(color)
                if brightness == 2:
                    attr |= curses.A_BOLD
                elif brightness == 0:
                    attr |= curses.A_DIM

                screen.attron(attr)
                screen.addstr(y, x, char)
                screen.attroff(attr)
            except curses.error:
                pass
