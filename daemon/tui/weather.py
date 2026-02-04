"""
TUI Weather Effects - Matrix rain and weather particle systems.

Extracted from dashboard.py for maintainability.
Contains WeatherMode enum and MatrixRain particle system.
"""

import math
import random
from enum import Enum
from typing import Dict, List, Optional, Tuple

# Handle curses import for Windows compatibility
try:
    import curses
    CURSES_AVAILABLE = True
except ImportError:
    curses = None
    CURSES_AVAILABLE = False

from .colors import Colors


class WeatherMode(Enum):
    """Weather modes for Matrix-style effects."""
    MATRIX = "matrix"      # Classic green Matrix rain
    RAIN = "rain"          # Blue rain
    SNOW = "snow"          # White/gray snow
    SAND = "sand"          # Brown/yellow sandstorm
    CALM = "calm"          # No particles, just wind (leaves/debris)

    @property
    def display_name(self) -> str:
        """Get display name for the weather mode."""
        return {
            WeatherMode.MATRIX: "Matrix",
            WeatherMode.RAIN: "Rain",
            WeatherMode.SNOW: "Snow",
            WeatherMode.SAND: "Sandstorm",
            WeatherMode.CALM: "Calm",
        }.get(self, self.value.title())


class MatrixRain:
    """Digital rain effect from The Matrix with depth simulation and weather modes."""

    # Weather-specific character sets
    WEATHER_CHARS = {
        WeatherMode.MATRIX: [
            ".-·:;'`",  # Layer 0: Tiny rain - minimal dots
            ".|!:;+-=",  # Layer 1: Simple ASCII
            "0123456789+-*/<>=$#",  # Layer 2: Numbers and symbols
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",  # Layer 3: Alphanumeric
            "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789$#@&",  # Layer 4: Nearest
        ],
        WeatherMode.RAIN: [
            ".|'`",  # Layer 0: Light drizzle
            ".|!:",  # Layer 1: Light rain
            ".|!:;",  # Layer 2: Rain
            "||!:;/\\",  # Layer 3: Heavy rain
            "|||///\\\\\\",  # Layer 4: Downpour
        ],
        WeatherMode.SNOW: [
            "··",  # Layer 0: Distant snowflakes
            ".·*",  # Layer 1: Small flakes
            ".*+",  # Layer 2: Medium flakes
            "*+❄",  # Layer 3: Large flakes (using simple chars for compatibility)
            "*❄❅❆",  # Layer 4: Big fluffy snowflakes
        ],
        WeatherMode.SAND: [
            ".,",  # Layer 0: Fine dust
            ".,;:",  # Layer 1: Fine sand
            ".,:;'",  # Layer 2: Sand particles
            ",:;~^",  # Layer 3: Coarse sand
            "~^°º",  # Layer 4: Larger particles
        ],
        WeatherMode.CALM: [
            "",  # Layer 0: No particles
            "",  # Layer 1: No particles
            "",  # Layer 2: No particles
            "",  # Layer 3: No particles
            "",  # Layer 4: No particles (wind effects only)
        ],
    }

    # Weather-specific speed multipliers (relative to base speeds)
    WEATHER_SPEED_MULT = {
        WeatherMode.MATRIX: 1.0,
        WeatherMode.RAIN: 1.2,   # Rain falls fast
        WeatherMode.SNOW: 0.4,   # Base snow speed (modified per-depth below)
        WeatherMode.SAND: 0.15,  # Sand falls very slowly (blows horizontally instead)
        WeatherMode.CALM: 0.0,   # No particles falling
    }

    # Snow-specific speeds: big flakes fall FASTER than small ones (opposite of rain)
    # Slowed down for more gentle snowfall
    SNOW_DEPTH_SPEEDS = [
        0.15,  # Layer 0: Small flakes - slowest
        0.2,   # Layer 1: Small-medium
        0.3,   # Layer 2: Medium
        0.45,  # Layer 3: Big - faster
        0.6,   # Layer 4: Biggest - fastest
    ]

    # Weather-specific length multipliers (sand/snow = short particles)
    WEATHER_LENGTHS = {
        WeatherMode.MATRIX: None,  # Use default DEPTH_LENGTHS
        WeatherMode.RAIN: None,    # Use default DEPTH_LENGTHS
        WeatherMode.SNOW: [(1, 1), (1, 1), (1, 2), (1, 2), (1, 2)],  # Single flakes
        WeatherMode.SAND: [(1, 1), (1, 1), (1, 1), (1, 2), (1, 2)],  # Tiny grains
        WeatherMode.CALM: [(0, 0), (0, 0), (0, 0), (0, 0), (0, 0)],  # No particles
    }

    # Weather-specific horizontal movement
    WEATHER_HORIZONTAL = {
        WeatherMode.MATRIX: (0, 0),       # No horizontal movement
        WeatherMode.RAIN: (-0.1, 0.1),    # Slight wind variation
        WeatherMode.SNOW: (-0.4, 0.4),    # Gentle drift both ways
        WeatherMode.SAND: (1.5, 3.0),     # Strong wind blowing right
        WeatherMode.CALM: (0, 0),         # No particles to move
    }

    # Weather-specific color mappings (bright, dim, fade1, fade2)
    WEATHER_COLORS = {
        WeatherMode.MATRIX: (Colors.MATRIX_BRIGHT, Colors.MATRIX_DIM, Colors.MATRIX_FADE1, Colors.MATRIX_FADE2),
        WeatherMode.RAIN: (Colors.RAIN_BRIGHT, Colors.RAIN_DIM, Colors.RAIN_FADE1, Colors.RAIN_FADE2),
        WeatherMode.SNOW: (Colors.SNOW_BRIGHT, Colors.SNOW_DIM, Colors.SNOW_FADE, Colors.SNOW_FADE),
        WeatherMode.SAND: (Colors.SAND_BRIGHT, Colors.SAND_DIM, Colors.SAND_FADE, Colors.SAND_FADE),
        WeatherMode.CALM: (Colors.MATRIX_DIM, Colors.MATRIX_FADE1, Colors.MATRIX_FADE2, Colors.MATRIX_FADE3),
    }

    # 5 depth layers - each with different character sets (simple=far, complex=near)
    # Layer 0: Farthest - tiny fast raindrops falling from sky
    # Layer 4: Nearest - big slow drops sliding down window
    DEPTH_CHARS = WEATHER_CHARS[WeatherMode.MATRIX]  # Default to Matrix

    # Speed ranges - REVERSED: tiny rain (layer 0) is FASTEST like falling from sky
    # Big drops (layer 4) are SLOWEST like sliding down a window
    DEPTH_SPEEDS = [
        (3.5, 5.0),   # Layer 0: FASTEST - tiny rain falling from sky
        (2.0, 3.0),   # Layer 1: Fast
        (1.0, 1.5),   # Layer 2: Medium
        (0.5, 0.8),   # Layer 3: Slow
        (0.2, 0.4),   # Layer 4: SLOWEST - sliding down window
    ]

    # Tail lengths for each depth (tiny rain = very short, big drops = long trails)
    DEPTH_LENGTHS = [
        (1, 3),    # Layer 0: Very short drops - single chars and short streaks
        (2, 6),    # Layer 1: Short
        (6, 12),   # Layer 2: Medium
        (12, 20),  # Layer 3: Long
        (18, 30),  # Layer 4: Very long trails
    ]

    # Distribution - massive tiny rain!
    # Layer 0: 3x more, Layer 1: 2x more, Layers 2-4: unchanged
    # Calculated: [0.60*3, 0.15*2, 0.12, 0.08, 0.05] = [1.80, 0.30, 0.12, 0.08, 0.05]
    # Normalized to sum to 1.0
    DEPTH_WEIGHTS = [0.766, 0.128, 0.051, 0.034, 0.021]

    # Splat characters for when tiny rain hits
    SPLAT_CHARS = ['+', '*', '×', '·']

    def __init__(self, width: int, height: int, weather_mode: WeatherMode = WeatherMode.MATRIX):
        self.width = width
        self.height = height
        self.weather_mode = weather_mode
        self.drops: List[Dict] = []
        self.splats: List[Dict] = []  # Splat effects when tiny rain hits
        # Increased by 2.35x to maintain absolute counts for layers 2-4
        self._target_drops = max(28, width * 7 // 10)
        self._init_drops()

        # Flicker state
        self._frame_count = 0
        self._global_flicker = 0.0  # 0-1 intensity of global flicker
        self._intermittent_flicker = False  # Major flicker event active

        # Snow-specific state: stuck snowflakes that fade over time
        self._stuck_snow: List[Dict] = []
        # Roof/sill snow - lasts 10x longer and doesn't count towards max
        self._roof_sill_snow: List[Dict] = []
        # Snow filter callback - returns True if position is valid for snow collection
        self._snow_filter: Optional[callable] = None
        # Roof/sill checker callback - returns True if position is on roof or window sill
        self._roof_sill_checker: Optional[callable] = None

        # Snow wind gusts - temporary bursts of sideways movement
        self._snow_gusts: List[Dict] = []
        if weather_mode == WeatherMode.SNOW:
            self._init_snow_gusts()

        # Sand-specific state: vertical gust columns
        self._sand_gusts: List[Dict] = []
        if weather_mode == WeatherMode.SAND:
            self._init_sand_gusts()

    def set_weather_mode(self, mode: WeatherMode):
        """Change the weather mode and reinitialize particles."""
        if mode != self.weather_mode:
            self.weather_mode = mode
            self.drops = []
            self.splats = []
            self._stuck_snow = []
            self._roof_sill_snow = []
            self._snow_gusts = []
            self._sand_gusts = []
            self._init_drops()
            if mode == WeatherMode.SNOW:
                self._init_snow_gusts()
            if mode == WeatherMode.SAND:
                self._init_sand_gusts()

    def set_snow_filter(self, filter_func: callable):
        """Set a callback function that checks if a position is valid for snow collection.

        The function should accept (x, y) and return True if snow can collect there.
        """
        self._snow_filter = filter_func

    def set_roof_sill_checker(self, checker_func: callable):
        """Set a callback function that checks if a position is on roof or window sill.

        Snow on these positions lasts 10x longer and doesn't count towards max.
        """
        self._roof_sill_checker = checker_func

    def set_glow_positions(self, positions: List[Tuple[int, int]]):
        """Set street light glow center positions for snow melting.

        Snow near these positions will melt faster.
        """
        self._glow_positions = positions

    def set_quick_melt_zones(self, sidewalk_y: int, mailbox_bounds: Tuple[int, int, int, int], street_y: int,
                              traffic_light_bounds: Optional[Tuple[int, int, int, int]] = None,
                              cafe_bounds: Optional[Tuple[int, int, int, int, int]] = None):
        """Set zones where snow melts very quickly (sidewalk, mailbox, traffic lines, traffic light, cafe).

        Args:
            sidewalk_y: Y coordinate of the sidewalk/curb
            mailbox_bounds: (x, y, width, height) of the mailbox
            street_y: Y coordinate of the street (for traffic lines)
            traffic_light_bounds: (x, y, width, height) of the traffic light
            cafe_bounds: (x, y, width, height, shell_roof_height) of the cafe - snow melts on building but not shell roof
        """
        self._quick_melt_sidewalk_y = sidewalk_y
        self._quick_melt_mailbox = mailbox_bounds
        self._quick_melt_street_y = street_y
        self._quick_melt_traffic_light = traffic_light_bounds
        self._quick_melt_cafe = cafe_bounds

    def _is_in_quick_melt_zone(self, x: int, y: int) -> bool:
        """Check if a position is in a quick-melt zone (sidewalk, mailbox, traffic light, traffic line)."""
        # Sidewalk
        if hasattr(self, '_quick_melt_sidewalk_y') and y == self._quick_melt_sidewalk_y:
            return True
        # Street/traffic lines
        if hasattr(self, '_quick_melt_street_y') and y == self._quick_melt_street_y:
            return True
        # Mailbox
        if hasattr(self, '_quick_melt_mailbox') and self._quick_melt_mailbox:
            mx, my, mw, mh = self._quick_melt_mailbox
            if mx <= x < mx + mw and my <= y < my + mh:
                return True
        # Traffic light
        if hasattr(self, '_quick_melt_traffic_light') and self._quick_melt_traffic_light:
            tx, ty, tw, th = self._quick_melt_traffic_light
            if tx <= x < tx + tw and ty <= y < ty + th:
                return True
        # Cafe (excluding shell roof which can accumulate snow)
        if hasattr(self, '_quick_melt_cafe') and self._quick_melt_cafe:
            cx, cy, cw, ch, shell_h = self._quick_melt_cafe
            # Only melt snow below the shell roof (shell_h rows from top)
            cafe_body_y = cy + shell_h
            if cx <= x < cx + cw and cafe_body_y <= y < cy + ch:
                return True
        return False

    def _is_in_glow_zone(self, x: int, y: int) -> bool:
        """Check if a position is within a street light glow cone."""
        if not hasattr(self, '_glow_positions') or not self._glow_positions:
            return False
        for light_x, light_y in self._glow_positions:
            # Glow cone: 4 rows below light, widening
            for row in range(5):
                spread = row + 1
                glow_y = light_y + 1 + row
                if y == glow_y and abs(x - light_x) <= spread:
                    return True
        return False

    def cycle_weather(self) -> WeatherMode:
        """Cycle to the next weather mode and return the new mode."""
        modes = list(WeatherMode)
        current_idx = modes.index(self.weather_mode)
        next_idx = (current_idx + 1) % len(modes)
        new_mode = modes[next_idx]
        self.set_weather_mode(new_mode)
        return new_mode

    def _init_sand_gusts(self):
        """Initialize vertical columns of faster-moving sand gusts."""
        self._sand_gusts = []
        # Create 3-6 gust columns across the screen
        num_gusts = random.randint(3, 6)
        for _ in range(num_gusts):
            self._sand_gusts.append({
                'x': random.randint(0, self.width - 1),
                'width': random.randint(2, 5),  # Gust column width
                'speed_mult': random.uniform(2.0, 4.0),  # How much faster than normal
                'life': random.randint(30, 80),  # Frames until gust moves/fades
                'opacity': random.uniform(0.7, 1.0),
            })

    def _init_snow_gusts(self):
        """Initialize wind gusts that push snow sideways."""
        self._snow_gusts = []
        # Start with 2-4 active gusts
        num_gusts = random.randint(2, 4)
        for _ in range(num_gusts):
            self._snow_gusts.append({
                'direction': random.choice([-1, 1]),  # -1 = left, 1 = right
                'strength': random.uniform(0.5, 2.0),  # How strong the push
                'y_start': random.randint(0, self.height - 1),
                'y_height': random.randint(5, 15),  # Vertical band height
                'life': random.randint(20, 60),  # Frames until gust fades
            })

    def _get_weather_chars(self) -> List[str]:
        """Get character sets for current weather mode."""
        return self.WEATHER_CHARS.get(self.weather_mode, self.WEATHER_CHARS[WeatherMode.MATRIX])

    def _get_speed_multiplier(self) -> float:
        """Get speed multiplier for current weather mode."""
        return self.WEATHER_SPEED_MULT.get(self.weather_mode, 1.0)

    def _get_weather_colors(self) -> tuple:
        """Get color tuple (bright, dim, fade1, fade2) for current weather mode."""
        return self.WEATHER_COLORS.get(self.weather_mode, self.WEATHER_COLORS[WeatherMode.MATRIX])

    def _init_drops(self):
        """Initialize rain drops at random positions across all depth layers."""
        self.drops = []
        for _ in range(self._target_drops):
            self._add_drop()

    def _add_drop(self, depth: Optional[int] = None):
        """Add a new rain drop at a random or specified depth layer."""
        if self.width <= 0:
            return

        # Choose depth layer based on weights if not specified
        if depth is None:
            depth = random.choices(range(5), weights=self.DEPTH_WEIGHTS)[0]

        speed_min, speed_max = self.DEPTH_SPEEDS[depth]

        # Get weather-specific lengths or use defaults
        weather_lengths = self.WEATHER_LENGTHS.get(self.weather_mode)
        if weather_lengths:
            len_min, len_max = weather_lengths[depth]
        else:
            len_min, len_max = self.DEPTH_LENGTHS[depth]

        # Apply weather-specific speed multiplier
        speed_mult = self._get_speed_multiplier()

        # Snow uses inverted depth speeds (big flakes = faster)
        if self.weather_mode == WeatherMode.SNOW:
            speed_mult = self.SNOW_DEPTH_SPEEDS[depth]

        weather_chars = self._get_weather_chars()

        # Get weather-specific horizontal movement
        h_min, h_max = self.WEATHER_HORIZONTAL.get(self.weather_mode, (0, 0))
        dx = random.uniform(h_min, h_max) if h_min != h_max else 0.0

        # Determine spawn position
        if self.weather_mode == WeatherMode.SAND:
            # Sand spawns from left edge and blows across
            start_x = random.randint(-10, 0)
            start_y = random.randint(0, self.height - 1)
        else:
            # Normal: spawn across width, start below cloud layer (row 3+)
            start_x = random.randint(0, self.width - 1)
            start_y = random.randint(3, 5)  # Start below solid cloud cover (rows 1-2)

        # Ensure length range is valid (max >= min)
        effective_max_len = max(len_min, min(len_max, max(1, self.height // 2)))

        # Skip adding drops if no characters for this weather mode (e.g., CALM mode)
        chars = weather_chars[depth]
        if not chars:
            return

        self.drops.append({
            'x': start_x,
            'y': start_y,
            'speed': random.uniform(speed_min, speed_max) * speed_mult,
            'length': random.randint(len_min, effective_max_len),
            'char_offset': random.randint(0, len(chars) - 1),
            'depth': depth,
            'phase': float(start_y),
            'dx': dx,  # Horizontal movement
            'fx': float(start_x),  # Fractional x position for smooth movement
        })

    def _add_splat(self, x: int, y: int):
        """Add a splat effect at the given position."""
        if 0 <= x < self.width and self.height // 2 <= y < self.height:
            self.splats.append({
                'x': x,
                'y': y,
                'life': random.randint(3, 8),  # Frames to live
                'char': random.choice(self.SPLAT_CHARS),
            })

    def update(self):
        """Update rain drop positions and flicker state."""
        self._frame_count += 1

        # Update flicker states (less flicker for non-Matrix modes)
        if self.weather_mode == WeatherMode.MATRIX:
            # Rapid low-level flicker - subtle constant shimmer (sine wave oscillation)
            self._global_flicker = 0.15 + 0.1 * math.sin(self._frame_count * 0.3)
            # Intermittent major flicker - brief stutter every few seconds
            if random.random() < 0.003:
                self._intermittent_flicker = True
            elif self._intermittent_flicker and random.random() < 0.3:
                self._intermittent_flicker = False
        else:
            self._global_flicker = 0.0
            self._intermittent_flicker = False

        # Update sand gusts if in sand mode
        if self.weather_mode == WeatherMode.SAND:
            self._update_sand_gusts()

        # Update snow gusts and stuck snow
        if self.weather_mode == WeatherMode.SNOW:
            self._update_snow_gusts()
            self._update_stuck_snow()

        weather_chars = self._get_weather_chars()

        new_drops = []
        for drop in self.drops:
            # Check if sand particle is in a gust column (moves faster)
            speed_boost = 1.0
            if self.weather_mode == WeatherMode.SAND:
                for gust in self._sand_gusts:
                    if gust['x'] <= drop['x'] < gust['x'] + gust['width']:
                        speed_boost = gust['speed_mult']
                        break

            drop['phase'] += drop['speed'] * speed_boost
            drop['y'] = int(drop['phase'])

            # Apply snow wind gusts - push flakes sideways
            gust_dx = 0.0
            if self.weather_mode == WeatherMode.SNOW:
                for gust in self._snow_gusts:
                    if gust['y_start'] <= drop['y'] < gust['y_start'] + gust['y_height']:
                        # Bigger flakes get pushed more by wind
                        size_factor = 0.5 + (drop['depth'] * 0.3)
                        gust_dx = gust['direction'] * gust['strength'] * size_factor
                        break

            # Update horizontal position for snow/sand
            base_dx = drop.get('dx', 0)
            total_dx = base_dx + gust_dx
            if total_dx != 0:
                dx_boost = speed_boost if self.weather_mode == WeatherMode.SAND else 1.0
                drop['fx'] = drop.get('fx', float(drop['x'])) + total_dx * dx_boost
                new_x = int(drop['fx'])

                # Sand blows off right edge and is removed
                if self.weather_mode == WeatherMode.SAND:
                    if new_x >= self.width:
                        continue  # Remove sand that went off right edge
                    drop['x'] = new_x
                else:
                    # Other modes wrap around
                    drop['x'] = new_x % self.width

            # Roll through characters as the drop falls
            # Tiny rain (layer 0) rolls fastest for that streaking effect
            roll_speed = 5 - drop['depth']  # Layer 0 = 5, Layer 4 = 1
            chars = weather_chars[drop['depth']]
            # Skip char_offset update if no characters (e.g., CALM mode with existing drops)
            if chars:
                drop['char_offset'] = (drop['char_offset'] + roll_speed) % len(chars)

            # Snow sticking behavior
            if self.weather_mode == WeatherMode.SNOW:
                # Big flakes (depth 3-4) can stick anywhere
                if drop['depth'] >= 3 and drop['y'] >= 0:
                    # Random chance to stick based on how far down the screen
                    stick_chance = 0.002 + (drop['y'] / self.height) * 0.01
                    if random.random() < stick_chance:
                        self._add_stuck_snow(drop['x'], drop['y'], drop['depth'], chars[drop['char_offset'] % len(chars)])
                        continue  # Remove this drop, it's now stuck

                # Small flakes (depth 0-2) fall to bottom 1/5th then stick
                elif drop['depth'] <= 2:
                    bottom_zone = self.height - (self.height // 5)
                    if drop['y'] >= bottom_zone:
                        # High chance to stick in bottom zone
                        if random.random() < 0.05:
                            self._add_stuck_snow(drop['x'], drop['y'], drop['depth'], chars[drop['char_offset'] % len(chars)])
                            continue

            # Check if tiny rain (layer 0) hit the ground (mid-screen to bottom)
            # Only create splats for Matrix and Rain modes
            if drop['depth'] == 0 and drop['y'] >= self.height:
                if self.weather_mode in (WeatherMode.MATRIX, WeatherMode.RAIN):
                    if random.random() < 0.7:  # 70% chance of splat
                        self._add_splat(drop['x'], self.height - 1)
                continue  # Don't keep this drop

            # Keep drop if still on screen (vertically)
            if drop['y'] - drop['length'] < self.height:
                new_drops.append(drop)

        self.drops = new_drops

        # Update splats - decrease life and remove dead ones
        new_splats = []
        for splat in self.splats:
            splat['life'] -= 1
            if splat['life'] > 0:
                new_splats.append(splat)
        self.splats = new_splats

        # Add new drops to maintain density (skip for CALM mode which has no particles)
        if self.weather_mode != WeatherMode.CALM:
            while len(self.drops) < self._target_drops:
                self._add_drop()

    def _add_stuck_snow(self, x: int, y: int, depth: int, char: str):
        """Add a snowflake that has stuck to the screen."""
        # Check if position is valid for snow collection
        if self._snow_filter and not self._snow_filter(x, y):
            return  # Position is not valid for snow collection

        # Check if this is roof/sill snow (lasts 10x longer, no max count)
        is_roof_sill = self._roof_sill_checker and self._roof_sill_checker(x, y)

        if is_roof_sill:
            # Roof/sill snow: lasts 10x longer (1600-4800), limit to 400
            if len(self._roof_sill_snow) < 400:
                self._roof_sill_snow.append({
                    'x': x,
                    'y': y,
                    'depth': depth,
                    'char': char,
                    'life': random.randint(1600, 4800),  # 10x longer melt time
                    'max_life': 4800,
                })
        else:
            # Regular stuck snow: limit to 800
            if len(self._stuck_snow) < 800:
                self._stuck_snow.append({
                    'x': x,
                    'y': y,
                    'depth': depth,
                    'char': char,
                    'life': random.randint(160, 480),
                    'max_life': 480,
                })

    def _update_stuck_snow(self):
        """Update stuck snow - slowly fade/melt away."""
        # Update regular stuck snow
        new_stuck = []
        for snow in self._stuck_snow:
            # Snow in quick-melt zones (sidewalk, mailbox, traffic lines) melts very fast
            if self._is_in_quick_melt_zone(snow['x'], snow['y']):
                snow['life'] -= 25  # Very fast melt
            # Snow in glow zones melts 10x faster (warmth from lights)
            elif self._is_in_glow_zone(snow['x'], snow['y']):
                snow['life'] -= 10
            else:
                snow['life'] -= 1
            if snow['life'] > 0:
                new_stuck.append(snow)
        self._stuck_snow = new_stuck

        # Update roof/sill snow (separate list)
        new_roof_sill = []
        for snow in self._roof_sill_snow:
            # Quick-melt zones
            if self._is_in_quick_melt_zone(snow['x'], snow['y']):
                snow['life'] -= 25
            # Roof/sill snow also melts faster in glow zones
            elif self._is_in_glow_zone(snow['x'], snow['y']):
                snow['life'] -= 10
            else:
                snow['life'] -= 1
            if snow['life'] > 0:
                new_roof_sill.append(snow)
        self._roof_sill_snow = new_roof_sill

    def _update_sand_gusts(self):
        """Update sand gust columns - they shift position over time."""
        for gust in self._sand_gusts:
            gust['life'] -= 1
            if gust['life'] <= 0:
                # Reset gust to new position
                gust['x'] = random.randint(0, self.width - 1)
                gust['width'] = random.randint(2, 5)
                gust['speed_mult'] = random.uniform(2.0, 4.0)
                gust['life'] = random.randint(30, 80)
                gust['opacity'] = random.uniform(0.7, 1.0)

    def _update_snow_gusts(self):
        """Update snow wind gusts - they fade and new ones appear."""
        new_gusts = []
        for gust in self._snow_gusts:
            gust['life'] -= 1
            if gust['life'] > 0:
                new_gusts.append(gust)

        self._snow_gusts = new_gusts

        # Randomly spawn new gusts
        if random.random() < 0.05 and len(self._snow_gusts) < 5:
            self._snow_gusts.append({
                'direction': random.choice([-1, 1]),
                'strength': random.uniform(0.5, 2.0),
                'y_start': random.randint(0, self.height - 1),
                'y_height': random.randint(5, 15),
                'life': random.randint(20, 60),
            })

    def resize(self, width: int, height: int):
        """Handle terminal resize."""
        old_width = self.width
        old_height = self.height
        self.width = width
        self.height = height
        self._target_drops = max(28, width * 7 // 10)  # Massive rain density

        # Remove drops and splats that are now out of bounds
        self.drops = [d for d in self.drops if d['x'] < width]
        self.splats = [s for s in self.splats if s['x'] < width and s['y'] < height]

        # Remove stuck snow that is now out of bounds
        self._stuck_snow = [s for s in self._stuck_snow if s['x'] < width and s['y'] < height]

        # Reinitialize sand gusts for new width
        if self.weather_mode == WeatherMode.SAND:
            if abs(width - old_width) > 10:
                self._init_sand_gusts()
            else:
                for gust in self._sand_gusts:
                    if gust['x'] >= width:
                        gust['x'] = random.randint(0, width - 1)

        # Add more drops if window got bigger
        if width > old_width:
            for _ in range(max(1, (width - old_width) * 7 // 10)):
                self._add_drop()

    def render(self, screen):
        """Render rain drops with depth-based visual effects and flicker."""
        if not CURSES_AVAILABLE or curses is None:
            return

        weather_chars = self._get_weather_chars()
        colors = self._get_weather_colors()

        # Sort drops by depth so farther ones render first (get overwritten by nearer)
        sorted_drops = sorted(self.drops, key=lambda d: d['depth'])

        for drop in sorted_drops:
            depth = drop['depth']
            chars = weather_chars[depth]

            # Skip rendering if no characters for this weather mode (e.g., CALM mode)
            if not chars:
                continue

            # During intermittent flicker, skip rendering some drops randomly
            if self._intermittent_flicker and random.random() < 0.4:
                continue

            for i in range(drop['length']):
                y = drop['y'] - i
                if 0 <= y < self.height and 0 <= drop['x'] < self.width:
                    # Rapid low-level flicker - randomly skip some chars
                    if random.random() < self._global_flicker * 0.3:
                        continue

                    # Character rolls through the charset as it falls
                    char_idx = (drop['char_offset'] + i * 2) % len(chars)
                    char = chars[char_idx]

                    # More character mutation flicker for nearer drops (Matrix mode only)
                    if self.weather_mode == WeatherMode.MATRIX:
                        if random.random() < 0.02 * (depth + 1):
                            char = random.choice(chars)
                        # Rapid flicker can also swap characters briefly
                        if random.random() < self._global_flicker * 0.15:
                            char = random.choice(chars)

                    try:
                        self._render_char(screen, y, drop['x'], char, i, depth)
                    except curses.error:
                        pass

        # Render splats (tiny rain impact effects) - only for Matrix and Rain modes
        if self.weather_mode in (WeatherMode.MATRIX, WeatherMode.RAIN):
            bright, dim, fade1, fade2 = colors
            for splat in self.splats:
                try:
                    # Splats fade based on remaining life
                    if splat['life'] > 5:
                        attr = curses.color_pair(bright) | curses.A_BOLD
                    elif splat['life'] > 2:
                        attr = curses.color_pair(dim)
                    else:
                        attr = curses.color_pair(fade1) | curses.A_DIM

                    screen.attron(attr)
                    screen.addstr(splat['y'], splat['x'], splat['char'])
                    screen.attroff(attr)
                except curses.error:
                    pass

        # Render stuck snow (melting snowflakes)
        if self.weather_mode == WeatherMode.SNOW:
            # Render regular stuck snow
            for snow in self._stuck_snow:
                try:
                    if 0 <= snow['x'] < self.width - 1 and 0 <= snow['y'] < self.height:
                        # Fade based on remaining life (melting effect)
                        life_ratio = snow['life'] / snow['max_life']
                        if life_ratio > 0.6:
                            attr = curses.color_pair(Colors.SNOW_BRIGHT) | curses.A_BOLD
                        elif life_ratio > 0.3:
                            attr = curses.color_pair(Colors.SNOW_DIM)
                        else:
                            attr = curses.color_pair(Colors.SNOW_FADE) | curses.A_DIM

                        screen.attron(attr)
                        screen.addstr(snow['y'], snow['x'], snow['char'])
                        screen.attroff(attr)
                except curses.error:
                    pass

            # Render roof/sill snow (lasts longer)
            for snow in self._roof_sill_snow:
                try:
                    if 0 <= snow['x'] < self.width - 1 and 0 <= snow['y'] < self.height:
                        # Fade based on remaining life (melting effect)
                        life_ratio = snow['life'] / snow['max_life']
                        if life_ratio > 0.6:
                            attr = curses.color_pair(Colors.SNOW_BRIGHT) | curses.A_BOLD
                        elif life_ratio > 0.3:
                            attr = curses.color_pair(Colors.SNOW_DIM)
                        else:
                            attr = curses.color_pair(Colors.SNOW_FADE) | curses.A_DIM

                        screen.attron(attr)
                        screen.addstr(snow['y'], snow['x'], snow['char'])
                        screen.attroff(attr)
                except curses.error:
                    pass

    def _render_char(self, screen, y: int, x: int, char: str, pos: int, depth: int):
        """Render a single character with depth-appropriate styling."""
        if not CURSES_AVAILABLE or curses is None:
            return

        # Depth 0 = farthest/dimmest, Depth 4 = nearest/brightest
        # Get weather-appropriate colors
        bright, dim, fade1, fade2 = self._get_weather_colors()

        # Use dark green for Matrix rain tails
        is_matrix = self.weather_mode == WeatherMode.MATRIX
        dark_tail = Colors.MATRIX_DARK if is_matrix else fade2

        if depth == 0:
            # Farthest layer - very dim, no head highlight
            if pos < 2:
                attr = curses.color_pair(dark_tail) | curses.A_DIM
            else:
                # Use dark green for Matrix tails, fade2 for others
                if is_matrix:
                    attr = curses.color_pair(Colors.MATRIX_DARK) | curses.A_DIM
                else:
                    attr = curses.color_pair(fade2) | curses.A_DIM
        elif depth == 1:
            # Far layer - dim
            if pos == 0:
                attr = curses.color_pair(fade1)
            elif pos < 3:
                attr = curses.color_pair(fade1) | curses.A_DIM
            else:
                attr = curses.color_pair(dark_tail) | curses.A_DIM
        elif depth == 2:
            # Middle layer - normal
            if pos == 0:
                attr = curses.color_pair(dim) | curses.A_BOLD
            elif pos < 3:
                attr = curses.color_pair(dim)
            elif pos < 6:
                attr = curses.color_pair(fade1) | curses.A_DIM
            else:
                attr = curses.color_pair(dark_tail) | curses.A_DIM
        elif depth == 3:
            # Near layer - bright
            if pos == 0:
                attr = curses.color_pair(bright) | curses.A_BOLD
            elif pos == 1:
                attr = curses.color_pair(dim) | curses.A_BOLD
            elif pos < 5:
                attr = curses.color_pair(dim)
            elif pos < 9:
                attr = curses.color_pair(fade1)
            else:
                attr = curses.color_pair(dark_tail) | curses.A_DIM
        else:  # depth == 4
            # Nearest layer - brightest, boldest
            if pos == 0:
                attr = curses.color_pair(bright) | curses.A_BOLD
            elif pos == 1:
                attr = curses.color_pair(bright)
            elif pos < 4:
                attr = curses.color_pair(dim) | curses.A_BOLD
            elif pos < 8:
                attr = curses.color_pair(dim)
            elif pos < 12:
                attr = curses.color_pair(fade1)
            else:
                attr = curses.color_pair(dark_tail)

        screen.attron(attr)
        screen.addstr(y, x, char)
        screen.attroff(attr)
