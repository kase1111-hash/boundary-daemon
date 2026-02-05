"""
TUI Color Definitions - Curses color pair management.

Extracted from dashboard.py for maintainability.
"""

# Handle curses import for Windows compatibility
try:
    import curses
    CURSES_AVAILABLE = True
except ImportError:
    curses = None
    CURSES_AVAILABLE = False


class Colors:
    """Color pairs for curses."""
    NORMAL = 0
    STATUS_OK = 1
    STATUS_WARN = 2
    STATUS_ERROR = 3
    HEADER = 4
    SELECTED = 5
    MUTED = 6
    ACCENT = 7
    MATRIX_BRIGHT = 8
    MATRIX_DIM = 9
    MATRIX_FADE1 = 10
    MATRIX_FADE2 = 11
    MATRIX_FADE3 = 12
    LIGHTNING = 13  # Inverted flash for lightning bolt
    # Alley scene colors
    ALLEY_DARK = 14      # Darkest shadows
    ALLEY_MID = 15       # Mid-tone buildings
    ALLEY_LIGHT = 16     # Lighter details
    ALLEY_BLUE = 17      # Muted blue accents
    # Creature colors
    RAT_YELLOW = 18      # Yellow rat for warnings
    SHADOW_RED = 19      # Red glowing eyes for threats
    # Weather mode colors
    RAIN_BRIGHT = 20     # Bright blue rain
    RAIN_DIM = 21        # Dim blue rain
    RAIN_FADE1 = 22      # Fading blue
    RAIN_FADE2 = 23      # Very faded blue
    SNOW_BRIGHT = 24     # Bright white snow
    SNOW_DIM = 25        # Dim gray snow
    SNOW_FADE = 26       # Faded gray snow
    SAND_BRIGHT = 27     # Bright sand/brown
    SAND_DIM = 28        # Dim sand
    SAND_FADE = 29       # Faded sand
    MATRIX_DARK = 30     # Dark green for rain tails
    BRICK_RED = 31       # Red brick color for upper building
    GREY_BLOCK = 32      # Grey block color for lower building
    DOOR_KNOB_GOLD = 33  # Gold door knob color
    CAFE_WARM = 34       # Warm yellow/orange for cafe interior
    # Weather-based box border colors
    BOX_BROWN = 35       # Brown for snow mode top/sides
    BOX_DARK_BROWN = 36  # Dark brown for rain mode
    BOX_GREY = 37        # Grey for sand mode
    BOX_WHITE = 38       # White for snow mode bottom
    # Weather-blended text colors
    TEXT_RAIN = 39       # Blue-tinted text for rain mode
    TEXT_SNOW = 40       # White text for snow mode
    TEXT_SAND = 41       # Yellow/tan text for sand mode
    # Christmas light colors (secret event Dec 20-31)
    XMAS_RED = 42        # Red Christmas light
    XMAS_GREEN = 43      # Green Christmas light
    CAFE_GREEN = 47      # Green for Shell Cafe turtle shell
    XMAS_BLUE = 44       # Blue Christmas light
    XMAS_YELLOW = 45     # Yellow Christmas light
    # Halloween colors (secret event Oct 24-31)
    HALLOWEEN_ORANGE = 46  # Orange pumpkin glow
    HALLOWEEN_PURPLE = 53  # Spooky purple (was 47, conflicted with CAFE_GREEN)
    # Firework colors (4th of July Jul 1-7)
    FIREWORK_WHITE = 48   # White burst
    FIREWORK_MAGENTA = 49 # Magenta burst
    # Easter colors
    EASTER_PINK = 50      # Pink easter egg
    EASTER_CYAN = 51      # Cyan easter egg
    EASTER_LAVENDER = 52  # Lavender easter egg
    # 3D Tunnel backdrop colors
    TUNNEL_FAR = 54       # Furthest depth - very dim
    TUNNEL_MID = 55       # Mid depth
    TUNNEL_NEAR = 56      # Near depth - brighter
    TUNNEL_BRIGHT = 57    # Brightest tunnel highlights

    @staticmethod
    def init_colors(matrix_mode: bool = False):
        """Initialize curses color pairs."""
        if not CURSES_AVAILABLE or curses is None:
            return
        curses.start_color()
        curses.use_default_colors()
        if matrix_mode:
            Colors._init_matrix_colors()
        else:
            curses.init_pair(Colors.STATUS_OK, curses.COLOR_GREEN, -1)
            curses.init_pair(Colors.STATUS_WARN, curses.COLOR_YELLOW, -1)
            curses.init_pair(Colors.STATUS_ERROR, curses.COLOR_RED, -1)
            curses.init_pair(Colors.HEADER, curses.COLOR_CYAN, -1)
            curses.init_pair(Colors.SELECTED, curses.COLOR_BLACK, curses.COLOR_WHITE)
            curses.init_pair(Colors.MUTED, curses.COLOR_WHITE, -1)
            curses.init_pair(Colors.ACCENT, curses.COLOR_MAGENTA, -1)

    @staticmethod
    def _init_matrix_colors():
        """Initialize Matrix-style green-on-black color scheme."""
        if not CURSES_AVAILABLE or curses is None:
            return
        # All green, all the time
        curses.init_pair(Colors.STATUS_OK, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.STATUS_WARN, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.STATUS_ERROR, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.HEADER, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.SELECTED, curses.COLOR_BLACK, curses.COLOR_GREEN)
        curses.init_pair(Colors.MUTED, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.ACCENT, curses.COLOR_GREEN, curses.COLOR_BLACK)
        # Matrix rain colors - bright to dim gradient
        curses.init_pair(Colors.MATRIX_BRIGHT, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.MATRIX_DIM, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.MATRIX_FADE1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.MATRIX_FADE2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.MATRIX_FADE3, curses.COLOR_BLACK, curses.COLOR_BLACK)
        # Dark green for rain tails - try to use custom dark green if terminal supports it
        try:
            if curses.can_change_color() and curses.COLORS >= 256:
                # Define a custom dark green color (RGB values scaled 0-1000)
                curses.init_color(100, 0, 300, 0)  # Dark green
                curses.init_pair(Colors.MATRIX_DARK, 100, curses.COLOR_BLACK)
            else:
                # Fallback: use normal green, will apply A_DIM when rendering
                curses.init_pair(Colors.MATRIX_DARK, curses.COLOR_GREEN, curses.COLOR_BLACK)
        except Exception:
            curses.init_pair(Colors.MATRIX_DARK, curses.COLOR_GREEN, curses.COLOR_BLACK)
        # Lightning flash - inverted bright white on green
        curses.init_pair(Colors.LIGHTNING, curses.COLOR_BLACK, curses.COLOR_WHITE)
        # Alley scene colors - muted blue and grey
        curses.init_pair(Colors.ALLEY_DARK, curses.COLOR_BLACK, curses.COLOR_BLACK)
        curses.init_pair(Colors.ALLEY_MID, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.ALLEY_LIGHT, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.ALLEY_BLUE, curses.COLOR_CYAN, curses.COLOR_BLACK)
        # Creature colors
        curses.init_pair(Colors.RAT_YELLOW, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(Colors.SHADOW_RED, curses.COLOR_RED, curses.COLOR_BLACK)
        # Weather mode colors
        # Rain (blue)
        curses.init_pair(Colors.RAIN_BRIGHT, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.RAIN_DIM, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(Colors.RAIN_FADE1, curses.COLOR_BLUE, curses.COLOR_BLACK)
        curses.init_pair(Colors.RAIN_FADE2, curses.COLOR_BLUE, curses.COLOR_BLACK)
        # Snow (white/gray)
        curses.init_pair(Colors.SNOW_BRIGHT, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.SNOW_DIM, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.SNOW_FADE, curses.COLOR_WHITE, curses.COLOR_BLACK)
        # Sand (yellow/brown - using yellow as closest to brown)
        curses.init_pair(Colors.SAND_BRIGHT, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(Colors.SAND_DIM, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(Colors.SAND_FADE, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        # Building colors
        curses.init_pair(Colors.BRICK_RED, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(Colors.GREY_BLOCK, curses.COLOR_WHITE, curses.COLOR_BLACK)
        # Door knob - gold/yellow
        curses.init_pair(Colors.DOOR_KNOB_GOLD, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        # Cafe warm interior color
        curses.init_pair(Colors.CAFE_WARM, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        # Weather-based box border colors
        curses.init_pair(Colors.BOX_BROWN, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(Colors.BOX_DARK_BROWN, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(Colors.BOX_GREY, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.BOX_WHITE, curses.COLOR_WHITE, curses.COLOR_BLACK)
        # Weather-blended text colors
        curses.init_pair(Colors.TEXT_RAIN, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(Colors.TEXT_SNOW, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.TEXT_SAND, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        # Christmas light colors
        curses.init_pair(Colors.XMAS_RED, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(Colors.XMAS_GREEN, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.CAFE_GREEN, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(Colors.XMAS_BLUE, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(Colors.XMAS_YELLOW, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        # Halloween colors
        curses.init_pair(Colors.HALLOWEEN_ORANGE, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(Colors.HALLOWEEN_PURPLE, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        # Firework colors
        curses.init_pair(Colors.FIREWORK_WHITE, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(Colors.FIREWORK_MAGENTA, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        # Easter colors
        curses.init_pair(Colors.EASTER_PINK, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        curses.init_pair(Colors.EASTER_CYAN, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(Colors.EASTER_LAVENDER, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        # 3D Tunnel backdrop colors - deep blues and cyans for cosmic depth
        curses.init_pair(Colors.TUNNEL_FAR, curses.COLOR_BLUE, curses.COLOR_BLACK)
        curses.init_pair(Colors.TUNNEL_MID, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(Colors.TUNNEL_NEAR, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(Colors.TUNNEL_BRIGHT, curses.COLOR_WHITE, curses.COLOR_BLACK)
