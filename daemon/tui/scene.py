"""
TUI Alley Scene - Main visual scene with buildings, street, and weather effects.

Extracted from dashboard.py for maintainability.
Contains AlleyScene class - the main animated backdrop scene.

This is the largest visual component (~7000 lines) containing:
- Building rendering (apartments, cafe, storefronts)
- Street and sidewalk rendering
- Traffic lights and street lights
- Dumpster, boxes, and other props
- Window animations and lighting effects
- Weather integration (snow accumulation, etc.)
- Holiday decorations (Christmas, Halloween, etc.)
"""

import math
import random
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

# Handle curses import for Windows compatibility
try:
    import curses
    CURSES_AVAILABLE = True
except ImportError:
    curses = None
    CURSES_AVAILABLE = False

from .colors import Colors
from .weather import WeatherMode

class AlleyScene:
    """
    Simple alley scene with dumpster, box, traffic light, buildings, cars, and pedestrians.
    """

    # Dumpster ASCII art (7 wide x 5 tall)
    DUMPSTER = [
        " _____ ",
        "|#####|",
        "|#####|",
        "|#####|",
        "|=====|",
    ]

    # Cardboard box ASCII art (5 wide x 4 tall) - solid blocks, no outline
    BOX = [
        "▓▓▓▓▓",
        "▓▓▓▓▓",
        "▓▒X▒▓",
        "▓▓▓▓▓",
    ]

    # Blue street mailbox (6 wide x 5 tall)
    MAILBOX = [
        " ____ ",
        "|====|",
        "|MAIL|",
        "|____|",
        "  ||  ",
    ]

    # Mailbox with slot open (when person is mailing letter)
    MAILBOX_OPEN = [
        " ____ ",
        "|=██=|",
        "|MAIL|",
        "|____|",
        "  ||  ",
    ]

    # Person mailing letter (facing right, arm extended)
    PERSON_MAILING = [
        "  O_",
        " /|─",
        " /\\",
    ]

    # Cafe storefront (well-lit, between buildings) - taller size
    # Turtle shell logo for Shell Cafe (hexagonal pattern with connected head area)
    BIG_SHELL_LOGO = [
        "                    ",
        "     ____________    ",
        "   / \\ __|__ /   \\   ",
        "  |   \\/   \\/ /   |  ",
        "  |   /\\___/\\ \\   |  ",
        "   \\ /  | |  \\ \\ /   ",
        "    \\___|_|___\\/     ",
    ]

    # Turtle head animation frames (peeks out from shell) - each frame is [head_row, neck]
    # Head with horizontal neck extending to the left, connecting to shell
    TURTLE_HEAD_FRAMES = [
        ["  .--.  ", " ( o o )", "==)-(   "],   # Normal eyes - neck extends left
        ["  .--.  ", " ( - - )", "==)-(   "],   # Blink
        ["  .--.  ", " ( o ~ )", "==)-(   "],   # Right wink
        ["  .--.  ", " ( ^ ^ )", "==)-(   "],   # Happy
    ]

    CAFE = [
        "       .-----.        ",
        "     .'       '.      ",
        "    / \\`-._.-'/ \\     ",
        "   |   \\ _ _ /   |    ",
        "   |    |_|_|    |    ",
        "    \\   / | \\   /     ",
        "     '-/_____\\-'      ",
        "   ___________________________   ",
        "  |     S H E L L  C A F E   |  ",
        "  |                          |  ",
        "  |  [====]    O     [====]  |  ",
        "  |  [    ]   /|\\    [    ]  |  ",
        "  |  [    ]  [===]   [    ]  |  ",
        "  |  [====]          [====]  |  ",
        "  |                          |  ",
        "  |  [====]          [====]  |  ",
        "  |  [    ]          [    ]  |  ",
        "  |  [    ]          [    ]  |  ",
        "  |  [====]          [====]  |  ",
        "  |                          |  ",
        "  |[=======================]|  ",
        "  |[                  OPEN ]|  ",
        "  |[__________________     ]|  ",
        "  |__________[  ]__________|  ",
    ]

    # Traffic light showing two sides (corner view) - compact head, tall pole
    # Left column is N/S direction (flat), right column is E/W direction (brackets)
    # All 6 lights shown as circles, off lights are gray
    TRAFFIC_LIGHT_TEMPLATE = [
        " .===. ",
        " (L(R) ",  # Red lights - right side has brackets
        " (L(R) ",  # Yellow lights
        " (L(R) ",  # Green lights
        " '===' ",
        "   ||  ",
        "   ||  ",
        "   ||  ",
        "   ||  ",
        "   ||  ",
        "   ||  ",
        "   ||  ",
    ]

    # Car sprites - classic ASCII art style (4 rows tall) with filled body panels
    # Body panels use █ (solid block) to be colored, structure uses regular chars
    # Design inspired by classic ASCII art archives
    CAR_RIGHT = [
        "      _____           ",
        "   __/  |  \\__        ",
        "  /  \\__|__/  \\       ",
        " |___(_)--(_)__|      ",
    ]
    CAR_LEFT = [
        "       _____          ",
        "      __/  |  \\__     ",
        "     /  \\__|__/  \\    ",
        "    |___(_)--(_)__|   ",
    ]

    # Taxi car sprites (yellow with TAXI sign on roof)
    TAXI_RIGHT = [
        "      _TAXI_          ",
        "   __/  |  \\__        ",
        "  /  \\__|__/  \\       ",
        " |___(_)--(_)__|      ",
    ]
    TAXI_LEFT = [
        "       _TAXI_         ",
        "      __/  |  \\__     ",
        "     /  \\__|__/  \\    ",
        "    |___(_)--(_)__|   ",
    ]

    # 4 car body colors
    CAR_BODY_COLORS = [
        Colors.SHADOW_RED,      # Red car
        Colors.ALLEY_BLUE,      # Blue car
        Colors.MATRIX_DIM,      # Green car
        Colors.GREY_BLOCK,      # Grey car
    ]

    # Truck sprites - delivery truck/van style (4 rows)
    TRUCK_RIGHT = [
        "     ___________      ",
        "    /           \\__   ",
        "   |  ████████  |--|  ",
        "   |__(_)----(_)__|   ",
    ]
    TRUCK_LEFT = [
        "      ___________     ",
        "   __/           \\    ",
        "  |--|  ████████  |   ",
        "   |__(_)----(_)__|   ",
    ]

    # Work truck with company logo area (template - text gets filled in)
    WORK_TRUCK_RIGHT = [
        "     ___________      ",
        "    /{logo:^11}\\__   ",
        "   | {line2:^10} |--|  ",
        "   |__(_)----(_)__|   ",
    ]
    WORK_TRUCK_LEFT = [
        "      ___________     ",
        "   __/{logo:^11}\\    ",
        "  |--| {line2:^10} |   ",
        "   |__(_)----(_)__|   ",
    ]

    # 4 truck body colors
    TRUCK_BODY_COLORS = [
        Colors.SHADOW_RED,      # Red truck
        Colors.ALLEY_BLUE,      # Blue truck
        Colors.RAT_YELLOW,      # Yellow truck
        Colors.MATRIX_DIM,      # Green truck
    ]

    # Noire York City department trucks (white with city logo)
    CITY_TRUCK_DEPARTMENTS = [
        ("NOIRE YORK", "WATER DEPT"),
        ("NOIRE YORK", "SANITATION"),
        ("NOIRE YORK", "PARKS DEPT"),
        ("NOIRE YORK", "ELECTRIC"),
        ("NOIRE YORK", "GAS & UTIL"),
        ("NOIRE YORK", "TRANSIT"),
        ("NOIRE YORK", "FIRE DEPT"),
        ("NOIRE YORK", "POLICE"),
    ]

    # Prop plane sprites (small single-engine plane)
    PROP_PLANE_RIGHT = [
        "     __",
        " ---(_)=====>",
        "     ~~",
    ]
    PROP_PLANE_LEFT = [
        "        __     ",
        " <=====(_)--- ",
        "        ~~     ",
    ]

    # Banner attachment characters
    BANNER_ATTACH = "~~o"
    BANNER_END = "o~~"

    # Semi-truck base sprites - big 18-wheeler (5 rows tall, much wider)
    # Text area is 27 chars wide (rows 1-2 inside the trailer)
    SEMI_RIGHT_BASE = [
        "                  _____________________________ ",
        "        _______  /  {line1:^27}  \\ ",
        "   ____/   |   ||   {line2:^27}   |",
        "  |__|__|__|__| |_____________________________|",
        "    (O)---(O)   -------(O)------------(O)--    ",
    ]
    SEMI_LEFT_BASE = [
        " _____________________________                  ",
        "/  {line1:^27}  \\  _______        ",
        "|   {line2:^27}   ||   |   \\____   ",
        "|_____________________________| |__|__|__|__|  ",
        "    --(O)------------(O)-------   (O)---(O)    ",
    ]

    # 50 unique trucking/advertising companies
    SEMI_COMPANIES = [
        # Logistics & Freight (10)
        "NEXUS FREIGHT", "TITAN LOGISTICS", "SWIFT HAUL", "IRONCLAD TRANSPORT",
        "VELOCITY CARGO", "APEX TRUCKING", "SUMMIT LOGISTICS", "TRAILBLAZER FREIGHT",
        "HORIZON CARRIERS", "REDLINE EXPRESS",
        # Tech & Computing (10)
        "CYBERLINK SYSTEMS", "QUANTUM DYNAMICS", "NEON CIRCUIT", "DATASTREAM INC",
        "PIXEL FORGE", "NEURAL NET CO", "BITWAVE TECH", "CLOUDPEAK SYSTEMS",
        "HEXCORE INDUSTRIES", "SYNTHWAVE LABS",
        # Food & Beverage (10)
        "MOUNTAIN BREW CO", "SUNRISE FARMS", "GOLDEN HARVEST", "ARCTIC FREEZE",
        "CRIMSON GRILL", "BLUE OCEAN FISH", "PRIME MEATS", "ORCHARD FRESH",
        "SUGAR RUSH CANDY", "MOONLIGHT DAIRY",
        # Industrial & Manufacturing (10)
        "STEEL DYNAMICS", "FORGE MASTERS", "CONCRETE KINGS", "LUMBER GIANT",
        "COPPER CREEK", "BOLT & IRON", "HEAVY METAL IND", "GRANITE WORKS",
        "ALLOY SOLUTIONS", "TURBINE POWER",
        # Retail & Consumer (10)
        "MEGA MART", "VALUE ZONE", "QUICK STOP", "BARGAIN BARN",
        "PRIME DELIVERY", "HOME ESSENTIALS", "EVERYDAY GOODS", "DISCOUNT DEPOT",
        "FAMILY FIRST", "SUPER SAVER",
    ]

    # 5 text layout styles for trailer (each returns line1, line2)
    SEMI_LAYOUTS = [
        # Style 0: Company name centered, tagline below
        lambda c: (c, "~ NATIONWIDE ~"),
        # Style 1: Company name with decorative borders
        lambda c: (f"★ {c} ★", "═══════════════════════════"),
        # Style 2: Company name with phone number style
        lambda c: (c, "1-800-DELIVER"),
        # Style 3: Company name with website
        lambda c: (c, "www.{}.com".format(c.lower().replace(' ', '')[:15])),
        # Style 4: Company name split if long, simple
        lambda c: (c[:14] if len(c) > 14 else c, c[14:] if len(c) > 14 else "TRUSTED SINCE 1987"),
    ]

    # 4 semi-truck trailer colors
    SEMI_COLORS = [
        Colors.ALLEY_LIGHT,     # White trailer
        Colors.SHADOW_RED,      # Red trailer
        Colors.ALLEY_BLUE,      # Blue trailer
        Colors.RAT_YELLOW,      # Yellow trailer
    ]

    # Warning/alert messages that scroll on truck when daemon events occur
    SEMI_WARNING_PREFIXES = [
        "⚠ ALERT: ", "⚡ WARNING: ", "🔔 NOTICE: ", "⛔ CRITICAL: ", "📢 BROADCAST: "
    ]

    # Car body colors for variety
    CAR_COLORS = [
        Colors.SHADOW_RED,      # Red
        Colors.ALLEY_BLUE,      # Blue
        Colors.RAT_YELLOW,      # Yellow
        Colors.MATRIX_DIM,      # Green
        Colors.ALLEY_LIGHT,     # White
    ]

    # Manhole cover (on street)
    MANHOLE = [
        "(====)",
    ]

    # Street drain (curb side)
    DRAIN = [
        "[|||]",
    ]

    # Steam animation frames
    STEAM_FRAMES = [
        ["  ~  ", " ~~~ ", "~~~~~"],
        [" ~~  ", "~~~~ ", " ~~~~"],
        ["~~   ", " ~~~ ", "~~~~ "],
    ]

    # Tree sprites for windy city effect (trunk centered under foliage)
    TREE = [
        "   (@@)   ",
        "  (@@@@@) ",
        " (@@@@@@@)",
        "  (@@@@@) ",
        "    ||    ",
        "    ||    ",
        "   _||_   ",
    ]

    # Tree blowing right (wind from left) - trunk stays centered
    TREE_WINDY_RIGHT = [
        "    (@@)  ",
        "   (@@@@@)",
        "  (@@@@@@@)",
        "   (@@@@) ",
        "    ||    ",
        "    ||    ",
        "   _||_   ",
    ]

    # Tree blowing left (wind from right) - trunk stays centered
    TREE_WINDY_LEFT = [
        "  (@@)    ",
        " (@@@@@)  ",
        "(@@@@@@@) ",
        " (@@@@)   ",
        "    ||    ",
        "    ||    ",
        "   _||_   ",
    ]

    # Pine tree sprite (taller, triangular)
    PINE_TREE = [
        "    *     ",
        "   /|\\   ",
        "  /|||\\  ",
        " /|||||\\",
        "  /|||\\  ",
        " /|||||\\",
        "/|||||||\\",
        "   |||    ",
        "   |||    ",
        "  _|||_   ",
    ]

    # Pine tree blowing right
    PINE_TREE_WINDY_RIGHT = [
        "     *    ",
        "    /|\\  ",
        "   /|||\\  ",
        "  /|||||\\",
        "   /|||\\  ",
        "  /|||||\\",
        " /|||||||\\",
        "    |||   ",
        "    |||   ",
        "   _|||_  ",
    ]

    # Pine tree blowing left
    PINE_TREE_WINDY_LEFT = [
        "    *     ",
        "   /|\\   ",
        "  /|||\\  ",
        " /|||||\\",
        "  /|||\\  ",
        " /|||||\\",
        "/|||||||\\",
        "   |||    ",
        "   |||    ",
        "  _|||_   ",
    ]

    # Debris sprites for windy weather
    DEBRIS_NEWSPAPER = ['▪', '▫', '□', '▢']
    DEBRIS_TRASH = ['~', '°', '·', '∘']
    DEBRIS_LEAVES = ['*', '✦', '✧', '⁕']

    # Wind wisp characters
    WIND_WISPS = ['~', '≈', '≋', '～', '-', '=']

    # ==========================================
    # HOLIDAY EVENT SPRITES
    # ==========================================

    # Pumpkin sprite (Halloween Oct 24-31)
    PUMPKIN = [
        " ,---, ",
        "(o ^ o)",
        " \\___/ ",
    ]

    # Spooky bare tree (Halloween - replaces regular trees)
    SPOOKY_TREE = [
        "    \\|/    ",
        "   --+--   ",
        "  / | \\  ",
        " /  |  \\ ",
        "    |     ",
        "   _|_    ",
    ]

    # Easter egg patterns (simple colored eggs)
    EASTER_EGG = [
        " /\\ ",
        "(  )",
        " \\/ ",
    ]

    # Firework burst patterns
    FIREWORK_BURST = [
        "  \\ | /  ",
        " -- * -- ",
        "  / | \\  ",
    ]

    FIREWORK_STAR = [
        "   *   ",
        " * + * ",
        "   *   ",
    ]

    FIREWORK_SHOWER = [
        " ' ' ' ",
        "  ' '  ",
        " ' ' ' ",
    ]

    # ==========================================
    # SMALL PARK ELEMENTS
    # ==========================================

    # Park bench (side view)
    PARK_BENCH = [
        " _______ ",
        "|_______|",
        " |     | ",
    ]

    # Small park lamp
    PARK_LAMP = [
        " (O) ",
        "  |  ",
        "  |  ",
        " _|_ ",
    ]

    # Small bush/shrub
    SMALL_BUSH = [
        " @@@ ",
        "@@@@@",
        " @@@ ",
    ]

    # Flower bed
    FLOWER_BED = [
        "*.*.*",
        "ooooo",
    ]

    # ==========================================
    # SEASONAL CONSTELLATIONS - Security Canary
    # Stars tied to memory monitor health
    # ==========================================

    # Spring constellation: Leo (the lion) - Mar-May
    # Recognizable by the "sickle" (backwards question mark) and triangle
    # Stars scaled 5x for visibility
    CONSTELLATION_LEO = {
        'name': 'Leo',
        'stars': [
            # Sickle (head) - backwards question mark shape
            (0, 0, 2),     # Regulus (brightest, alpha)
            (10, -10, 1),  # Eta Leonis
            (20, -15, 1),  # Gamma (Algieba)
            (30, -10, 2),  # Zeta
            (35, 0, 1),    # Mu
            (25, 5, 1),    # Epsilon
            # Body/hindquarters triangle
            (50, 0, 2),    # Denebola (beta, tail)
            (40, -5, 1),   # Delta
            (30, 5, 1),    # Theta
        ],
    }

    # Summer constellation: Scorpius (the scorpion) - Jun-Aug
    # Recognizable by the curved tail and red Antares
    # Stars scaled 5x for visibility
    CONSTELLATION_SCORPIUS = {
        'name': 'Scorpius',
        'stars': [
            # Head/claws
            (0, 0, 1),     # Graffias (beta)
            (10, -5, 1),   # Dschubba (delta)
            (20, 0, 1),    # Pi Scorpii
            # Body with Antares (heart)
            (25, 10, 2),   # Antares (alpha, red supergiant)
            (30, 15, 1),   # Tau
            # Curved tail
            (35, 25, 1),   # Epsilon
            (40, 30, 2),   # Mu
            (50, 35, 1),   # Zeta
            (60, 30, 1),   # Eta
            (70, 25, 2),   # Shaula (lambda, stinger)
            (75, 20, 1),   # Lesath (upsilon)
        ],
    }

    # Fall constellation: Pegasus (the winged horse) - Sep-Nov
    # Recognizable by the Great Square
    # Stars scaled 5x for visibility
    CONSTELLATION_PEGASUS = {
        'name': 'Pegasus',
        'stars': [
            # The Great Square
            (0, 0, 2),     # Markab (alpha)
            (40, 0, 2),    # Scheat (beta)
            (40, -30, 2),  # Algenib (gamma)
            (0, -30, 2),   # Alpheratz (actually Andromeda alpha)
            # Neck and head
            (-15, 10, 1),  # Homam (zeta)
            (-30, 15, 1),  # Biham (theta)
            (-45, 10, 2),  # Enif (epsilon, nose)
        ],
    }

    # Winter constellation: Orion (the hunter) - Dec-Feb
    # Most recognizable - belt of 3 stars, Betelgeuse and Rigel
    # Stars scaled 5x for visibility
    CONSTELLATION_ORION = {
        'name': 'Orion',
        'stars': [
            # Shoulders
            (0, 0, 2),    # Betelgeuse (alpha, red)
            (40, 0, 1),   # Bellatrix (gamma)
            # Belt (3 stars in a row)
            (10, 15, 2),  # Alnitak (zeta)
            (20, 15, 2),  # Alnilam (epsilon)
            (30, 15, 2),  # Mintaka (delta)
            # Feet
            (0, 30, 2),   # Saiph (kappa)
            (40, 30, 2),  # Rigel (beta, blue-white)
            # Sword (below belt)
            (20, 25, 1),  # Orion Nebula area
        ],
    }

    # ==========================================
    # METEOR QTE EVENT - Quick Time Event
    # ==========================================

    # Meteor sprites (falling chunks)
    METEOR_LARGE = [
        " @@@ ",
        "@@@@@",
        "@@@@@",
        " @@@ ",
    ]

    METEOR_MEDIUM = [
        " @@ ",
        "@@@@",
        " @@ ",
    ]

    METEOR_SMALL = [
        " @ ",
        "@@@",
    ]

    # Missile sprite (rising from bottom)
    MISSILE = [
        " ^ ",
        "/|\\",
        " | ",
    ]

    # Explosion animation frames
    EXPLOSION_FRAMES = [
        [" * "],
        ["***", " * "],
        ["*.*", "***", "*.*"],
        [" . ", ".*.", " . "],
        ["   "],
    ]

    # NPC caller (person waving for help)
    NPC_CALLER = [
        " O/ ",
        "/|  ",
        "/ \\ ",
    ]

    # QTE key mappings: key -> (column_index, row_index)
    # Columns spread across screen, rows are vertical layers
    # Keys: 6, 7, 8, 9, 0 for columns
    # Rows: top (0), middle (1), bottom (2)
    QTE_KEYS = ['6', '7', '8', '9', '0']

    # Person walking animation frames (arm swinging) - basic person
    # Pedestrian sprites with leg animation (4 frames for walking cycle)
    PERSON_RIGHT_FRAMES = [
        [" O ", "/| ", " | ", "/| "],   # Right arm back, right leg forward
        [" O ", " |\\", " | ", "|| "],   # Left arm back, legs together
        [" O ", "/| ", " | ", "|\\ "],   # Right arm back, left leg back
        [" O ", " |\\", " | ", "|| "],   # Left arm back, legs together
    ]
    PERSON_LEFT_FRAMES = [
        [" O ", " |\\", " | ", " |\\"],  # Left arm back, left leg forward
        [" O ", "/| ", " | ", " ||"],   # Right arm back, legs together
        [" O ", " |\\", " | ", " /|"],  # Left arm back, right leg back
        [" O ", "/| ", " | ", " ||"],   # Right arm back, legs together
    ]

    # Person with hat (~, on head) - with leg animation
    PERSON_HAT_RIGHT_FRAMES = [
        [" ~ ", " O ", "/| ", "/| "],   # Hat, right leg forward
        [" , ", " O ", " |\\", "|| "],   # Hat, legs together
        [" ~ ", " O ", "/| ", "|\\ "],   # Hat, left leg back
        [" , ", " O ", " |\\", "|| "],   # Hat, legs together
    ]
    PERSON_HAT_LEFT_FRAMES = [
        [" ~ ", " O ", " |\\", " |\\"],  # Hat, left leg forward
        [" , ", " O ", "/| ", " ||"],   # Hat, legs together
        [" ~ ", " O ", " |\\", " /|"],  # Hat, right leg back
        [" , ", " O ", "/| ", " ||"],   # Hat, legs together
    ]

    # Person with briefcase (# carried) - with leg animation
    PERSON_BRIEFCASE_RIGHT_FRAMES = [
        [" O ", "/|#", " | ", "/| "],   # Briefcase, right leg forward
        [" O ", " |#", " | ", "|| "],   # Briefcase, legs together
        [" O ", "/|#", " | ", "|\\ "],   # Briefcase, left leg back
        [" O ", " |#", " | ", "|| "],   # Briefcase, legs together
    ]
    PERSON_BRIEFCASE_LEFT_FRAMES = [
        [" O ", "#|\\", " | ", " |\\"],  # Briefcase, left leg forward
        [" O ", "#| ", " | ", " ||"],   # Briefcase, legs together
        [" O ", "#|\\", " | ", " /|"],  # Briefcase, right leg back
        [" O ", "#| ", " | ", " ||"],   # Briefcase, legs together
    ]

    # Person with skirt (A-line shape) - with leg animation
    PERSON_SKIRT_RIGHT_FRAMES = [
        [" O ", "/| ", "/A\\", "> |"],   # Skirt, right knee forward
        [" O ", " |\\", "/A\\", "| |"],   # Skirt, legs together
        [" O ", "/| ", "/A\\", "| >"],   # Skirt, left knee forward (still facing right)
        [" O ", " |\\", "/A\\", "| |"],   # Skirt, legs together
    ]
    PERSON_SKIRT_LEFT_FRAMES = [
        [" O ", " |\\", "/A\\", "| <"],  # Skirt, left knee forward
        [" O ", "/| ", "/A\\", "| |"],  # Skirt, legs together
        [" O ", " |\\", "/A\\", "< |"],  # Skirt, right knee forward (still facing left)
        [" O ", "/| ", "/A\\", "| |"],  # Skirt, legs together
    ]

    # All person types for random selection
    PERSON_TYPES_RIGHT = [
        PERSON_RIGHT_FRAMES,
        PERSON_HAT_RIGHT_FRAMES,
        PERSON_BRIEFCASE_RIGHT_FRAMES,
        PERSON_SKIRT_RIGHT_FRAMES,
    ]
    PERSON_TYPES_LEFT = [
        PERSON_LEFT_FRAMES,
        PERSON_HAT_LEFT_FRAMES,
        PERSON_BRIEFCASE_LEFT_FRAMES,
        PERSON_SKIRT_LEFT_FRAMES,
    ]

    # Skin tone colors for diversity
    SKIN_TONES = [
        Colors.ALLEY_LIGHT,     # Light skin
        Colors.RAT_YELLOW,      # Tan/olive
        Colors.BOX_BROWN,       # Brown
        Colors.ALLEY_MID,       # Medium brown
        Colors.GREY_BLOCK,      # Dark
    ]

    # Clothing colors for variety
    CLOTHING_COLORS = [
        Colors.SHADOW_RED,      # Red
        Colors.ALLEY_BLUE,      # Blue
        Colors.MATRIX_DIM,      # Green
        Colors.RAT_YELLOW,      # Yellow
        Colors.GREY_BLOCK,      # Grey
        Colors.ALLEY_MID,       # Brown
        Colors.STATUS_OK,       # Bright green
        Colors.ALLEY_LIGHT,     # White
    ]

    # Knocked out person sprite (lying on ground)
    KNOCKED_OUT_SPRITE = ["___o___"]

    # Ambulance sprite (4 rows, wider)
    AMBULANCE_RIGHT = [
        "  ___+___________  ",
        " |  ░░░ AMBULANCE| ",
        " |_░░░___________|_",
        " (O)-----------(O) ",
    ]
    AMBULANCE_LEFT = [
        "  ___________+___  ",
        " |AMBULANCE ░░░  | ",
        "_|___________░░░_| ",
        " (O)-----------(O) ",
    ]

    # Paramedic sprite (small, kneeling)
    PARAMEDIC_SPRITE = [" o ", "/|>", " A "]

    # ==========================================
    # WOMAN IN RED EVENT - Matrix iconic scene
    # ==========================================

    # Woman in red - blonde hair, red dress (walking right)
    WOMAN_RED_RIGHT_FRAMES = [
        ["~o~", "/|\\", "/A\\", "> |"],   # Walking frame 1
        ["~o~", "\\|/", "/A\\", "| |"],   # Walking frame 2
        ["~o~", "/|\\", "/A\\", "| <"],   # Walking frame 3
        ["~o~", "\\|/", "/A\\", "| |"],   # Walking frame 4
    ]

    # Woman in red - walking left
    WOMAN_RED_LEFT_FRAMES = [
        ["~o~", "\\|/", "/A\\", "| <"],   # Walking frame 1
        ["~o~", "/|\\", "/A\\", "| |"],   # Walking frame 2
        ["~o~", "\\|/", "/A\\", "> |"],   # Walking frame 3
        ["~o~", "/|\\", "/A\\", "| |"],   # Walking frame 4
    ]

    # Woman in red - waving (stationary, arm raised)
    WOMAN_RED_WAVE_FRAMES = [
        ["~o~", "\\|/", "/A\\", "| |"],   # Wave down
        ["~o~", "\\|_", "/A\\", "| |"],   # Wave mid
        ["~o~", "\\|^", "/A\\", "| |"],   # Wave up
        ["~o~", "\\|_", "/A\\", "| |"],   # Wave mid
    ]

    # Agent Smith - suit and sunglasses (walking/running right)
    AGENT_SMITH_RIGHT_FRAMES = [
        ["[=]", "/|\\", "[H]", "/ \\"],   # Running frame 1
        ["[=]", "\\|/", "[H]", " | "],    # Running frame 2
        ["[=]", "/|\\", "[H]", "\\ /"],   # Running frame 3
        ["[=]", "\\|/", "[H]", " | "],    # Running frame 4
    ]

    # Agent Smith - suit and sunglasses (walking/running left)
    AGENT_SMITH_LEFT_FRAMES = [
        ["[=]", "\\|/", "[H]", "/ \\"],   # Running frame 1
        ["[=]", "/|\\", "[H]", " | "],    # Running frame 2
        ["[=]", "\\|/", "[H]", "\\ /"],   # Running frame 3
        ["[=]", "/|\\", "[H]", " | "],    # Running frame 4
    ]

    # Neo - long coat, sunglasses (walking right)
    NEO_RIGHT_FRAMES = [
        ["(O)", "/|\\", "###", "/ \\"],   # Walking frame 1
        ["(O)", "\\|/", "###", " | "],    # Walking frame 2
        ["(O)", "/|\\", "###", "\\ /"],   # Walking frame 3
        ["(O)", "\\|/", "###", " | "],    # Walking frame 4
    ]

    # Neo - long coat, sunglasses (walking left / running away)
    NEO_LEFT_FRAMES = [
        ["(O)", "\\|/", "###", "/ \\"],   # Running frame 1
        ["(O)", "/|\\", "###", " | "],    # Running frame 2
        ["(O)", "\\|/", "###", "\\ /"],   # Running frame 3
        ["(O)", "/|\\", "###", " | "],    # Running frame 4
    ]

    # Morpheus - bald, long coat (walking right)
    MORPHEUS_RIGHT_FRAMES = [
        ["(0)", "/|\\", "%%%", "/ \\"],   # Walking frame 1
        ["(0)", "\\|/", "%%%", " | "],    # Walking frame 2
        ["(0)", "/|\\", "%%%", "\\ /"],   # Walking frame 3
        ["(0)", "\\|/", "%%%", " | "],    # Walking frame 4
    ]

    # Morpheus - bald, long coat (walking left / running away)
    MORPHEUS_LEFT_FRAMES = [
        ["(0)", "\\|/", "%%%", "/ \\"],   # Running frame 1
        ["(0)", "/|\\", "%%%", " | "],    # Running frame 2
        ["(0)", "\\|/", "%%%", "\\ /"],   # Running frame 3
        ["(0)", "/|\\", "%%%", " | "],    # Running frame 4
    ]

    # Transform effect frames (woman to agent glitch)
    TRANSFORM_FRAMES = [
        ["~o~", "/|\\", "/A\\", "| |"],   # Woman
        ["###", "###", "###", "###"],     # Glitch 1
        ["[=]", "???", "[H]", "???"],     # Partial transform
        ["###", "###", "###", "###"],     # Glitch 2
        ["[=]", "\\|/", "[H]", " | "],    # Agent Smith
    ]

    # UFO for abduction event
    UFO_SPRITE = [
        "    ___    ",
        " __/   \\__ ",
        "/  o   o  \\",
        "\\____*____/",
    ]

    # Tractor beam (extends below UFO)
    TRACTOR_BEAM = [
        "    |||    ",
        "   |||||   ",
        "  |||||||  ",
        " ||||||||| ",
    ]

    # Cow being abducted
    COW_SPRITE = [
        " ^__^",
        " (oo)",
        "/----\\",
        "||  ||",
    ]

    # Street light - taller pole
    STREET_LIGHT = [
        " ___ ",
        "[___]",
        "  |  ",
        "  |  ",
        "  |  ",
        "  |  ",
        "  |  ",
        "  |  ",
    ]

    # Street sign - Claude Av
    STREET_SIGN = [
        ".----------.",
        "| Claude Av|",
        "'----------'",
        "     ||     ",
        "     ||     ",
        "     ||     ",
    ]

    # Static cityscape backdrop (drawn behind main buildings in the gap)
    # 140 chars wide, dense city skyline with various building heights and solid walls
    CITYSCAPE = [
        "         T                    |~|                 T              T                    |~|              T           ",  # Row 0
        "   ___  /|\\        ___       |█|    ___         /|\\   ___      /|\\        ___       |█|    ___      /|\\   ___    ",  # Row 1
        "  |███| |█|  ___  |███|  ___ |█|   |███|  ___  |█|█| |███| ___ |█|  ___  |███|  ___ |█|   |███| ___ |█|█| |███|   ",  # Row 2
        "  |[ ]| |█| |███| |[ ]| |███||█|   |[ ]| |███| |█|█| |[ ]||███||█| |███| |[ ]| |███||█|   |[ ]||███||█|█| |[ ]|   ",  # Row 3
        "  |[ ]| |█| |[ ]| |[ ]| |[ ]||█|   |[ ]| |[ ]| |█|█| |[ ]||[ ]||█| |[ ]| |[ ]| |[ ]||█|   |[ ]||[ ]||█|█| |[ ]|   ",  # Row 4
        "  |[ ]| |█| |[ ]| |[ ]| |[ ]||█|   |[ ]| |[ ]| |█|█| |[ ]||[ ]||█| |[ ]| |[ ]| |[ ]||█|   |[ ]||[ ]||█|█| |[ ]|   ",  # Row 5
        "  |[ ]| |█| |[ ]| |[ ]| |[ ]||█|   |[ ]| |[ ]| |█|█| |[ ]||[ ]||█| |[ ]| |[ ]| |[ ]||█|   |[ ]||[ ]||█|█| |[ ]|   ",  # Row 6
        "  |[ ]| |█| |[ ]| |[ ]| |[ ]||█|   |[ ]| |[ ]| |█|█| |[ ]||[ ]||█| |[ ]| |[ ]| |[ ]||█|   |[ ]||[ ]||█|█| |[ ]|   ",  # Row 7
        "  |███| |█| |███| |███| |███||█|   |███| |███| |█|█| |███||███||█| |███| |███| |███||█|   |███||███||█|█| |███|   ",  # Row 8
        "        |█|              |███||█|              |█|█|      |███||█|              |███||█|        |███||█|█|         ",  # Row 9
        "        |█|              |[ ]||█|              |█|█|      |[ ]||█|              |[ ]||█|        |[ ]||█|█|         ",  # Row 10
        "        |█|              |[ ]||█|              |█|█|      |[ ]||█|              |[ ]||█|        |[ ]||█|█|         ",  # Row 11
        "        |█|              |███||█|              |█|█|      |███||█|              |███||█|        |███||█|█|         ",  # Row 12
        "        |_|                  |_|              |_||_|          |_|                  |_|             |_||_|         ",  # Row 13
    ]

    # Building wireframe - 2X TALL, 2X WIDE with mixed window sizes, two doors with stoops
    BUILDING = [
        "                         _____                                  ",
        "       __O__            |     |                  __O__          ",
        "      / === \\          |     |  [===]          / === \\         ",
        "     (==//\\==)         |_____|  [===]         (==//\\==)        ",
        ".--------------------------------------------------------------.",
        "                                                                ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "                                                                ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "                                                                ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "                                                                ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "                                                                ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [        ]    [    ]  [    ]    [        ]    [    ]         ",
        "   [========]    [====]  [====]    [========]    [====]         ",
        "            .------.                    .------.                ",
        "            |      |                    |      |                ",
        "            |      |                    |      |                ",
        "            |      |                    |      |                ",
        "            | [==] |                    | [==] |                ",
        "____________|______|____________________|______|________________",
        "      ______.------.____          ______.------.____            ",
    ]

    # Second building (right side) - 2X TALL, 2X WIDE with two doors with stoops
    BUILDING2 = [
        "              _____                                      ",
        "             |     |     __O__               __O__         ",
        "      [===]  |     |    / === \\            / === \\        ",
        "      [===]  |_____|   (==//\\==)          (==//\\==)       ",
        ".----------------------------------------------------------.",
        "                                                            ",
        "     [========]    [====]    [========]    [====]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [========]    [====]    [========]    [====]           ",
        "                                                            ",
        "     [========]    [====]    [========]    [====]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [========]    [====]    [========]    [====]           ",
        "                                                            ",
        "     [========]    [====]    [========]    [====]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [========]    [====]    [========]    [====]           ",
        "                                                            ",
        "     [========]    [====]    [========]    [====]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [========]    [====]    [========]    [====]           ",
        "                                                            ",
        "     [========]    [====]    [========]    [====]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [        ]    [    ]    [        ]    [    ]           ",
        "     [========]    [====]    [========]    [====]           ",
        "            .------.                    .------.            ",
        "            |      |                    |      |            ",
        "            |      |                    |      |            ",
        "            |      |                    |      |            ",
        "            | [==] |                    | [==] |            ",
        "____________|______|____________________|______|____________",
        "      ______.------.____          ______.------.____        ",
    ]

    # Window positions for people animation (relative to building sprite)
    # Each entry is (row_offset, col_offset) for the middle of a window interior
    BUILDING_WINDOW_POSITIONS = [
        (8, 7), (8, 19), (8, 27), (8, 39),      # First row (inside window interiors)
        (14, 7), (14, 19), (14, 27), (14, 39),  # Second row
        (20, 7), (20, 19), (20, 27), (20, 39),  # Third row
        (26, 7), (26, 19), (26, 27), (26, 39),  # Fourth row
        (32, 7), (32, 19), (32, 27), (32, 39),  # Fifth row
    ]
    BUILDING2_WINDOW_POSITIONS = [
        (8, 9), (8, 21), (8, 33), (8, 45),      # First row (inside window interiors)
        (14, 9), (14, 21), (14, 33), (14, 45),  # Second row
        (20, 9), (20, 21), (20, 33), (20, 45),  # Third row
        (26, 9), (26, 21), (26, 33), (26, 45),  # Fourth row
        (32, 9), (32, 21), (32, 33), (32, 45),  # Fifth row
    ]

    # Door positions relative to building sprite (col_offset from building_x)
    # These are the two doors on each building
    BUILDING_DOOR_OFFSETS = [12, 40]   # Two doors on BUILDING
    BUILDING2_DOOR_OFFSETS = [12, 40]  # Two doors on BUILDING2

    # Person hailing taxi (arm raised)
    PERSON_HAILING_RIGHT = [
        " O/",
        "/| ",
        "/\\",
    ]
    PERSON_HAILING_LEFT = [
        "\\O ",
        " |\\",
        "/\\",
    ]

    # Open door overlay (replaces closed door section)
    DOOR_OPEN = [
        ".──────.",
        "|░░░░░░|",
        "|░░░░░░|",
        "|░░░░░░|",
        "|░[==]░|",
    ]

    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height
        self.scene: List[List[Tuple[str, int]]] = []
        # Store object positions for rat hiding
        self.dumpster_x = 0
        self.dumpster_y = 0
        self.box_x = 0
        self.box_y = 0
        # Store building positions for window people
        self._building_x = 0
        self._building_y = 0
        self._building2_x = 0
        self._building2_y = 0
        # Park position (between vanishing road and right building)
        self._park_x = 0
        self._park_y = 0
        self._park_width = 0
        # Store building bottom for rat constraints
        self._building_bottom_y = height - 3
        # Traffic light state
        self._traffic_frame = 0
        self._traffic_state = 'NS_GREEN'  # NS_GREEN, NS_YELLOW, EW_GREEN, EW_YELLOW
        self._state_duration = 0
        # Horizontal cars on the street
        self._cars: List[Dict] = []
        self._car_spawn_timer = 0
        # Audio state for car sounds
        self._audio_muted = False
        self._car_sound_cooldown = 0
        # Close-up car (perspective effect - shrinks as it passes)
        self._closeup_car: Dict = None
        self._closeup_car_timer = 0
        # Pedestrians on the street
        self._pedestrians: List[Dict] = []
        self._pedestrian_spawn_timer = 0
        # Knocked out pedestrians from lightning
        self._knocked_out_peds: List[Dict] = []  # {x, y, timer, skin_color, clothing_color}
        # Ambulance for revival
        self._ambulance: Dict = None  # {x, direction, state, target_ped, paramedic_x}
        self._ambulance_cooldown = 0
        # Lightning strike position for knockout detection
        self._last_lightning_x = -1
        # Interaction states for pedestrians
        self._mailbox_interaction: Dict = None  # {ped, state, timer} - person mailing letter
        self._open_doors: List[Dict] = []  # [{building, door_idx, timer}] - currently open doors
        self._door_positions: List[Dict] = []  # Calculated door x positions
        self._waiting_taxi_peds: List[Dict] = []  # Peds waiting for taxi {ped, timer}
        self._taxi_pickup: Dict = None  # {taxi, ped, state, timer} - taxi picking up person
        # Street light flicker effect
        self._street_light_positions: List[Tuple[int, int]] = []
        self._street_light_flicker = [1.0, 1.0]  # Brightness per light (0-1)
        self._flicker_timer = 0
        # Building window lights (same flicker pattern as street lights, no pole)
        self._building_window_lights: List[Tuple[int, int]] = []  # (x, y) positions
        self._building_window_flicker = []  # Brightness per window light (0-1)
        # All window data with scenes and light states
        # Each window: {x, y, width, height, building, scene_type, light_on, brightness, scene_chars}
        self._all_windows: List[Dict] = []
        self._window_light_timer = 0  # Timer for random light on/off
        # Window scene types - each creates unique interior content
        self._window_scene_types = [
            'empty', 'plant', 'lamp', 'tv', 'cat', 'bookshelf', 'desk',
            'curtains', 'blinds', 'person_standing', 'couple', 'kitchen'
        ]
        # Window people - list of active silhouettes {window_idx, building, direction, progress}
        # Pre-spawn some people so windows aren't empty at start
        self._window_people: List[Dict] = [
            {'building': 1, 'window_idx': 2, 'direction': 1, 'progress': 0.5, 'state': 'staring', 'state_timer': 0, 'stare_duration': 200, 'wave_count': 0, 'wave_frame': 0},
            {'building': 1, 'window_idx': 8, 'direction': -1, 'progress': 0.3, 'state': 'walking', 'state_timer': 0, 'stare_duration': 150, 'wave_count': 0, 'wave_frame': 0},
            {'building': 2, 'window_idx': 5, 'direction': 1, 'progress': 0.6, 'state': 'staring', 'state_timer': 0, 'stare_duration': 180, 'wave_count': 0, 'wave_frame': 0},
            {'building': 2, 'window_idx': 12, 'direction': -1, 'progress': 0.4, 'state': 'walking', 'state_timer': 0, 'stare_duration': 160, 'wave_count': 0, 'wave_frame': 0},
        ]
        self._window_spawn_timer = 0
        # Window positions for layering (filled during _draw_building)
        self._window_interior_positions: List[Tuple[int, int]] = []
        self._window_frame_positions: List[Tuple[int, int, str]] = []  # (x, y, char)
        self._sidewalk_positions: List[Tuple[int, int, str, int]] = []  # (x, y, char, color)
        # Cafe people in the lower window (Shell Cafe)
        self._cafe_people: List[Dict] = [
            {'x_offset': 0.0, 'direction': 1, 'arm_frame': 0, 'move_timer': 0, 'arm_timer': 0},
            {'x_offset': 6.0, 'direction': -1, 'arm_frame': 1, 'move_timer': 30, 'arm_timer': 15},
            {'x_offset': 12.0, 'direction': 1, 'arm_frame': 0, 'move_timer': 60, 'arm_timer': 45},
        ]
        self._cafe_people_timer = 0
        # Turtle head animation (peeks out of shell and winks)
        self._turtle_active = False
        self._turtle_frame = 0  # 0=normal, 1=left wink, 2=right wink, 3=happy
        self._turtle_timer = 0
        self._turtle_cooldown = random.randint(300, 600)  # 5-10 seconds at 60fps
        self._turtle_visible_duration = 0
        self._turtle_side = 1  # 1=right side, -1=left side
        self._turtle_state = 'hidden'  # hidden, peeking, winking, retreating
        # Semi-truck advertising system - seeded randomness for screenshot validation
        self._semi_seed_base = int(time.time())  # Base seed from startup time
        self._semi_spawn_counter = 0  # Increments each semi spawn for unique seeds
        self._semi_active_warnings: List[Dict] = []  # Active warning trucks {car_ref, message, scroll_pos}
        self._last_event_check = 0  # Timer for checking real daemon events
        self._known_event_ids: set = set()  # Track seen events to avoid duplicates
        # Prop plane with scrolling banner for announcements
        self._prop_plane: Dict = None  # {x, y, direction, speed, message, scroll_offset}
        self._prop_plane_queue: List[str] = []  # Queue of messages to display
        self._prop_plane_cooldown = 0  # Cooldown between planes
        # Manholes and drains with occasional steam
        self._manhole_positions: List[Tuple[int, int]] = []  # (x, y)
        self._drain_positions: List[Tuple[int, int]] = []  # (x, y)
        self._steam_effects: List[Dict] = []  # {x, y, frame, timer, duration}
        self._steam_spawn_timer = 0
        # Windy city weather - debris, leaves, wind wisps
        self._debris: List[Dict] = []  # {x, y, char, color, speed, state, timer, stop_x}
        self._leaves: List[Dict] = []  # {x, y, char, speed, wobble}
        self._wind_wisps: List[Dict] = []  # {x, y, chars, speed}
        self._debris_spawn_timer = 0
        self._wind_wisp_timer = 0
        self._tree_positions: List[Tuple[int, int]] = []  # (x, y) for trees
        self._pine_tree_positions: List[Tuple[int, int]] = []  # (x, y) for pine trees

        # Christmas lights (secret event Dec 20-31)
        self._christmas_mode = self._check_christmas_week()
        self._christmas_light_frame = 0
        self._christmas_light_timer = 0
        # Halloween (secret event Oct 24-31)
        self._halloween_mode = self._check_halloween_week()
        self._pumpkin_positions: List[Tuple[int, int]] = []  # (x, y) for pumpkins
        self._pumpkin_glow_frame = 0
        self._pumpkin_glow_timer = 0
        # 4th of July (secret event Jul 1-7)
        self._july4th_mode = self._check_july4th_week()
        self._fireworks: List[Dict] = []  # {x, y, frame, color, type}
        self._firework_timer = 0
        # Easter (secret event - Sunday in spring)
        self._easter_mode = self._check_easter_week()
        self._easter_egg_positions: List[Tuple[int, int, int]] = []  # (x, y, color_idx)
        self._tree_sway_frame = 0

        # ==========================================
        # SECURITY CANARY SYSTEM
        # Visual elements tied to daemon monitor health
        # If monitors fail, scene elements disappear
        # ==========================================
        self._security_canary = {
            'stars': True,          # Tied to memory_monitor
            'clouds': True,         # Tied to resource_monitor
            'traffic_lights': True, # Tied to health_monitor
            'street_lights': True,  # Tied to state_monitor
            'trees': True,          # Tied to file_integrity
            'pedestrians': True,    # Tied to process_security
            'cafe_lights': True,    # Tied to wifi_security
            'vehicles': True,       # Tied to log_watchdog
        }
        self._canary_check_timer = 0
        self._canary_check_interval = 300  # Check every 5 seconds at 60fps

        # Seasonal constellation (position in sky, based on date)
        self._constellation = self._get_seasonal_constellation()
        self._constellation_x = 0  # Set during scene generation
        self._constellation_y = 0
        self._star_twinkle_timer = 0
        self._star_twinkle_frame = 0

        # Background stars (small twinkling dots filling the sky)
        self._background_stars: List[Dict] = []
        self._init_background_stars()

        # Master frame counter for update throttling (performance optimization)
        self._frame_count = 0

        # Scene seeding - deterministic random based on date for consistency
        # Same date = same scene layout (for screenshot validation)
        today = datetime.now()
        self._scene_seed = today.year * 10000 + today.month * 100 + today.day
        random.seed(self._scene_seed)

        # Wind direction: 1 = blowing right (from left), -1 = blowing left (from right)
        self._wind_direction = 1
        self._wind_direction_timer = 0
        self._wind_direction_change_interval = random.randint(10800, 54000)  # 3-15 minutes at ~60fps
        # Meteor damage overlays - {x, y, char, timer, fade_time}
        self._damage_overlays: List[Dict] = []
        self._damage_fade_time = 18000  # ~5 minutes at 60fps (300 seconds * 60)
        # Woman in Red event - rare Matrix scene
        self._woman_red_active = False
        self._woman_red_state = 'idle'  # idle, neo_morpheus_enter, woman_enters, woman_passes, woman_waves, woman_pauses, transform, chase, cooldown
        self._woman_red_timer = 0
        self._woman_red_cooldown = 0
        self._woman_red_x = 0.0  # Woman's x position
        self._neo_x = 0.0  # Neo's x position
        self._morpheus_x = 0.0  # Morpheus's x position
        self._agent_x = 0.0  # Agent Smith's x position (after transform)
        self._woman_red_frame = 0
        self._neo_frame = 0
        self._morpheus_frame = 0
        self._agent_frame = 0
        self._transform_frame = 0
        self._frame_timer = 0
        # Meteor QTE event - quick time event
        self._qte_enabled = False  # Toggle for QTE events (off by default)
        self._qte_pending_activation = False  # Waiting for delayed activation
        self._qte_activation_time = 0.0  # When to activate QTE
        self._qte_active = False
        self._qte_state = 'idle'  # idle, warning, active, success, failure, cooldown
        self._qte_timer = 0
        self._qte_cooldown = 0
        self._qte_meteors: List[Dict] = []  # {x, y, col, row, speed, size, called}
        self._qte_missiles: List[Dict] = []  # {x, y, target_col, target_row, speed}
        self._qte_explosions: List[Dict] = []  # {x, y, frame, timer}
        self._qte_current_callout = None  # (col, row, key) - current key NPC is calling
        self._qte_callout_timer = 0
        self._qte_score = 0
        self._qte_misses = 0
        self._qte_npc_x = 0
        self._qte_npc_message = ""
        self._qte_message_timer = 0  # Timer for auto-clearing messages
        self._qte_message_duration = 90  # Frames to show message (1.5 sec at 60fps)
        self._qte_wave = 0  # Current wave of meteors
        self._qte_total_waves = 5  # Total waves per event
        self._qte_pending_keys: List[str] = []  # Keys player needs to press
        self._qte_last_meteor_positions: List[Tuple[int, int, int, int]] = []  # (x, y, w, h) for cleanup
        # Skyline buildings with animated window lights
        self._skyline_windows: List[Dict] = []  # {x, y, on, timer, toggle_time}
        self._skyline_buildings: List[Dict] = []  # {x, y, width, height, windows}
        # OPEN sign animation state
        self._open_sign_phase = 0  # 0=off, 1=O, 2=OP, 3=OPE, 4=OPEN, 5-9=flash
        self._open_sign_timer = 0
        self._open_sign_speed = 2  # Frames per phase (10x faster)
        # Calm mode flag - more debris/leaves, no particles
        self._calm_mode = False
        # Full weather mode for road effects
        self._weather_mode = WeatherMode.MATRIX
        # Road/sidewalk weather effects - subtle rolling changes
        self._road_effects: List[Dict] = []  # {x, y, char, color, timer, duration, type}
        self._road_effect_timer = 0
        self._road_effect_interval = 30  # Spawn new effects every ~0.5 sec at 60fps
        # Colorful animated garden in front of Shell Cafe
        self._garden_cache: List[List[Tuple[int, int, str, int]]] = []  # Cached frames
        self._garden_frame_idx = 0
        self._garden_cache_valid = False
        self._garden_x = 0  # Set during scene generation
        self._garden_y = 0
        self._garden_width = 20
        # UFO abduction event - super rare
        self._ufo_active = False
        self._ufo_state = 'idle'  # idle, descend, abduct, ascend, cooldown
        self._ufo_timer = 0
        self._ufo_cooldown = 0
        self._ufo_x = 0.0
        self._ufo_y = 0.0
        self._ufo_target_y = 0.0
        self._cow_y = 0.0  # Cow being abducted
        # Cloud layer with wisps
        self._clouds: List[Dict] = []
        self._init_clouds()
        self._generate_scene()

    def resize(self, width: int, height: int):
        """Regenerate scene for new dimensions."""
        self.width = width
        self.height = height
        self._cars = []  # Clear cars on resize
        self._closeup_car = None  # Clear close-up car on resize
        self._pedestrians = []  # Clear pedestrians on resize
        self._woman_red_active = False  # Reset woman in red event
        self._woman_red_state = 'idle'
        self._qte_active = False  # Reset QTE event
        self._qte_state = 'idle'
        self._qte_meteors = []
        self._qte_missiles = []
        self._qte_explosions = []
        self._init_clouds()  # Reinit clouds for new size
        self._generate_scene()

    def _check_christmas_week(self) -> bool:
        """Check if it's Christmas week (Dec 20-31) for secret lights event."""
        today = datetime.now()
        return today.month == 12 and today.day >= 20

    def _check_halloween_week(self) -> bool:
        """Check if it's Halloween week (Oct 24-31) for spooky event."""
        today = datetime.now()
        return today.month == 10 and today.day >= 24

    def _check_july4th_week(self) -> bool:
        """Check if it's 4th of July week (Jul 1-7) for fireworks event."""
        today = datetime.now()
        return today.month == 7 and today.day <= 7

    def _check_easter_week(self) -> bool:
        """Check if it's Easter week (Easter Sunday +/- 3 days)."""
        today = datetime.now()
        # Calculate Easter Sunday using Anonymous Gregorian algorithm
        year = today.year
        a = year % 19
        b = year // 100
        c = year % 100
        d = b // 4
        e = b % 4
        f = (b + 8) // 25
        g = (b - f + 1) // 3
        h = (19 * a + b - d - g + 15) % 30
        i = c // 4
        k = c % 4
        l = (32 + 2 * e + 2 * i - h - k) % 7
        m = (a + 11 * h + 22 * l) // 451
        month = (h + l - 7 * m + 114) // 31
        day = ((h + l - 7 * m + 114) % 31) + 1
        easter = datetime(year, month, day)
        # Check if within 3 days of Easter
        diff = abs((today - easter).days)
        return diff <= 3

    def _get_seasonal_constellation(self) -> dict:
        """Get the constellation for the current season."""
        today = datetime.now()
        month = today.month
        # Spring: March-May -> Leo
        if 3 <= month <= 5:
            return self.CONSTELLATION_LEO
        # Summer: June-August -> Scorpius
        elif 6 <= month <= 8:
            return self.CONSTELLATION_SCORPIUS
        # Fall: September-November -> Pegasus
        elif 9 <= month <= 11:
            return self.CONSTELLATION_PEGASUS
        # Winter: December-February -> Orion
        else:
            return self.CONSTELLATION_ORION

    def _init_background_stars(self):
        """Initialize background star positions for the night sky."""
        self._background_stars = []
        # Generate many small stars across the upper portion of screen
        # Stars should be in the sky area (roughly upper 40% of screen)
        sky_height = max(20, self.height // 2 - 5)

        # Create 80-120 background stars with varying brightness
        num_stars = random.randint(80, 120)
        for _ in range(num_stars):
            self._background_stars.append({
                'x': random.randint(5, max(10, self.width - 10)),
                'y': random.randint(2, sky_height),
                'brightness': random.choice([1, 1, 1, 2]),  # Mostly dim, some bright
                'twinkle_offset': random.randint(0, 3),  # Randomize twinkle phase
            })

    def _check_security_canaries(self, daemon_client=None):
        """
        Check daemon monitor health and update canary state.
        Visual elements disappear when their tied monitor fails.

        Monitor -> Visual Element mapping:
        - memory_monitor    -> stars (constellation)
        - resource_monitor  -> clouds
        - health_monitor    -> traffic lights
        - state_monitor     -> street lights
        - file_integrity    -> trees/foliage
        - process_security  -> pedestrians
        - wifi_security     -> cafe lights
        - log_watchdog      -> vehicles
        """
        if daemon_client is None:
            return  # Can't check without client

        # Default all to True (assume healthy)
        monitors_healthy = {
            'memory_monitor': True,
            'resource_monitor': True,
            'health_monitor': True,
            'state_monitor': True,
            'file_integrity': True,
            'process_security': True,
            'wifi_security': True,
            'log_watchdog': True,
        }

        # Try to get status from daemon
        try:
            if hasattr(daemon_client, '_send_request'):
                response = daemon_client._send_request('get_health_stats')
                if response.get('success'):
                    stats = response.get('health_stats', {})
                    # Check each monitor's health status
                    monitors = stats.get('monitors', {})
                    for monitor_name, status in monitors.items():
                        if monitor_name in monitors_healthy:
                            monitors_healthy[monitor_name] = status.get('healthy', True)

                # Also check monitoring summary
                response = daemon_client._send_request('get_monitoring_summary')
                if response.get('success'):
                    summary = response.get('summary', {})
                    # Check specific monitor availability
                    if not summary.get('memory_monitor_active', True):
                        monitors_healthy['memory_monitor'] = False
                    if not summary.get('resource_monitor_active', True):
                        monitors_healthy['resource_monitor'] = False
        except Exception:
            pass  # Fail silently, keep previous canary state

        # Update canary state based on monitor health
        self._security_canary['stars'] = monitors_healthy['memory_monitor']
        self._security_canary['clouds'] = monitors_healthy['resource_monitor']
        self._security_canary['traffic_lights'] = monitors_healthy['health_monitor']
        self._security_canary['street_lights'] = monitors_healthy['state_monitor']
        self._security_canary['trees'] = monitors_healthy['file_integrity']
        self._security_canary['pedestrians'] = monitors_healthy['process_security']
        self._security_canary['cafe_lights'] = monitors_healthy['wifi_security']
        self._security_canary['vehicles'] = monitors_healthy['log_watchdog']

    def _update_security_canaries(self, daemon_client=None):
        """Periodically check security canary status."""
        self._canary_check_timer += 1
        if self._canary_check_timer >= self._canary_check_interval:
            self._canary_check_timer = 0
            self._check_security_canaries(daemon_client)

        # Update star twinkle animation
        self._star_twinkle_timer += 1
        if self._star_twinkle_timer >= 30:  # Twinkle every half second
            self._star_twinkle_timer = 0
            self._star_twinkle_frame = (self._star_twinkle_frame + 1) % 4

    def _update_christmas_lights(self):
        """Update Christmas light animation frame."""
        if not self._christmas_mode:
            return
        self._christmas_light_timer += 1
        # Change light pattern every 15 frames (~4 times per second at 60fps)
        if self._christmas_light_timer >= 15:
            self._christmas_light_timer = 0
            self._christmas_light_frame = (self._christmas_light_frame + 1) % 4

    def _update_halloween(self):
        """Update Halloween pumpkin glow animation."""
        if not self._halloween_mode:
            return
        self._pumpkin_glow_timer += 1
        # Flicker glow every 10-20 frames
        if self._pumpkin_glow_timer >= random.randint(10, 20):
            self._pumpkin_glow_timer = 0
            self._pumpkin_glow_frame = (self._pumpkin_glow_frame + 1) % 3

    def _update_fireworks(self):
        """Update 4th of July firework animations."""
        if not self._july4th_mode:
            return
        self._firework_timer += 1
        # Spawn new firework every 30-90 frames
        if self._firework_timer >= random.randint(30, 90):
            self._firework_timer = 0
            # Launch firework at random x position in sky
            self._fireworks.append({
                'x': random.randint(10, self.width - 10),
                'y': random.randint(3, 12),
                'frame': 0,
                'color': random.choice([Colors.XMAS_RED, Colors.FIREWORK_WHITE,
                                       Colors.XMAS_BLUE, Colors.FIREWORK_MAGENTA,
                                       Colors.XMAS_YELLOW]),
                'type': random.choice(['burst', 'star', 'shower']),
            })
        # Update existing fireworks
        for fw in self._fireworks[:]:
            fw['frame'] += 1
            if fw['frame'] > 20:  # Firework fades after 20 frames
                self._fireworks.remove(fw)

    def _build_garden_cache(self):
        """Build cached animation frames for the colorful garden."""
        import math

        # Garden parameters
        num_frames = 60  # Animation loop frames
        width = self._garden_width
        height = 3  # 3 rows of garden

        # Flower/plant types with colors
        # Format: (char, color)
        flowers = [
            ('@', Colors.SHADOW_RED),  # Red flower
            ('*', Colors.RAT_YELLOW),        # Yellow flower
            ('%', Colors.STATUS_OK),         # Green plant
            ('#', Colors.RAIN_BRIGHT),       # Blue flower
            ('&', Colors.EASTER_PINK),       # Pink flower
            ('+', Colors.EASTER_LAVENDER),   # Purple flower
        ]

        stems = [
            ('|', Colors.STATUS_OK),
            ('/', Colors.STATUS_OK),
            ('\\', Colors.STATUS_OK),
        ]

        leaves = [
            ('~', Colors.STATUS_OK),
            (',', Colors.STATUS_OK),
            ("'", Colors.STATUS_OK),
        ]

        # Generate plant positions (deterministic based on width)
        plant_positions = []
        for i in range(0, width, 3):  # Plant every 3 chars
            flower = flowers[i % len(flowers)]
            stem = stems[i % len(stems)]
            leaf = leaves[i % len(leaves)]
            plant_positions.append({
                'x': i,
                'flower': flower,
                'stem': stem,
                'leaf': leaf,
                'phase': (i * 0.7) % (2 * math.pi),  # Phase offset for wave
            })

        self._garden_cache = []

        for frame in range(num_frames):
            frame_data = []
            t = frame * (2 * math.pi / num_frames)

            for plant in plant_positions:
                px = plant['x']
                phase = plant['phase']

                # Calculate sway offset (wind effect)
                sway = math.sin(t + phase) * 0.5
                sway_offset = int(sway + 0.5)  # -1, 0, or 1

                # Top row: flowers (sway with wind)
                flower_x = px + sway_offset
                if 0 <= flower_x < width:
                    frame_data.append((0, flower_x, plant['flower'][0], plant['flower'][1]))

                # Middle row: stems (slight sway)
                stem_char = plant['stem'][0]
                # Change stem angle based on sway
                if sway > 0.2:
                    stem_char = '/'
                elif sway < -0.2:
                    stem_char = '\\'
                else:
                    stem_char = '|'
                frame_data.append((1, px, stem_char, plant['stem'][1]))

                # Bottom row: leaves/grass (wave pattern)
                leaf_offset = int(math.sin(t * 2 + phase) * 0.5 + 0.5)
                for dx in [-1, 0, 1]:
                    lx = px + dx + leaf_offset
                    if 0 <= lx < width:
                        # Vary grass characters
                        grass_chars = [',', "'", '~', '"', '.']
                        grass_char = grass_chars[(px + dx + frame) % len(grass_chars)]
                        frame_data.append((2, lx, grass_char, Colors.STATUS_OK))

            self._garden_cache.append(frame_data)

        self._garden_cache_valid = True

    def _init_clouds(self):
        """Initialize cloud layer with cumulus clouds and wisps."""
        self._clouds = []

        # Create big, FAST-moving cumulus clouds (closer, more detailed)
        num_cumulus = max(2, self.width // 60)
        for i in range(num_cumulus):
            # Large cumulus cloud shapes - move fast
            self._clouds.append({
                'x': random.uniform(0, self.width),
                'y': random.randint(4, 8),  # Mid-sky area
                'speed': random.uniform(0.15, 0.30),  # Fast movement for big clouds
                'type': 'cumulus',
                'chars': random.choice([
                    # Big puffy cumulus
                    ['      .-~~~-.      ',
                     '    .~       ~.    ',
                     '   (    ~~~    )   ',
                     '  (  .~     ~.  )  ',
                     ' (  (         )  ) ',
                     '  ~~~~~~~~~~~~~~~  '],
                    # Wide cumulus
                    ['    .--~~~--.    ',
                     '  .~         ~.  ',
                     ' (    ~~~~~    ) ',
                     '(               )',
                     ' ~~~~~~~~~~~~~~~'],
                    # Tall cumulus
                    ['     .~~.     ',
                     '   .~    ~.   ',
                     '  (        )  ',
                     ' (    ~~    ) ',
                     '(            )',
                     ' ~~~~~~~~~~~~'],
                    # Smaller cumulus
                    ['   .~~~.   ',
                     ' .~     ~. ',
                     '(         )',
                     ' ~~~~~~~~~'],
                ]),
            })

        # Create smaller main clouds - move very slow
        num_clouds = max(3, self.width // 40)  # More clouds
        for i in range(num_clouds):
            # Main cloud body - very slow
            self._clouds.append({
                'x': random.uniform(0, self.width),
                'y': random.randint(3, 6),  # Upper area
                'speed': random.uniform(0.01, 0.03),  # Very slow movement for small clouds
                'type': 'main',
                'chars': random.choice([
                    ['  ___  ', ' (   ) ', '(_____)', '  ~~~  '],
                    [' ~~~ ', '(   )', ' ~~~ '],
                    ['_____', '(   )', '~~~~~'],
                ]),
            })
            # Wisps below main clouds - slowest
            for _ in range(2):
                self._clouds.append({
                    'x': random.uniform(0, self.width),
                    'y': random.randint(6, 12),
                    'speed': random.uniform(0.005, 0.02),  # Even slower wisps
                    'type': 'wisp',
                    'char': random.choice(['~', '≈', '-', '.']),
                    'length': random.randint(3, 8),
                })

        # Create additional lower clouds - slowest, drift near buildings
        num_low_clouds = max(2, self.width // 60)
        for i in range(num_low_clouds):
            self._clouds.append({
                'x': random.uniform(0, self.width),
                'y': random.randint(10, 18),  # Lower on screen, near building tops
                'speed': random.uniform(0.008, 0.02),  # Very slow drift
                'type': 'main',
                'chars': random.choice([
                    ['  ___  ', ' (   ) ', '(_____)', '  ~~~  '],
                    [' ~~~ ', '(   )', ' ~~~ '],
                    ['_____', '(   )', '~~~~~'],
                    ['   ~~~   ', ' (     ) ', '(       )', ' ~~~~~~~ '],
                ]),
            })

        # Create DISTANT background clouds - behind everything, very slow, dim
        num_distant = max(2, self.width // 50)
        for i in range(num_distant):
            self._clouds.append({
                'x': random.uniform(0, self.width),
                'y': random.randint(5, 15),  # Mid-sky area behind buildings
                'speed': random.uniform(0.003, 0.01),  # Extremely slow drift
                'type': 'distant',
                'chars': random.choice([
                    # Hazy distant cloud
                    ['  .---.  ', ' (     ) ', '(       )', ' ~~~~~~~ '],
                    # Stretched distant cloud
                    ['    ~~~~    ', '  (      )  ', ' (        ) ', '~~~~~~~~~~~~'],
                    # Small distant puff
                    ['  ~~~  ', ' (   ) ', '~~~~~~'],
                    # Wispy distant cloud
                    ['   .~~~.   ', ' ~~     ~~ ', '~~~~~~~~~~~'],
                ]),
            })

        # Create HUGE foreground clouds - biggest, fastest, rendered on top
        num_foreground = max(1, self.width // 100)
        for i in range(num_foreground):
            self._clouds.append({
                'x': random.uniform(0, self.width),
                'y': random.randint(2, 10),  # Can go higher on screen
                'speed': random.uniform(0.4, 0.7),  # Very fast movement
                'type': 'foreground',
                'chars': random.choice([
                    # Massive storm cloud
                    ['          .--~~~~~~~--.          ',
                     '       .~~             ~~.       ',
                     '     .~                   ~.     ',
                     '   .~    ~~~~~~~~~~~        ~.   ',
                     '  (    ~~           ~~        )  ',
                     ' (   ~                 ~       ) ',
                     '(  (      ~~~~~~~       )      ) ',
                     ' (   ~               ~        )  ',
                     '  ~~                        ~~   ',
                     '    ~~~~~~~~~~~~~~~~~~~~~~~~~    '],
                    # Wide fluffy cloud
                    ['       .--~~~~~~~---.       ',
                     '    .~~             ~~.    ',
                     '  .~                   ~.  ',
                     ' (      ~~~~~~~~~~       ) ',
                     '(                         )',
                     ' ~~~~~~~~~~~~~~~~~~~~~~~~~ '],
                    # Giant cumulus
                    ['        .~~~~.        ',
                     '     .~~      ~~.     ',
                     '   .~            ~.   ',
                     '  (    ~~~~~~~~    )  ',
                     ' (                  ) ',
                     '(      ~~~~~~        )',
                     ' ~~~~~~~~~~~~~~~~~~~~ '],
                ]),
            })

    def _update_clouds(self):
        """Update cloud positions - drift in wind direction."""
        for cloud in self._clouds:
            # Clouds move in wind direction
            cloud['x'] += cloud['speed'] * self._wind_direction

            # Wrap around based on wind direction
            if cloud['type'] in ['main', 'cumulus', 'foreground', 'distant']:
                cloud_width = len(cloud['chars'][0]) if cloud['chars'] else 5
                if self._wind_direction > 0:
                    # Wind blowing right - wrap from left
                    if cloud['x'] > self.width + cloud_width:
                        cloud['x'] = -cloud_width
                else:
                    # Wind blowing left - wrap from right
                    if cloud['x'] < -cloud_width:
                        cloud['x'] = self.width + cloud_width
            else:
                # Wisps
                wisp_len = cloud.get('length', 5)
                if self._wind_direction > 0:
                    if cloud['x'] > self.width + wisp_len:
                        cloud['x'] = -wisp_len
                else:
                    if cloud['x'] < -wisp_len:
                        cloud['x'] = self.width + wisp_len

    def _update_steam(self):
        """Update steam effects from manholes and drains - rare occurrence."""
        self._steam_spawn_timer += 1

        # Rarely spawn steam (about 1 in 800 frames)
        if self._steam_spawn_timer >= random.randint(600, 1000):
            self._steam_spawn_timer = 0
            # Choose a random manhole or drain
            all_positions = self._manhole_positions + self._drain_positions
            if all_positions and len(self._steam_effects) < 2:  # Max 2 steam at once
                pos = random.choice(all_positions)
                self._steam_effects.append({
                    'x': pos[0],
                    'y': pos[1],
                    'frame': 0,
                    'timer': 0,
                    'duration': random.randint(40, 80),  # Short duration
                })

        # Update existing steam effects
        new_steam = []
        for steam in self._steam_effects:
            steam['timer'] += 1
            # Animate frame
            if steam['timer'] % 5 == 0:
                steam['frame'] = (steam['frame'] + 1) % len(self.STEAM_FRAMES)
            # Keep if not expired
            if steam['timer'] < steam['duration']:
                new_steam.append(steam)
        self._steam_effects = new_steam

    def _update_woman_red(self):
        """Update the Woman in Red event - rare Matrix iconic scene."""
        # Handle cooldown
        if self._woman_red_cooldown > 0:
            self._woman_red_cooldown -= 1
            return

        # If idle, check for rare trigger
        if self._woman_red_state == 'idle':
            # Rare trigger - about 1 in 2000 frames when not in cooldown
            if random.randint(1, 2000) == 1:
                self._woman_red_active = True
                self._woman_red_state = 'neo_morpheus_enter'
                self._woman_red_timer = 0
                # Neo and Morpheus enter from left
                self._neo_x = -10.0
                self._morpheus_x = -16.0  # Morpheus slightly behind
                # Woman starts off screen right
                self._woman_red_x = float(self.width + 10)
            return

        # Update timer and frame animation
        self._woman_red_timer += 1
        self._frame_timer += 1
        if self._frame_timer >= 4:  # Animation speed
            self._frame_timer = 0
            self._woman_red_frame = (self._woman_red_frame + 1) % 4
            self._neo_frame = (self._neo_frame + 1) % 4
            self._morpheus_frame = (self._morpheus_frame + 1) % 4
            self._agent_frame = (self._agent_frame + 1) % 4

        screen_center = self.width // 2

        if self._woman_red_state == 'neo_morpheus_enter':
            # Neo and Morpheus walk in from left and stop near center-left
            self._neo_x += 0.5
            self._morpheus_x += 0.5
            # Stop when Neo reaches about 1/3 of screen
            if self._neo_x >= screen_center - 20:
                self._woman_red_state = 'woman_enters'
                self._woman_red_timer = 0

        elif self._woman_red_state == 'woman_enters':
            # Woman in red walks from right toward center
            self._woman_red_x -= 0.4
            # When she reaches center, transition to passing
            if self._woman_red_x <= screen_center + 10:
                self._woman_red_state = 'woman_passes'
                self._woman_red_timer = 0

        elif self._woman_red_state == 'woman_passes':
            # Woman walks past Neo and Morpheus
            self._woman_red_x -= 0.4
            # When past them, stop and wave
            if self._woman_red_x <= self._neo_x - 5:
                self._woman_red_state = 'woman_waves'
                self._woman_red_timer = 0

        elif self._woman_red_state == 'woman_waves':
            # Woman stops and waves at Neo and Morpheus
            if self._woman_red_timer >= 60:  # Wave for about 60 frames
                self._woman_red_state = 'woman_pauses'
                self._woman_red_timer = 0

        elif self._woman_red_state == 'woman_pauses':
            # Brief pause before transformation
            if self._woman_red_timer >= 30:
                self._woman_red_state = 'transform'
                self._woman_red_timer = 0
                self._transform_frame = 0

        elif self._woman_red_state == 'transform':
            # Woman transforms into Agent Smith (glitch effect)
            if self._woman_red_timer % 8 == 0:
                self._transform_frame += 1
            if self._transform_frame >= len(self.TRANSFORM_FRAMES):
                self._woman_red_state = 'chase'
                self._woman_red_timer = 0
                self._agent_x = self._woman_red_x

        elif self._woman_red_state == 'chase':
            # Agent Smith chases Neo and Morpheus off screen left
            self._agent_x -= 0.8  # Agent runs fast
            self._neo_x -= 1.0  # Neo runs faster (escaping)
            self._morpheus_x -= 1.0  # Morpheus runs too
            # End when everyone is off screen
            if self._agent_x < -15 and self._neo_x < -15:
                self._woman_red_state = 'idle'
                self._woman_red_active = False
                self._woman_red_cooldown = 3000  # Long cooldown before next event

    def set_calm_mode(self, calm: bool):
        """Set calm mode - more debris/leaves, less mid-screen clutter."""
        self._calm_mode = calm

    def set_weather_mode(self, mode: WeatherMode):
        """Set the weather mode for road effects."""
        self._weather_mode = mode
        # Clear existing effects when weather changes
        self._road_effects = []

    def toggle_qte(self) -> bool:
        """Toggle QTE (meteor game) on/off. Returns new state."""
        self._qte_enabled = not self._qte_enabled
        # If disabling while active, cancel the current event
        if not self._qte_enabled and self._qte_active:
            self._qte_active = False
            self._qte_state = 'idle'
            self._qte_meteors = []
            self._qte_missiles = []
            self._qte_explosions = []
        return self._qte_enabled

    def toggle_mute(self) -> bool:
        """Toggle audio mute on/off. Returns new mute state."""
        self._audio_muted = not self._audio_muted
        return self._audio_muted

    def is_muted(self) -> bool:
        """Check if audio is muted."""
        return self._audio_muted

    def _speak_text(self, text: str, speed: float = 1.0, pitch: float = 0.0) -> bool:
        """Speak text using TTS engine in background thread. Returns True if started."""
        if self._audio_muted or not self._tts_manager:
            return False

        def _tts_worker():
            try:
                params = VoiceParameters(speed=speed, pitch=pitch) if VoiceParameters is not None else None
                request = TTSRequest(text=text, params=params) if TTSRequest is not None and params else None
                if request:
                    self._tts_manager.synthesize(request)
                    logger.debug(f"TTS spoke: {text[:50]}...")
            except Exception as e:
                logger.debug(f"TTS error: {e}")

        try:
            # Run TTS in background thread to avoid blocking UI
            tts_thread = threading.Thread(target=_tts_worker, daemon=True)
            tts_thread.start()
            return True
        except Exception as e:
            logger.debug(f"TTS thread error: {e}")
        return False

    def _play_sound_effect(self, audio_intent) -> bool:
        """Play a sound effect from an AudioIntent using TTS. Returns True if successful."""
        if self._audio_muted or not self._tts_manager:
            return False

        try:
            # Use the onomatopoeia text for TTS synthesis
            text = audio_intent.onomatopoeia
            speed = audio_intent.speed if hasattr(audio_intent, 'speed') else 1.0
            pitch = audio_intent.pitch_shift if hasattr(audio_intent, 'pitch_shift') else 0.0

            return self._speak_text(text, speed=speed, pitch=pitch)
        except Exception as e:
            logger.debug(f"Sound effect error: {e}")
        return False

    def _play_car_sound(self, vehicle_type: str):
        """Play TTS car sound effect based on vehicle type."""
        if self._audio_muted or not AUDIO_ENGINE_AVAILABLE:
            return

        # Cooldown to prevent sound spam
        if self._car_sound_cooldown > 0:
            self._car_sound_cooldown -= 1
            return

        try:
            audio_engine = get_audio_engine()
            # Generate scene event audio for car
            audio_intent = audio_engine.generate_scene_event_audio('car')
            # Actually play the sound using TTS
            self._play_sound_effect(audio_intent)
            # Set cooldown (60 frames = ~1 second at 60fps)
            self._car_sound_cooldown = 60
        except Exception as e:
            logger.debug(f"Car sound error: {e}")

    def _update_ufo(self):
        """Update UFO cow abduction event - super rare."""
        # Handle cooldown
        if self._ufo_cooldown > 0:
            self._ufo_cooldown -= 1
            return

        # Very rare chance to trigger UFO event (about 1 in 50000 frames ~ once per 15 min)
        if not self._ufo_active and random.random() < 0.00002:
            self._ufo_active = True
            self._ufo_state = 'descend'
            self._ufo_timer = 0
            # Position UFO above a building (behind building gap)
            building1_right = self._building_x + len(self.BUILDING[0])
            building2_left = self._building2_x if self._building2_x > 0 else self.width
            gap_center = (building1_right + building2_left) // 2
            self._ufo_x = float(gap_center)
            self._ufo_y = -10.0  # Start above screen
            self._ufo_target_y = float(self.height // 2 + 5)  # Descend to mid-low area
            self._cow_y = self._ufo_target_y + 8  # Cow starts below UFO target

        if not self._ufo_active:
            return

        self._ufo_timer += 1

        if self._ufo_state == 'descend':
            # UFO descends slowly behind buildings
            self._ufo_y += 0.3
            if self._ufo_y >= self._ufo_target_y:
                self._ufo_y = self._ufo_target_y
                self._ufo_state = 'abduct'
                self._ufo_timer = 0

        elif self._ufo_state == 'abduct':
            # Cow rises up in tractor beam
            self._cow_y -= 0.15
            if self._cow_y <= self._ufo_y + len(self.UFO_SPRITE):
                self._ufo_state = 'ascend'
                self._ufo_timer = 0

        elif self._ufo_state == 'ascend':
            # UFO ascends with cow
            self._ufo_y -= 0.4
            self._cow_y = self._ufo_y + len(self.UFO_SPRITE)  # Cow attached
            if self._ufo_y < -15:
                self._ufo_state = 'idle'
                self._ufo_active = False
                self._ufo_cooldown = 36000  # ~10 minute cooldown

    def _update_wind(self):
        """Update wind effects - debris, leaves, and wisps blowing across screen."""
        street_y = self.height - 3
        curb_y = self.height - 4

        # Update wind direction timer - change direction every 3-15 minutes
        self._wind_direction_timer += 1
        if self._wind_direction_timer >= self._wind_direction_change_interval:
            self._wind_direction_timer = 0
            self._wind_direction *= -1  # Flip direction
            self._wind_direction_change_interval = random.randint(10800, 54000)

        # Update tree sway animation
        self._tree_sway_frame = (self._tree_sway_frame + 1) % 20

        # === DEBRIS SYSTEM (simple state machine) ===
        self._debris_spawn_timer += 1
        if self._debris_spawn_timer > 30:
            self._debris_spawn_timer = 0
            max_items = 12 if self._calm_mode else 6
            if len(self._debris) < max_items:
                # Pick debris type
                debris_type = random.choice(['leaf', 'leaf', 'newspaper', 'trash'])
                if debris_type == 'leaf':
                    char = random.choice(['*', '✦', '✧', '⁕', '@'])
                    color_type = 'leaf'
                elif debris_type == 'newspaper':
                    char = random.choice(['▪', '▫', '□', '▢'])
                    color_type = 'paper'
                else:
                    char = random.choice(['~', '°', '·'])
                    color_type = 'trash'

                # Spawn from upwind side
                if self._wind_direction > 0:
                    spawn_x = -2.0
                else:
                    spawn_x = float(self.width + 2)

                self._debris.append({
                    'x': spawn_x,
                    'y': float(random.choice([curb_y, street_y, street_y - 1])),
                    'char': char,
                    'color': color_type,
                    'speed': random.uniform(0.3, 0.8),
                    'state': 'blowing',
                    'timer': 0,
                    'stop_x': random.uniform(0.2, 0.7) * self.width,
                })

        # Update debris with state machine
        new_debris = []
        for d in self._debris:
            if d['state'] == 'blowing':
                d['x'] += d['speed'] * self._wind_direction
                # Check if reached stop point
                if self._wind_direction > 0 and d['x'] >= d['stop_x']:
                    d['state'] = 'slowing'
                elif self._wind_direction < 0 and d['x'] <= d['stop_x']:
                    d['state'] = 'slowing'
            elif d['state'] == 'slowing':
                d['speed'] *= 0.85
                d['x'] += d['speed'] * self._wind_direction
                if d['speed'] < 0.05:
                    d['state'] = 'stopped'
                    d['timer'] = 0
            elif d['state'] == 'stopped':
                d['timer'] += 1
                if d['timer'] > 60:  # Fixed duration to avoid random in tight loop
                    d['state'] = 'resuming'
                    d['timer'] = 0
            elif d['state'] == 'resuming':
                d['speed'] = min(d['speed'] + 0.02, 0.6)
                d['x'] += d['speed'] * self._wind_direction

            # Keep if on screen
            if -5 < d['x'] < self.width + 5:
                new_debris.append(d)
        self._debris = new_debris

        # === WIND WISPS ===
        max_wisps = 2 if self._calm_mode else 5
        self._wind_wisp_timer += 1
        if self._wind_wisp_timer > 45:
            self._wind_wisp_timer = 0
            if len(self._wind_wisps) < max_wisps:
                wisp_chars = ''.join([random.choice(self.WIND_WISPS) for _ in range(random.randint(3, 8))])
                spawn_x = -5.0 if self._wind_direction > 0 else float(self.width + 5)
                wisp_y = random.randint(3, max(4, self.height // 3))
                self._wind_wisps.append({
                    'x': spawn_x,
                    'y': float(wisp_y),
                    'chars': wisp_chars,
                    'speed': random.uniform(1.0, 2.5),
                })

        new_wisps = []
        for w in self._wind_wisps:
            w['x'] += w['speed'] * self._wind_direction
            if -10 < w['x'] < self.width + 10:
                new_wisps.append(w)
        self._wind_wisps = new_wisps

        # === LEAVES FROM TREES ===
        leaf_chance = 0.08 if self._calm_mode else 0.03
        max_leaves = 30 if self._calm_mode else 15
        for tree_x, tree_y in self._tree_positions:
            if random.random() < leaf_chance and len(self._leaves) < max_leaves:
                self._leaves.append({
                    'x': float(tree_x + random.randint(2, 7)),
                    'y': float(tree_y + random.randint(0, 3)),
                    'char': random.choice(self.DEBRIS_LEAVES),
                    'speed': random.uniform(0.5, 1.5),
                    'fall_speed': random.uniform(0.1, 0.3),
                    'wobble': random.uniform(0, 6.28),
                })

        new_leaves = []
        for leaf in self._leaves:
            leaf['x'] += leaf['speed'] * self._wind_direction
            leaf['y'] += leaf['fall_speed']
            leaf['wobble'] += 0.2
            leaf['x'] += math.sin(leaf['wobble']) * 0.3
            if -5 < leaf['x'] < self.width + 5 and leaf['y'] < street_y + 2:
                new_leaves.append(leaf)
        self._leaves = new_leaves

    def _update_qte(self):
        """Update meteor QTE event - quick time event."""
        # Skip if QTE is disabled
        if not self._qte_enabled:
            return

        # Handle cooldown
        if self._qte_cooldown > 0:
            self._qte_cooldown -= 1
            return

        ground_y = self.height - 5  # Ground level for meteor impact

        # If idle, check for rare trigger
        if self._qte_state == 'idle':
            # Rare trigger - about 1 in 3000 frames
            if random.randint(1, 3000) == 1:
                self._qte_active = True
                self._qte_state = 'warning'
                self._qte_timer = 0
                self._qte_score = 0
                self._qte_misses = 0
                self._qte_wave = 0
                self._qte_meteors = []
                self._qte_missiles = []
                self._qte_explosions = []
                self._qte_pending_keys = []
                # NPC appears on the left side
                self._qte_npc_x = 5
                self._qte_npc_message = "HELP! METEORS!"
                self._qte_message_timer = 0
                self._qte_last_meteor_positions = []  # Clear cleanup tracking
            return

        self._qte_timer += 1

        # Update message timer - auto-clear messages after duration
        if self._qte_npc_message:
            self._qte_message_timer += 1
            if self._qte_message_timer >= self._qte_message_duration:
                # Don't clear during warning or end states
                if self._qte_state == 'active':
                    self._qte_npc_message = ""
                    self._qte_message_timer = 0

        if self._qte_state == 'warning':
            # Warning phase - NPC appears and warns
            if self._qte_timer >= 60:
                self._qte_state = 'active'
                self._qte_timer = 0
                self._qte_wave = 1
                self._spawn_qte_wave()

        elif self._qte_state == 'active':
            # Update callout timer
            self._qte_callout_timer += 1

            # Spawn new callout if needed
            if self._qte_current_callout is None and self._qte_callout_timer >= 30:
                self._spawn_qte_callout()
                self._qte_callout_timer = 0

            # Update meteors (falling)
            new_meteors = []
            for meteor in self._qte_meteors:
                if meteor['called']:
                    meteor['y'] += meteor['speed']
                    # Check if meteor hit ground
                    if meteor['y'] >= ground_y:
                        self._qte_misses += 1
                        self._spawn_explosion(meteor['x'], ground_y, ground_impact=True)
                        # Clear current callout so next meteor can be called
                        self._qte_current_callout = None
                        continue
                new_meteors.append(meteor)
            self._qte_meteors = new_meteors

            # Update missiles (rising)
            new_missiles = []
            for missile in self._qte_missiles:
                missile['y'] -= missile['speed']
                # Check collision with meteors
                hit = False
                for meteor in self._qte_meteors:
                    if meteor['called'] and abs(missile['x'] - meteor['x']) < 4 and abs(missile['y'] - meteor['y']) < 3:
                        self._spawn_explosion(meteor['x'], meteor['y'])
                        self._qte_meteors.remove(meteor)
                        self._qte_score += 1
                        # Clear current callout so next meteor can be called
                        self._qte_current_callout = None
                        hit = True
                        break
                if not hit and missile['y'] > 3:
                    new_missiles.append(missile)
            self._qte_missiles = new_missiles

            # Update explosions
            new_explosions = []
            for exp in self._qte_explosions:
                exp['timer'] += 1
                if exp['timer'] % 4 == 0:
                    exp['frame'] += 1
                if exp['frame'] < len(self.EXPLOSION_FRAMES):
                    new_explosions.append(exp)
            self._qte_explosions = new_explosions

            # Check wave completion - wait for explosions to finish too
            active_meteors = [m for m in self._qte_meteors if m['called']]
            uncalled_meteors = [m for m in self._qte_meteors if not m['called']]
            explosions_done = len(self._qte_explosions) == 0
            if len(active_meteors) == 0 and len(uncalled_meteors) == 0 and len(self._qte_missiles) == 0 and explosions_done:
                self._qte_wave += 1
                if self._qte_wave > self._qte_total_waves:
                    # All waves complete
                    if self._qte_misses <= 2:
                        self._qte_state = 'success'
                    else:
                        self._qte_state = 'failure'
                    self._qte_timer = 0
                else:
                    self._spawn_qte_wave()

        elif self._qte_state == 'success':
            self._qte_npc_message = f"WE DID IT! Score: {self._qte_score}"
            if self._qte_timer >= 120:
                self._qte_state = 'idle'
                self._qte_active = False
                self._qte_cooldown = 5000

        elif self._qte_state == 'failure':
            self._qte_npc_message = f"THE CITY... Hits: {self._qte_score}"
            if self._qte_timer >= 120:
                self._qte_state = 'idle'
                self._qte_active = False
                self._qte_cooldown = 5000

    def _spawn_qte_wave(self):
        """Spawn a wave of meteors for QTE."""
        # Calculate column positions spread across screen
        col_width = (self.width - 40) // 5
        col_starts = [20 + i * col_width + col_width // 2 for i in range(5)]

        # Row heights (3 layers)
        row_heights = [8, 15, 22]  # Top, middle, bottom starting y

        # Spawn 2-4 meteors per wave
        num_meteors = min(self._qte_wave + 1, 4)
        used_positions = set()

        for _ in range(num_meteors):
            col = random.randint(0, 4)
            row = random.randint(0, 2)
            pos_key = (col, row)

            # Avoid duplicate positions
            attempts = 0
            while pos_key in used_positions and attempts < 10:
                col = random.randint(0, 4)
                row = random.randint(0, 2)
                pos_key = (col, row)
                attempts += 1

            used_positions.add(pos_key)

            # Determine meteor size based on row
            if row == 0:
                size = 'large'
                speed = 0.15
            elif row == 1:
                size = 'medium'
                speed = 0.2
            else:
                size = 'small'
                speed = 0.25

            self._qte_meteors.append({
                'x': col_starts[col],
                'y': float(row_heights[row]),
                'col': col,
                'row': row,
                'speed': speed,
                'size': size,
                'called': False,  # Not falling yet until called
            })

        self._qte_current_callout = None
        self._qte_callout_timer = 0

    def _spawn_qte_callout(self):
        """Spawn a new callout for the NPC to say."""
        # Find uncalled meteors
        uncalled = [m for m in self._qte_meteors if not m['called']]
        if not uncalled:
            self._qte_current_callout = None
            return

        # Pick a random uncalled meteor
        meteor = random.choice(uncalled)
        key = self.QTE_KEYS[meteor['col']]
        row_name = ['TOP', 'MID', 'LOW'][meteor['row']]

        self._qte_current_callout = (meteor['col'], meteor['row'], key)
        self._qte_npc_message = f"PRESS [{key}] {row_name}!"
        self._qte_message_timer = 0  # Reset message timer for new callout

        # Start the meteor falling
        meteor['called'] = True

    def _spawn_explosion(self, x: float, y: float, ground_impact: bool = False):
        """Spawn an explosion at the given position."""
        self._qte_explosions.append({
            'x': int(x),
            'y': int(y),
            'frame': 0,
            'timer': 0,
        })

        # If this is a ground impact, create damage overlay
        if ground_impact:
            self._spawn_damage_overlay(int(x), int(y))

    def _spawn_damage_overlay(self, x: int, y: int):
        """Spawn a damage overlay at impact site (lasts 5 minutes)."""
        damage_chars = ['░', '▒', '▓', '█', '#', 'X', '*']
        # Create a crater/damage pattern around impact point
        for dx in range(-3, 4):
            for dy in range(-2, 2):
                px = x + dx
                py = y + dy
                if 0 <= px < self.width - 1 and 0 <= py < self.height:
                    # Damage intensity decreases with distance
                    dist = abs(dx) + abs(dy)
                    if dist <= 4 and random.random() < (1.0 - dist * 0.15):
                        char = random.choice(damage_chars[:3] if dist > 2 else damage_chars)
                        self._damage_overlays.append({
                            'x': px,
                            'y': py,
                            'char': char,
                            'timer': 0,
                            'fade_time': self._damage_fade_time + random.randint(-1000, 1000),
                        })

    def _update_damage_overlays(self):
        """Update damage overlays - fade after 5 minutes."""
        new_overlays = []
        for overlay in self._damage_overlays:
            overlay['timer'] += 1
            if overlay['timer'] < overlay['fade_time']:
                new_overlays.append(overlay)
        self._damage_overlays = new_overlays

    def handle_qte_key(self, key: str) -> bool:
        """Handle a key press for the QTE event. Returns True if key was consumed."""
        if not self._qte_active or self._qte_state != 'active':
            return False

        if key not in self.QTE_KEYS:
            return False

        col = self.QTE_KEYS.index(key)

        # Check if there's a called meteor in this column to hit with missile
        called_meteors = [m for m in self._qte_meteors if m['called'] and m['col'] == col]
        if called_meteors:
            # Launch missile at the meteor
            meteor = called_meteors[0]
            col_width = (self.width - 40) // 5
            col_x = 20 + col * col_width + col_width // 2
            self._qte_missiles.append({
                'x': col_x,
                'y': float(self.height - 6),
                'target_col': col,
                'target_row': meteor['row'],
                'speed': 1.5,
            })
            # Clear current callout so NPC calls next one
            if self._qte_current_callout and self._qte_current_callout[0] == col:
                self._qte_current_callout = None
                self._qte_callout_timer = 20  # Short delay before next callout
            return True

        # Check if there's an uncalled meteor to activate
        uncalled = [m for m in self._qte_meteors if not m['called'] and m['col'] == col]
        if uncalled:
            # Activate the meteor (start it falling)
            meteor = uncalled[0]
            meteor['called'] = True
            return True

        return False

    def _update_skyline_windows(self):
        """Update animated skyline windows - toggle lights on/off."""
        # Get visibility bounds (set during _draw_distant_buildings)
        vis_left = getattr(self, '_skyline_visible_left', 0)
        vis_right = getattr(self, '_skyline_visible_right', self.width)

        # Get cafe bounds to avoid drawing windows behind cafe
        cafe_bounds = getattr(self, '_cafe_bounds', (0, 0, 0, 0))
        cafe_left, cafe_right, cafe_top, cafe_bottom = cafe_bounds

        for window in self._skyline_windows:
            if not window['animated']:
                continue

            window['timer'] += 1
            if window['timer'] >= window['toggle_time']:
                window['timer'] = 0
                window['on'] = not window['on']
                # Update the scene with new window state (only if in visible region and not behind cafe)
                px, py = window['x'], window['y']
                # Skip if behind cafe
                if cafe_left <= px <= cafe_right and cafe_top <= py <= cafe_bottom:
                    continue
                if vis_left <= px <= vis_right and 0 <= py < self.height:
                    if window['on']:
                        self.scene[py][px] = ('▪', Colors.RAT_YELLOW)
                    else:
                        self.scene[py][px] = ('▫', Colors.ALLEY_DARK)

    def _update_open_sign(self):
        """Update OPEN sign animation - lights up O, P, E, N then flashes."""
        self._open_sign_timer += 1
        if self._open_sign_timer >= self._open_sign_speed:
            self._open_sign_timer = 0
            self._open_sign_phase += 1
            if self._open_sign_phase > 9:  # 0-4 = lighting up, 5-9 = flashing
                self._open_sign_phase = 0

    def _render_cafe_sign(self, screen):
        """Render cafe sign with green SHELL CAFE and animated OPEN sign."""
        if not hasattr(self, 'cafe_x') or not hasattr(self, 'cafe_y'):
            return

        cafe_x = self.cafe_x
        cafe_y = self.cafe_y

        # Render big shell on roof - all green
        for row_idx in range(8):  # First 8 rows are the shell roof
            if row_idx < len(self.CAFE):
                for col_idx, char in enumerate(self.CAFE[row_idx]):
                    if char not in ' ':
                        px = cafe_x + col_idx
                        py = cafe_y + row_idx
                        if 0 <= px < self.width - 1 and 0 <= py < self.height:
                            try:
                                # All green for the shell
                                attr = curses.color_pair(Colors.CAFE_GREEN) | curses.A_BOLD
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                            except curses.error:
                                pass

        # Find the SHELL CAFE text in the sprite (row 8 after turtle shell)
        if len(self.CAFE) > 8:
            sign_row = self.CAFE[8]  # "  |     S H E L L  C A F E   |  "
            for col_idx, char in enumerate(sign_row):
                if char in 'SHELLCAFE':
                    px = cafe_x + col_idx
                    py = cafe_y + 8
                    if 0 <= px < self.width - 1 and 0 <= py < self.height:
                        try:
                            # Green bold for SHELL CAFE
                            attr = curses.color_pair(Colors.CAFE_GREEN) | curses.A_BOLD
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

        # Find and animate the OPEN sign (row 21 in CAFE sprite, after turtle shell)
        if len(self.CAFE) > 21:
            open_row = self.CAFE[21]  # "  |[                  OPEN ]|  "
            open_start = open_row.find('OPEN')
            if open_start != -1:
                # Determine which letters are lit based on phase
                # Phase 0: all off, 1: O, 2: OP, 3: OPE, 4: OPEN, 5-9: flash on/off
                letters = ['O', 'P', 'E', 'N']
                for i, letter in enumerate(letters):
                    px = cafe_x + open_start + i
                    py = cafe_y + 21
                    if 0 <= px < self.width - 1 and 0 <= py < self.height:
                        try:
                            if self._open_sign_phase == 0:
                                # All off - white/unlit
                                attr = curses.color_pair(Colors.ALLEY_MID)
                            elif self._open_sign_phase <= 4:
                                # Lighting up one by one
                                if i < self._open_sign_phase:
                                    # This letter is lit - bright yellow
                                    attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                                else:
                                    # Not lit yet - white/unlit
                                    attr = curses.color_pair(Colors.ALLEY_MID)
                            else:
                                # Flashing phase (5-9) - alternate on/off
                                if self._open_sign_phase % 2 == 1:
                                    attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                                else:
                                    attr = curses.color_pair(Colors.ALLEY_MID)
                            screen.attron(attr)
                            screen.addstr(py, px, letter)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_trees(self, screen):
        """Render trees on top of buildings (foreground layer). Tied to file_integrity health."""
        # Security canary: no trees if file integrity monitor is down
        if not self._security_canary.get('trees', True):
            return
        for tree_x, tree_y in self._tree_positions:
            # During Halloween, use spooky bare trees
            if self._halloween_mode:
                tree_sprite = self.SPOOKY_TREE
                for row_idx, row in enumerate(tree_sprite):
                    for col_idx, char in enumerate(row):
                        px = tree_x + col_idx
                        py = tree_y + row_idx
                        if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                            try:
                                # Spooky purple/dark colors
                                if char in '\\|/-+':
                                    attr = curses.color_pair(Colors.HALLOWEEN_PURPLE) | curses.A_DIM
                                else:
                                    attr = curses.color_pair(Colors.ALLEY_MID)
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                            except curses.error:
                                pass
            else:
                # Normal tree rendering
                if self._wind_direction > 0:
                    tree_sprite = self.TREE_WINDY_RIGHT
                else:
                    tree_sprite = self.TREE_WINDY_LEFT

                for row_idx, row in enumerate(tree_sprite):
                    for col_idx, char in enumerate(row):
                        px = tree_x + col_idx
                        py = tree_y + row_idx
                        if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                            try:
                                if char == '@':
                                    # Leaves - green
                                    attr = curses.color_pair(Colors.MATRIX_DIM)
                                elif char in '()|':
                                    # Trunk - brown/dark
                                    attr = curses.color_pair(Colors.SAND_DIM)
                                else:
                                    attr = curses.color_pair(Colors.ALLEY_MID)
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                            except curses.error:
                                pass

    def _render_pine_trees(self, screen):
        """Render pine trees on top of buildings (foreground layer)."""
        if not hasattr(self, '_pine_tree_positions'):
            return

        # Christmas light colors cycle through 4 patterns
        xmas_colors = [Colors.XMAS_RED, Colors.XMAS_GREEN, Colors.XMAS_BLUE, Colors.XMAS_YELLOW]

        for tree_x, tree_y in self._pine_tree_positions:
            # Use windy pine sprite based on wind direction
            if self._wind_direction > 0:
                tree_sprite = self.PINE_TREE_WINDY_RIGHT
            else:
                tree_sprite = self.PINE_TREE_WINDY_LEFT

            for row_idx, row in enumerate(tree_sprite):
                for col_idx, char in enumerate(row):
                    px = tree_x + col_idx
                    py = tree_y + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        try:
                            # Check for Christmas lights on branch rows (rows 1-6 have branches)
                            is_light = False
                            if self._christmas_mode and row_idx >= 1 and row_idx <= 6:
                                # Place lights on alternating positions along branches
                                # Pattern shifts with frame to create "chasing" effect
                                light_pattern = (col_idx + self._christmas_light_frame) % 3 == 0
                                if char in '/\\' and light_pattern:
                                    is_light = True
                                    # Cycle color based on position and frame
                                    color_idx = (col_idx + row_idx + self._christmas_light_frame) % 4
                                    attr = curses.color_pair(xmas_colors[color_idx]) | curses.A_BOLD
                                    screen.attron(attr)
                                    screen.addstr(py, px, 'o')  # Light bulb
                                    screen.attroff(attr)

                            if not is_light:
                                if char == '*':
                                    # Star on top - yellow (extra bright during Christmas)
                                    attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                                    if self._christmas_mode:
                                        # Blink the star
                                        if self._christmas_light_frame % 2 == 0:
                                            attr |= curses.A_BLINK if hasattr(curses, 'A_BLINK') else 0
                                elif char in '/\\|':
                                    # Pine needles and trunk - green
                                    attr = curses.color_pair(Colors.MATRIX_DIM)
                                else:
                                    attr = curses.color_pair(Colors.ALLEY_MID)
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_fireworks(self, screen):
        """Render 4th of July fireworks in the sky."""
        if not self._july4th_mode:
            return
        for fw in self._fireworks:
            # Get sprite based on type
            if fw['type'] == 'burst':
                sprite = self.FIREWORK_BURST
            elif fw['type'] == 'star':
                sprite = self.FIREWORK_STAR
            else:
                sprite = self.FIREWORK_SHOWER
            # Calculate fade based on frame
            if fw['frame'] < 5:
                attr = curses.color_pair(fw['color']) | curses.A_BOLD
            elif fw['frame'] < 12:
                attr = curses.color_pair(fw['color'])
            else:
                attr = curses.color_pair(fw['color']) | curses.A_DIM
            # Render sprite centered on position
            for row_idx, row in enumerate(sprite):
                for col_idx, char in enumerate(row):
                    px = fw['x'] - len(row) // 2 + col_idx
                    py = fw['y'] + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char not in ' ':
                        try:
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_pumpkins(self, screen):
        """Render Halloween pumpkins with flickering glow."""
        if not self._halloween_mode:
            return
        for pumpkin_x, pumpkin_y in self._pumpkin_positions:
            # Flicker effect based on glow frame
            if self._pumpkin_glow_frame == 0:
                attr = curses.color_pair(Colors.HALLOWEEN_ORANGE) | curses.A_BOLD
            elif self._pumpkin_glow_frame == 1:
                attr = curses.color_pair(Colors.HALLOWEEN_ORANGE)
            else:
                attr = curses.color_pair(Colors.HALLOWEEN_ORANGE) | curses.A_DIM
            for row_idx, row in enumerate(self.PUMPKIN):
                for col_idx, char in enumerate(row):
                    px = pumpkin_x + col_idx
                    py = pumpkin_y + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char not in ' ':
                        try:
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_easter_eggs(self, screen):
        """Render Easter eggs hidden around the scene."""
        if not self._easter_mode:
            return
        egg_colors = [Colors.EASTER_PINK, Colors.EASTER_CYAN, Colors.EASTER_LAVENDER,
                      Colors.XMAS_YELLOW, Colors.XMAS_GREEN]
        for egg_x, egg_y, color_idx in self._easter_egg_positions:
            attr = curses.color_pair(egg_colors[color_idx % len(egg_colors)]) | curses.A_BOLD
            for row_idx, row in enumerate(self.EASTER_EGG):
                for col_idx, char in enumerate(row):
                    px = egg_x + col_idx
                    py = egg_y + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char not in ' ':
                        try:
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_background_stars(self, screen):
        """Render background stars filling the night sky."""
        # Only show stars when tunnel effect is disabled
        if getattr(self, '_tunnel_enabled', True):
            return

        # Security canary: no stars if memory monitor is down
        if not self._security_canary.get('stars', True):
            return

        # Reinitialize if empty (e.g., after resize)
        if not self._background_stars:
            self._init_background_stars()

        for star in self._background_stars:
            px = star['x']
            py = star['y']

            if 0 <= px < self.width - 1 and 1 <= py < self.height // 2:
                try:
                    # Twinkle based on brightness and offset
                    twinkle_phase = (self._star_twinkle_frame + star['twinkle_offset']) % 4

                    if star['brightness'] == 2:
                        # Brighter background stars
                        if twinkle_phase == 0:
                            char = '.'
                            attr = curses.color_pair(Colors.ALLEY_LIGHT)
                        elif twinkle_phase == 1:
                            char = '·'
                            attr = curses.color_pair(Colors.GREY_BLOCK)
                        else:
                            char = '.'
                            attr = curses.color_pair(Colors.ALLEY_MID)
                    else:
                        # Dim background stars
                        if twinkle_phase % 2 == 0:
                            char = '.'
                            attr = curses.color_pair(Colors.ALLEY_MID) | curses.A_DIM
                        else:
                            char = '·'
                            attr = curses.color_pair(Colors.GREY_BLOCK) | curses.A_DIM

                    screen.attron(attr)
                    screen.addstr(py, px, char)
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_constellation(self, screen):
        """Render seasonal constellation in the sky. Tied to memory_monitor health."""
        # Only show stars when tunnel effect is disabled
        if getattr(self, '_tunnel_enabled', True):
            return

        # Security canary: no stars if memory monitor is down
        if not self._security_canary.get('stars', True):
            return

        if not self._constellation:
            return

        # Position constellation in upper sky area (scale down offsets for better fit)
        base_x = self._constellation_x
        base_y = self._constellation_y

        stars = self._constellation.get('stars', [])
        for dx, dy, brightness in stars:
            # Scale down the constellation coordinates (they were 5x scaled)
            px = base_x + (dx // 2)  # Reduce horizontal spread
            py = base_y + (dy // 3)  # Reduce vertical spread

            # Expanded sky area for constellations
            if 0 <= px < self.width - 1 and 1 <= py < self.height // 2:  # Keep in upper half
                try:
                    # More visible star characters based on brightness
                    if brightness == 2:
                        # Bright star - prominent with twinkle
                        if self._star_twinkle_frame == 0:
                            char = '★'
                            attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_BOLD
                        elif self._star_twinkle_frame == 1:
                            char = '*'
                            attr = curses.color_pair(Colors.ALLEY_LIGHT)
                        elif self._star_twinkle_frame == 2:
                            char = '✦'
                            attr = curses.color_pair(Colors.GREY_BLOCK) | curses.A_BOLD
                        else:
                            char = '*'
                            attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_DIM
                    else:
                        # Dim star - still visible but subtler
                        if self._star_twinkle_frame % 2 == 0:
                            char = '*'
                            attr = curses.color_pair(Colors.GREY_BLOCK)
                        else:
                            char = '·'
                            attr = curses.color_pair(Colors.ALLEY_MID)

                    screen.attron(attr)
                    screen.addstr(py, px, char)
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_dotted_fog(self, screen):
        """Render dotted fog layer (behind clouds).
        Uses persistent fog positions that slowly drift for smooth animation.
        """
        # Initialize persistent fog state if needed
        if not hasattr(self, '_fog_particles') or len(self._fog_particles) == 0:
            self._fog_particles = []
            fog_chars = ['░', '·', '.', '∙']
            # Create fog particles with positions and drift speeds
            for row in range(3, 9):
                density = max(0.03, 0.18 - (row - 3) * 0.03)
                for x in range(self.width - 1):
                    if random.random() < density:
                        self._fog_particles.append({
                            'x': float(x),
                            'y': row,
                            'char': random.choice(fog_chars),
                            'drift_x': random.uniform(-0.02, 0.02),  # Very slow drift
                        })
            self._fog_update_counter = 0

        # Only update fog positions every 10 frames for slow movement
        self._fog_update_counter = getattr(self, '_fog_update_counter', 0) + 1
        if self._fog_update_counter >= 10:
            self._fog_update_counter = 0
            for particle in self._fog_particles:
                particle['x'] += particle['drift_x']
                # Wrap around screen edges
                if particle['x'] < 0:
                    particle['x'] = self.width - 2
                elif particle['x'] >= self.width - 1:
                    particle['x'] = 0

        # Render fog particles
        for particle in self._fog_particles:
            px = int(particle['x'])
            py = particle['y']
            if 0 <= px < self.width - 1 and 0 <= py < self.height:
                try:
                    attr = curses.color_pair(Colors.GREY_BLOCK) | curses.A_DIM
                    screen.attron(attr)
                    screen.addstr(py, px, particle['char'])
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_clouds(self, screen):
        """Render cloud layer."""
        # Security canary: no clouds if resource monitor is down
        if not self._security_canary.get('clouds', True):
            return
        # Early exit if no clouds
        if not self._clouds:
            return
        for cloud in self._clouds:
            if cloud['type'] in ['main', 'cumulus']:
                # Render multi-line cloud (main or cumulus)
                # Cumulus clouds are brighter (no A_DIM)
                for row_idx, row in enumerate(cloud['chars']):
                    for col_idx, char in enumerate(row):
                        px = int(cloud['x']) + col_idx
                        py = cloud['y'] + row_idx
                        if 0 <= px < self.width - 1 and 0 <= py < self.height and char not in ' ':
                            try:
                                if cloud['type'] == 'cumulus':
                                    # Cumulus clouds are brighter/closer
                                    attr = curses.color_pair(Colors.ALLEY_LIGHT)
                                else:
                                    attr = curses.color_pair(Colors.GREY_BLOCK) | curses.A_DIM
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                            except curses.error:
                                pass
            elif cloud['type'] == 'wisp':
                # Render wisp
                for i in range(cloud['length']):
                    px = int(cloud['x']) + i
                    py = cloud['y']
                    if 0 <= px < self.width - 1 and 0 <= py < self.height:
                        try:
                            attr = curses.color_pair(Colors.GREY_BLOCK) | curses.A_DIM
                            screen.attron(attr)
                            screen.addstr(py, px, cloud['char'])
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_foreground_clouds(self, screen):
        """Render large foreground clouds on top of the scene."""
        for cloud in self._clouds:
            if cloud['type'] == 'foreground':
                # Render huge foreground cloud - brightest, on top
                for row_idx, row in enumerate(cloud['chars']):
                    for col_idx, char in enumerate(row):
                        px = int(cloud['x']) + col_idx
                        py = cloud['y'] + row_idx
                        if 0 <= px < self.width - 1 and 0 <= py < self.height and char not in ' ':
                            try:
                                # Foreground clouds are brightest white
                                attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_BOLD
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                            except curses.error:
                                pass

    def _render_distant_clouds(self, screen):
        """Render distant background clouds - behind everything, very dim."""
        for cloud in self._clouds:
            if cloud['type'] == 'distant':
                # Render distant cloud - very dim, behind everything
                for row_idx, row in enumerate(cloud['chars']):
                    for col_idx, char in enumerate(row):
                        px = int(cloud['x']) + col_idx
                        py = cloud['y'] + row_idx
                        if 0 <= px < self.width - 1 and 0 <= py < self.height and char not in ' ':
                            try:
                                # Distant clouds are very dim grey
                                attr = curses.color_pair(Colors.MATRIX_FADE2) | curses.A_DIM
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                            except curses.error:
                                pass

    def _render_ufo(self, screen):
        """Render UFO cow abduction event."""
        if not self._ufo_active:
            return

        ufo_x = int(self._ufo_x) - len(self.UFO_SPRITE[0]) // 2
        ufo_y = int(self._ufo_y)

        # Render tractor beam first (behind cow)
        if self._ufo_state in ('abduct', 'ascend'):
            beam_x = ufo_x + (len(self.UFO_SPRITE[0]) - len(self.TRACTOR_BEAM[0])) // 2
            beam_y = ufo_y + len(self.UFO_SPRITE)
            for row_idx, row in enumerate(self.TRACTOR_BEAM):
                # Repeat beam to reach cow
                py = beam_y + row_idx
                while py < int(self._cow_y):
                    for col_idx, char in enumerate(row):
                        px = beam_x + col_idx
                        if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                            try:
                                # Green tractor beam
                                attr = curses.color_pair(Colors.MATRIX_DIM)
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                            except curses.error:
                                pass
                    py += len(self.TRACTOR_BEAM)

        # Render UFO
        for row_idx, row in enumerate(self.UFO_SPRITE):
            py = ufo_y + row_idx
            for col_idx, char in enumerate(row):
                px = ufo_x + col_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    try:
                        if char in 'o*':
                            # Lights - yellow
                            attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                        else:
                            # Body - silver/white
                            attr = curses.color_pair(Colors.ALLEY_LIGHT)
                        screen.attron(attr)
                        screen.addstr(py, px, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

        # Render cow (during abduct or ascend)
        if self._ufo_state in ('abduct', 'ascend'):
            cow_x = int(self._ufo_x) - len(self.COW_SPRITE[0]) // 2
            cow_y = int(self._cow_y)
            for row_idx, row in enumerate(self.COW_SPRITE):
                py = cow_y + row_idx
                for col_idx, char in enumerate(row):
                    px = cow_x + col_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        try:
                            attr = curses.color_pair(Colors.ALLEY_MID)
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _generate_scene(self):
        """Generate scene with buildings, dumpster, box, curb, street, and street lights."""
        if self.width <= 0 or self.height <= 0:
            self.scene = []
            return

        # Clear window position tracking for layering
        self._window_interior_positions = []
        self._window_frame_positions = []

        # Initialize with empty space
        self.scene = [[(' ', Colors.ALLEY_DARK) for _ in range(self.width)]
                      for _ in range(self.height)]

        # Street and curb moved up 2 rows from bottom
        street_y = self.height - 3
        curb_y = self.height - 4

        # Ground level is just above curb (moved up from previous position)
        ground_y = curb_y - 1

        # Draw solid cloud cover at top (double line)
        self._draw_cloud_cover()

        # Position seasonal constellation in the sky (between buildings, below clouds)
        # Use seeded random for consistent daily positioning
        random.seed(self._scene_seed)
        # Center constellations on screen (5x scaled, largest ~75 chars wide)
        # Center horizontally with some variance
        center_x = self.width // 2 - 20  # Offset for constellation width
        self._constellation_x = center_x + random.randint(-10, 10)
        self._constellation_y = random.randint(15, 22)  # Mid-sky position
        # Reset random to time-based for dynamic elements
        random.seed()

        # Calculate building positions first for overlap avoidance
        self._building_x = 9
        building1_right = self._building_x + len(self.BUILDING[0])
        self._building2_x = self.width - len(self.BUILDING2[0]) - 11 if self.width > 60 else self.width

        # Calculate cafe position early for overlap avoidance (must match line ~4001)
        gap_center = (building1_right + self._building2_x) // 2
        cafe_width = len(self.CAFE[0])
        cafe_height = len(self.CAFE)
        cafe_left = gap_center - cafe_width // 2 - 28  # Match actual cafe_x calculation
        cafe_right = cafe_left + cafe_width
        cafe_top = ground_y - cafe_height - 3  # Match actual cafe_y calculation
        cafe_bottom = cafe_top + cafe_height

        # Draw distant buildings FIRST (furthest back) - only in gap between buildings
        # Pass cafe bounds so cityscape windows don't show through cafe
        self._draw_distant_buildings(gap_center, ground_y, building1_right, self._building2_x,
                                     cafe_left, cafe_right, cafe_top, cafe_bottom)

        # Draw mid-range buildings (behind big buildings, avoid cafe area)
        self._draw_midrange_buildings(ground_y, cafe_left, cafe_right)

        # Draw first building wireframe in background (left side)
        # Position building so its bottom edge is at ground level
        # Shifted 6 chars toward center (right)
        # Uses grey blocks on bottom half story, red bricks on upper portions
        self._building_x = 9
        self._building_y = ground_y - len(self.BUILDING) + 1
        self._draw_building(self.BUILDING, self._building_x, max(1, self._building_y))
        self._building_bottom_y = ground_y  # Store for rat constraint
        # Add side walls to building 1 (left side lighter, right side darker/shadow)
        self._draw_building_side_walls(self._building_x, max(1, self._building_y),
                                       len(self.BUILDING[0]), len(self.BUILDING), 'left')
        self._draw_building_side_walls(self._building_x, max(1, self._building_y),
                                       len(self.BUILDING[0]), len(self.BUILDING), 'right')

        # Draw second building on the right side
        # Shifted 6 chars toward center (left)
        # Uses grey blocks on bottom half story, red bricks on upper portions
        if self.width > 60:
            self._building2_x = self.width - len(self.BUILDING2[0]) - 11
            self._building2_y = ground_y - len(self.BUILDING2) + 1
            self._draw_building(self.BUILDING2, self._building2_x, max(1, self._building2_y))
            # Add side walls to building 2
            self._draw_building_side_walls(self._building2_x, max(1, self._building2_y),
                                           len(self.BUILDING2[0]), len(self.BUILDING2), 'left')
            self._draw_building_side_walls(self._building2_x, max(1, self._building2_y),
                                           len(self.BUILDING2[0]), len(self.BUILDING2), 'right')

        # Setup ALL building windows with unique scenes and light states
        # Big windows are [========] (8 chars), small are [====] (4 chars)
        self._all_windows = []
        self._building_window_lights = []

        # Building 1 window definitions: (col, width, is_big)
        b1_windows = [
            (4, 8, True), (17, 4, False), (24, 4, False), (37, 8, True), (50, 4, False)
        ]
        b1_window_rows = [7, 13, 19, 25, 31]  # Rows with window tops

        # Building 2 window definitions
        b2_windows = [
            (6, 8, True), (19, 4, False), (30, 8, True), (43, 4, False)
        ]

        # Create all windows for building 1
        for row in b1_window_rows:
            for col, width, is_big in b1_windows:
                wx = self._building_x + col
                wy = max(1, self._building_y) + row
                if 0 < wx < self.width - 5 and 0 < wy < self.height - 5:
                    # Assign unique scene and random light state
                    scene_type = random.choice(self._window_scene_types)
                    # More varied brightness - use discrete levels
                    light_on = random.random() > 0.25  # 75% chance light is on
                    if light_on:
                        # Discrete brightness levels: dim (0.3), medium (0.6), bright (1.0)
                        brightness = random.choice([0.3, 0.5, 0.7, 0.9, 1.0])
                    else:
                        brightness = 0.0
                    window = {
                        'x': wx, 'y': wy, 'width': width, 'height': 3,
                        'building': 1, 'scene_type': scene_type,
                        'light_on': light_on, 'brightness': brightness,
                        'is_big': is_big, 'scene_chars': self._generate_window_scene(scene_type, width)
                    }
                    self._all_windows.append(window)
                    # Only big windows get light glow effect (moved up 2 rows from window top)
                    if is_big:
                        self._building_window_lights.append((wx + width // 2, wy - 1))

        # Create all windows for building 2
        if self.width > 60:
            for row in b1_window_rows:  # Same row pattern
                for col, width, is_big in b2_windows:
                    wx = self._building2_x + col
                    wy = max(1, self._building2_y) + row
                    if 0 < wx < self.width - 5 and 0 < wy < self.height - 5:
                        scene_type = random.choice(self._window_scene_types)
                        light_on = random.random() > 0.25
                        if light_on:
                            brightness = random.choice([0.3, 0.5, 0.7, 0.9, 1.0])
                        else:
                            brightness = 0.0
                        window = {
                            'x': wx, 'y': wy, 'width': width, 'height': 3,
                            'building': 2, 'scene_type': scene_type,
                            'light_on': light_on, 'brightness': brightness,
                            'is_big': is_big, 'scene_chars': self._generate_window_scene(scene_type, width)
                        }
                        self._all_windows.append(window)
                        # Only big windows get light glow
                        if is_big:
                            self._building_window_lights.append((wx + width // 2, wy - 1))

        # Initialize flicker brightness from window states (only for windows with lights)
        self._building_window_flicker = []
        for w in self._all_windows:
            if w['is_big']:
                self._building_window_flicker.append(w['brightness'])

        # Draw street lights between buildings (in the gap)
        self._draw_street_lights(ground_y)

        # Draw curb/sidewalk - store positions for front-layer rendering
        # Exclude area between traffic light pole and Claude St sign pole (fill with bars)
        self._sidewalk_positions = []
        # Traffic light is at box_x + len(BOX[0]) + 96, street sign will be calculated later
        # We'll update this after street sign position is known
        traffic_light_pole_x = self.box_x + len(self.BOX[0]) + 96 if hasattr(self, 'box_x') else self.width - 20
        for x in range(self.width - 1):
            # Store sidewalk position for rendering on top of scene (but behind sprites)
            self._sidewalk_positions.append((x, curb_y, '▄', Colors.ALLEY_MID))
        # Store traffic light x for later sidewalk exclusion update
        self._traffic_light_pole_x = traffic_light_pole_x

        # Draw street surface (two rows)
        for x in range(self.width - 1):
            self.scene[street_y][x] = ('▓', Colors.ALLEY_DARK)
            if street_y + 1 < self.height:
                self.scene[street_y + 1][x] = ('▓', Colors.ALLEY_DARK)

        # Add dashed lane markings on bottom street row (every 4 chars, 2 on 2 off)
        if self.width > 30:
            lane_y = street_y + 1 if street_y + 1 < self.height else street_y
            for x in range(0, self.width - 1, 4):
                if x + 1 < self.width - 1:
                    self.scene[lane_y][x] = ('=', Colors.RAT_YELLOW)
                    self.scene[lane_y][x + 1] = ('=', Colors.RAT_YELLOW)

        # Add manholes to the street (every ~30 chars)
        self._manhole_positions = []
        for x in range(15, self.width - 15, 30):
            manhole_x = x + random.randint(-3, 3)  # Slight random offset
            if 5 < manhole_x < self.width - 10:
                self._manhole_positions.append((manhole_x, street_y))
                # Draw manhole cover
                for i, char in enumerate(self.MANHOLE[0]):
                    if manhole_x + i < self.width - 1:
                        self.scene[street_y][manhole_x + i] = (char, Colors.ALLEY_MID)

        # Add drains along the curb (every ~25 chars)
        self._drain_positions = []
        for x in range(10, self.width - 10, 25):
            drain_x = x + random.randint(-2, 2)  # Slight random offset
            if 3 < drain_x < self.width - 8:
                self._drain_positions.append((drain_x, curb_y))
                # Draw drain
                for i, char in enumerate(self.DRAIN[0]):
                    if drain_x + i < self.width - 1:
                        self.scene[curb_y][drain_x + i] = (char, Colors.ALLEY_DARK)

        # Place trees - one on left, two in front of right building
        self._tree_positions = []
        self._pine_tree_positions = []  # Pine trees stored separately
        tree_height = len(self.TREE)
        tree_width = len(self.TREE[0])
        pine_height = len(self.PINE_TREE)
        building2_left = self._building2_x if self._building2_x > 0 else self.width
        building2_width = len(self.BUILDING2[0]) if self.BUILDING2 else 60

        # Tree 1: in front of left building
        tree1_x = self._building_x + 15
        # Tree 2: in front of right building (center-left of building2)
        tree2_x = building2_left + building2_width // 3
        # Tree 3: in front of right building (center-right of building2)
        tree3_x = building2_left + 2 * building2_width // 3

        for tree_x in [tree1_x, tree2_x, tree3_x]:
            # Check tree fits and doesn't overlap with cafe
            cafe_left = getattr(self, 'cafe_x', 0)
            cafe_right = cafe_left + len(self.CAFE[0]) if hasattr(self, 'cafe_x') else 0
            overlaps_cafe = cafe_left - 5 < tree_x < cafe_right + 5

            # Allow trees in front of building2 (not just in the gap)
            if tree_x > building1_right + 2 and tree_x + tree_width < self.width - 2 and not overlaps_cafe:
                tree_y = ground_y - tree_height + 1
                self._tree_positions.append((tree_x, tree_y))
                self._draw_tree(tree_x, tree_y)

        # Note: Pine tree is placed after cafe is drawn (below)

        # Place dumpster to the LEFT of building 1 (moved up 4 rows)
        self.dumpster_x = 2
        self.dumpster_y = ground_y - len(self.DUMPSTER) + 1 - 4  # Moved up 4 rows
        self._draw_sprite(self.DUMPSTER, self.dumpster_x, self.dumpster_y, Colors.ALLEY_MID)

        # Place box in front of left building (moved up 4 rows)
        building1_right = self._building_x + len(self.BUILDING[0])
        building2_left = self._building2_x if self._building2_x > 0 else self.width
        gap_center = (building1_right + building2_left) // 2
        self.box_x = self._building_x + 2  # In front of left building (shifted 3 left)
        self.box_y = ground_y - len(self.BOX) + 1 - 2  # Moved up 2 rows
        self._draw_box_with_label(self.box_x, self.box_y)

        # Place blue mailbox near building 1 (shifted 2 chars left)
        self.mailbox_x = self._building_x + len(self.BUILDING[0]) + 1
        self.mailbox_y = ground_y - len(self.MAILBOX) + 1
        self._draw_sprite(self.MAILBOX, self.mailbox_x, self.mailbox_y, Colors.ALLEY_BLUE)

        # Calculate door positions for pedestrian interactions
        self._door_positions = []
        # Building 1 doors
        for door_offset in self.BUILDING_DOOR_OFFSETS:
            door_x = self._building_x + door_offset
            self._door_positions.append({'building': 1, 'x': door_x, 'y': ground_y})
        # Building 2 doors
        for door_offset in self.BUILDING2_DOOR_OFFSETS:
            door_x = self._building2_x + door_offset
            self._door_positions.append({'building': 2, 'x': door_x, 'y': ground_y})
        # Cafe door (center bottom of cafe)
        cafe_door_x = gap_center - 28 + 14  # Approximate door position
        self._door_positions.append({'building': 'cafe', 'x': cafe_door_x, 'y': ground_y})

        # Calculate cafe position first (shifted 11 chars left)
        self.cafe_x = gap_center - len(self.CAFE[0]) // 2 - 28  # 10 more left (was -18)
        self.cafe_y = ground_y - len(self.CAFE) - 3  # Moved up 4 rows total (2 more)

        # Place well-lit Cafe between buildings (center of gap)
        self._draw_cafe(self.cafe_x, self.cafe_y)

        # Setup colorful garden in front of Shell Cafe (in the dead space)
        self._garden_x = self.cafe_x + 2
        self._garden_y = ground_y - 4  # Just above ground level
        self._garden_width = len(self.CAFE[0]) - 4  # Match cafe width minus margins
        self._garden_cache_valid = False  # Rebuild cache for new position
        self._build_garden_cache()

        # Pine tree: to the right of Shell Cafe, 4 rows higher than regular trees
        cafe_right = self.cafe_x + len(self.CAFE[0])
        pine_height = len(self.PINE_TREE)
        pine_x = cafe_right + 3  # 3 chars to the right of cafe
        pine_y = ground_y - pine_height + 1 - 4  # 4 rows higher than regular trees
        if pine_x + len(self.PINE_TREE[0]) < self.width - 2 and pine_y > 0:
            self._pine_tree_positions.append((pine_x, pine_y))
            self._draw_pine_tree(pine_x, pine_y)

        # Place pumpkins during Halloween (near trees and buildings)
        if self._halloween_mode:
            self._pumpkin_positions = []
            # Pumpkin near each tree
            for tree_x, tree_y in self._tree_positions:
                pumpkin_x = tree_x + random.randint(-3, 3)
                pumpkin_y = ground_y - 3  # On ground level
                if 0 < pumpkin_x < self.width - 10:
                    self._pumpkin_positions.append((pumpkin_x, pumpkin_y))
            # Extra pumpkin near cafe door
            self._pumpkin_positions.append((self.cafe_x + 2, ground_y - 3))

        # Place easter eggs during Easter (hidden around scene)
        if self._easter_mode:
            self._easter_egg_positions = []
            # Hide eggs near trees
            for i, (tree_x, tree_y) in enumerate(self._tree_positions):
                egg_x = tree_x + random.randint(-2, 5)
                egg_y = ground_y - 3
                if 0 < egg_x < self.width - 6:
                    self._easter_egg_positions.append((egg_x, egg_y, i))
            # Hide eggs near cafe
            self._easter_egg_positions.append((self.cafe_x + 5, ground_y - 3, 3))
            # Hide eggs near buildings
            if hasattr(self, '_building_x'):
                self._easter_egg_positions.append((self._building_x + 8, ground_y - 3, 4))

        # Draw crosswalk between cafe and right building (shifted right 12 chars total)
        # cafe_right already calculated above
        self._crosswalk_x = cafe_right + 13  # +12 to move vanishing street right
        self._crosswalk_width = 32  # Store for car occlusion
        self._draw_crosswalk(self._crosswalk_x, curb_y, street_y)

        # Draw small park between vanishing road and right building
        park_left = self._crosswalk_x + self._crosswalk_width + 2  # After crosswalk (reduced gap)
        park_right = self._building2_x - 2 if self._building2_x > 0 else self.width - 15
        park_width = park_right - park_left
        if park_width >= 15:  # Reduced minimum from 20 to 15
            self._draw_park(park_left, curb_y, park_width)

        # Draw street sign near crosswalk (shifted 12 chars right)
        sign_x = self._crosswalk_x + self._crosswalk_width // 2 - len(self.STREET_SIGN[0]) // 2 + 16
        sign_y = ground_y - len(self.STREET_SIGN) + 1
        self._street_sign_x = sign_x  # Store for sidewalk exclusion
        self._draw_street_sign(sign_x, sign_y)

        # Update sidewalk to exclude area between traffic light and Claude St poles
        # Fill with vertical bars instead
        if hasattr(self, '_traffic_light_pole_x') and hasattr(self, '_street_sign_x'):
            exclude_start = min(self._traffic_light_pole_x, self._street_sign_x) + 2
            exclude_end = max(self._traffic_light_pole_x, self._street_sign_x) - 1
            updated_sidewalk = []
            for (x, y, char, color) in self._sidewalk_positions:
                if exclude_start <= x <= exclude_end:
                    # Replace sidewalk with vertical bars in this area
                    updated_sidewalk.append((x, y, '|', Colors.ALLEY_DARK))
                else:
                    updated_sidewalk.append((x, y, char, color))
            self._sidewalk_positions = updated_sidewalk

        # Add building street numbers
        self._draw_building_numbers(ground_y)

    def _draw_street_sign(self, x: int, y: int):
        """Draw a street sign at the given position."""
        for row_idx, row in enumerate(self.STREET_SIGN):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    if char in '.-\'|':
                        self.scene[py][px] = (char, Colors.ALLEY_MID)
                    else:
                        # Text - green like street signs
                        self.scene[py][px] = (char, Colors.MATRIX_DIM)

    def _draw_building_numbers(self, ground_y: int):
        """Draw building street numbers beside doorways in gold."""
        # Building 1 numbers - to the side of doors
        # Find door positions in BUILDING sprite
        door_row = len(self.BUILDING) - 5  # Row beside doors (middle of door)
        # Draw numbers to the LEFT side of each door
        number1_x = self._building_x + 8  # Left side of first door
        number2_x = self._building_x + 36  # Left side of second door
        number_y = self._building_y + door_row - 2  # Raised 2 rows

        # Building 1 - odd side (741, 743) - 3 digit vertical numbers beside door
        numbers1 = "741"
        numbers2 = "743"
        for i, char in enumerate(numbers1):
            py = number_y + i
            if 0 <= number1_x < self.width - 1 and 0 <= py < self.height:
                self.scene[py][number1_x] = (char, Colors.DOOR_KNOB_GOLD)
        for i, char in enumerate(numbers2):
            py = number_y + i
            if 0 <= number2_x < self.width - 1 and 0 <= py < self.height:
                self.scene[py][number2_x] = (char, Colors.DOOR_KNOB_GOLD)

        # Building 2 numbers - even side (742, 744)
        if self._building2_x > 0:
            number3_x = self._building2_x + 8  # Left side of first door
            number4_x = self._building2_x + 36  # Left side of second door
            number_y2 = self._building2_y + door_row - 2  # Raised 2 rows
            numbers3 = "742"
            numbers4 = "744"
            for i, char in enumerate(numbers3):
                py = number_y2 + i
                if 0 <= number3_x < self.width - 1 and 0 <= py < self.height:
                    self.scene[py][number3_x] = (char, Colors.DOOR_KNOB_GOLD)
            for i, char in enumerate(numbers4):
                py = number_y2 + i
                if 0 <= number4_x < self.width - 1 and 0 <= py < self.height:
                    self.scene[py][number4_x] = (char, Colors.DOOR_KNOB_GOLD)

    def _generate_window_scene(self, scene_type: str, width: int) -> List[str]:
        """Generate unique mini scene content for a window based on type and width."""
        # Each scene type returns 3 rows of characters to fill the window interior
        # Width is 8 for big windows, 4 for small windows

        if width >= 8:  # Big windows
            if scene_type == 'empty':
                return ['        ', '        ', '        ']
            elif scene_type == 'plant':
                return ['  ,@,   ', '  |#|   ', '  ~~~   ']
            elif scene_type == 'lamp':
                return ['   /\\   ', '   ||   ', '  ____  ']
            elif scene_type == 'tv':
                return [' [====] ', ' [    ] ', '  ~~~~  ']
            elif scene_type == 'cat':
                return ['        ', ' /\\_/\\  ', ' (o.o)  ']
            elif scene_type == 'bookshelf':
                return ['||||||||', '|--||--|', '||||||||']
            elif scene_type == 'desk':
                return ['  ___   ', ' |   |  ', ' |___|  ']
            elif scene_type == 'curtains':
                return ['|\\    /|', '| \\  / |', '|  \\/  |']
            elif scene_type == 'blinds':
                return ['========', '========', '========']
            elif scene_type == 'person_standing':
                return ['   O    ', '  /|\\   ', '  / \\   ']
            elif scene_type == 'couple':
                return [' O   O  ', '/|\\ /|\\ ', '/ \\ / \\ ']
            elif scene_type == 'kitchen':
                return [' []  [] ', ' |    | ', ' ~~~~~~ ']
            else:
                return ['        ', '        ', '        ']
        else:  # Small windows (width 4)
            if scene_type == 'empty':
                return ['    ', '    ', '    ']
            elif scene_type == 'plant':
                return [' @  ', ' |  ', ' ~  ']
            elif scene_type == 'lamp':
                return [' /\\ ', ' || ', ' __ ']
            elif scene_type == 'tv':
                return ['[==]', '[  ]', ' ~~ ']
            elif scene_type == 'cat':
                return ['/\\_/', '(oo)', '    ']
            elif scene_type == 'bookshelf':
                return ['||||', '|--|', '||||']
            elif scene_type == 'desk':
                return [' __ ', '|  |', '|__|']
            elif scene_type == 'curtains':
                return ['|\\/|', '|  |', '|/\\|']
            elif scene_type == 'blinds':
                return ['====', '====', '====']
            elif scene_type == 'person_standing':
                return [' O  ', '/|\\ ', '/ \\ ']
            elif scene_type == 'couple':
                return ['O O ', '|| |', '    ']
            elif scene_type == 'kitchen':
                return ['[][]', '|  |', '~~~~']
            else:
                return ['    ', '    ', '    ']

    def _draw_street_lights(self, ground_y: int):
        """Draw street lights along the scene and store positions for flicker effect."""
        light_height = len(self.STREET_LIGHT)
        # Position lights so they stand on the ground
        light_y = ground_y - light_height + 1

        # Place street lights between the buildings (in the alley gap)
        self._street_light_positions = []
        # Calculate gap between buildings
        building1_right = self._building_x + len(self.BUILDING[0])
        building2_left = self._building2_x if self._building2_x > 0 else self.width
        gap_center = (building1_right + building2_left) // 2
        # Position lights in the gap between buildings (moved 4 chars outward)
        light_x_positions = [gap_center - 42, gap_center + 42]
        for light_x in light_x_positions:
            if 0 < light_x < self.width - len(self.STREET_LIGHT[0]) - 1:
                self._draw_sprite(self.STREET_LIGHT, light_x, max(1, light_y), Colors.ALLEY_LIGHT)
                # Store position for flicker effect (center of light head)
                self._street_light_positions.append((light_x + 2, max(1, light_y) + 1))

    def _draw_cloud_cover(self):
        """Draw solid double-line cloud cover at top of screen.
        Note: Dotted fog is now rendered separately in _render_dotted_fog (behind clouds).
        """
        # Draw two solid lines of clouds right below the status area (rows 1-2)
        # Mostly solid blocks with occasional texture variation
        for row in range(1, 3):  # Rows 1 and 2
            for x in range(self.width - 1):
                # 80% solid blocks, 20% texture variation
                r = random.random()
                if r < 0.80:
                    char = '█'  # Solid block
                elif r < 0.90:
                    char = '▓'  # Dense shade
                elif r < 0.97:
                    char = '▒'  # Medium shade
                else:
                    char = '░'  # Light shade (rare)
                self.scene[row][x] = (char, Colors.GREY_BLOCK)

    def _draw_distant_buildings(self, center_x: int, ground_y: int, left_boundary: int, right_boundary: int,
                                 cafe_left: int = 0, cafe_right: int = 0, cafe_top: int = 0, cafe_bottom: int = 0):
        """Draw static cityscape backdrop in the gap between main buildings."""
        # Initialize skyline windows list
        self._skyline_windows = []
        self._skyline_buildings = []

        # Store visibility bounds
        self._skyline_visible_left = left_boundary + 1
        self._skyline_visible_right = right_boundary - 1

        # Store cafe bounds for window filtering
        self._cafe_bounds = (cafe_left, cafe_right, cafe_top, cafe_bottom)

        # Position cityscape centered in the gap
        cityscape_width = len(self.CITYSCAPE[0]) if self.CITYSCAPE else 0
        cityscape_height = len(self.CITYSCAPE)
        gap_width = right_boundary - left_boundary

        # Center the cityscape in the gap
        cityscape_x = left_boundary + (gap_width - cityscape_width) // 2

        # Position at top of the visible gap area (above the cafe/street level)
        cityscape_y = ground_y - cityscape_height - 6

        # Draw the static cityscape
        for row_idx, row in enumerate(self.CITYSCAPE):
            py = cityscape_y + row_idx
            if py < 0 or py >= self.height:
                continue

            for col_idx, char in enumerate(row):
                px = cityscape_x + col_idx
                if px < 0 or px >= self.width - 1:
                    continue
                # Only draw in visible gap
                if px <= left_boundary or px >= right_boundary:
                    continue
                if char == ' ':
                    continue

                # Color based on character
                if char in '[]':
                    # Window brackets
                    color = Colors.ALLEY_MID
                    # Check if this is a window position (between brackets)
                    # and set up animation
                elif char == '█':
                    # Solid wall blocks - darker for filled appearance
                    color = Colors.ALLEY_DARK
                elif char in '|_/\\':
                    # Building structure/outlines
                    color = Colors.ALLEY_MID
                elif char in '~T':
                    # Antenna/tower tops
                    color = Colors.ALLEY_MID
                elif char in '.:\'"':
                    # Building details
                    color = Colors.ALLEY_DARK
                elif char == '=':
                    # Window/structure fill
                    color = Colors.ALLEY_MID
                else:
                    color = Colors.ALLEY_DARK

                self.scene[py][px] = (char, color)

        # Add animated windows at window bracket positions [ ]
        # Find all window positions in the cityscape
        for row_idx, row in enumerate(self.CITYSCAPE):
            py = cityscape_y + row_idx
            if py < 2 or py >= self.height:
                continue

            col_idx = 0
            while col_idx < len(row) - 2:
                # Look for [ ] pattern (window)
                if row[col_idx:col_idx+3] == '[ ]':
                    px = cityscape_x + col_idx + 1  # Center of window
                    if left_boundary < px < right_boundary and 0 <= px < self.width - 1:
                        # Skip windows that would be behind the cafe
                        if (cafe_left <= px <= cafe_right and cafe_top <= py <= cafe_bottom):
                            col_idx += 3
                            continue
                        # Add animated window
                        rand_val = random.random()
                        if rand_val < 0.3:
                            is_on = True
                            is_animated = random.random() < 0.3
                        else:
                            is_on = False
                            is_animated = random.random() < 0.15

                        toggle_time = random.randint(100, 400) if is_animated else 0
                        self._skyline_windows.append({
                            'x': px,
                            'y': py,
                            'on': is_on,
                            'animated': is_animated,
                            'timer': random.randint(0, toggle_time) if is_animated else 0,
                            'toggle_time': toggle_time,
                        })

                        # Draw initial window state
                        if is_on:
                            self.scene[py][px] = ('▪', Colors.RAT_YELLOW)
                    col_idx += 3
                else:
                    col_idx += 1

    def _draw_outline_building(self, building: List[str], x: int, base_y: int, color: int):
        """Draw a building outline at the given position."""
        building_height = len(building)
        by = base_y - building_height + 1
        for row_idx, row in enumerate(building):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = by + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    self.scene[py][px] = (char, color)

    def _draw_midrange_buildings(self, ground_y: int, cafe_left: int = 0, cafe_right: int = 0):
        """Draw mid-range buildings above 1/5 of screen, behind big buildings."""
        # Mid-range building sprites - larger than distant, outline style
        midrange_buildings = [
            [
                "  ____  ",
                " |    | ",
                " | [] | ",
                " |    | ",
                " | [] | ",
                " |____| ",
            ],
            [
                " _______ ",
                "|       |",
                "| [] [] |",
                "|       |",
                "| [] [] |",
                "|_______|",
            ],
            [
                "  ___  ",
                " |   | ",
                " | o | ",
                " |   | ",
                " |___| ",
            ],
            [
                " _________ ",
                "|         |",
                "| []   [] |",
                "|         |",
                "| []   [] |",
                "|         |",
                "|_________|",
            ],
        ]

        # Position at 1/5 from bottom of screen
        midrange_y = self.height - (self.height // 5)

        # Draw across the screen, but skip cafe area
        positions = list(range(0, self.width, 20))
        for i, pos_x in enumerate(positions):
            # Skip if overlapping with cafe area
            if cafe_left - 10 < pos_x < cafe_right + 5:
                continue
            building = midrange_buildings[i % len(midrange_buildings)]
            building_height = len(building)
            by = midrange_y - building_height
            for row_idx, row in enumerate(building):
                for col_idx, char in enumerate(row):
                    px = pos_x + col_idx
                    py = by + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        self.scene[py][px] = (char, Colors.ALLEY_MID)

    def _draw_tree(self, x: int, y: int):
        """Draw a tree at the given position, blowing in wind direction."""
        # Use windy tree sprite based on wind direction
        if self._wind_direction > 0:
            tree_sprite = self.TREE_WINDY_RIGHT
        else:
            tree_sprite = self.TREE_WINDY_LEFT
        for row_idx, row in enumerate(tree_sprite):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    # Use different colors for different parts
                    if char == '@':
                        # Leaves - green
                        self.scene[py][px] = (char, Colors.MATRIX_DIM)
                    elif char in '()|':
                        # Trunk and outline - brown/dark
                        self.scene[py][px] = (char, Colors.SAND_DIM)
                    elif char == '_':
                        # Base
                        self.scene[py][px] = (char, Colors.ALLEY_MID)
                    else:
                        self.scene[py][px] = (char, Colors.ALLEY_MID)

    def _draw_pine_tree(self, x: int, y: int):
        """Draw a pine tree at the given position, blowing in wind direction."""
        # Use windy pine sprite based on wind direction
        if self._wind_direction > 0:
            tree_sprite = self.PINE_TREE_WINDY_RIGHT
        else:
            tree_sprite = self.PINE_TREE_WINDY_LEFT
        for row_idx, row in enumerate(tree_sprite):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    if char == '*':
                        # Star on top - yellow
                        self.scene[py][px] = (char, Colors.RAT_YELLOW)
                    elif char in '/\\|':
                        # Pine needles and trunk - green
                        self.scene[py][px] = (char, Colors.MATRIX_DIM)
                    elif char == '_':
                        # Base
                        self.scene[py][px] = (char, Colors.ALLEY_MID)
                    else:
                        self.scene[py][px] = (char, Colors.MATRIX_DIM)

    def _draw_park(self, x: int, y: int, width: int):
        """Draw a small park with grass, bench, lamp, bushes and flowers."""
        if width < 15:
            return  # Too narrow for park

        # Store park position for pedestrian avoidance
        self._park_x = x
        self._park_y = y
        self._park_width = width

        # Draw grass base (green textured ground)
        grass_height = 4
        for row in range(grass_height):
            for col in range(width):
                px = x + col
                py = y - row
                if 0 <= px < self.width - 1 and 0 <= py < self.height:
                    # Varied grass texture
                    if (col + row) % 3 == 0:
                        self.scene[py][px] = ('░', Colors.MATRIX_DIM)
                    elif (col + row) % 5 == 0:
                        self.scene[py][px] = ('▒', Colors.STATUS_OK)
                    else:
                        self.scene[py][px] = ('░', Colors.STATUS_OK)

        # Draw a small fence at the front of the park
        fence_y = y
        for col in range(width):
            px = x + col
            if 0 <= px < self.width - 1 and 0 <= fence_y < self.height:
                if col == 0 or col == width - 1:
                    self.scene[fence_y][px] = ('|', Colors.ALLEY_MID)
                elif col % 4 == 0:
                    self.scene[fence_y][px] = ('|', Colors.ALLEY_MID)
                else:
                    self.scene[fence_y][px] = ('-', Colors.ALLEY_MID)

        # Draw park bench (in the middle)
        bench_x = x + width // 2 - len(self.PARK_BENCH[0]) // 2
        bench_y = y - 3
        for row_idx, row in enumerate(self.PARK_BENCH):
            for col_idx, char in enumerate(row):
                px = bench_x + col_idx
                py = bench_y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    self.scene[py][px] = (char, Colors.ALLEY_MID)

        # Draw park lamp (on the left side)
        lamp_x = x + 3
        lamp_y = y - len(self.PARK_LAMP)
        for row_idx, row in enumerate(self.PARK_LAMP):
            for col_idx, char in enumerate(row):
                px = lamp_x + col_idx
                py = lamp_y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    if char == 'O':
                        # Lamp glow - warm yellow
                        self.scene[py][px] = (char, Colors.RAT_YELLOW)
                    elif char in '()':
                        self.scene[py][px] = (char, Colors.ALLEY_LIGHT)
                    else:
                        self.scene[py][px] = (char, Colors.ALLEY_MID)

        # Draw bushes (on either side)
        bush1_x = x + 1
        bush2_x = x + width - len(self.SMALL_BUSH[0]) - 1
        bush_y = y - len(self.SMALL_BUSH)
        for bush_x in [bush1_x, bush2_x]:
            for row_idx, row in enumerate(self.SMALL_BUSH):
                for col_idx, char in enumerate(row):
                    px = bush_x + col_idx
                    py = bush_y + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        self.scene[py][px] = (char, Colors.MATRIX_DIM)

        # Draw flower bed (in front of bench)
        flower_x = x + width // 2 - len(self.FLOWER_BED[0]) // 2
        flower_y = y - 1
        for row_idx, row in enumerate(self.FLOWER_BED):
            for col_idx, char in enumerate(row):
                px = flower_x + col_idx
                py = flower_y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    if char == '*':
                        # Flowers - random colors (red, yellow, pink)
                        colors = [Colors.STATUS_ERROR, Colors.RAT_YELLOW, Colors.SHADOW_RED]
                        self.scene[py][px] = (char, random.choice(colors))
                    elif char == '.':
                        self.scene[py][px] = (char, Colors.STATUS_OK)  # Stems
                    else:
                        self.scene[py][px] = (char, Colors.MATRIX_DIM)  # Soil

    def _draw_cafe(self, x: int, y: int):
        """Draw a well-lit cafe storefront filled with warm color."""
        # Store cafe position
        self.cafe_x = x
        self.cafe_y = y

        total_rows = len(self.CAFE)
        total_cols = len(self.CAFE[0]) if self.CAFE else 0

        # Draw the cafe with warm lighting colors and fill empty space
        for row_idx, row in enumerate(self.CAFE):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height:
                    # Check if we're inside the cafe walls (between the | characters)
                    inside_cafe = False
                    if row_idx >= 1 and row_idx < total_rows - 1:
                        # Find wall positions in this row
                        left_wall = row.find('|')
                        right_wall = row.rfind('|')
                        if left_wall != -1 and right_wall != -1 and left_wall < col_idx < right_wall:
                            inside_cafe = True

                    if char != ' ':
                        # Use green for shell and cafe text, neutral for structure
                        # Turtle shell is rows 0-6
                        is_shell_row = row_idx < 7
                        if is_shell_row and char in '/\\|_`':
                            color = Colors.CAFE_GREEN  # Green turtle shell outline
                        elif char in 'SHELLCAFE':
                            color = Colors.CAFE_GREEN  # Green cafe name
                        elif char in 'OPEN':
                            color = Colors.ALLEY_LIGHT  # OPEN sign stays white
                        elif char in '[]=' or char == '~':
                            color = Colors.ALLEY_MID  # Windows - gray, no glow
                        elif char == 'O' and inside_cafe:
                            color = Colors.ALLEY_DARK  # People silhouettes - dark
                        elif char in '/\\' and not is_shell_row:
                            color = Colors.ALLEY_DARK  # People arms - dark
                        elif char == '|' and not is_shell_row:
                            color = Colors.ALLEY_MID  # Walls - gray
                        elif char in '_.-' and not is_shell_row:
                            color = Colors.ALLEY_MID  # Structure - gray
                        else:
                            color = Colors.ALLEY_MID  # Structure - gray
                        self.scene[py][px] = (char, color)
                    elif inside_cafe:
                        # Fill empty interior space with dark blocks (no warm glow)
                        self.scene[py][px] = ('▓', Colors.ALLEY_DARK)

    def is_valid_snow_position(self, x: int, y: int) -> bool:
        """Check if a position is valid for snow to collect.

        Snow can collect on: roof, window sills, ground, dumpster, box, curb.
        Snow should NOT collect on: building face (walls, between windows).
        """
        # Always allow snow on the ground/curb area (bottom 5 rows)
        ground_y = self.height - 5
        if y >= ground_y:
            return True

        # Check if position is on roof (within 2 rows of building top)
        if y <= self._building_y + 1 or y <= self._building2_y + 1:
            return True

        # Check if position is in the gap between buildings (alley)
        building1_right = self._building_x + len(self.BUILDING[0])
        building2_left = self._building2_x if self._building2_x > 0 else self.width
        if building1_right < x < building2_left:
            return True  # In the alley gap, allow snow

        # Check if position is on a window sill (rows with [====] pattern - every 6-7 rows)
        # Window sill rows relative to building top are: row 7, 13, 19, 25, 31 (bottom of each window section)
        # These correspond to building_y + row_offset
        building_sill_offsets = [7, 13, 19, 25, 31]

        # Check building 1
        if self._building_x <= x < self._building_x + len(self.BUILDING[0]):
            for offset in building_sill_offsets:
                sill_y = self._building_y + offset
                if y == sill_y or y == sill_y + 1:
                    return True
            return False  # On building face but not on sill

        # Check building 2
        if self._building2_x > 0 and self._building2_x <= x < self._building2_x + len(self.BUILDING2[0]):
            for offset in building_sill_offsets:
                sill_y = self._building2_y + offset
                if y == sill_y or y == sill_y + 1:
                    return True
            return False  # On building face but not on sill

        # Outside buildings, allow snow
        return True

    def is_roof_or_sill(self, x: int, y: int) -> bool:
        """Check if a position is specifically on a roof or window sill.

        Used to determine if snow should last 10x longer.
        """
        # Check if position is on roof (within 2 rows of building top)
        if self._building_y > 0 and y <= self._building_y + 1:
            if self._building_x <= x < self._building_x + len(self.BUILDING[0]):
                return True
        if self._building2_y > 0 and y <= self._building2_y + 1:
            if self._building2_x <= x < self._building2_x + len(self.BUILDING2[0]):
                return True

        # Check if position is on a window sill
        building_sill_offsets = [7, 13, 19, 25, 31]

        # Check building 1
        if self._building_x <= x < self._building_x + len(self.BUILDING[0]):
            for offset in building_sill_offsets:
                sill_y = self._building_y + offset
                if y == sill_y or y == sill_y + 1:
                    return True

        # Check building 2
        if self._building2_x > 0 and self._building2_x <= x < self._building2_x + len(self.BUILDING2[0]):
            for offset in building_sill_offsets:
                sill_y = self._building2_y + offset
                if y == sill_y or y == sill_y + 1:
                    return True

        return False

    def _generate_semi_sprite(self, direction: int, warning_message: Optional[str] = None) -> Tuple[List[str], int, int, int, str]:
        """Generate a unique semi-truck sprite with advertising.

        Uses seeded randomness based on system time for screenshot validation.
        Returns: (sprite, company_idx, layout_idx, color_idx, seed_hex)
        """
        # Create unique seed from base time + spawn counter
        self._semi_spawn_counter += 1
        seed = self._semi_seed_base + self._semi_spawn_counter
        rng = random.Random(seed)

        # Select company (50 options)
        company_idx = rng.randint(0, len(self.SEMI_COMPANIES) - 1)
        company = self.SEMI_COMPANIES[company_idx]

        # Select layout style (5 options)
        layout_idx = rng.randint(0, len(self.SEMI_LAYOUTS) - 1)

        # Select color (4 options)
        color_idx = rng.randint(0, len(self.SEMI_COLORS) - 1)

        # Generate seed hex for validation (last 8 chars of hex seed)
        seed_hex = format(seed & 0xFFFFFFFF, '08X')

        # Get text content from layout
        if warning_message:
            # Warning truck - show scrolling message
            line1 = warning_message[:27]
            line2 = warning_message[27:54] if len(warning_message) > 27 else ""
        else:
            # Normal advertising truck
            line1, line2 = self.SEMI_LAYOUTS[layout_idx](company)

        # Build sprite from base template
        # Note: Sprite shows which way truck FACES - cab must lead when moving
        if direction == 1:  # Going right - cab on right leads
            base = self.SEMI_LEFT_BASE
        else:  # Going left - cab on left leads
            base = self.SEMI_RIGHT_BASE

        sprite = []
        for row in base:
            formatted = row.format(line1=line1[:27], line2=line2[:27])
            sprite.append(formatted)

        return sprite, company_idx, layout_idx, color_idx, seed_hex

    def _get_semi_validation_string(self, car: Dict) -> str:
        """Get the validation string for a semi-truck (for screenshot verification)."""
        if car.get('type') != 'semi':
            return ""
        seed_hex = car.get('seed_hex', '????????')
        company_idx = car.get('company_idx', 0)
        layout_idx = car.get('layout_idx', 0)
        color_idx = car.get('color_idx', 0)
        return f"SEMI-{seed_hex}-C{company_idx:02d}L{layout_idx}K{color_idx}"

    def _generate_work_truck_sprite(self, direction: int, logo: str, line2: str) -> List[str]:
        """Generate a work truck sprite with logo text."""
        if direction == 1:
            base = self.WORK_TRUCK_RIGHT
        else:
            base = self.WORK_TRUCK_LEFT
        sprite = []
        for row in base:
            formatted = row.format(logo=logo[:10], line2=line2[:10])
            sprite.append(formatted)
        return sprite

    def _spawn_car(self, warning_message: Optional[str] = None):
        """Spawn a new car, taxi, truck, work truck, city truck, or semi-truck on the street.

        Vehicle distribution:
        - 45% regular cars (4 colors)
        - 10% taxis (yellow)
        - 20% regular trucks (4 colors with company names)
        - 10% work trucks (white with company logos)
        - 5% city trucks (Noire York departments)
        - 10% semi-trucks (50 companies, 5 layouts, 4 colors)

        Args:
            warning_message: If provided, spawns a warning semi-truck with this message
        """
        # Force semi if warning_message is provided
        if warning_message:
            vehicle_roll = 1.0  # Force semi
        else:
            vehicle_roll = random.random()

        # Play car sound effect via TTS audio engine
        self._play_car_sound('vehicle')

        # Determine direction first
        direction = 1 if random.random() < 0.5 else -1
        extra_data = {}

        if vehicle_roll < 0.45:
            # Regular car with random color from 4 options
            vehicle_type = 'car'
            sprite_right = self.CAR_RIGHT
            sprite_left = self.CAR_LEFT
            body_color = random.choice(self.CAR_BODY_COLORS)
            speed_range = (0.8, 1.5)
            spawn_offset = 25

        elif vehicle_roll < 0.55:
            # Taxi (always yellow)
            vehicle_type = 'taxi'
            sprite_right = self.TAXI_RIGHT
            sprite_left = self.TAXI_LEFT
            body_color = Colors.RAT_YELLOW
            speed_range = (0.9, 1.6)  # Taxis drive a bit faster
            spawn_offset = 25
            extra_data = {'is_taxi': True}

        elif vehicle_roll < 0.75:
            # Regular truck with color and company name
            vehicle_type = 'truck'
            sprite_right = self.TRUCK_RIGHT
            sprite_left = self.TRUCK_LEFT
            body_color = random.choice(self.TRUCK_BODY_COLORS)
            speed_range = (0.6, 1.2)
            spawn_offset = 30
            # Pick a random company name from the semi companies
            company = random.choice(self.SEMI_COMPANIES)
            extra_data = {'company': company}

        elif vehicle_roll < 0.85:
            # Work truck (white with company logo)
            vehicle_type = 'work_truck'
            company = random.choice(self.SEMI_COMPANIES)
            # Generate sprite with company name
            sprite = self._generate_work_truck_sprite(direction, company[:10], "SERVICE")
            body_color = Colors.ALLEY_LIGHT  # White
            speed_range = (0.5, 1.0)
            spawn_offset = 30
            extra_data = {'company': company}

            # Work truck already has sprite, spawn and return
            if direction == 1:
                self._cars.append({
                    'x': float(-spawn_offset),
                    'direction': 1,
                    'speed': random.uniform(*speed_range),
                    'sprite': sprite,
                    'color': body_color,
                    'type': vehicle_type,
                    **extra_data,
                })
            else:
                self._cars.append({
                    'x': float(self.width + spawn_offset),
                    'direction': -1,
                    'speed': random.uniform(*speed_range),
                    'sprite': sprite,
                    'color': body_color,
                    'type': vehicle_type,
                    **extra_data,
                })
            return

        elif vehicle_roll < 0.90:
            # Noire York City truck (white with city department)
            vehicle_type = 'city_truck'
            dept = random.choice(self.CITY_TRUCK_DEPARTMENTS)
            sprite = self._generate_work_truck_sprite(direction, dept[0][:10], dept[1][:10])
            body_color = Colors.ALLEY_LIGHT  # White city trucks
            speed_range = (0.4, 0.9)  # City trucks drive slower
            spawn_offset = 30
            extra_data = {'department': dept[1]}

            # City truck already has sprite, spawn and return
            if direction == 1:
                self._cars.append({
                    'x': float(-spawn_offset),
                    'direction': 1,
                    'speed': random.uniform(*speed_range),
                    'sprite': sprite,
                    'color': body_color,
                    'type': vehicle_type,
                    **extra_data,
                })
            else:
                self._cars.append({
                    'x': float(self.width + spawn_offset),
                    'direction': -1,
                    'speed': random.uniform(*speed_range),
                    'sprite': sprite,
                    'color': body_color,
                    'type': vehicle_type,
                    **extra_data,
                })
            return

        else:
            # Semi-truck with advertising
            vehicle_type = 'semi'
            speed_range = (0.4, 0.8)
            spawn_offset = 55  # Semi is much wider
            # Generate unique semi with advertising
            sprite, company_idx, layout_idx, color_idx, seed_hex = self._generate_semi_sprite(
                direction, warning_message
            )
            # Use semi-specific color
            body_color = self.SEMI_COLORS[color_idx]
            extra_data = {
                'company_idx': company_idx,
                'layout_idx': layout_idx,
                'color_idx': color_idx,
                'seed_hex': seed_hex,
                'is_warning': warning_message is not None,
                'warning_message': warning_message,
            }

            # Semi already has sprite, spawn and return
            if direction == 1:
                self._cars.append({
                    'x': float(-spawn_offset),
                    'direction': 1,
                    'speed': random.uniform(*speed_range),
                    'sprite': sprite,
                    'color': body_color,
                    'type': vehicle_type,
                    **extra_data,
                })
            else:
                self._cars.append({
                    'x': float(self.width + spawn_offset),
                    'direction': -1,
                    'speed': random.uniform(*speed_range),
                    'sprite': sprite,
                    'color': body_color,
                    'type': vehicle_type,
                    **extra_data,
                })
            return

        # For regular car/taxi/truck, spawn with the selected sprite
        if direction == 1:
            self._cars.append({
                'x': float(-spawn_offset),
                'direction': 1,
                'speed': random.uniform(*speed_range),
                'sprite': sprite_right,
                'color': body_color,
                'type': vehicle_type,
                **extra_data,
            })
        else:
            self._cars.append({
                'x': float(self.width + spawn_offset),
                'direction': -1,
                'speed': random.uniform(*speed_range),
                'sprite': sprite_left,
                'color': body_color,
                'type': vehicle_type,
                **extra_data,
            })

    def update(self):
        """Update traffic light state, cars, pedestrians, street light flicker, and window people.

        Performance optimized: Uses frame counters to throttle slow updates.
        - Every frame (fast): cars, pedestrians, traffic lights, QTE
        - Every 2 frames: closeup car, wind, steam, damage overlays
        - Every 3 frames: clouds, window people, cafe people
        - Every 5 frames: road effects, street lights, skyline windows
        - Every 10 frames: security canaries, holidays, UFO, prop plane
        """
        self._traffic_frame += 1
        self._frame_count += 1

        # State machine for traffic lights (with all-red transition) - EVERY FRAME
        self._state_duration += 1

        if self._traffic_state == 'NS_GREEN':
            if self._state_duration >= 80:
                self._traffic_state = 'NS_YELLOW'
                self._state_duration = 0
        elif self._traffic_state == 'NS_YELLOW':
            if self._state_duration >= 40:
                self._traffic_state = 'ALL_RED_TO_EW'
                self._state_duration = 0
        elif self._traffic_state == 'ALL_RED_TO_EW':
            if self._state_duration >= 15:
                self._traffic_state = 'EW_GREEN'
                self._state_duration = 0
        elif self._traffic_state == 'EW_GREEN':
            if self._state_duration >= 80:
                self._traffic_state = 'EW_YELLOW'
                self._state_duration = 0
        elif self._traffic_state == 'EW_YELLOW':
            if self._state_duration >= 40:
                self._traffic_state = 'ALL_RED_TO_NS'
                self._state_duration = 0
        elif self._traffic_state == 'ALL_RED_TO_NS':
            if self._state_duration >= 15:
                self._traffic_state = 'NS_GREEN'
                self._state_duration = 0

        # === EVERY FRAME (critical animations) ===
        self._update_cars()
        self._update_pedestrians()
        self._update_qte()  # QTE needs fast response
        self._update_woman_red()  # Special event needs smooth animation

        # === EVERY 2 FRAMES ===
        if self._frame_count % 2 == 0:
            self._update_closeup_car()
            self._update_wind()
            self._update_steam()
            self._update_damage_overlays()
            self._update_turtle()
            self._update_open_sign()

        # === EVERY 3 FRAMES ===
        if self._frame_count % 3 == 0:
            self._update_clouds()
            self._update_window_people()
            self._update_cafe_people()
            self._update_knocked_out_and_ambulance()

        # === EVERY 5 FRAMES ===
        if self._frame_count % 5 == 0:
            self._update_road_effects()
            self._update_street_light_flicker()
            self._update_skyline_windows()

        # === EVERY 10 FRAMES (slow updates) ===
        if self._frame_count % 10 == 0:
            self._update_security_canaries()
            self._update_ufo()
            self._update_prop_plane()
            # Holiday events (only during their active periods)
            if self._christmas_mode:
                self._update_christmas_lights()
            if self._halloween_mode:
                self._update_halloween()
            if self._july4th_mode:
                self._update_fireworks()

        # Wrap frame counter to prevent overflow
        if self._frame_count >= 1000:
            self._frame_count = 0

        # Update garden animation frame
        self._update_garden()

    def _update_garden(self):
        """Advance garden animation frame."""
        if self._garden_cache and self._garden_cache_valid:
            self._garden_frame_idx = (self._garden_frame_idx + 1) % len(self._garden_cache)

    def _update_road_effects(self):
        """Update subtle weather effects on road/sidewalk."""
        street_y = self.height - 3
        curb_y = self.height - 4

        # Update existing effects - decrement timers and remove expired
        self._road_effects = [e for e in self._road_effects if e['timer'] < e['duration']]
        for effect in self._road_effects:
            effect['timer'] += 1

        # Spawn new effects occasionally
        self._road_effect_timer += 1
        if self._road_effect_timer < self._road_effect_interval:
            return
        self._road_effect_timer = 0

        # Limit total effects to keep it subtle
        if len(self._road_effects) >= 8:
            return

        # Random chance to spawn based on weather
        if random.random() > 0.4:  # 40% chance per interval
            return

        # Pick random position on road or sidewalk
        x = random.randint(5, self.width - 10)
        y = random.choice([street_y, street_y + 1, curb_y]) if street_y + 1 < self.height else random.choice([street_y, curb_y])

        # Weather-specific effects
        if self._weather_mode == WeatherMode.MATRIX:
            # Code rifts - brief glimpses of matrix code through cracks
            chars = ['0', '1', '|', '/', '\\', 'ｱ', 'ｲ', 'ｳ']
            effect = {
                'x': x, 'y': y,
                'char': random.choice(chars),
                'color': Colors.MATRIX_BRIGHT,
                'timer': 0,
                'duration': random.randint(8, 20),  # Quick flash
                'type': 'code_rift'
            }
        elif self._weather_mode == WeatherMode.RAIN:
            # Water puddles and blue spots
            chars = ['~', '≈', '░', '▒', '.']
            effect = {
                'x': x, 'y': y,
                'char': random.choice(chars),
                'color': Colors.RAIN_DIM,
                'timer': 0,
                'duration': random.randint(60, 180),  # Longer lasting puddles
                'type': 'puddle'
            }
        elif self._weather_mode == WeatherMode.SNOW:
            # Blowing snow and frost patches
            chars = ['*', '·', '.', ':', '+']
            effect = {
                'x': x, 'y': y,
                'char': random.choice(chars),
                'color': Colors.SNOW_DIM,
                'timer': 0,
                'duration': random.randint(40, 120),
                'type': 'snow_patch'
            }
        elif self._weather_mode == WeatherMode.SAND:
            # Dust settling and sand drifts
            chars = ['.', ',', ':', '~', '°']
            effect = {
                'x': x, 'y': y,
                'char': random.choice(chars),
                'color': Colors.SAND_DIM,
                'timer': 0,
                'duration': random.randint(30, 90),
                'type': 'dust'
            }
        else:  # CALM
            # Subtle dust motes
            chars = ['.', ',', "'"]
            effect = {
                'x': x, 'y': y,
                'char': random.choice(chars),
                'color': Colors.ALLEY_MID,
                'timer': 0,
                'duration': random.randint(60, 150),
                'type': 'dust_mote'
            }

        self._road_effects.append(effect)

    def _update_cars(self):
        """Update car/truck/semi positions and spawn new vehicles."""
        # Spawn new vehicles occasionally
        self._car_spawn_timer += 1
        if self._car_spawn_timer >= random.randint(40, 100):
            if len(self._cars) < 3:  # Max 3 vehicles at once
                self._spawn_car()
            self._car_spawn_timer = 0

        # Update open doors (close them after pedestrian enters)
        new_open_doors = []
        for door in self._open_doors:
            door['timer'] += 1
            if door['timer'] < 50:  # Keep door open for 50 frames
                new_open_doors.append(door)
        self._open_doors = new_open_doors

        # Update taxi pickup state
        if self._taxi_pickup:
            self._taxi_pickup['timer'] += 1
            if self._taxi_pickup['state'] == 'stopping':
                # Taxi slowing down
                taxi = self._taxi_pickup['taxi']
                taxi['speed'] = max(0.1, taxi['speed'] - 0.1)
                if taxi['speed'] <= 0.1:
                    self._taxi_pickup['state'] = 'boarding'
                    self._taxi_pickup['timer'] = 0
            elif self._taxi_pickup['state'] == 'boarding':
                # Person getting in (handled in pedestrian update)
                if self._taxi_pickup['timer'] > 30:
                    self._taxi_pickup['state'] = 'leaving'
            elif self._taxi_pickup['state'] == 'leaving':
                # Taxi driving away
                taxi = self._taxi_pickup['taxi']
                taxi['speed'] = min(1.5, taxi['speed'] + 0.1)
                if self._taxi_pickup['timer'] > 60:
                    # Remove ped from waiting list
                    ped = self._taxi_pickup.get('ped')
                    if ped in self._waiting_taxi_peds:
                        self._waiting_taxi_peds.remove(ped)
                    self._taxi_pickup = None

        # Update vehicle positions
        new_cars = []
        for car in self._cars:
            # Check if this taxi should stop for a waiting pedestrian
            if car.get('is_taxi') and self._waiting_taxi_peds and not self._taxi_pickup:
                for ped in self._waiting_taxi_peds:
                    ped_x = ped.get('x', 0)
                    # Taxi is near the waiting pedestrian
                    if abs(car['x'] - ped_x) < 15:
                        # Start pickup sequence
                        self._taxi_pickup = {
                            'taxi': car,
                            'ped': ped,
                            'state': 'stopping',
                            'timer': 0
                        }
                        break

            car['x'] += car['direction'] * car['speed']

            # Calculate margin based on vehicle type (semis are much wider)
            vehicle_type = car.get('type', 'car')
            if vehicle_type == 'semi':
                margin = 60
            elif vehicle_type == 'truck':
                margin = 35
            else:
                margin = 30

            # Keep vehicle if it's still on screen (with margin)
            if -margin < car['x'] < self.width + margin:
                new_cars.append(car)

        self._cars = new_cars

    def _update_closeup_car(self):
        """Update close-up car perspective effect with two types: approaching and departing."""
        # Spawn new close-up car occasionally
        self._closeup_car_timer += 1
        if self._closeup_car is None and self._closeup_car_timer >= random.randint(200, 400):
            self._closeup_car_timer = 0
            # Calculate position between right street light and traffic light
            building1_right = self._building_x + len(self.BUILDING[0]) if hasattr(self, '_building_x') else 70
            building2_left = self._building2_x if hasattr(self, '_building2_x') else self.width - 60
            gap_center = (building1_right + building2_left) // 2
            street_light_x = gap_center + 38
            traffic_light_x = self.box_x + len(self.BOX[0]) + 100 if hasattr(self, 'box_x') else self.width - 20
            car_x = (street_light_x + traffic_light_x) // 2

            # Randomly choose car type: approaching (from distance) or departing (from behind camera)
            car_type = random.choice(['approaching', 'departing'])

            # Randomly decide if this closeup car is a taxi (25% chance)
            is_taxi = random.random() < 0.25

            if car_type == 'approaching':
                # Approaching: starts small/far, grows big, then disappears behind camera
                self._closeup_car = {
                    'x': float(car_x),
                    'direction': random.choice([-1, 1]),  # Face left or right
                    'scale': 0.5,  # Start small (far away)
                    'type': 'approaching',
                    'phase': 0,    # 0=growing, 1=passing behind camera
                    'scale_speed': 0.12,
                    'is_taxi': is_taxi,
                }
            else:
                # Departing: starts big (just passed camera), shrinks as it drives away
                self._closeup_car = {
                    'x': float(car_x),
                    'direction': random.choice([-1, 1]),  # Face left or right
                    'scale': 3.0,  # Start big (just passed camera)
                    'type': 'departing',
                    'phase': 0,    # 0=shrinking away
                    'scale_speed': 0.10,
                    'is_taxi': is_taxi,
                }

        # Update close-up car
        if self._closeup_car:
            car = self._closeup_car

            if car['type'] == 'approaching':
                # Approaching car: grows then passes behind camera
                if car['phase'] == 0:
                    # Growing phase - car approaching from distance
                    car['scale'] += car['scale_speed']
                    if car['scale'] >= 3.0:
                        car['scale'] = 3.0
                        car['phase'] = 1  # Now passing behind camera
                else:
                    # Passing behind camera - shrinks slightly then disappears
                    car['scale'] += car['scale_speed'] * 0.5  # Grows a tiny bit more
                    if car['scale'] >= 3.5:
                        self._closeup_car = None  # Passed behind camera

            else:  # departing
                # Departing car: shrinks as it drives away into distance
                car['scale'] -= car['scale_speed']
                if car['scale'] <= 0.3:
                    self._closeup_car = None  # Too far away to see

    def _spawn_pedestrian(self):
        """Spawn a new pedestrian on the sidewalk with random accessories, colors, and spacing."""
        # Check spacing - don't spawn if too close to existing pedestrians
        min_spacing = 8  # Minimum 8 chars between pedestrians
        direction = 1 if random.random() < 0.5 else -1

        if direction == 1:
            spawn_x = -5.0
            # Check for pedestrians near spawn point
            for ped in self._pedestrians:
                if ped['direction'] == 1 and abs(ped['x'] - spawn_x) < min_spacing:
                    return  # Too close, skip spawn
        else:
            spawn_x = float(self.width + 2)
            for ped in self._pedestrians:
                if ped['direction'] == -1 and abs(ped['x'] - spawn_x) < min_spacing:
                    return  # Too close, skip spawn

        # Randomly choose person type (basic, hat, briefcase, skirt)
        person_type_idx = random.randint(0, len(self.PERSON_TYPES_RIGHT) - 1)

        # Randomly choose skin tone and clothing color for diversity
        skin_color = random.choice(self.SKIN_TONES)
        clothing_color = random.choice(self.CLOTHING_COLORS)

        # Determine interaction behavior (50% have a destination)
        interaction = None
        destination_x = None
        rand = random.random()
        if rand < 0.15 and self._door_positions:
            # 15% go to a door (pick a door in their direction of travel)
            valid_doors = [d for d in self._door_positions
                          if (direction == 1 and d['x'] > spawn_x + 20) or
                             (direction == -1 and d['x'] < spawn_x - 20)]
            if valid_doors:
                door = random.choice(valid_doors)
                interaction = 'door'
                destination_x = door['x']
        elif rand < 0.22 and hasattr(self, 'mailbox_x'):
            # 7% mail a letter
            if (direction == 1 and self.mailbox_x > spawn_x) or \
               (direction == -1 and self.mailbox_x < spawn_x):
                interaction = 'mailbox'
                destination_x = self.mailbox_x - 2  # Stop next to mailbox
        elif rand < 0.30:
            # 8% hail a taxi
            # Pick a spot to wait at
            interaction = 'hail_taxi'
            if direction == 1:
                destination_x = random.uniform(self.width * 0.3, self.width * 0.7)
            else:
                destination_x = random.uniform(self.width * 0.3, self.width * 0.7)

        if direction == 1:
            # Pedestrian going right (spawn on left)
            self._pedestrians.append({
                'x': spawn_x,
                'direction': 1,
                'speed': random.uniform(0.3, 0.6),  # Slower than cars
                'frames': self.PERSON_TYPES_RIGHT[person_type_idx],
                'frame_idx': 0,
                'frame_timer': 0,
                'skin_color': skin_color,
                'clothing_color': clothing_color,
                'y_offset': random.choice([-1, 0, 1]),  # Wander on 2-row sidewalk
                'target_y_offset': random.choice([-1, 0, 1]),
                'y_wander_timer': random.randint(30, 80),
                'interaction': interaction,
                'destination_x': destination_x,
                'interaction_state': None,
                'interaction_timer': 0,
            })
        else:
            # Pedestrian going left (spawn on right)
            self._pedestrians.append({
                'x': spawn_x,
                'direction': -1,
                'speed': random.uniform(0.3, 0.6),
                'frames': self.PERSON_TYPES_LEFT[person_type_idx],
                'frame_idx': 0,
                'frame_timer': 0,
                'skin_color': skin_color,
                'clothing_color': clothing_color,
                'y_offset': random.choice([-1, 0, 1]),  # Wander on 2-row sidewalk
                'target_y_offset': random.choice([-1, 0, 1]),
                'y_wander_timer': random.randint(30, 80),
                'interaction': interaction,
                'destination_x': destination_x,
                'interaction_state': None,
                'interaction_timer': 0,
            })

    def _update_pedestrians(self):
        """Update pedestrian positions and spawn new pedestrians."""
        # Check if meteor event is active - pedestrians should panic
        meteor_active = self._qte_active and self._qte_state == 'active'

        # Check if woman in red scene is active - don't spawn during it
        woman_red_active = self._woman_red_active and self._woman_red_state not in ['idle', 'cooldown']

        # Spawn new pedestrians frequently (more pedestrians now)
        self._pedestrian_spawn_timer += 1
        spawn_interval = random.randint(3, 10)  # Spawn faster for more people
        if self._pedestrian_spawn_timer >= spawn_interval:
            if woman_red_active:
                max_peds = 6  # Few during Matrix scene
            elif meteor_active:
                max_peds = 12  # Fewer during meteor (they're running away)
            else:
                max_peds = 50  # Doubled from 25 to 50 pedestrians
            if len(self._pedestrians) < max_peds:
                self._spawn_pedestrian()
            self._pedestrian_spawn_timer = 0

        # Update pedestrian positions and arm animation
        new_pedestrians = []
        for ped in self._pedestrians:
            # During meteor event, pedestrians panic!
            if meteor_active:
                if not ped.get('panicking'):
                    # Start panicking - run faster in a random direction
                    ped['panicking'] = True
                    ped['panic_timer'] = 0
                    # Most run off screen, some dart around first
                    if random.random() < 0.7:
                        # Run off screen fast
                        ped['direction'] = random.choice([-1, 1])
                        ped['speed'] = random.uniform(1.5, 2.5)  # Run fast!
                    else:
                        # Dart around briefly before running
                        ped['darting'] = True
                        ped['dart_changes'] = random.randint(2, 4)

                if ped.get('darting'):
                    ped['panic_timer'] += 1
                    # Change direction rapidly while darting
                    if ped['panic_timer'] % 15 == 0:
                        ped['direction'] *= -1
                        ped['dart_changes'] -= 1
                        if ped['dart_changes'] <= 0:
                            # Done darting, now run off
                            ped['darting'] = False
                            ped['direction'] = random.choice([-1, 1])
                            ped['speed'] = random.uniform(1.8, 2.5)

                # Faster arm animation when panicking
                ped['frame_timer'] += 1
                if ped['frame_timer'] >= 1:  # Super fast arm swing
                    ped['frame_timer'] = 0
                    ped['frame_idx'] = (ped['frame_idx'] + 1) % len(ped['frames'])
            else:
                # Normal walking
                ped.pop('panicking', None)
                ped.pop('darting', None)

                # Check for interaction states
                interaction = ped.get('interaction')
                interaction_state = ped.get('interaction_state')
                destination_x = ped.get('destination_x')

                # Handle active interactions (pedestrian is stopped doing something)
                if interaction_state == 'mailing':
                    # Mailing a letter - stand still, animate
                    ped['interaction_timer'] += 1
                    if ped['interaction_timer'] > 60:  # Done mailing
                        self._mailbox_interaction = None
                        ped['interaction'] = None
                        ped['interaction_state'] = None
                        # Continue walking off screen
                    else:
                        self._mailbox_interaction = {'ped': ped, 'timer': ped['interaction_timer']}
                        continue  # Skip movement, add to new list at end
                elif interaction_state == 'entering_door':
                    # Entering a door - fade out / disappear
                    ped['interaction_timer'] += 1
                    if ped['interaction_timer'] > 30:  # Gone
                        # Remove door from open list after delay
                        continue  # Don't add to new_pedestrians, ped disappears
                    else:
                        new_pedestrians.append(ped)
                        continue  # Skip normal movement
                elif interaction_state == 'hailing':
                    # Hailing a taxi - wait for one to stop
                    ped['interaction_timer'] += 1
                    if ped['interaction_timer'] > 300:  # Give up after 5 seconds
                        ped['interaction'] = None
                        ped['interaction_state'] = None
                    elif self._taxi_pickup and self._taxi_pickup.get('ped') == ped:
                        # Taxi stopped for us
                        if self._taxi_pickup['state'] == 'boarding':
                            ped['interaction_timer'] += 1
                            if ped['interaction_timer'] > 20:
                                # Get in taxi and leave
                                self._taxi_pickup['state'] = 'leaving'
                                continue  # Remove pedestrian
                    new_pedestrians.append(ped)
                    continue  # Skip normal movement

                # Check if approaching destination
                if interaction and destination_x is not None and interaction_state is None:
                    dist = abs(ped['x'] - destination_x)
                    if dist < 3:  # Close enough to destination
                        if interaction == 'mailbox':
                            ped['interaction_state'] = 'mailing'
                            ped['interaction_timer'] = 0
                            ped['x'] = destination_x  # Snap to position
                            new_pedestrians.append(ped)
                            continue
                        elif interaction == 'door':
                            ped['interaction_state'] = 'entering_door'
                            ped['interaction_timer'] = 0
                            # Open the door
                            for door in self._door_positions:
                                if abs(door['x'] - destination_x) < 3:
                                    self._open_doors.append({
                                        'building': door['building'],
                                        'x': door['x'],
                                        'timer': 0
                                    })
                                    break
                            new_pedestrians.append(ped)
                            continue
                        elif interaction == 'hail_taxi':
                            ped['interaction_state'] = 'hailing'
                            ped['interaction_timer'] = 0
                            self._waiting_taxi_peds.append(ped)
                            new_pedestrians.append(ped)
                            continue

                # Normal arm animation
                ped['frame_timer'] += 1
                if ped['frame_timer'] >= 3:  # Normal arm swing
                    ped['frame_timer'] = 0
                    ped['frame_idx'] = (ped['frame_idx'] + 1) % len(ped['frames'])

            # Movement (skip if in certain states)
            if ped.get('interaction_state') not in ['mailing', 'entering_door', 'hailing']:
                ped['x'] += ped['direction'] * ped['speed']

            # Y wandering - pedestrians drift up/down on sidewalk to pass each other
            # Allow walking 4 rows closer (more negative offset) when under a building
            if not meteor_active:
                ped['y_wander_timer'] = ped.get('y_wander_timer', 50) - 1
                if ped['y_wander_timer'] <= 0:
                    # Check if under a building - allows walking closer to cafe
                    under_building = False
                    ped_x = ped['x']
                    if hasattr(self, '_building_x') and hasattr(self, '_building2_x'):
                        b1_left = self._building_x
                        b1_right = self._building_x + len(self.BUILDING[0])
                        b2_left = self._building2_x
                        b2_right = self._building2_x + len(self.BUILDING2[0])
                        if b1_left < ped_x < b1_right or b2_left < ped_x < b2_right:
                            under_building = True
                    # Pick new target y position - allow up to -5 when under building
                    # Walk 2 rows lower in front of buildings (positive offset = lower on screen)
                    if under_building:
                        ped['target_y_offset'] = random.choice([-5, -4, -3, -2, -1, 0, 1])
                    else:
                        ped['target_y_offset'] = random.choice([1, 2, 3])
                    ped['y_wander_timer'] = random.randint(40, 100)

                # Gradually move toward target y
                current_y = ped.get('y_offset', 0)
                target_y = ped.get('target_y_offset', 0)
                if current_y < target_y:
                    ped['y_offset'] = current_y + 1
                elif current_y > target_y:
                    ped['y_offset'] = current_y - 1

            # Keep pedestrian if still on screen (with margin)
            if -10 < ped['x'] < self.width + 10:
                new_pedestrians.append(ped)

        self._pedestrians = new_pedestrians

    def check_lightning_knockout(self, lightning_x: int):
        """Check if lightning struck near any pedestrians and knock them out."""
        self._last_lightning_x = lightning_x
        curb_y = self.height - 4  # Where pedestrians walk

        # Check each pedestrian for proximity to lightning
        knocked_out = []
        remaining = []
        for ped in self._pedestrians:
            ped_x = int(ped['x'])
            # If lightning is within 5 chars of pedestrian, knock them out
            if abs(ped_x - lightning_x) < 6:
                # Knock out this pedestrian
                knocked_out.append({
                    'x': ped_x,
                    'y': curb_y,
                    'timer': 0,
                    'skin_color': ped.get('skin_color', Colors.ALLEY_LIGHT),
                    'clothing_color': ped.get('clothing_color', Colors.ALLEY_MID),
                    'reviving': False,
                })
            else:
                remaining.append(ped)

        self._pedestrians = remaining
        self._knocked_out_peds.extend(knocked_out)
        # Limit knocked out peds to prevent memory growth (ambulance cleans up normally)
        if len(self._knocked_out_peds) > 10:
            self._knocked_out_peds = self._knocked_out_peds[-10:]

    def _update_knocked_out_and_ambulance(self):
        """Update knocked out pedestrians and ambulance revival system."""
        # Handle knocked out pedestrians
        for ko_ped in self._knocked_out_peds:
            ko_ped['timer'] += 1

        # Spawn ambulance if there are knocked out peds and no active ambulance
        if self._knocked_out_peds and self._ambulance is None and self._ambulance_cooldown <= 0:
            # Find the first knocked out ped to help
            target = self._knocked_out_peds[0]
            # Ambulance comes from whichever side is closer
            if target['x'] < self.width // 2:
                spawn_x = self.width + 25
                direction = -1
            else:
                spawn_x = -25
                direction = 1

            self._ambulance = {
                'x': float(spawn_x),
                'direction': direction,
                'state': 'arriving',  # arriving, stopped, paramedic_out, reviving, paramedic_return, leaving
                'target_ped': target,
                'paramedic_x': 0.0,
                'timer': 0,
            }

        # Update ambulance cooldown
        if self._ambulance_cooldown > 0:
            self._ambulance_cooldown -= 1

        # Update ambulance state machine
        if self._ambulance:
            amb = self._ambulance
            amb['timer'] += 1

            if amb['state'] == 'arriving':
                # Drive towards the knocked out pedestrian
                amb['x'] += amb['direction'] * 0.8
                target_x = amb['target_ped']['x']
                # Stop when close to the target
                if abs(amb['x'] - target_x) < 12:
                    amb['state'] = 'stopped'
                    amb['timer'] = 0

            elif amb['state'] == 'stopped':
                # Wait briefly then send out paramedic
                if amb['timer'] > 30:
                    amb['state'] = 'paramedic_out'
                    amb['timer'] = 0
                    # Paramedic starts at ambulance position
                    if amb['direction'] == 1:
                        amb['paramedic_x'] = amb['x'] + 10  # Right side of ambulance
                    else:
                        amb['paramedic_x'] = amb['x'] - 2  # Left side of ambulance

            elif amb['state'] == 'paramedic_out':
                # Paramedic walks to victim
                target_x = amb['target_ped']['x']
                if abs(amb['paramedic_x'] - target_x) > 2:
                    # Walk towards victim
                    if amb['paramedic_x'] < target_x:
                        amb['paramedic_x'] += 0.5
                    else:
                        amb['paramedic_x'] -= 0.5
                else:
                    amb['state'] = 'reviving'
                    amb['timer'] = 0
                    amb['target_ped']['reviving'] = True

            elif amb['state'] == 'reviving':
                # Reviving takes time
                if amb['timer'] > 90:  # 1.5 seconds
                    # Remove the knocked out ped from list
                    if amb['target_ped'] in self._knocked_out_peds:
                        self._knocked_out_peds.remove(amb['target_ped'])
                    amb['state'] = 'paramedic_return'
                    amb['timer'] = 0

            elif amb['state'] == 'paramedic_return':
                # Paramedic walks back to ambulance
                if amb['direction'] == 1:
                    target_x = amb['x'] + 10
                else:
                    target_x = amb['x'] - 2

                if abs(amb['paramedic_x'] - target_x) > 1:
                    if amb['paramedic_x'] < target_x:
                        amb['paramedic_x'] += 0.5
                    else:
                        amb['paramedic_x'] -= 0.5
                else:
                    amb['state'] = 'leaving'
                    amb['timer'] = 0

            elif amb['state'] == 'leaving':
                # Ambulance drives away
                amb['x'] += amb['direction'] * 1.0
                # Remove when off screen
                if amb['x'] < -30 or amb['x'] > self.width + 30:
                    self._ambulance = None
                    self._ambulance_cooldown = 120  # 2 second cooldown before next ambulance

    def _update_street_light_flicker(self):
        """Update street light flicker effect."""
        self._flicker_timer += 1

        # Randomly adjust flicker brightness for each light
        for i in range(len(self._street_light_flicker)):
            # Slight random variation
            if random.random() < 0.1:  # 10% chance of flicker per frame
                # Flicker down briefly
                self._street_light_flicker[i] = random.uniform(0.3, 0.7)
            elif self._street_light_flicker[i] < 1.0:
                # Gradually return to full brightness
                self._street_light_flicker[i] = min(1.0, self._street_light_flicker[i] + 0.1)

        # Update building window lights with on/off and brightness variation
        self._window_light_timer += 1

        # Update all windows (scenes visible based on light state)
        # Flicker array only tracks big windows that have light glows
        flicker_idx = 0
        for window in self._all_windows:
            # Occasionally toggle lights on/off (~0.3% chance per frame = ~once per 5.5 sec)
            if random.random() < 0.003:
                window['light_on'] = not window['light_on']
                if window['light_on']:
                    # Use discrete brightness levels for visible variation
                    window['brightness'] = random.choice([0.3, 0.5, 0.7, 0.9, 1.0])
                else:
                    window['brightness'] = 0.0

            # Only update flicker for big windows (they have light glows)
            if window['is_big'] and flicker_idx < len(self._building_window_flicker):
                if window['light_on']:
                    if random.random() < 0.03:  # 3% chance - subtle flicker
                        self._building_window_flicker[flicker_idx] = window['brightness'] * random.uniform(0.6, 0.95)
                    else:
                        # Gradually return to window's brightness level
                        target = window['brightness']
                        if self._building_window_flicker[flicker_idx] < target:
                            self._building_window_flicker[flicker_idx] = min(target, self._building_window_flicker[flicker_idx] + 0.05)
                else:
                    self._building_window_flicker[flicker_idx] = 0.0
                flicker_idx += 1

    def _update_window_people(self):
        """Update people walking by windows with walk/stare/wave animations."""
        self._window_spawn_timer += 1

        # Spawn people frequently (about every 60-150 frames) for more activity
        if self._window_spawn_timer >= random.randint(60, 150):
            self._window_spawn_timer = 0
            if len(self._window_people) < 8:  # Allow up to 8 window people at once
                # Pick a random window from either building
                building = random.choice([1, 2])
                if building == 1:
                    positions = self.BUILDING_WINDOW_POSITIONS
                    window_idx = random.randint(0, len(positions) - 1)
                else:
                    positions = self.BUILDING2_WINDOW_POSITIONS
                    window_idx = random.randint(0, len(positions) - 1)

                # Start from edge, walking state
                start_left = random.random() < 0.5
                self._window_people.append({
                    'building': building,
                    'window_idx': window_idx,
                    'direction': 1 if start_left else -1,
                    'progress': 0.0 if start_left else 1.0,
                    'state': 'walking',  # walking, staring, waving, leaving
                    'state_timer': 0,
                    'stare_duration': random.randint(80, 200),  # Long stare
                    'wave_count': 0,
                    'wave_frame': 0,
                })

        # Update existing window people
        new_window_people = []
        for person in self._window_people:
            person['state_timer'] += 1

            if person['state'] == 'walking':
                # Move person across window
                speed = 0.03
                person['progress'] += person['direction'] * speed

                # Check if reached center of window - stop to stare
                if 0.35 < person['progress'] < 0.65 and random.random() < 0.02:
                    person['state'] = 'staring'
                    person['state_timer'] = 0
                    person['progress'] = 0.5  # Center in window

                # Keep walking if not done
                if person['progress'] < -0.3 or person['progress'] > 1.3:
                    continue  # Remove person - walked off

            elif person['state'] == 'staring':
                # Person stares out window for a long time
                if person['state_timer'] >= person['stare_duration']:
                    # Start waving before leaving
                    person['state'] = 'waving'
                    person['state_timer'] = 0
                    person['wave_count'] = 0

            elif person['state'] == 'waving':
                # Wave animation - 3 waves
                person['wave_frame'] = (person['state_timer'] // 5) % 2  # Alternate every 5 frames
                if person['state_timer'] >= 30:  # Wave for 30 frames (about 3 waves)
                    person['state'] = 'leaving'
                    person['state_timer'] = 0
                    # Pick direction to leave
                    person['direction'] = random.choice([-1, 1])

            elif person['state'] == 'leaving':
                # Walk away from window
                speed = 0.04
                person['progress'] += person['direction'] * speed

                # Remove when off screen
                if person['progress'] < -0.3 or person['progress'] > 1.3:
                    continue  # Remove person

            new_window_people.append(person)

        self._window_people = new_window_people

    def _update_cafe_people(self):
        """Update the 3 people in Shell Cafe's lower window - gentle movement and arm animation."""
        self._cafe_people_timer += 1

        for person in self._cafe_people:
            person['move_timer'] += 1
            person['arm_timer'] += 1

            # Move person slightly back and forth within their zone
            if person['move_timer'] >= random.randint(30, 60):
                person['move_timer'] = 0
                # Small movements within their section of the window
                person['x_offset'] += person['direction'] * 0.5
                # Bounds check - each person has a ~5 char zone
                base_x = self._cafe_people.index(person) * 6.0
                if person['x_offset'] > base_x + 2.0:
                    person['direction'] = -1
                elif person['x_offset'] < base_x - 2.0:
                    person['direction'] = 1
                # Occasionally reverse direction randomly
                if random.random() < 0.2:
                    person['direction'] *= -1

            # Animate arms - cycle through arm positions
            if person['arm_timer'] >= random.randint(20, 50):
                person['arm_timer'] = 0
                person['arm_frame'] = (person['arm_frame'] + 1) % 4

    def _update_turtle(self):
        """Update turtle head animation - peeks out of shell and winks."""
        self._turtle_timer += 1

        if self._turtle_state == 'hidden':
            # Wait for cooldown then peek out
            if self._turtle_timer >= self._turtle_cooldown:
                self._turtle_state = 'peeking'
                self._turtle_timer = 0
                self._turtle_frame = 0  # Normal eyes
                self._turtle_side = random.choice([1, -1])  # Random side
                self._turtle_visible_duration = random.randint(180, 360)  # 3-6 seconds

        elif self._turtle_state == 'peeking':
            # Stay visible, occasionally wink
            if self._turtle_timer >= 30:  # Every 0.5 seconds
                self._turtle_timer = 0
                # 30% chance to wink
                if random.random() < 0.3:
                    self._turtle_state = 'winking'
                    self._turtle_frame = random.choice([1, 2])  # Left or right wink
                else:
                    self._turtle_frame = random.choice([0, 0, 0, 3])  # Mostly normal, sometimes happy
            # Check if should retreat
            self._turtle_visible_duration -= 1
            if self._turtle_visible_duration <= 0:
                self._turtle_state = 'retreating'
                self._turtle_timer = 0

        elif self._turtle_state == 'winking':
            # Brief wink then back to peeking
            if self._turtle_timer >= 15:  # 0.25 second wink
                self._turtle_state = 'peeking'
                self._turtle_timer = 0
                self._turtle_frame = 0

        elif self._turtle_state == 'retreating':
            # Go back to hidden
            if self._turtle_timer >= 20:
                self._turtle_state = 'hidden'
                self._turtle_timer = 0
                self._turtle_cooldown = random.randint(300, 900)  # 5-15 seconds

    def queue_plane_announcement(self, message: str):
        """Queue a message to be displayed by a prop plane with banner.

        Used for mode changes, weather changes, and similar announcements.
        """
        self._prop_plane_queue.append(message)

    def _update_prop_plane(self):
        """Update prop plane position and spawn new planes for queued messages."""
        # Handle cooldown
        if self._prop_plane_cooldown > 0:
            self._prop_plane_cooldown -= 1

        # Spawn new plane if queue has messages and no active plane
        if self._prop_plane is None and self._prop_plane_queue and self._prop_plane_cooldown <= 0:
            message = self._prop_plane_queue.pop(0)
            direction = random.choice([1, -1])
            # Plane flies in upper portion of screen
            y = random.randint(3, max(4, self.height // 4))

            if direction == 1:
                x = -len(self.PROP_PLANE_RIGHT[1]) - len(message) - 10
            else:
                x = self.width + 10

            self._prop_plane = {
                'x': float(x),
                'y': y,
                'direction': direction,
                'speed': random.uniform(2.0, 3.5),  # 5x faster
                'message': message,
                'scroll_offset': 0,
            }
            self._prop_plane_cooldown = 300  # 5 seconds between planes

        # Update active plane
        if self._prop_plane:
            self._prop_plane['x'] += self._prop_plane['direction'] * self._prop_plane['speed']

            # Check if plane has exited screen
            plane_width = len(self.PROP_PLANE_RIGHT[1]) + len(self._prop_plane['message']) + 10
            if self._prop_plane['direction'] == 1:
                if self._prop_plane['x'] > self.width + 10:
                    self._prop_plane = None
            else:
                if self._prop_plane['x'] < -plane_width:
                    self._prop_plane = None

    def _get_traffic_light_colors(self) -> Tuple[Tuple[str, int], Tuple[str, int], Tuple[str, int],
                                                   Tuple[str, int], Tuple[str, int], Tuple[str, int]]:
        """Get the current light colors for both directions.

        Returns: (ns_red, ns_yellow, ns_green, ew_red, ew_yellow, ew_green)
        Each is a tuple of (char, color).
        """
        # Define light states - off lights are gray circles
        off = ('o', Colors.GREY_BLOCK)
        red_on = ('O', Colors.SHADOW_RED)
        yellow_on = ('O', Colors.RAT_YELLOW)
        green_on = ('O', Colors.STATUS_OK)

        if self._traffic_state == 'NS_GREEN':
            # NS has green, EW has red
            return (off, off, green_on, red_on, off, off)
        elif self._traffic_state == 'NS_YELLOW':
            # NS has yellow, EW has red
            return (off, yellow_on, off, red_on, off, off)
        elif self._traffic_state == 'ALL_RED_TO_EW':
            # Both red (transition from NS to EW)
            return (red_on, off, off, red_on, off, off)
        elif self._traffic_state == 'EW_GREEN':
            # NS has red, EW has green
            return (red_on, off, off, off, off, green_on)
        elif self._traffic_state == 'EW_YELLOW':
            # NS has red, EW has yellow
            return (red_on, off, off, off, yellow_on, off)
        elif self._traffic_state == 'ALL_RED_TO_NS':
            # Both red (transition from EW to NS)
            return (red_on, off, off, red_on, off, off)
        else:
            # Default to NS green
            return (off, off, green_on, red_on, off, off)

    def _draw_sprite(self, sprite: List[str], x: int, y: int, color: int):
        """Draw an ASCII sprite at the given position."""
        for row_idx, row in enumerate(sprite):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    self.scene[py][px] = (char, color)

    def _draw_box_with_label(self, x: int, y: int):
        """Draw box with hashtag fill and white label."""
        for row_idx, row in enumerate(self.BOX):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    if char == 'X':
                        # White label
                        self.scene[py][px] = ('#', Colors.ALLEY_LIGHT)
                    else:
                        self.scene[py][px] = (char, Colors.SAND_DIM)

    def _draw_crosswalk(self, x: int, curb_y: int, street_y: int):
        """Draw vanishing street with hashtag crosswalk at sidewalk level."""
        crosswalk_width = 32

        # Draw hashtag (#) crosswalk pattern at sidewalk/street level
        # Pattern: horizontal bars with vertical stripes forming a grid
        hashtag_height = 3  # Height of crosswalk pattern
        hashtag_start_y = street_y - hashtag_height + 1  # At street level

        for cy in range(hashtag_height):
            py = hashtag_start_y + cy
            if 0 <= py < self.height:
                for cx in range(crosswalk_width):
                    px = x + cx
                    if 0 <= px < self.width - 1:
                        # Horizontal bars at top and bottom of pattern
                        if cy == 0 or cy == hashtag_height - 1:
                            self.scene[py][px] = ('═', Colors.ALLEY_LIGHT)
                        # Vertical bars every 4 characters
                        elif cx % 4 == 0:
                            self.scene[py][px] = ('║', Colors.ALLEY_LIGHT)
                        else:
                            # Street surface between stripes
                            self.scene[py][px] = ('▒', Colors.ALLEY_MID)

        # Draw vanishing street effect above the curb
        # Starts at curb and ends at lower 1/5th of screen
        vanish_end_y = self.height - (self.height // 5)  # Lower 1/5th of screen
        vanish_start_y = curb_y - 1  # Just above curb

        # Calculate crosswalk center for vanishing point
        crosswalk_center = x + crosswalk_width // 2

        for row_y in range(vanish_start_y, vanish_end_y - 1, -1):
            # Calculate perspective narrowing as we go up
            progress = (vanish_start_y - row_y) / max(1, vanish_start_y - vanish_end_y)
            # Street narrows as it goes into distance
            half_width = int((crosswalk_width // 2) * (1.0 - progress * 0.7))

            for offset in range(-half_width, half_width + 1):
                px = crosswalk_center + offset
                if 0 <= px < self.width - 1 and vanish_end_y <= row_y < vanish_start_y:
                    # Draw street surface with lane markings
                    if offset == 0:
                        # Center line - vertical || pattern (yellow)
                        self.scene[row_y][px] = ('|', Colors.RAT_YELLOW)
                    elif offset == 1:
                        # Second | of the || center line
                        self.scene[row_y][px] = ('|', Colors.RAT_YELLOW)
                    elif offset == -half_width:
                        # Left edge line (use forward slash for perspective - narrows toward top)
                        self.scene[row_y][px] = ('/', Colors.ALLEY_MID)
                    elif offset == half_width:
                        # Right edge line (use backslash for perspective - narrows toward top)
                        self.scene[row_y][px] = ('\\', Colors.ALLEY_MID)
                    else:
                        # Street surface
                        self.scene[row_y][px] = ('▓', Colors.ALLEY_DARK)

    def _draw_building(self, sprite: List[str], x: int, y: int):
        """Draw a building with grey blocks on bottom half story and red bricks on upper.

        The bottom ~8 rows (near door/porch) get grey blocks, upper rows get red bricks.
        Windows remain in blue/cyan color. Satellite dishes are grey.
        Brick outline around windows. Grey blocks fully filled with transparent texture.
        Door knobs rendered in gold. Roof items have solid dark backgrounds.
        """
        total_rows = len(sprite)
        # Grey block section: bottom 11 rows (half story with door, one row lower)
        grey_start_row = total_rows - 7  # 4 less grey (was -11), 4 more brick
        # Brick character for even texture
        brick_char = '▓'
        # Roof items section (rows with satellite dishes, antennas, etc.)
        roof_items_end = 5  # First 5 rows are roof items

        # First pass: find window boundaries for each row
        def is_inside_window(row_str: str, col: int) -> bool:
            """Check if a column is inside a window (between [ and ])."""
            # Find all [ and ] positions in the row
            bracket_open = -1
            for i, c in enumerate(row_str):
                if c == '[':
                    bracket_open = i
                elif c == ']':
                    if bracket_open != -1 and bracket_open < col < i:
                        return True
                    bracket_open = -1
            return False

        def is_window_outline(row_str: str, col: int) -> bool:
            """Check if position is adjacent to a window (for brick outline)."""
            # Check if there's a [ or ] within 1 character
            for offset in [-1, 0, 1]:
                check_col = col + offset
                if 0 <= check_col < len(row_str):
                    if row_str[check_col] in '[]':
                        return True
            return False

        # Helper to check if position is adjacent to a roof item (for filling behind items)
        def is_near_roof_item(row_str: str, col: int, row_idx: int, sprite: List[str]) -> bool:
            """Check if a position is adjacent to a roof item character."""
            roof_chars = 'O_|/\\()=[]'
            # Check horizontally adjacent
            for offset in [-1, 0, 1]:
                check_col = col + offset
                if 0 <= check_col < len(row_str):
                    if row_str[check_col] in roof_chars:
                        return True
            # Check vertically adjacent
            for row_offset in [-1, 1]:
                check_row = row_idx + row_offset
                if 0 <= check_row < len(sprite):
                    if col < len(sprite[check_row]) and sprite[check_row][col] in roof_chars:
                        return True
            return False

        for row_idx, row in enumerate(sprite):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height:
                    # Roof items rows (0-4) - only fill behind actual roof items, not entire area
                    if row_idx < roof_items_end:
                        if char == ' ':
                            # Only fill with dark if adjacent to a roof item
                            if is_near_roof_item(row, col_idx, row_idx, sprite):
                                self.scene[py][px] = ('█', Colors.ALLEY_DARK)
                            # Otherwise leave empty (transparent to sky/tunnel)
                        elif char in 'O_|/\\()=':
                            # Roof item characters - grey
                            self.scene[py][px] = (char, Colors.GREY_BLOCK)
                        elif char == '-':
                            # Roof line
                            self.scene[py][px] = (char, Colors.ALLEY_BLUE)
                        elif char == '.':
                            # Roof edge
                            self.scene[py][px] = (char, Colors.ALLEY_MID)
                        else:
                            self.scene[py][px] = (char, Colors.GREY_BLOCK)
                        continue

                    # Check if inside a window
                    inside_window = is_inside_window(row, col_idx)

                    if char != ' ':
                        # Determine color based on character and position
                        if char in '[]=' or (char == '-' and row_idx == roof_items_end):
                            # Window frames and roof line - keep blue
                            color = Colors.ALLEY_BLUE
                            # Store window frame positions for layering (draw on top of window people)
                            if char in '[]=':
                                self._window_frame_positions.append((px, py, char))
                        elif char in '|_.':
                            # Structural elements
                            if row_idx >= grey_start_row:
                                color = Colors.GREY_BLOCK
                            else:
                                color = Colors.BRICK_RED
                        elif char == '#':
                            # Check if this is a door window (# inside brackets in door area)
                            # Door windows are in the grey zone and have pattern |[####]|
                            if row_idx >= grey_start_row and inside_window:
                                # Door window - render in blue
                                color = Colors.ALLEY_BLUE
                            elif row_idx >= grey_start_row:
                                color = Colors.GREY_BLOCK
                            else:
                                color = Colors.BRICK_RED
                        else:
                            # Default
                            if row_idx >= grey_start_row:
                                color = Colors.GREY_BLOCK
                            else:
                                color = Colors.BRICK_RED

                        self.scene[py][px] = (char, color)
                    else:
                        # Empty space - add texture based on zone
                        # Fill window interior with SOLID dark background (prevents seeing through)
                        if inside_window:
                            self.scene[py][px] = ('█', Colors.ALLEY_DARK)
                            # Store window interior position for layering
                            self._window_interior_positions.append((px, py))
                            continue

                        if row_idx >= roof_items_end and row_idx < grey_start_row:
                            # Red brick zone - fill completely
                            self.scene[py][px] = (brick_char, Colors.BRICK_RED)
                        elif row_idx >= grey_start_row and row_idx < total_rows - 2:
                            # Grey zone - fill with consistent blocks (no random smudges)
                            # Bottom row of grey zone gets smudged texture
                            if row_idx == total_rows - 3:
                                # Smudge row at bottom of building (just above porch)
                                self.scene[py][px] = ('▒', Colors.GREY_BLOCK)
                            else:
                                # Solid consistent grey blocks
                                self.scene[py][px] = ('▓', Colors.GREY_BLOCK)
                        # Bottom 2 rows (porch/stoop level) - leave empty, no blocks

        # Second pass: add door knobs
        # Find door positions (look for the door pattern .------.)
        for row_idx, row in enumerate(sprite):
            if '.------.' in row:
                door_col = row.index('.------.')
                # Door knob should be in middle of door, on the right side
                knob_row = row_idx + 3  # Middle of door
                knob_col = door_col + 6  # Right side of door
                if knob_row < total_rows:
                    knob_px = x + knob_col
                    knob_py = y + knob_row
                    if 0 <= knob_px < self.width - 1 and 0 <= knob_py < self.height:
                        self.scene[knob_py][knob_px] = ('o', Colors.DOOR_KNOB_GOLD)

    def _draw_building_side_walls(self, building_x: int, building_y: int, building_width: int, building_height: int, side: str):
        """Draw 3-character wide vanishing point side walls on buildings.

        Args:
            building_x: Left edge of building
            building_y: Top of building
            building_width: Width of building sprite
            building_height: Height of building sprite
            side: 'left' for lighter wall, 'right' for darker shadow wall
        """
        wall_width = 3
        wall_chars = ['▓', '▒', '░']  # Gradient from building edge outward

        # Skip top rows (rooftop items) - start lower to avoid being too tall
        start_row = 5

        for row in range(start_row, building_height - 2):  # Skip bottom porch rows
            py = building_y + row
            if py < 0 or py >= self.height:
                continue

            for w in range(wall_width):
                if side == 'left':
                    # Left side wall - lighter color (sun-lit), extends left
                    px = building_x - w - 1
                    # Lighter color
                    color = Colors.ALLEY_MID if w == 0 else Colors.ALLEY_LIGHT
                    char = wall_chars[w] if w < len(wall_chars) else '░'
                else:
                    # Right side wall - darker color (shadow), extends right
                    px = building_x + building_width + w
                    # Darker color for shadow
                    color = Colors.ALLEY_DARK
                    char = wall_chars[wall_width - w - 1] if w < len(wall_chars) else '░'

                if 0 <= px < self.width - 1:
                    self.scene[py][px] = (char, color)

    def render(self, screen):
        """Render the alley scene to the screen with proper layering."""
        # Render background stars first (furthest back, only when tunnel is off)
        self._render_background_stars(screen)

        # Render constellation (behind clouds and buildings, only when tunnel is off)
        self._render_constellation(screen)

        # Render distant clouds first (furthest back, behind everything)
        self._render_distant_clouds(screen)

        # Render dotted fog layer (behind main clouds)
        self._render_dotted_fog(screen)

        # Render main clouds (behind buildings, on top of fog)
        self._render_clouds(screen)

        # Render UFO event (in sky, behind buildings)
        self._render_ufo(screen)

        # Render static scene elements (except window frames - those go on top)
        for y, row in enumerate(self.scene):
            if y >= self.height:
                break
            for x, (char, color) in enumerate(row):
                if x >= self.width - 1:  # Leave last column empty to avoid scroll
                    break
                if char != ' ':
                    try:
                        attr = curses.color_pair(color) | curses.A_DIM
                        screen.attron(attr)
                        screen.addstr(y, x, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

        # Render window scenes (unique mini scenes inside each window)
        self._render_window_scenes(screen)

        # Render window people silhouettes (behind window frames)
        self._render_window_people(screen)

        # Render cafe people in Shell Cafe lower window
        self._render_cafe_people(screen)

        # Render cafe sign (green SHELL CAFE and animated OPEN sign)
        self._render_cafe_sign(screen)

        # Render turtle head peeking from shell
        self._render_turtle(screen)

        # Render colorful animated garden in front of Shell Cafe
        self._render_garden(screen)

        # Render prop plane with banner (flies in sky)
        self._render_prop_plane(screen)

        # Render window frames on top of window people (so people appear inside)
        self._render_window_frames(screen)

        # Render trees as foreground layer (in front of buildings)
        self._render_trees(screen)
        self._render_pine_trees(screen)

        # Render holiday events
        self._render_fireworks(screen)  # 4th of July fireworks in sky
        self._render_pumpkins(screen)   # Halloween pumpkins near trees
        self._render_easter_eggs(screen)  # Easter eggs hidden in scene

        # Render sidewalk/curb on top of scene but behind all sprites
        self._render_sidewalk(screen)

        # Render subtle weather effects on road/sidewalk
        self._render_road_effects(screen)

        # Render street light flicker effects
        self._render_street_light_flicker(screen)

        # Render building window lights (glow without pole)
        self._render_building_window_lights(screen)

        # Render steam effects from manholes/drains
        self._render_steam(screen)

        # Render meteor damage overlays
        self._render_damage_overlays(screen)

        # Render wind effects (debris, leaves, wisps)
        self._render_wind(screen)

        # Render open mailbox if someone is mailing
        self._render_mailbox_interaction(screen)

        # Render open doors
        self._render_open_doors(screen)

        # Render pedestrians on the sidewalk
        self._render_pedestrians(screen)

        # Render knocked out pedestrians and ambulance
        self._render_knocked_out_peds(screen)
        self._render_ambulance(screen)

        # Render Woman in Red event (on top of regular pedestrians)
        self._render_woman_red(screen)

        # Render traffic light (dynamic - lights change)
        self._render_traffic_light(screen)

        # Render close-up car (perspective effect)
        self._render_closeup_car(screen)

        # Render horizontal cars on the street LAST (on top of everything)
        self._render_cars(screen)

        # Render foreground clouds (big, fast, on top of scene)
        self._render_foreground_clouds(screen)

        # Render QTE event (meteors, missiles, explosions, NPC) on top of everything
        self._render_qte(screen)

        # Render solid fog layer at top (on top of EVERYTHING)
        self._render_fog_layer(screen)

    def _render_fog_layer(self, screen):
        """Render solid fog layer at top of screen - on top of everything."""
        # Render solid cloud cover at rows 1-2, on top of all other rendering
        for row in range(1, 3):
            for x in range(self.width - 1):
                if 0 <= row < self.height:
                    try:
                        # Get the stored fog character from scene
                        char, color = self.scene[row][x] if x < len(self.scene[row]) else ('█', Colors.GREY_BLOCK)
                        if char in '█▓▒░':  # Only render fog characters
                            attr = curses.color_pair(color)
                            screen.attron(attr)
                            screen.addstr(row, x, char)
                            screen.attroff(attr)
                    except curses.error:
                        pass

    def _render_window_frames(self, screen):
        """Render window frames on top of window people for proper layering."""
        for px, py, char in self._window_frame_positions:
            if 0 <= px < self.width - 1 and 0 <= py < self.height:
                try:
                    attr = curses.color_pair(Colors.ALLEY_BLUE) | curses.A_DIM
                    screen.attron(attr)
                    screen.addstr(py, px, char)
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_sidewalk(self, screen):
        """Render sidewalk/curb on top of scene but behind sprites."""
        for px, py, char, color in self._sidewalk_positions:
            if 0 <= px < self.width - 1 and 0 <= py < self.height:
                try:
                    attr = curses.color_pair(color)
                    screen.attron(attr)
                    screen.addstr(py, px, char)
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_road_effects(self, screen):
        """Render subtle weather effects on road/sidewalk."""
        for effect in self._road_effects:
            x, y = effect['x'], effect['y']
            if 0 <= x < self.width - 1 and 0 <= y < self.height:
                # Calculate fade based on timer (fade in/out)
                progress = effect['timer'] / effect['duration']
                # Quick fade in, longer fade out
                if progress < 0.1:
                    # Fade in
                    alpha = progress / 0.1
                elif progress > 0.7:
                    # Fade out
                    alpha = (1.0 - progress) / 0.3
                else:
                    alpha = 1.0

                # Skip if too faded
                if alpha < 0.3:
                    continue

                try:
                    attr = curses.color_pair(effect['color'])
                    # Bright for code rifts and new effects
                    if effect['type'] == 'code_rift' or alpha > 0.8:
                        attr |= curses.A_BOLD
                    elif alpha < 0.5:
                        attr |= curses.A_DIM

                    screen.attron(attr)
                    screen.addstr(y, x, effect['char'])
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_steam(self, screen):
        """Render steam rising from manholes and drains."""
        if not self._steam_effects:
            return
        for steam in self._steam_effects:
            frame = self.STEAM_FRAMES[steam['frame']]
            base_x = steam['x']
            base_y = steam['y']

            # Draw steam rising (3 rows above the source)
            for row_idx, row in enumerate(frame):
                py = base_y - row_idx - 1  # Above the manhole/drain
                for col_idx, char in enumerate(row):
                    px = base_x + col_idx - 2  # Center the steam
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        try:
                            # Steam is white/light gray
                            attr = curses.color_pair(Colors.ALLEY_LIGHT)
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_damage_overlays(self, screen):
        """Render meteor damage overlays on the scene - fades from red to gray."""
        if not self._damage_overlays:
            return
        for overlay in self._damage_overlays:
            px = overlay['x']
            py = overlay['y']
            if 0 <= px < self.width - 1 and 0 <= py < self.height:
                try:
                    # Damage fades gradually: red -> orange -> gray -> dim gray -> gone
                    fade_progress = overlay['timer'] / overlay['fade_time']
                    if fade_progress < 0.15:
                        # Fresh damage - bright red
                        attr = curses.color_pair(Colors.SHADOW_RED) | curses.A_BOLD
                    elif fade_progress < 0.3:
                        # Cooling - red, no bold
                        attr = curses.color_pair(Colors.BRICK_RED)
                    elif fade_progress < 0.5:
                        # Cooled - bright gray
                        attr = curses.color_pair(Colors.ALLEY_LIGHT)
                    elif fade_progress < 0.7:
                        # Fading - medium gray
                        attr = curses.color_pair(Colors.ALLEY_MID)
                    elif fade_progress < 0.85:
                        # Old - dim gray
                        attr = curses.color_pair(Colors.GREY_BLOCK) | curses.A_DIM
                    else:
                        # Almost gone - very dim
                        attr = curses.color_pair(Colors.ALLEY_DARK) | curses.A_DIM
                    screen.attron(attr)
                    screen.addstr(py, px, overlay['char'])
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_wind(self, screen):
        """Render wind effects - debris, leaves, and wisps."""
        # Early exit if no wind effects
        if not self._debris and not self._wind_wisps and not self._leaves:
            return
        # Render debris (newspapers, trash, leaves on ground)
        for d in self._debris:
            px = int(d['x'])
            py = int(d['y'])
            if 0 <= px < self.width - 1 and 0 <= py < self.height:
                try:
                    if d.get('color') == 'leaf':
                        attr = curses.color_pair(Colors.MATRIX_DIM)
                    elif d.get('color') == 'paper':
                        attr = curses.color_pair(Colors.ALLEY_LIGHT)
                    else:
                        attr = curses.color_pair(Colors.ALLEY_MID)
                    screen.attron(attr)
                    screen.addstr(py, px, d['char'])
                    screen.attroff(attr)
                except curses.error:
                    pass

        # Render wind wisps in sky
        for w in self._wind_wisps:
            px = int(w['x'])
            py = int(w['y'])
            for i, char in enumerate(w['chars']):
                cx = px + i
                if 0 <= cx < self.width - 1 and 0 <= py < self.height:
                    try:
                        attr = curses.color_pair(Colors.ALLEY_MID) | curses.A_DIM
                        screen.attron(attr)
                        screen.addstr(py, cx, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

        # Render leaves blowing from trees
        for leaf in self._leaves:
            px = int(leaf['x'])
            py = int(leaf['y'])
            if 0 <= px < self.width - 1 and 0 <= py < self.height:
                try:
                    attr = curses.color_pair(Colors.MATRIX_DIM)
                    screen.attron(attr)
                    screen.addstr(py, px, leaf['char'])
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_mailbox_interaction(self, screen):
        """Render open mailbox when someone is mailing a letter."""
        if not self._mailbox_interaction:
            return

        timer = self._mailbox_interaction.get('timer', 0)
        # Only show open mailbox during middle of interaction
        if 10 < timer < 50:
            # Draw open mailbox over the regular mailbox
            mailbox_x = getattr(self, 'mailbox_x', 0)
            mailbox_y = getattr(self, 'mailbox_y', 0)
            if mailbox_x > 0:
                for row_idx, row in enumerate(self.MAILBOX_OPEN):
                    for col_idx, char in enumerate(row):
                        px = mailbox_x + col_idx
                        py = mailbox_y + row_idx
                        if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                            try:
                                # Open slot is highlighted
                                if char == '█':
                                    attr = curses.color_pair(Colors.ALLEY_DARK)
                                else:
                                    attr = curses.color_pair(Colors.ALLEY_BLUE)
                                screen.attron(attr)
                                screen.addstr(py, px, char)
                                screen.attroff(attr)
                            except curses.error:
                                pass

    def _render_open_doors(self, screen):
        """Render open doors when people are entering buildings."""
        if not self._open_doors:
            return

        ground_y = self.height - 1
        for door in self._open_doors:
            door_x = door.get('x', 0)
            building = door.get('building')

            # Door is at ground level, 5 rows tall
            door_y = ground_y - 4

            # Render open door overlay
            for row_idx, row in enumerate(self.DOOR_OPEN):
                for col_idx, char in enumerate(row):
                    px = door_x + col_idx - 3  # Center the door
                    py = door_y + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        try:
                            # Dark interior with frame
                            if char == '░':
                                attr = curses.color_pair(Colors.ALLEY_DARK)
                            elif char in '.|─[]':
                                attr = curses.color_pair(Colors.ALLEY_MID)
                            else:
                                attr = curses.color_pair(Colors.GREY_BLOCK)
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_qte(self, screen):
        """Render the meteor QTE event - meteors, missiles, explosions, NPC."""
        if not self._qte_active:
            # Clear any leftover positions from previous frame when QTE ends
            for (px, py, w, h) in self._qte_last_meteor_positions:
                for dy in range(h):
                    for dx in range(w):
                        cx, cy = px + dx, py + dy
                        if 0 <= cx < self.width - 1 and 0 <= cy < self.height:
                            try:
                                screen.addstr(cy, cx, ' ')
                            except curses.error:
                                pass
            self._qte_last_meteor_positions = []
            return

        # Track current meteor positions for cleanup next frame
        current_positions = []

        # Render meteors
        for meteor in self._qte_meteors:
            px = int(meteor['x'])
            py = int(meteor['y'])

            # Select sprite based on size
            if meteor['size'] == 'large':
                sprite = self.METEOR_LARGE
            elif meteor['size'] == 'medium':
                sprite = self.METEOR_MEDIUM
            else:
                sprite = self.METEOR_SMALL

            # Draw meteor sprite
            for row_idx, row in enumerate(sprite):
                for col_idx, char in enumerate(row):
                    cx = px + col_idx - len(row) // 2
                    cy = py + row_idx
                    if 0 <= cx < self.width - 1 and 0 <= cy < self.height and char != ' ':
                        try:
                            # Meteors are orange/red when falling, gray when waiting
                            if meteor['called']:
                                attr = curses.color_pair(Colors.SHADOW_RED) | curses.A_BOLD
                            else:
                                attr = curses.color_pair(Colors.ALLEY_MID)
                            screen.attron(attr)
                            screen.addstr(cy, cx, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

            # Track meteor position for cleanup (include sprite bounds + label)
            sprite_w = len(sprite[0]) if sprite else 5
            sprite_h = len(sprite) + 2  # +2 for label above
            current_positions.append((px - sprite_w // 2, py - 2, sprite_w + 3, sprite_h + 2))

            # Draw key indicator above meteor
            if not meteor['called']:
                key = self.QTE_KEYS[meteor['col']]
                key_x = px
                key_y = py - 1
                if 0 <= key_x < self.width - 1 and 0 <= key_y < self.height:
                    try:
                        attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                        screen.attron(attr)
                        screen.addstr(key_y, key_x, f"[{key}]")
                        screen.attroff(attr)
                    except curses.error:
                        pass

        # Save positions for cleanup next frame
        self._qte_last_meteor_positions = current_positions

        # Render missiles
        for missile in self._qte_missiles:
            px = int(missile['x'])
            py = int(missile['y'])

            for row_idx, row in enumerate(self.MISSILE):
                for col_idx, char in enumerate(row):
                    cx = px + col_idx - len(row) // 2
                    cy = py + row_idx
                    if 0 <= cx < self.width - 1 and 0 <= cy < self.height and char != ' ':
                        try:
                            attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_BOLD
                            screen.attron(attr)
                            screen.addstr(cy, cx, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

        # Render explosions
        for exp in self._qte_explosions:
            frame_idx = min(exp['frame'], len(self.EXPLOSION_FRAMES) - 1)
            frame = self.EXPLOSION_FRAMES[frame_idx]
            px = exp['x']
            py = exp['y']

            for row_idx, row in enumerate(frame):
                for col_idx, char in enumerate(row):
                    cx = px + col_idx - len(row) // 2
                    cy = py + row_idx - len(frame) // 2
                    if 0 <= cx < self.width - 1 and 0 <= cy < self.height and char != ' ':
                        try:
                            attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                            screen.attron(attr)
                            screen.addstr(cy, cx, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

        # Render NPC caller
        npc_x = self._qte_npc_x
        npc_y = self.height - 8

        for row_idx, row in enumerate(self.NPC_CALLER):
            for col_idx, char in enumerate(row):
                cx = npc_x + col_idx
                cy = npc_y + row_idx
                if 0 <= cx < self.width - 1 and 0 <= cy < self.height and char != ' ':
                    try:
                        attr = curses.color_pair(Colors.MATRIX_BRIGHT) | curses.A_BOLD
                        screen.attron(attr)
                        screen.addstr(cy, cx, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

        # Render NPC message/callout
        if self._qte_npc_message:
            msg_x = npc_x + 5
            msg_y = npc_y
            msg = self._qte_npc_message
            if 0 <= msg_y < self.height and msg_x + len(msg) < self.width:
                try:
                    # Message box background
                    attr = curses.color_pair(Colors.ALLEY_DARK)
                    screen.attron(attr)
                    screen.addstr(msg_y, msg_x - 1, ' ' * (len(msg) + 2))
                    screen.attroff(attr)

                    # Message text
                    attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                    screen.attron(attr)
                    screen.addstr(msg_y, msg_x, msg)
                    screen.attroff(attr)
                except curses.error:
                    pass

        # Render wave/score info
        if self._qte_state == 'active':
            info = f"Wave {self._qte_wave}/{self._qte_total_waves} | Score: {self._qte_score} | Miss: {self._qte_misses}"
            info_x = self.width // 2 - len(info) // 2
            info_y = 5
            if 0 <= info_y < self.height and 0 <= info_x < self.width:
                try:
                    attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_BOLD
                    screen.attron(attr)
                    screen.addstr(info_y, info_x, info)
                    screen.attroff(attr)
                except curses.error:
                    pass

    def _render_woman_red(self, screen):
        """Render the Woman in Red event characters."""
        if not self._woman_red_active:
            return

        curb_y = self.height - 4  # Same as pedestrians

        def draw_character(x, sprite, color, is_blonde=False, is_transform=False):
            """Helper to draw a character sprite at position."""
            px_start = int(x)
            sprite_height = len(sprite)

            for row_idx, row in enumerate(sprite):
                for col_idx, char in enumerate(row):
                    px = px_start + col_idx
                    py = curb_y - (sprite_height - 1 - row_idx)

                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        try:
                            # Special coloring for woman in red
                            if is_blonde and row_idx == 0 and char == '~':
                                # Blonde hair - yellow
                                attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                            elif is_transform and char == '#':
                                # Glitch effect - flashing
                                attr = curses.color_pair(Colors.MATRIX_BRIGHT) | curses.A_BOLD
                            elif is_transform and char == '?':
                                # Partial transform - dim
                                attr = curses.color_pair(Colors.ALLEY_MID)
                            else:
                                attr = curses.color_pair(color)
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

        # Render based on current state
        if self._woman_red_state in ['neo_morpheus_enter', 'woman_enters', 'woman_passes', 'woman_waves', 'woman_pauses']:
            # Draw Neo (dark coat)
            neo_sprite = self.NEO_RIGHT_FRAMES[self._neo_frame]
            draw_character(self._neo_x, neo_sprite, Colors.ALLEY_BLUE)

            # Draw Morpheus (slightly behind Neo)
            morpheus_sprite = self.MORPHEUS_RIGHT_FRAMES[self._morpheus_frame]
            draw_character(self._morpheus_x, morpheus_sprite, Colors.GREY_BLOCK)

        if self._woman_red_state in ['woman_enters', 'woman_passes']:
            # Draw Woman in Red walking left
            woman_sprite = self.WOMAN_RED_LEFT_FRAMES[self._woman_red_frame]
            draw_character(self._woman_red_x, woman_sprite, Colors.SHADOW_RED, is_blonde=True)

        elif self._woman_red_state == 'woman_waves':
            # Draw Woman waving (10x faster)
            wave_frame = (self._woman_red_timer // 1) % len(self.WOMAN_RED_WAVE_FRAMES)
            woman_sprite = self.WOMAN_RED_WAVE_FRAMES[wave_frame]
            draw_character(self._woman_red_x, woman_sprite, Colors.SHADOW_RED, is_blonde=True)

        elif self._woman_red_state == 'woman_pauses':
            # Draw Woman standing still (last wave frame)
            woman_sprite = self.WOMAN_RED_WAVE_FRAMES[0]
            draw_character(self._woman_red_x, woman_sprite, Colors.SHADOW_RED, is_blonde=True)

        elif self._woman_red_state == 'transform':
            # Draw transform effect
            frame_idx = min(self._transform_frame, len(self.TRANSFORM_FRAMES) - 1)
            transform_sprite = self.TRANSFORM_FRAMES[frame_idx]
            draw_character(self._woman_red_x, transform_sprite, Colors.MATRIX_BRIGHT, is_transform=True)

        elif self._woman_red_state == 'chase':
            # Draw Neo running away (left)
            neo_sprite = self.NEO_LEFT_FRAMES[self._neo_frame]
            draw_character(self._neo_x, neo_sprite, Colors.ALLEY_BLUE)

            # Draw Morpheus running away (left)
            morpheus_sprite = self.MORPHEUS_LEFT_FRAMES[self._morpheus_frame]
            draw_character(self._morpheus_x, morpheus_sprite, Colors.GREY_BLOCK)

            # Draw Agent Smith chasing (left)
            agent_sprite = self.AGENT_SMITH_LEFT_FRAMES[self._agent_frame]
            draw_character(self._agent_x, agent_sprite, Colors.ALLEY_MID)

    def _render_cars(self, screen):
        """Render vehicles (cars, trucks, semis) on the street. Tied to log_watchdog health."""
        # Security canary: no vehicles if log watchdog is down
        if not self._security_canary.get('vehicles', True):
            return
        # Early exit if no cars
        if not self._cars:
            return
        # Vehicles are 4-5 rows tall, bottom row at street level
        street_y = self.height - 1
        # Vehicles can't render above the 1/5th line
        min_car_y = self.height // 5

        for car in self._cars:
            # Apply lane offset based on direction:
            # Cars going left (direction==-1, "down screen"/far lane) offset 8 chars left
            # Cars going right (direction==1, "up screen"/near lane) offset 2 chars left
            direction = car.get('direction', 1)
            if direction == -1:
                lane_offset = -8  # Far lane - 8 chars to the left
            else:
                lane_offset = -2  # Near lane - 2 chars to the left
            x = int(car['x']) + lane_offset
            sprite = car['sprite']
            sprite_height = len(sprite)
            body_color = car.get('color', Colors.ALLEY_LIGHT)

            for row_idx, row in enumerate(sprite):
                for col_idx, char in enumerate(row):
                    px = x + col_idx
                    # Position sprite so bottom row is at street level
                    py = street_y - (sprite_height - 1 - row_idx)

                    # Don't render cars above the 1/5th line
                    if 0 <= px < self.width - 1 and min_car_y <= py < self.height and char != ' ':
                        try:
                            # Realistic vehicle coloring with colored outlines:
                            # - Tires (O) are dark/black
                            # - Outline chars (/, \, -, _, |) get car's color
                            # - Body panels (█) get the car's color (bold)
                            # - Parentheses around tires stay dark
                            if char == 'O':
                                # Tire center - dark black
                                attr = curses.color_pair(Colors.ALLEY_DARK) | curses.A_BOLD
                            elif char in '()':
                                # Tire edges - dark
                                attr = curses.color_pair(Colors.ALLEY_DARK)
                            elif char == '█':
                                # Body panels - car's color (bold)
                                attr = curses.color_pair(body_color) | curses.A_BOLD
                            elif char in '/\\':
                                # Windshield and diagonal outlines - car's color
                                attr = curses.color_pair(body_color)
                            elif char in '-_':
                                # Horizontal outlines - car's color
                                attr = curses.color_pair(body_color)
                            elif char == '|':
                                # Vertical outlines and windows - car's color
                                attr = curses.color_pair(body_color)
                            elif char == '°':
                                # Headlight - bright yellow
                                attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                            else:
                                # Other chars (letters for TAXI etc) - car's color
                                attr = curses.color_pair(body_color)
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_pedestrians(self, screen):
        """Render pedestrians on the sidewalk. Tied to process_security health."""
        # Security canary: no pedestrians if process security is down
        if not self._security_canary.get('pedestrians', True):
            return
        # Early exit if no pedestrians
        if not self._pedestrians:
            return
        # Pedestrians walk on the curb/sidewalk area (at street level)
        base_curb_y = self.height - 1

        for ped in self._pedestrians:
            x = int(ped['x'])
            # Get y offset for wandering (pedestrians can be on different rows)
            y_offset = ped.get('y_offset', 0)
            curb_y = base_curb_y + y_offset  # Apply wandering offset

            # Check for special interaction poses
            interaction_state = ped.get('interaction_state')
            if interaction_state == 'hailing':
                # Use hailing pose instead of walking
                if ped.get('direction', 1) == 1:
                    sprite = self.PERSON_HAILING_RIGHT
                else:
                    sprite = self.PERSON_HAILING_LEFT
            elif interaction_state == 'mailing':
                # Use mailing pose
                sprite = self.PERSON_MAILING
            elif interaction_state == 'entering_door':
                # Fade out effect - skip rendering after a few frames
                timer = ped.get('interaction_timer', 0)
                if timer > 15:
                    continue  # Don't render, they're inside
                # Get current animation frame for partial render
                frames = ped.get('frames', [])
                frame_idx = ped.get('frame_idx', 0)
                if frames and frame_idx < len(frames):
                    sprite = frames[frame_idx]
                else:
                    continue
            else:
                # Get current animation frame
                frames = ped.get('frames', [])
                frame_idx = ped.get('frame_idx', 0)
                if frames and frame_idx < len(frames):
                    sprite = frames[frame_idx]
                else:
                    continue

            sprite_height = len(sprite)
            # Get colors for this pedestrian
            skin_color = ped.get('skin_color', Colors.ALLEY_LIGHT)
            clothing_color = ped.get('clothing_color', Colors.ALLEY_MID)

            for row_idx, row in enumerate(sprite):
                for col_idx, char in enumerate(row):
                    px = x + col_idx
                    # Position sprite so bottom row is at curb level
                    py = curb_y - (sprite_height - 1 - row_idx)

                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        try:
                            # Row 0 = head (skin tone), row 1-2 = body (clothing), row 3 = legs
                            if row_idx == 0:  # Head row - use skin tone
                                color = skin_color
                            elif row_idx in [1, 2]:  # Body rows - use clothing color
                                color = clothing_color
                            else:  # Legs - darker
                                color = Colors.GREY_BLOCK
                            attr = curses.color_pair(color)
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_knocked_out_peds(self, screen):
        """Render knocked out pedestrians lying on the ground."""
        curb_y = self.height - 1

        for ko_ped in self._knocked_out_peds:
            x = int(ko_ped['x'])
            y = curb_y

            sprite = self.KNOCKED_OUT_SPRITE[0]
            skin_color = ko_ped.get('skin_color', Colors.ALLEY_LIGHT)

            for col_idx, char in enumerate(sprite):
                px = x + col_idx - 3  # Center the sprite
                if 0 <= px < self.width - 1 and 0 <= y < self.height and char != ' ':
                    try:
                        # Use flashing color if being revived
                        if ko_ped.get('reviving', False) and ko_ped['timer'] % 10 < 5:
                            color = Colors.STATUS_OK
                        else:
                            color = skin_color
                        attr = curses.color_pair(color)
                        screen.attron(attr)
                        screen.addstr(y, px, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

    def _render_ambulance(self, screen):
        """Render ambulance and paramedic."""
        if not self._ambulance:
            return

        amb = self._ambulance
        x = int(amb['x'])
        curb_y = self.height - 1
        y = curb_y - 3  # Ambulance is 4 rows tall

        # Choose sprite based on direction
        if amb['direction'] == 1:
            sprite = self.AMBULANCE_RIGHT
        else:
            sprite = self.AMBULANCE_LEFT

        # Render ambulance
        for row_idx, row in enumerate(sprite):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = y + row_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    try:
                        # Red cross, white body
                        if char == '+':
                            color = Colors.SHADOW_RED
                        elif char in ['░', 'O']:
                            color = Colors.ALLEY_LIGHT
                        else:
                            color = Colors.GREY_BLOCK
                        attr = curses.color_pair(color)
                        screen.attron(attr)
                        screen.addstr(py, px, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

        # Render paramedic if out of ambulance
        if amb['state'] in ['paramedic_out', 'reviving', 'paramedic_return']:
            para_x = int(amb['paramedic_x'])
            para_y = curb_y - 2  # Paramedic is 3 rows
            for row_idx, row in enumerate(self.PARAMEDIC_SPRITE):
                for col_idx, char in enumerate(row):
                    px = para_x + col_idx
                    py = para_y + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                        try:
                            # Green uniform
                            color = Colors.STATUS_OK
                            attr = curses.color_pair(color)
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_closeup_car(self, screen):
        """Render close-up car with perspective shrinking effect."""
        if not self._closeup_car:
            return

        car = self._closeup_car
        x = int(car['x'])  # Position calculated in _update_closeup_car
        scale = car['scale']
        direction = car['direction']
        is_taxi = car.get('is_taxi', False)
        # Calculate vertical offset based on scale (moves up as car shrinks)
        # At scale 3.0 (largest) = 0 offset, at scale 0.8 (smallest) = moves up
        scale_progress = (3.0 - scale) / 2.2  # 0 to 1 as car shrinks
        y_offset = int(scale_progress * (self.height // 5))  # Move up 1/5 of screen

        # Different car/taxi sprites based on scale (biggest to smallest)
        if scale >= 2.5:
            # Huge car (just passed camera)
            if is_taxi:
                if direction == 1:
                    sprite = [
                        "     _TAXI_       ",
                        "  .============.",
                        " /              \\",
                        "|  [O]      [O]  |",
                        "|________________|",
                        "  (__)       (__)",
                    ]
                else:
                    sprite = [
                        "      _TAXI_      ",
                        ".============.  ",
                        "/              \\",
                        "|  [O]      [O]  |",
                        "|________________|",
                        "  (__)       (__) ",
                    ]
            else:
                if direction == 1:
                    sprite = [
                        "  .============.",
                        " /              \\",
                        "|  [O]      [O]  |",
                        "|________________|",
                        "  (__)       (__)",
                    ]
                else:
                    sprite = [
                        ".============.  ",
                        "/              \\",
                        "|  [O]      [O]  |",
                        "|________________|",
                        "  (__)       (__) ",
                    ]
        elif scale >= 1.8:
            # Large car
            if is_taxi:
                if direction == 1:
                    sprite = [
                        "   _TAXI_   ",
                        " .========.",
                        "|  [O]  [O] |",
                        "|__________|",
                        " (__)  (__)",
                    ]
                else:
                    sprite = [
                        "   _TAXI_   ",
                        ".========. ",
                        "| [O]  [O] |",
                        "|__________|",
                        "(__)  (__) ",
                    ]
            else:
                if direction == 1:
                    sprite = [
                        " .========.",
                        "|  [O]  [O] |",
                        "|__________|",
                        " (__)  (__)",
                    ]
                else:
                    sprite = [
                        ".========. ",
                        "| [O]  [O] |",
                        "|__________|",
                        "(__)  (__) ",
                    ]
        elif scale >= 1.3:
            # Medium car (normal-ish)
            if is_taxi:
                if direction == 1:
                    sprite = [
                        " _TAXI_",
                        " .=====.",
                        "| O  O |",
                        "|______|",
                        " ()  ()",
                    ]
                else:
                    sprite = [
                        "_TAXI_ ",
                        ".=====. ",
                        "| O  O |",
                        "|______|",
                        "()  () ",
                    ]
            else:
                if direction == 1:
                    sprite = [
                        " .=====.",
                        "| O  O |",
                        "|______|",
                        " ()  ()",
                    ]
                else:
                    sprite = [
                        ".=====. ",
                        "| O  O |",
                        "|______|",
                        "()  () ",
                    ]
        else:
            # Small car (far away) - no TAXI text visible at this distance
            if direction == 1:
                sprite = [
                    " .==.",
                    "|OO|",
                ]
            else:
                sprite = [
                    ".==. ",
                    "|OO|",
                ]

        # Position car at street level (shifted up 2 rows + y_offset for perspective)
        street_y = self.height - 3 - y_offset
        sprite_height = len(sprite)

        # Use yellow for taxis, white for regular cars
        car_color = Colors.RAT_YELLOW if is_taxi else Colors.ALLEY_LIGHT

        # Render car on top of vanishing street (street is background)
        for row_idx, row in enumerate(sprite):
            for col_idx, char in enumerate(row):
                px = x + col_idx
                py = street_y - (sprite_height - 1 - row_idx)

                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    try:
                        attr = curses.color_pair(car_color) | curses.A_BOLD
                        screen.attron(attr)
                        screen.addstr(py, px, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

    def _render_street_light_flicker(self, screen):
        """Render flickering light effects under street lights. Tied to state_monitor."""
        # Security canary: no street lights if state monitor is down
        if not self._security_canary.get('street_lights', True):
            return
        # Light glow characters - brightest to dimmest
        glow_chars = ['█', '▓', '▒', '░']

        for i, (light_x, light_y) in enumerate(self._street_light_positions):
            if i >= len(self._street_light_flicker):
                continue

            brightness = self._street_light_flicker[i]

            # Draw light glow underneath the lamp (cone of light)
            # Brighter at top, dimmer at bottom
            glow_y = light_y + 1  # Start just below the lamp head
            for row in range(4):  # 4 rows of glow
                spread = row + 1  # Wider as it goes down
                # Top rows are brighter, bottom rows are dimmer
                row_brightness = brightness * (1.0 - row * 0.2)

                for dx in range(-spread, spread + 1):
                    px = light_x + dx
                    py = glow_y + row

                    if 0 <= px < self.width - 1 and 0 <= py < self.height:
                        # Pick glow character - brighter chars for top rows
                        dist_factor = abs(dx) / (spread + 1)
                        # Top row uses brightest char, bottom uses dimmest
                        char_idx = min(3, row + int(dist_factor * 2))
                        glow_char = glow_chars[char_idx] if row_brightness > 0.2 else ' '

                        if glow_char != ' ':
                            try:
                                # Top rows get BOLD, bottom rows get DIM
                                if row == 0:
                                    attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                                elif row == 1:
                                    attr = curses.color_pair(Colors.RAT_YELLOW)
                                else:
                                    attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_DIM
                                screen.attron(attr)
                                screen.addstr(py, px, glow_char)
                                screen.attroff(attr)
                            except curses.error:
                                pass

    def _render_building_window_lights(self, screen):
        """Render flickering light glow from building windows (no pole, just glow).
        Single row cone with most transparent blocks at edges.
        """
        # Gradient from solid to transparent: █ ▓ ▒ ░
        glow_chars = ['▓', '▒', '░']  # No solid block, start with semi-transparent

        for i, (light_x, light_y) in enumerate(self._building_window_lights):
            if i >= len(self._building_window_flicker):
                continue

            brightness = self._building_window_flicker[i]

            # Single row cone, 3 chars wide on each side
            spread = 2  # Width on each side
            py = light_y

            for dx in range(-spread, spread + 1):
                px = light_x + dx

                if 0 <= px < self.width - 1 and 0 <= py < self.height:
                    # More transparent at edges
                    dist = abs(dx)
                    if dist == 0:
                        char_idx = 0  # Center: ▓ (most solid of our set)
                    elif dist == 1:
                        char_idx = 1  # Mid: ▒
                    else:
                        char_idx = 2  # Edge: ░ (most transparent)

                    glow_char = glow_chars[char_idx] if brightness > 0.3 else ' '

                    if glow_char != ' ':
                        try:
                            attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_DIM
                            screen.attron(attr)
                            screen.addstr(py, px, glow_char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_window_scenes(self, screen):
        """Render unique mini scenes inside each building window."""
        for window in self._all_windows:
            brightness = window['brightness']

            # Skip completely dark windows (no scene visible)
            if brightness < 0.1:
                continue

            scene_chars = window.get('scene_chars', [])
            if not scene_chars:
                continue

            wx = window['x']
            wy = window['y']
            width = window['width']

            # Choose color based on brightness level for visible variation
            # Bright (0.9-1.0) = bright yellow, Medium (0.6-0.8) = mid tone,
            # Dim (0.3-0.5) = dark, Very dim (<0.3) = barely visible
            if brightness >= 0.9:
                color = Colors.RAT_YELLOW  # Bright warm light
                attr_mod = curses.A_BOLD
            elif brightness >= 0.7:
                color = Colors.RAT_YELLOW
                attr_mod = 0  # Normal
            elif brightness >= 0.5:
                color = Colors.ALLEY_MID
                attr_mod = 0
            elif brightness >= 0.3:
                color = Colors.ALLEY_MID
                attr_mod = curses.A_DIM
            else:
                color = Colors.ALLEY_DARK
                attr_mod = curses.A_DIM

            # Render each row of the scene
            for row_idx, row_chars in enumerate(scene_chars):
                py = wy + row_idx
                if py >= self.height:
                    continue

                for col_idx, char in enumerate(row_chars):
                    if col_idx >= width:
                        break
                    px = wx + col_idx
                    if px >= self.width - 1:
                        continue

                    # Only render non-space characters
                    if char != ' ':
                        try:
                            attr = curses.color_pair(color) | attr_mod
                            screen.attron(attr)
                            screen.addstr(py, px, char)
                            screen.attroff(attr)
                        except curses.error:
                            pass

    def _render_window_people(self, screen):
        """Render silhouettes of people walking by windows with animations."""
        for person in self._window_people:
            building = person['building']
            window_idx = person['window_idx']
            progress = person['progress']
            state = person.get('state', 'walking')

            # Get window position
            if building == 1:
                positions = self.BUILDING_WINDOW_POSITIONS
                base_x = self._building_x
                base_y = self._building_y
            else:
                positions = self.BUILDING2_WINDOW_POSITIONS
                base_x = self._building2_x
                base_y = self._building2_y

            if window_idx >= len(positions):
                continue

            row_offset, col_offset = positions[window_idx]
            window_x = base_x + col_offset
            window_y = base_y + row_offset

            # Calculate silhouette position within window (4 chars wide)
            window_width = 4
            silhouette_x = window_x + int(progress * window_width)

            # Choose silhouette based on state
            if state == 'walking' or state == 'leaving':
                # Walking silhouette - person shape
                silhouette = ['O', '|']  # Head and body
            elif state == 'staring':
                # Staring out window - face visible
                silhouette = ['O', '█']  # Head and shoulders
            elif state == 'waving':
                # Waving animation
                wave_frame = person.get('wave_frame', 0)
                if wave_frame == 0:
                    silhouette = ['O/', '█']  # Hand up right
                else:
                    silhouette = ['\\O', '█']  # Hand up left

            # Draw silhouette (2 chars tall) - use light color so visible against dark windows
            try:
                attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_BOLD
                screen.attron(attr)
                for i, char in enumerate(silhouette):
                    y = window_y + i
                    if 0 <= silhouette_x < self.width - 2 and 0 <= y < self.height:
                        screen.addstr(y, silhouette_x, char)
                screen.attroff(attr)
            except curses.error:
                pass

    def _render_cafe_people(self, screen):
        """Render the 3 people in Shell Cafe. Tied to wifi_security health."""
        # Security canary: no cafe people/lights if wifi security is down
        if not self._security_canary.get('cafe_lights', True):
            return
        if not hasattr(self, 'cafe_x') or not hasattr(self, 'cafe_y'):
            return

        # First floor door area is at rows 21-22 of CAFE sprite (0-indexed, after turtle shell)
        # Row 21: "[                  OPEN ]" - visible through door glass
        # Row 22: "[__________________     ]" - lower door area
        window_row = 21  # Row with people heads (door glass area)
        body_row = 22    # Row with bodies/arms
        window_start_col = 4  # Start of door glass content area

        # Arm animation frames (both arms shown)
        # Frame 0: arms down, Frame 1: left up, Frame 2: both up, Frame 3: right up
        arm_frames = [
            ('/|\\', '/ \\'),   # Frame 0: arms down
            ('\\|\\', '\\ \\'),  # Frame 1: left arm up
            ('\\|/', '\\ /'),    # Frame 2: both arms up (wave)
            ('/|/', '/ /'),      # Frame 3: right arm up
        ]

        for person in self._cafe_people:
            x_offset = int(person['x_offset'])
            arm_frame = person['arm_frame'] % len(arm_frames)

            # Calculate screen position
            px = self.cafe_x + window_start_col + x_offset
            py_head = self.cafe_y + window_row
            py_body = self.cafe_y + body_row

            if not (0 <= px < self.width - 3 and 0 <= py_head < self.height and 0 <= py_body < self.height):
                continue

            try:
                # Draw head
                attr = curses.color_pair(Colors.CAFE_WARM)
                screen.attron(attr)
                screen.addstr(py_head, px + 1, 'O')  # Head centered above body
                screen.attroff(attr)

                # Draw body with animated arms
                upper_body, lower_body = arm_frames[arm_frame]
                screen.attron(attr)
                screen.addstr(py_body, px, upper_body)  # Arms and torso
                screen.attroff(attr)
            except curses.error:
                pass

    def _render_turtle(self, screen):
        """Render turtle head peeking out of shell and winking."""
        if self._turtle_state == 'hidden':
            return

        if not hasattr(self, 'cafe_x') or not hasattr(self, 'cafe_y'):
            return

        # Turtle peeks out at row 3-4 of CAFE (middle of turtle shell logo)
        # Shell spans roughly columns 2-22 of CAFE sprite
        shell_row = 3
        turtle_y = self.cafe_y + shell_row

        # Position based on which side turtle peeks from
        if self._turtle_side == 1:  # Right side
            turtle_x = self.cafe_x + 22  # Right edge of shell
        else:  # Left side
            turtle_x = self.cafe_x - 6  # Left edge of shell

        # Get the current turtle head frame (list: [head_top, head_mid/eyes, chin_with_neck])
        frame = self.TURTLE_HEAD_FRAMES[self._turtle_frame]
        head_top = frame[0]
        head_mid = frame[1] if len(frame) > 1 else ""
        chin_neck = frame[2] if len(frame) > 2 else ""  # Chin with horizontal neck

        if not (0 <= turtle_x < self.width - len(head_top) and 0 <= turtle_y < self.height):
            return

        try:
            # Draw turtle head in green (like shell logo)
            attr = curses.color_pair(Colors.STATUS_OK) | curses.A_BOLD
            screen.attron(attr)
            # Draw head top (outline)
            screen.addstr(turtle_y, turtle_x, head_top)
            # Draw head middle (eyes)
            if head_mid and turtle_y + 1 < self.height:
                screen.addstr(turtle_y + 1, turtle_x, head_mid)
            # Draw chin with horizontal neck extending to left
            if chin_neck and turtle_y + 2 < self.height:
                screen.addstr(turtle_y + 2, turtle_x, chin_neck)
            screen.attroff(attr)
        except curses.error:
            pass

    def _render_garden(self, screen):
        """Render the animated colorful garden in front of Shell Cafe."""
        if not self._garden_cache or not self._garden_cache_valid:
            return

        if not hasattr(self, '_garden_x') or not hasattr(self, '_garden_y'):
            return

        # Get current animation frame
        frame_data = self._garden_cache[self._garden_frame_idx]

        # Render each element in the frame
        for row, rel_x, char, color in frame_data:
            px = self._garden_x + rel_x
            py = self._garden_y + row

            if 0 <= px < self.width and 0 <= py < self.height:
                try:
                    attr = curses.color_pair(color) | curses.A_BOLD
                    screen.addstr(py, px, char, attr)
                except curses.error:
                    pass

    def _render_prop_plane(self, screen):
        """Render prop plane with trailing banner message."""
        if self._prop_plane is None:
            return

        plane = self._prop_plane
        x = int(plane['x'])
        y = plane['y']
        direction = plane['direction']
        message = plane['message']

        # Select plane sprite based on direction
        # Banner must trail BEHIND the plane (opposite side of nose)
        if direction == 1:
            plane_sprite = self.PROP_PLANE_RIGHT
            banner_offset = -len(message) - 8  # Banner trails behind (left of plane)
        else:
            plane_sprite = self.PROP_PLANE_LEFT
            banner_offset = len(plane_sprite[1]) + 2  # Banner trails behind (right of plane)

        # Draw plane
        for row_idx, row in enumerate(plane_sprite):
            py = y + row_idx
            for col_idx, char in enumerate(row):
                px = x + col_idx
                if 0 <= px < self.width - 1 and 0 <= py < self.height and char != ' ':
                    try:
                        if char in '(_)':
                            # Engine/body - dark
                            attr = curses.color_pair(Colors.GREY_BLOCK) | curses.A_BOLD
                        elif char in '-=':
                            # Wings - light
                            attr = curses.color_pair(Colors.ALLEY_LIGHT) | curses.A_BOLD
                        elif char == '>':
                            # Nose pointing right
                            attr = curses.color_pair(Colors.SHADOW_RED) | curses.A_BOLD
                        elif char == '<':
                            # Nose pointing left
                            attr = curses.color_pair(Colors.SHADOW_RED) | curses.A_BOLD
                        elif char == '~':
                            # Tail/exhaust
                            attr = curses.color_pair(Colors.ALLEY_MID)
                        elif char == '_':
                            # Top
                            attr = curses.color_pair(Colors.ALLEY_LIGHT)
                        else:
                            attr = curses.color_pair(Colors.ALLEY_LIGHT)
                        screen.attron(attr)
                        screen.addstr(py, px, char)
                        screen.attroff(attr)
                    except curses.error:
                        pass

        # Draw banner connection and message
        banner_y = y + 1  # Middle row of plane
        banner_x = x + banner_offset

        # Draw connection rope (trails behind banner)
        if direction == 1:
            # Moving right - rope connects on right side of banner, extends to plane on right
            rope = "]o~~"
            rope_x = banner_x + len(message)
        else:
            # Moving left - rope connects on left side of banner, extends to plane on left
            rope = "~~o["
            rope_x = banner_x - 4

        for i, char in enumerate(rope):
            px = rope_x + i
            if 0 <= px < self.width - 1 and 0 <= banner_y < self.height:
                try:
                    attr = curses.color_pair(Colors.ALLEY_MID)
                    screen.attron(attr)
                    screen.addstr(banner_y, px, char)
                    screen.attroff(attr)
                except curses.error:
                    pass

        # Draw banner message
        if direction == 1:
            msg_x = rope_x + len(rope)
        else:
            msg_x = banner_x

        for i, char in enumerate(message):
            px = msg_x + i
            if 0 <= px < self.width - 1 and 0 <= banner_y < self.height:
                try:
                    # Alternating colors for visibility
                    if i % 2 == 0:
                        attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD
                    else:
                        attr = curses.color_pair(Colors.SHADOW_RED) | curses.A_BOLD
                    screen.attron(attr)
                    screen.addstr(banner_y, px, char)
                    screen.attroff(attr)
                except curses.error:
                    pass

        # Draw banner end
        if direction == 1:
            end = "]"
            end_x = msg_x + len(message)
        else:
            end = "["
            end_x = msg_x - 1

        if 0 <= end_x < self.width - 1 and 0 <= banner_y < self.height:
            try:
                attr = curses.color_pair(Colors.ALLEY_MID)
                screen.attron(attr)
                screen.addstr(banner_y, end_x, end)
                screen.attroff(attr)
            except curses.error:
                pass

    def _render_traffic_light(self, screen):
        """Render the traffic light with current light states. Tied to health_monitor."""
        # Security canary: no traffic lights if health monitor is down
        if not self._security_canary.get('traffic_lights', True):
            return
        # Position traffic light on right side of scene (shifted 4 chars left)
        light_x = min(self.width - 10, self.box_x + len(self.BOX[0]) + 96)
        light_y = self.height - len(self.TRAFFIC_LIGHT_TEMPLATE) - 1  # Above curb, moved down

        if light_x < 0 or light_y < 0:
            return

        # Get current light states
        ns_red, ns_yellow, ns_green, ew_red, ew_yellow, ew_green = self._get_traffic_light_colors()

        # Render each row of traffic light
        # Compact template has lights at rows 1 (red), 2 (yellow), 3 (green)
        for row_idx, row in enumerate(self.TRAFFIC_LIGHT_TEMPLATE):
            for col_idx, char in enumerate(row):
                px = light_x + col_idx
                py = light_y + row_idx

                if not (0 <= px < self.width - 1 and 0 <= py < self.height):
                    continue
                if char == ' ':
                    continue

                # Determine color based on character position
                color = Colors.ALLEY_MID
                render_char = char

                if char == 'L':  # Left side lights (N/S direction)
                    if row_idx == 1:  # Red position
                        render_char, color = ns_red
                    elif row_idx == 2:  # Yellow position
                        render_char, color = ns_yellow
                    elif row_idx == 3:  # Green position
                        render_char, color = ns_green
                elif char == 'R':  # Right side lights (E/W direction)
                    if row_idx == 1:  # Red position
                        render_char, color = ew_red
                    elif row_idx == 2:  # Yellow position
                        render_char, color = ew_yellow
                    elif row_idx == 3:  # Green position
                        render_char, color = ew_green
                else:
                    render_char = char

                try:
                    if char in 'LR':
                        # Lights get bold when on
                        if render_char == 'O':
                            attr = curses.color_pair(color) | curses.A_BOLD
                        else:
                            attr = curses.color_pair(color) | curses.A_DIM
                    else:
                        # Structure of light
                        attr = curses.color_pair(Colors.ALLEY_MID) | curses.A_DIM

                    screen.attron(attr)
                    screen.addstr(py, px, render_char)
                    screen.attroff(attr)
                except curses.error:
                    pass


