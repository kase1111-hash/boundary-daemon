"""
TUI Creatures - Animated creatures for the alley scene.

Extracted from dashboard.py for maintainability.
Contains LightningBolt, AlleyRat, and LurkingShadow classes.
"""

import math
import random
from typing import List, Tuple

# Handle curses import for Windows compatibility
try:
    import curses
    CURSES_AVAILABLE = True
except ImportError:
    curses = None
    CURSES_AVAILABLE = False

from .colors import Colors


class LightningBolt:
    """
    Generates and renders dramatic lightning bolt across the screen.

    Creates a jagged lightning bolt path from top to bottom with
    screen flash and rapid flicker effect.
    """

    # Lightning bolt segment characters
    BOLT_CHARS = ['/', '\\', '|', '⚡', '╲', '╱', '│', '┃']

    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height
        self.path: List[Tuple[int, int]] = []  # (y, x) coordinates
        self._generate_bolt()

    def _generate_bolt(self):
        """Generate a jagged lightning bolt path from top to bottom."""
        self.path = []
        if self.width <= 0 or self.height <= 0:
            return

        # Start from random position in top third
        x = random.randint(self.width // 4, 3 * self.width // 4)
        y = 0

        while y < self.height:
            self.path.append((y, x))

            # Move down 1-3 rows
            y += random.randint(1, 3)

            # Jag left or right randomly
            direction = random.choice([-2, -1, -1, 0, 1, 1, 2])
            x = max(1, min(self.width - 2, x + direction))

            # Occasionally add a branch
            if random.random() < 0.15 and len(self.path) > 3:
                branch_x = x + random.choice([-3, -2, 2, 3])
                branch_y = y
                for _ in range(random.randint(2, 5)):
                    if 0 <= branch_x < self.width and branch_y < self.height:
                        self.path.append((branch_y, branch_x))
                        branch_y += 1
                        branch_x += random.choice([-1, 0, 1])

    def render(self, screen, flash_intensity: float = 1.0):
        """
        Render the lightning bolt with optional flash intensity.

        Args:
            screen: curses screen object
            flash_intensity: 0.0-1.0, controls visibility (for flicker effect)
        """
        if not CURSES_AVAILABLE or curses is None:
            return

        if flash_intensity < 0.3:
            return  # Don't render during dim phase

        for y, x in self.path:
            if 0 <= y < self.height and 0 <= x < self.width:
                try:
                    char = random.choice(self.BOLT_CHARS)
                    attr = curses.color_pair(Colors.LIGHTNING) | curses.A_BOLD
                    if flash_intensity < 0.7:
                        attr = curses.color_pair(Colors.MATRIX_BRIGHT) | curses.A_BOLD
                    screen.attron(attr)
                    screen.addstr(y, x, char)
                    screen.attroff(attr)
                except curses.error:
                    pass

    @staticmethod
    def flash_screen(screen, width: int, height: int):
        """Flash the entire screen white briefly."""
        if not CURSES_AVAILABLE or curses is None:
            return

        attr = curses.color_pair(Colors.LIGHTNING)
        try:
            for y in range(height):
                screen.attron(attr)
                screen.addstr(y, 0, ' ' * (width - 1))
                screen.attroff(attr)
        except curses.error:
            pass


class AlleyRat:
    """
    Yellow ASCII rat that scurries around the alley when security warnings appear.

    The rat appears near the dumpster or edges of the scene and moves
    in quick, erratic patterns when there are active warnings.
    """

    # Rat animation frames - no visible eyes
    # Sitting: 2x2 chars, Moving: 1x3 chars (horizontal running)
    RAT_FRAMES = {
        'right': [
            # Running right - 1x3 horizontal (tail-body-head)
            ["~=>"],
            ["_->"],
        ],
        'left': [
            # Running left - 1x3 horizontal (head-body-tail)
            ["<=~"],
            ["<-_"],
        ],
        'idle': [
            # Sitting rat - 2x2, no eyes (just fur/shape)
            ["()", "vv"],  # Curled up
            ["{}", "^^"],  # Slightly different
        ],
        'look_left': [
            ["<)", "vv"],  # Head turned left, 2x2
        ],
        'look_right': [
            ["(>", "vv"],  # Head turned right, 2x2
        ],
    }

    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height
        self.active = False
        self.visible = False

        # Position and movement
        self.x = 0.0
        self.y = 0.0
        self.target_x = 0.0
        self.target_y = 0.0
        self.direction = 'idle'
        self.speed = 0.0

        # Animation state
        self.frame = 0
        self.frame_counter = 0
        self.pause_counter = 0

        # Behavior state
        self._hiding = True
        self._flee_timer = 0

        # Hopping state - discrete jumps instead of continuous movement
        self._hop_cooldown = 0
        self._look_timer = 0
        self._look_direction = 'idle'

        # Hiding spots (positions behind objects)
        self._hiding_spots: List[Tuple[float, float]] = []

        # Floor constraint (building bottom level) - rat can't go above this
        self._floor_y = height * 4 // 5  # Default, updated by set_hiding_spots

    def set_hiding_spots(self, alley_scene):
        """Set hiding spots based on alley scene objects."""
        self._hiding_spots = []
        if alley_scene:
            # Behind dumpster (to the right of it)
            dumpster_behind_x = alley_scene.dumpster_x + 2
            dumpster_y = alley_scene.dumpster_y + 2
            self._hiding_spots.append((float(dumpster_behind_x), float(dumpster_y)))

            # Behind box (to the right of it)
            box_behind_x = alley_scene.box_x + 2
            box_y = alley_scene.box_y + 1
            self._hiding_spots.append((float(box_behind_x), float(box_y)))

            # Set floor constraint from building bottom - rat can't climb above this
            self._floor_y = alley_scene._building_bottom_y

    def resize(self, width: int, height: int):
        """Handle terminal resize."""
        self.width = width
        self.height = height
        # Keep rat in bounds
        self.x = min(self.x, width - 3)
        self.y = min(self.y, height - 3)

    def activate(self):
        """Activate the rat when warnings appear."""
        if not self.active:
            self.active = True
            self.visible = True
            self._hiding = False
            # Spawn at building bottom level, near dumpster area (above curb)
            max_y = self.height - 5
            min_y = min(self._floor_y, max_y)  # Ensure valid range
            self.x = float(random.randint(8, max(10, self.width // 4)))
            self.y = float(random.randint(min_y, max_y))  # Stay above curb
            self._pick_new_target()

    def deactivate(self):
        """Deactivate the rat when warnings clear."""
        # Rat runs off screen to hide
        if self.active and not self._hiding:
            self._hiding = True
            self.target_x = -5.0  # Run off left edge
            self.target_y = self.y
            self.speed = 1.5  # Fast escape

    def _pick_new_target(self):
        """Pick a new target position for the rat to scurry to."""
        # Stay at building bottom level, above the curb (can hide behind building)
        max_y = self.height - 5  # Stay above curb and street
        min_y = min(self._floor_y, max_y)  # Ensure valid range

        if random.random() < 0.6:
            # Most of the time, stay still and look around
            self.target_x = self.x
            self.target_y = self.y
            self.pause_counter = random.randint(40, 100)  # Longer pauses
            self.speed = 0
            self.direction = 'idle'
            self._look_timer = random.randint(15, 35)  # Start looking around
        elif random.random() < 0.4 and self._hiding_spots:
            # Sometimes hide behind dumpster or box
            hide_spot = random.choice(self._hiding_spots)
            self.target_x = hide_spot[0]
            self.target_y = hide_spot[1]
            # Use hopping
            self.speed = 0
            self._hop_cooldown = 0

            # Set direction based on target
            if self.target_x > self.x:
                self.direction = 'right'
            else:
                self.direction = 'left'
        else:
            # Occasionally hop to a random spot at building bottom level (above curb)
            self.target_x = float(random.randint(6, max(7, self.width // 3)))
            self.target_y = float(random.randint(min_y, max_y))
            # Use hopping - will move in discrete jumps
            self.speed = 0  # Don't move continuously
            self._hop_cooldown = 0  # Ready to hop

            # Set direction based on target
            if self.target_x > self.x:
                self.direction = 'right'
            else:
                self.direction = 'left'

    def update(self):
        """Update rat position and animation."""
        if not self.active:
            return

        self.frame_counter += 1

        # Handle looking around while idle - slow animation
        if self.direction == 'idle' and self.pause_counter > 0:
            self._look_timer -= 1
            if self._look_timer <= 0:
                # Switch look direction
                look_choice = random.random()
                if look_choice < 0.3:
                    self._look_direction = 'look_left'
                elif look_choice < 0.6:
                    self._look_direction = 'look_right'
                else:
                    self._look_direction = 'idle'
                self._look_timer = random.randint(20, 50)

            # Slow blink animation for idle (every 20 frames)
            if self.frame_counter % 20 == 0:
                frames = self.RAT_FRAMES.get(self._look_direction, self.RAT_FRAMES['idle'])
                self.frame = (self.frame + 1) % len(frames)
        elif self.direction in ('left', 'right'):
            # Moving animation - cycle frames while hopping
            if self._hop_cooldown <= 3:  # Only animate during hop
                if self.frame_counter % 3 == 0:
                    frames = self.RAT_FRAMES.get(self.direction, self.RAT_FRAMES['idle'])
                    self.frame = (self.frame + 1) % len(frames)

        # Handle pause (idle state)
        if self.pause_counter > 0:
            self.pause_counter -= 1
            if self.pause_counter == 0:
                self._pick_new_target()
            return

        # Handle fleeing (continuous fast movement)
        if self._hiding and self.speed > 0:
            dx = self.target_x - self.x
            dy = self.target_y - self.y
            dist = math.sqrt(dx * dx + dy * dy)
            if dist < 0.5 or self.x < 0:
                self.active = False
                self.visible = False
            else:
                self.x += (dx / dist) * self.speed
                self.y += (dy / dist) * self.speed
            return

        # Hopping movement - discrete jumps with pauses between
        if self.direction in ('left', 'right'):
            self._hop_cooldown -= 1
            if self._hop_cooldown <= 0:
                # Make a hop towards target
                dx = self.target_x - self.x
                dy = self.target_y - self.y
                dist = math.sqrt(dx * dx + dy * dy)

                if dist < 1.5:
                    # Reached target, pause and pick new target
                    self._pick_new_target()
                else:
                    # Hop a fixed distance (1-2 units)
                    hop_dist = min(dist, random.uniform(1.0, 2.0))
                    self.x += (dx / dist) * hop_dist
                    self.y += (dy / dist) * hop_dist
                    # Pause between hops
                    self._hop_cooldown = random.randint(8, 20)

    def render(self, screen):
        """Render the rat."""
        if not self.visible or not self.active or not CURSES_AVAILABLE or curses is None:
            return

        # Use look direction when idle
        render_direction = self.direction
        if self.direction == 'idle':
            render_direction = self._look_direction if self._look_direction else 'idle'

        frames = self.RAT_FRAMES.get(render_direction, self.RAT_FRAMES['idle'])
        frame = frames[self.frame % len(frames)]

        ix = int(self.x)
        iy = int(self.y)

        attr = curses.color_pair(Colors.RAT_YELLOW) | curses.A_BOLD

        try:
            for row_idx, row in enumerate(frame):
                for col_idx, char in enumerate(row):
                    px = ix + col_idx
                    py = iy + row_idx
                    if 0 <= px < self.width - 1 and 0 <= py < self.height - 1 and char != ' ':
                        screen.attron(attr)
                        screen.addstr(py, px, char)
                        screen.attroff(attr)
        except curses.error:
            pass


class LurkingShadow:
    """
    Lurking shadow with glowing red eyes that appears when threats are detected.

    The shadow lurks in dark corners of the alley, with only its red eyes
    visible. Occasionally blinks and shifts position.
    """

    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height
        self.active = False

        # Position (eyes position)
        self.x = 0
        self.y = 0

        # Blinking state
        self.eyes_open = True
        self.blink_counter = 0
        self.blink_interval = random.randint(30, 80)

        # Movement state
        self.move_counter = 0
        self.move_interval = random.randint(100, 300)

        # Intensity (for flickering eyes)
        self.intensity = 1.0
        self.flicker_counter = 0

    def resize(self, width: int, height: int):
        """Handle terminal resize."""
        self.width = width
        self.height = height
        # Keep in bounds
        self.x = min(self.x, width - 3)
        self.y = min(self.y, height - 2)

    def activate(self):
        """Activate the shadow when threats appear."""
        if not self.active:
            self.active = True
            self._choose_lurk_position()

    def deactivate(self):
        """Deactivate the shadow."""
        self.active = False

    def _choose_lurk_position(self):
        """Choose a dark corner to lurk in."""
        # Lurk only at screen edges, in the lower half
        positions = []

        # Lower half starts at height // 2
        lower_half_start = self.height // 2
        lower_bound = self.height - 4  # Don't go too close to bottom

        # Left edge - lower half only
        positions.append((random.randint(0, 5), random.randint(lower_half_start, lower_bound)))
        positions.append((random.randint(0, 3), random.randint(lower_half_start, lower_bound)))

        # Right edge - lower half only
        positions.append((self.width - random.randint(3, 8), random.randint(lower_half_start, lower_bound)))
        positions.append((self.width - random.randint(2, 6), random.randint(lower_half_start, lower_bound)))

        # Pick one
        pos = random.choice(positions)
        self.x = max(0, min(pos[0], self.width - 3))
        self.y = max(lower_half_start, min(pos[1], self.height - 2))

        # Reset blink/move timers
        self.blink_interval = random.randint(30, 80)
        self.move_interval = random.randint(100, 300)

    def update(self):
        """Update shadow state."""
        if not self.active:
            return

        self.blink_counter += 1
        self.move_counter += 1
        self.flicker_counter += 1

        # Subtle intensity flicker
        self.intensity = 0.8 + 0.2 * math.sin(self.flicker_counter * 0.1)

        # Blink occasionally
        if self.blink_counter >= self.blink_interval:
            self.blink_counter = 0
            self.eyes_open = not self.eyes_open
            if self.eyes_open:
                # Eyes were closed, now open - new blink interval
                self.blink_interval = random.randint(30, 80)
            else:
                # Closing eyes briefly
                self.blink_interval = random.randint(2, 5)

        # Move to new position occasionally
        if self.move_counter >= self.move_interval:
            self.move_counter = 0
            self._choose_lurk_position()

    def render(self, screen):
        """Render the lurking shadow with glowing red eyes."""
        if not self.active or not self.eyes_open or not CURSES_AVAILABLE or curses is None:
            return

        # The shadow itself is invisible (dark)
        # Only render the glowing red eyes

        # Eyes: two dots with a space between
        eyes = "o o"

        # Determine intensity (for flickering effect)
        if self.intensity > 0.9:
            attr = curses.color_pair(Colors.SHADOW_RED) | curses.A_BOLD
        else:
            attr = curses.color_pair(Colors.SHADOW_RED)

        try:
            if 0 <= self.y < self.height - 1 and 0 <= self.x < self.width - 3:
                screen.attron(attr)
                screen.addstr(self.y, self.x, eyes)
                screen.attroff(attr)
        except curses.error:
            pass
