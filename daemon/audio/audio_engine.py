"""
Audio Engine for Boundary Daemon

Generates audio intents for TTS-based procedural sound synthesis.
Uses onomatopoeia library for sound effect generation.

Inspired by Tile-Crawler's audio engine pattern.
"""

import json
import os
import random
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List


@dataclass
class AudioIntent:
    """Audio intent to be processed by TTS engine."""
    event_type: str  # sfx, ambient, alert, ui_feedback, notification
    onomatopoeia: str  # The text to speak/synthesize
    emotion: str = "neutral"
    intensity: float = 0.5  # 0.0 to 1.0
    pitch_shift: float = 0.0  # -12 to +12 semitones
    speed: float = 1.0  # 0.5 to 2.0
    reverb: float = 0.3  # 0.0 to 1.0
    style: str = "cyberpunk"
    spatial: Optional[Dict[str, float]] = None  # {pan: -1 to 1, distance: 0 to 1}
    loop: bool = False
    priority: int = 5  # 1-10, higher = more important


@dataclass
class AudioBatch:
    """Batch of audio intents for a single event."""
    primary: AudioIntent
    ambient: Optional[AudioIntent] = None
    alert: Optional[AudioIntent] = None
    layers: List[AudioIntent] = field(default_factory=list)


class AudioEngine:
    """
    Generates audio intents for security events and UI feedback.
    Uses onomatopoeia library for procedural sound generation.
    """

    def __init__(self):
        self.onomatopoeia = self._load_onomatopoeia_library()
        self.processing_presets = self._load_processing_presets()
        self.alert_level = 0.0  # 0.0 (calm) to 1.0 (critical)
        self.ambient_mode = "normal"  # normal, rain, storm, alert

    def _load_onomatopoeia_library(self) -> Dict[str, Dict[str, List[str]]]:
        """Load the onomatopoeia library for sound generation."""
        return {
            "alerts": {
                "warning": ["BEEP", "boop boop", "ding ding", "woop woop"],
                "critical": ["BWAAA", "ALERT ALERT", "DANGER", "WARNING WARNING"],
                "info": ["ding", "blip", "chirp", "ping"],
                "success": ["ta-da!", "ding!", "woohoo", "yes!"],
                "error": ["buzzzz", "errrrr", "bzzzt", "nope"],
            },
            "ui": {
                "click": ["click", "tap", "tick", "pop"],
                "hover": ["whsh", "fwip", "swoosh"],
                "select": ["bleep", "blip", "ding"],
                "open": ["whoosh", "swish", "fwoom"],
                "close": ["thud", "clunk", "snap"],
                "scroll": ["whirr", "zzzip", "shhhh"],
                "type": ["tap tap tap", "click click", "tickticktick"],
            },
            "security": {
                "scan_start": ["bweep bweep", "initiating scan", "scanning"],
                "scan_complete": ["scan complete", "all clear", "done"],
                "threat_detected": ["THREAT DETECTED", "INTRUDER ALERT", "BREACH"],
                "quarantine": ["isolating", "contained", "locked down"],
                "connection": ["connecting", "beep boop beep", "handshaking"],
                "disconnect": ["connection lost", "offline", "disconnected"],
            },
            "ambient": {
                "rain": ["pitter patter", "drip drop", "shhhhhh"],
                "storm": ["RUMBLE", "CRASH", "BOOM"],
                "wind": ["whoooosh", "howwwl", "whistling"],
                "city": ["distant hum", "traffic", "city sounds"],
                "matrix": ["digital rain", "cascade", "data flow"],
            },
            "events": {
                "pedestrian": ["footsteps", "walking", "shuffle shuffle"],
                "car": ["vroom", "beep beep", "engine hum"],
                "lightning": ["CRACK", "ZAP", "THUNDER"],
                "door": ["creak", "slam", "click"],
                "cafe": ["coffee brewing", "chatter", "clink clink"],
            },
        }

    def _load_processing_presets(self) -> Dict[str, Dict[str, float]]:
        """Load audio processing presets for different contexts."""
        return {
            "normal": {"reverb": 0.2, "pitch": 0.0, "speed": 1.0},
            "alert": {"reverb": 0.1, "pitch": 2.0, "speed": 1.2},
            "calm": {"reverb": 0.4, "pitch": -1.0, "speed": 0.9},
            "dramatic": {"reverb": 0.6, "pitch": -2.0, "speed": 0.8},
            "urgent": {"reverb": 0.1, "pitch": 3.0, "speed": 1.4},
            "cyberpunk": {"reverb": 0.3, "pitch": 0.0, "speed": 1.0},
        }

    def _pick_onomatopoeia(self, category: str, subcategory: str) -> str:
        """Pick a random onomatopoeia from the library."""
        try:
            options = self.onomatopoeia.get(category, {}).get(subcategory, [])
            if options:
                return random.choice(options)
        except Exception:
            pass
        return "..."

    def _get_preset(self, preset_name: str = "normal") -> Dict[str, float]:
        """Get processing preset by name."""
        return self.processing_presets.get(preset_name, self.processing_presets["normal"])

    def set_alert_level(self, level: float):
        """Set the current alert level (affects ambient audio)."""
        self.alert_level = max(0.0, min(1.0, level))

    def set_ambient_mode(self, mode: str):
        """Set ambient audio mode."""
        self.ambient_mode = mode

    # === Security Event Audio ===

    def generate_threat_audio(self, severity: str = "medium") -> AudioBatch:
        """Generate audio for threat detection event."""
        preset = self._get_preset("alert" if severity == "critical" else "normal")

        if severity == "critical":
            sfx = self._pick_onomatopoeia("alerts", "critical")
            intensity = 1.0
            priority = 10
        elif severity == "high":
            sfx = self._pick_onomatopoeia("security", "threat_detected")
            intensity = 0.8
            priority = 8
        else:
            sfx = self._pick_onomatopoeia("alerts", "warning")
            intensity = 0.5
            priority = 6

        primary = AudioIntent(
            event_type="alert",
            onomatopoeia=sfx,
            emotion="danger",
            intensity=intensity,
            pitch_shift=preset["pitch"],
            speed=preset["speed"],
            reverb=preset["reverb"],
            priority=priority,
        )

        return AudioBatch(primary=primary)

    def generate_scan_audio(self, phase: str = "start") -> AudioIntent:
        """Generate audio for security scanning."""
        if phase == "start":
            sfx = self._pick_onomatopoeia("security", "scan_start")
            emotion = "focused"
        elif phase == "complete":
            sfx = self._pick_onomatopoeia("security", "scan_complete")
            emotion = "triumphant"
        else:
            sfx = self._pick_onomatopoeia("security", "connection")
            emotion = "neutral"

        return AudioIntent(
            event_type="sfx",
            onomatopoeia=sfx,
            emotion=emotion,
            intensity=0.5,
            priority=4,
        )

    def generate_quarantine_audio(self) -> AudioBatch:
        """Generate audio for quarantine/isolation event."""
        primary = AudioIntent(
            event_type="alert",
            onomatopoeia=self._pick_onomatopoeia("security", "quarantine"),
            emotion="serious",
            intensity=0.7,
            pitch_shift=-2,
            speed=0.9,
            reverb=0.4,
            priority=7,
        )

        ambient = AudioIntent(
            event_type="ambient",
            onomatopoeia="lockdown sequence",
            emotion="tense",
            intensity=0.4,
            loop=True,
            priority=2,
        )

        return AudioBatch(primary=primary, ambient=ambient)

    # === UI Audio ===

    def generate_ui_audio(self, action: str) -> AudioIntent:
        """Generate UI feedback audio."""
        sfx = self._pick_onomatopoeia("ui", action)

        action_intensity = {
            "click": 0.3,
            "select": 0.4,
            "open": 0.5,
            "close": 0.4,
            "error": 0.6,
            "success": 0.5,
        }

        return AudioIntent(
            event_type="ui_feedback",
            onomatopoeia=sfx,
            emotion="neutral",
            intensity=action_intensity.get(action, 0.3),
            speed=1.0,
            reverb=0.1,
            priority=3,
        )

    def generate_notification_audio(self, level: str = "info") -> AudioIntent:
        """Generate notification audio."""
        sfx = self._pick_onomatopoeia("alerts", level)

        level_config = {
            "info": {"emotion": "neutral", "intensity": 0.3, "priority": 4},
            "success": {"emotion": "triumphant", "intensity": 0.5, "priority": 5},
            "warning": {"emotion": "tense", "intensity": 0.6, "priority": 6},
            "error": {"emotion": "danger", "intensity": 0.7, "priority": 7},
            "critical": {"emotion": "danger", "intensity": 1.0, "priority": 9},
        }

        config = level_config.get(level, level_config["info"])

        return AudioIntent(
            event_type="notification",
            onomatopoeia=sfx,
            emotion=config["emotion"],
            intensity=config["intensity"],
            priority=config["priority"],
        )

    # === Scene/Ambient Audio ===

    def generate_ambient_audio(self, scene: str = "city") -> AudioIntent:
        """Generate ambient background audio."""
        sfx = self._pick_onomatopoeia("ambient", scene)

        return AudioIntent(
            event_type="ambient",
            onomatopoeia=sfx,
            emotion="atmospheric",
            intensity=0.3,
            speed=0.8,
            reverb=0.6,
            loop=True,
            priority=1,
        )

    def generate_weather_audio(self, weather: str = "rain") -> AudioBatch:
        """Generate weather-based ambient audio."""
        primary = AudioIntent(
            event_type="ambient",
            onomatopoeia=self._pick_onomatopoeia("ambient", weather),
            emotion="atmospheric",
            intensity=0.4,
            reverb=0.5,
            loop=True,
            priority=2,
        )

        layers = []
        if weather == "storm":
            layers.append(AudioIntent(
                event_type="sfx",
                onomatopoeia=self._pick_onomatopoeia("events", "lightning"),
                emotion="dramatic",
                intensity=0.8,
                priority=5,
            ))

        return AudioBatch(primary=primary, layers=layers)

    def generate_scene_event_audio(self, event: str) -> AudioIntent:
        """Generate audio for scene events (pedestrians, cars, etc.)."""
        sfx = self._pick_onomatopoeia("events", event)

        event_config = {
            "pedestrian": {"intensity": 0.2, "reverb": 0.3},
            "car": {"intensity": 0.4, "reverb": 0.2},
            "lightning": {"intensity": 0.9, "reverb": 0.5},
            "door": {"intensity": 0.4, "reverb": 0.3},
            "cafe": {"intensity": 0.3, "reverb": 0.4},
        }

        config = event_config.get(event, {"intensity": 0.3, "reverb": 0.3})

        return AudioIntent(
            event_type="sfx",
            onomatopoeia=sfx,
            emotion="neutral",
            intensity=config["intensity"],
            reverb=config["reverb"],
            priority=4,
        )


# Global instance
_audio_engine: Optional[AudioEngine] = None


def get_audio_engine() -> AudioEngine:
    """Get the global audio engine instance."""
    global _audio_engine
    if _audio_engine is None:
        _audio_engine = AudioEngine()
    return _audio_engine
