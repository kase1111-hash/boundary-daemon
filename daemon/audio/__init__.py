"""
Audio Module for Boundary Daemon

Provides STT (Speech-to-Text) and TTS (Text-to-Speech) capabilities
for voice control and audio feedback in the TUI dashboard.

Inspired by Tile-Crawler and ASCII-City sound engine patterns.
"""

from .audio_engine import (
    AudioEngine,
    AudioIntent,
    AudioBatch,
    get_audio_engine,
)
from .tts_engine import (
    TTSEngine,
    TTSEngineType,
    TTSRequest,
    AudioData,
    AudioFormat,
    MockTTSEngine,
    TTSEngineManager,
    TTSEngineError,
)
from .stt_engine import (
    STTEngine,
    STTStatus,
    STTResult,
    MockSTTEngine,
    WhisperSTTEngine,
    VoskSTTEngine,
    create_stt_engine,
)

__all__ = [
    # Audio Engine
    'AudioEngine',
    'AudioIntent',
    'AudioBatch',
    'get_audio_engine',
    # TTS
    'TTSEngine',
    'TTSEngineType',
    'TTSRequest',
    'AudioData',
    'AudioFormat',
    'MockTTSEngine',
    'TTSEngineManager',
    'TTSEngineError',
    # STT
    'STTEngine',
    'STTStatus',
    'STTResult',
    'MockSTTEngine',
    'WhisperSTTEngine',
    'VoskSTTEngine',
    'create_stt_engine',
]
