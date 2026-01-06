"""
TTS Engine System - Text-to-speech synthesis backends.

Provides a unified interface for multiple TTS engines with
fallback support and mock implementation for testing.

Inspired by ASCII-City's TTS engine pattern.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List
import hashlib
import time


class TTSEngineType(Enum):
    """Available TTS engine types."""
    MOCK = "mock"
    PYTTSX3 = "pyttsx3"
    PIPER = "piper"
    SYSTEM = "system"  # OS built-in TTS


class AudioFormat(Enum):
    """Output audio formats."""
    WAV = "wav"
    MP3 = "mp3"
    OGG = "ogg"
    RAW = "raw"  # Raw PCM data


@dataclass
class VoiceParameters:
    """Voice synthesis parameters."""
    pitch: float = 0.0  # -12 to +12 semitones
    speed: float = 1.0  # 0.5 to 2.0
    volume: float = 1.0  # 0.0 to 1.0
    voice_id: str = "default"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'pitch': self.pitch,
            'speed': self.speed,
            'volume': self.volume,
            'voice_id': self.voice_id,
        }


@dataclass
class AudioData:
    """Container for synthesized audio data."""
    data: bytes
    format: AudioFormat = AudioFormat.WAV
    sample_rate: int = 22050
    channels: int = 1
    bit_depth: int = 16
    duration_ms: int = 0
    text: str = ""
    voice_id: str = ""
    engine: str = ""
    generation_time_ms: int = 0

    def __post_init__(self):
        """Estimate duration if not provided."""
        if self.duration_ms == 0 and self.data:
            bytes_per_sample = self.bit_depth // 8
            samples = len(self.data) // (bytes_per_sample * self.channels)
            self.duration_ms = int((samples / self.sample_rate) * 1000)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize metadata (not audio data)."""
        return {
            'format': self.format.value,
            'sample_rate': self.sample_rate,
            'channels': self.channels,
            'bit_depth': self.bit_depth,
            'duration_ms': self.duration_ms,
            'text': self.text,
            'voice_id': self.voice_id,
            'engine': self.engine,
            'generation_time_ms': self.generation_time_ms,
        }


@dataclass
class TTSRequest:
    """Request for TTS synthesis."""
    text: str
    params: VoiceParameters = field(default_factory=VoiceParameters)
    format: AudioFormat = AudioFormat.WAV
    speed_override: Optional[float] = None
    pitch_override: Optional[float] = None

    def get_effective_params(self) -> VoiceParameters:
        """Get parameters with any overrides applied."""
        params = VoiceParameters(
            pitch=self.params.pitch,
            speed=self.params.speed,
            volume=self.params.volume,
            voice_id=self.params.voice_id,
        )
        if self.speed_override is not None:
            params.speed = self.speed_override
        if self.pitch_override is not None:
            params.pitch = self.pitch_override
        return params

    def get_cache_key(self) -> str:
        """Generate cache key for this request."""
        params = self.get_effective_params()
        key_data = f"{self.text}:{params.to_dict()}:{self.format.value}"
        return hashlib.md5(key_data.encode()).hexdigest()


class TTSEngine(ABC):
    """Abstract base class for TTS engines."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize engine with optional configuration."""
        self.config = config or {}
        self._initialized = False

    @property
    @abstractmethod
    def engine_type(self) -> TTSEngineType:
        """Return the engine type identifier."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable engine name."""
        pass

    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the engine. Returns True if successful."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the engine is available and ready."""
        pass

    @abstractmethod
    def synthesize(self, request: TTSRequest) -> AudioData:
        """Synthesize speech from text."""
        pass

    @abstractmethod
    def get_supported_formats(self) -> List[AudioFormat]:
        """Return list of supported output formats."""
        pass

    def shutdown(self) -> None:
        """Clean up engine resources."""
        self._initialized = False


class MockTTSEngine(TTSEngine):
    """Mock TTS engine for testing."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._synthesis_count = 0
        self._last_request: Optional[TTSRequest] = None
        self._failure_mode = False
        self._latency_ms = config.get('latency_ms', 10) if config else 10

    @property
    def engine_type(self) -> TTSEngineType:
        return TTSEngineType.MOCK

    @property
    def name(self) -> str:
        return "Mock TTS Engine"

    def initialize(self) -> bool:
        self._initialized = True
        return True

    def is_available(self) -> bool:
        return self._initialized and not self._failure_mode

    def set_failure_mode(self, enabled: bool) -> None:
        """Enable/disable failure mode for testing error handling."""
        self._failure_mode = enabled

    def synthesize(self, request: TTSRequest) -> AudioData:
        """Generate mock audio data."""
        if self._failure_mode:
            raise TTSEngineError("Mock engine in failure mode")

        if not self._initialized:
            raise TTSEngineError("Engine not initialized")

        start_time = time.time()

        # Simulate latency
        if self._latency_ms > 0:
            time.sleep(self._latency_ms / 1000.0)

        # Calculate mock audio duration based on text
        # Approximate: 150 words per minute = 2.5 words per second
        words = len(request.text.split())
        duration_ms = int((words / 2.5) * 1000)
        duration_ms = max(100, duration_ms)  # Minimum 100ms

        # Apply speed modifier
        params = request.get_effective_params()
        speed_factor = 0.5 + params.speed  # 0.5x to 1.5x
        duration_ms = int(duration_ms / speed_factor)

        # Generate mock audio bytes
        sample_rate = 22050
        bytes_per_second = sample_rate * 2  # 16-bit = 2 bytes
        num_bytes = int((duration_ms / 1000.0) * bytes_per_second)

        # Create deterministic mock data based on text hash
        text_hash = hashlib.md5(request.text.encode()).digest()
        mock_data = (text_hash * ((num_bytes // 16) + 1))[:num_bytes]

        self._synthesis_count += 1
        self._last_request = request

        generation_time = int((time.time() - start_time) * 1000)

        return AudioData(
            data=mock_data,
            format=request.format,
            sample_rate=sample_rate,
            channels=1,
            bit_depth=16,
            duration_ms=duration_ms,
            text=request.text,
            voice_id=params.voice_id,
            engine=self.name,
            generation_time_ms=generation_time,
        )

    def get_supported_formats(self) -> List[AudioFormat]:
        return [AudioFormat.WAV, AudioFormat.RAW]

    @property
    def synthesis_count(self) -> int:
        """Number of synthesis calls made."""
        return self._synthesis_count

    @property
    def last_request(self) -> Optional[TTSRequest]:
        """Last synthesis request received."""
        return self._last_request

    def reset_stats(self) -> None:
        """Reset test statistics."""
        self._synthesis_count = 0
        self._last_request = None


class Pyttsx3Engine(TTSEngine):
    """pyttsx3-based TTS engine (cross-platform)."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._engine = None

    @property
    def engine_type(self) -> TTSEngineType:
        return TTSEngineType.PYTTSX3

    @property
    def name(self) -> str:
        return "pyttsx3 TTS"

    def initialize(self) -> bool:
        try:
            import pyttsx3
            self._engine = pyttsx3.init()
            self._initialized = True
            return True
        except ImportError:
            return False
        except Exception:
            return False

    def is_available(self) -> bool:
        return self._initialized and self._engine is not None

    def synthesize(self, request: TTSRequest) -> AudioData:
        if not self._initialized or self._engine is None:
            raise TTSEngineError("pyttsx3 not initialized")

        start_time = time.time()
        params = request.get_effective_params()

        # Configure engine
        self._engine.setProperty('rate', int(150 * params.speed))
        self._engine.setProperty('volume', params.volume)

        # Note: pyttsx3 doesn't easily support in-memory audio
        # This is a simplified implementation
        self._engine.say(request.text)
        self._engine.runAndWait()

        generation_time = int((time.time() - start_time) * 1000)

        # Return empty audio data (actual audio was played)
        return AudioData(
            data=b'',
            format=AudioFormat.RAW,
            duration_ms=generation_time,
            text=request.text,
            voice_id=params.voice_id,
            engine=self.name,
            generation_time_ms=generation_time,
        )

    def get_supported_formats(self) -> List[AudioFormat]:
        return [AudioFormat.RAW]  # Direct playback only

    def shutdown(self) -> None:
        if self._engine:
            self._engine.stop()
            self._engine = None
        self._initialized = False


class TTSEngineError(Exception):
    """Exception raised by TTS engines."""
    pass


class TTSEngineManager:
    """Manages multiple TTS engines with fallback support."""

    def __init__(self):
        self._engines: Dict[TTSEngineType, TTSEngine] = {}
        self._primary_engine: Optional[TTSEngineType] = None
        self._fallback_order: List[TTSEngineType] = []
        self._cache: Dict[str, AudioData] = {}
        self._cache_enabled = True
        self._max_cache_size = 100

    def register_engine(
        self,
        engine: TTSEngine,
        set_primary: bool = False
    ) -> None:
        """Register a TTS engine."""
        engine_type = engine.engine_type
        self._engines[engine_type] = engine

        if set_primary or self._primary_engine is None:
            self._primary_engine = engine_type

        if engine_type not in self._fallback_order:
            self._fallback_order.append(engine_type)

    def set_primary_engine(self, engine_type: TTSEngineType) -> bool:
        """Set the primary engine type."""
        if engine_type in self._engines:
            self._primary_engine = engine_type
            return True
        return False

    def set_fallback_order(self, order: List[TTSEngineType]) -> None:
        """Set the fallback order for engines."""
        self._fallback_order = [t for t in order if t in self._engines]

    def get_engine(self, engine_type: TTSEngineType) -> Optional[TTSEngine]:
        """Get a specific engine by type."""
        return self._engines.get(engine_type)

    def get_available_engines(self) -> List[TTSEngine]:
        """Get list of available engines."""
        return [e for e in self._engines.values() if e.is_available()]

    def initialize_all(self) -> Dict[TTSEngineType, bool]:
        """Initialize all registered engines."""
        results = {}
        for engine_type, engine in self._engines.items():
            try:
                results[engine_type] = engine.initialize()
            except Exception:
                results[engine_type] = False
        return results

    def synthesize(
        self,
        request: TTSRequest,
        use_cache: bool = True
    ) -> AudioData:
        """Synthesize speech using available engines."""
        # Check cache
        if use_cache and self._cache_enabled:
            cache_key = request.get_cache_key()
            if cache_key in self._cache:
                return self._cache[cache_key]

        # Try engines in order
        errors = []

        # Primary first
        if self._primary_engine:
            engine = self._engines.get(self._primary_engine)
            if engine and engine.is_available():
                try:
                    result = engine.synthesize(request)
                    self._cache_result(request, result)
                    return result
                except Exception as e:
                    errors.append(f"{engine.name}: {e}")

        # Then fallbacks
        for engine_type in self._fallback_order:
            if engine_type == self._primary_engine:
                continue

            engine = self._engines.get(engine_type)
            if engine and engine.is_available():
                try:
                    result = engine.synthesize(request)
                    self._cache_result(request, result)
                    return result
                except Exception as e:
                    errors.append(f"{engine.name}: {e}")

        raise TTSEngineError(f"All TTS engines failed: {'; '.join(errors)}")

    def _cache_result(self, request: TTSRequest, result: AudioData) -> None:
        """Cache a synthesis result."""
        if not self._cache_enabled:
            return

        cache_key = request.get_cache_key()

        # Evict oldest if at capacity
        if len(self._cache) >= self._max_cache_size:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]

        self._cache[cache_key] = result

    def clear_cache(self) -> None:
        """Clear the synthesis cache."""
        self._cache.clear()

    def set_cache_enabled(self, enabled: bool) -> None:
        """Enable or disable caching."""
        self._cache_enabled = enabled

    def shutdown_all(self) -> None:
        """Shutdown all engines."""
        for engine in self._engines.values():
            try:
                engine.shutdown()
            except Exception:
                pass
