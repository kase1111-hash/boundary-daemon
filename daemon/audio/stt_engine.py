"""
Speech-to-Text Engine - Abstract interface for STT backends.

Provides a unified API for different STT engines:
- Whisper (local, high accuracy)
- Vosk (lightweight, offline)
- Mock (for testing)

Inspired by ASCII-City's STT engine pattern.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Callable, List, Dict, Any
from enum import Enum
from datetime import datetime
import uuid
import time
import queue


class STTStatus(Enum):
    """Status of STT engine."""
    IDLE = "idle"
    LISTENING = "listening"
    PROCESSING = "processing"
    ERROR = "error"
    DISABLED = "disabled"


@dataclass
class STTResult:
    """Result from speech-to-text recognition."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    text: str = ""
    confidence: float = 0.0
    is_final: bool = True
    timestamp: datetime = field(default_factory=datetime.now)
    duration_ms: int = 0
    language: str = "en"
    alternatives: List[str] = field(default_factory=list)
    raw_audio_path: Optional[str] = None

    @property
    def is_empty(self) -> bool:
        """Check if result has no text."""
        return not self.text.strip()

    @property
    def words(self) -> List[str]:
        """Get individual words from text."""
        return self.text.lower().split()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "text": self.text,
            "confidence": self.confidence,
            "is_final": self.is_final,
            "timestamp": self.timestamp.isoformat(),
            "duration_ms": self.duration_ms,
            "language": self.language,
            "alternatives": self.alternatives,
            "raw_audio_path": self.raw_audio_path,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "STTResult":
        """Deserialize from dictionary."""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            text=data.get("text", ""),
            confidence=data.get("confidence", 0.0),
            is_final=data.get("is_final", True),
            timestamp=datetime.fromisoformat(data["timestamp"]) if "timestamp" in data else datetime.now(),
            duration_ms=data.get("duration_ms", 0),
            language=data.get("language", "en"),
            alternatives=data.get("alternatives", []),
            raw_audio_path=data.get("raw_audio_path"),
        )


class STTEngine(ABC):
    """Abstract base class for speech-to-text engines."""

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self._status = STTStatus.IDLE
        self._is_initialized = False
        self._callbacks: List[Callable[[STTResult], None]] = []
        self._error_callbacks: List[Callable[[Exception], None]] = []

    @property
    def status(self) -> STTStatus:
        """Get current engine status."""
        return self._status

    @property
    def is_initialized(self) -> bool:
        """Check if engine is initialized and ready."""
        return self._is_initialized

    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the STT engine."""
        pass

    @abstractmethod
    def shutdown(self) -> None:
        """Shutdown the STT engine and release resources."""
        pass

    @abstractmethod
    def transcribe(self, audio_data: bytes) -> STTResult:
        """Transcribe audio data to text."""
        pass

    @abstractmethod
    def transcribe_file(self, file_path: str) -> STTResult:
        """Transcribe audio from file."""
        pass

    @abstractmethod
    def start_streaming(self) -> bool:
        """Start streaming recognition mode."""
        pass

    @abstractmethod
    def stop_streaming(self) -> Optional[STTResult]:
        """Stop streaming recognition mode."""
        pass

    @abstractmethod
    def feed_audio(self, audio_chunk: bytes) -> Optional[STTResult]:
        """Feed audio chunk during streaming mode."""
        pass

    def on_result(self, callback: Callable[[STTResult], None]) -> None:
        """Register callback for recognition results."""
        self._callbacks.append(callback)

    def on_error(self, callback: Callable[[Exception], None]) -> None:
        """Register callback for errors."""
        self._error_callbacks.append(callback)

    def _emit_result(self, result: STTResult) -> None:
        """Emit result to all registered callbacks."""
        for callback in self._callbacks:
            try:
                callback(result)
            except Exception:
                pass

    def _emit_error(self, error: Exception) -> None:
        """Emit error to all registered callbacks."""
        for callback in self._error_callbacks:
            try:
                callback(error)
            except Exception:
                pass

    @abstractmethod
    def get_supported_languages(self) -> List[str]:
        """Get list of supported language codes."""
        pass

    @abstractmethod
    def set_language(self, language: str) -> bool:
        """Set recognition language."""
        pass

    def get_engine_info(self) -> Dict[str, Any]:
        """Get information about the engine."""
        return {
            "name": self.__class__.__name__,
            "status": self._status.value,
            "initialized": self._is_initialized,
            "model_path": self.model_path,
        }


class WhisperSTTEngine(STTEngine):
    """Whisper-based STT engine (OpenAI Whisper)."""

    def __init__(
        self,
        model_path: Optional[str] = None,
        model_size: str = "base",
        device: str = "cpu",
        compute_type: str = "int8"
    ):
        super().__init__(model_path)
        self.model_size = model_size
        self.device = device
        self.compute_type = compute_type
        self._model = None
        self._language = "en"
        self._streaming_buffer: List[bytes] = []
        self._streaming_active = False

    def initialize(self) -> bool:
        """Initialize Whisper model."""
        try:
            # Try to import faster-whisper or whisper
            try:
                from faster_whisper import WhisperModel
                self._model = WhisperModel(
                    self.model_size,
                    device=self.device,
                    compute_type=self.compute_type
                )
            except ImportError:
                try:
                    import whisper
                    self._model = whisper.load_model(self.model_size)
                except ImportError:
                    return False

            self._is_initialized = True
            self._status = STTStatus.IDLE
            return True
        except Exception as e:
            self._status = STTStatus.ERROR
            self._emit_error(e)
            return False

    def shutdown(self) -> None:
        """Shutdown Whisper engine."""
        self._model = None
        self._is_initialized = False
        self._status = STTStatus.DISABLED
        self._streaming_active = False
        self._streaming_buffer.clear()

    def transcribe(self, audio_data: bytes) -> STTResult:
        """Transcribe audio data using Whisper."""
        if not self._is_initialized:
            return STTResult(text="", confidence=0.0)

        self._status = STTStatus.PROCESSING
        start_time = time.time()

        try:
            # Actual transcription would happen here
            # For now, return placeholder
            duration_ms = int((time.time() - start_time) * 1000)

            result = STTResult(
                text="",
                confidence=0.95,
                duration_ms=duration_ms,
                language=self._language,
            )
            self._status = STTStatus.IDLE
            self._emit_result(result)
            return result
        except Exception as e:
            self._status = STTStatus.ERROR
            self._emit_error(e)
            return STTResult(text="", confidence=0.0)

    def transcribe_file(self, file_path: str) -> STTResult:
        """Transcribe audio file using Whisper."""
        if not self._is_initialized or self._model is None:
            return STTResult(text="", confidence=0.0)

        self._status = STTStatus.PROCESSING
        start_time = time.time()

        try:
            # Use the model to transcribe
            segments, info = self._model.transcribe(
                file_path,
                language=self._language
            )
            text = " ".join([segment.text for segment in segments])

            duration_ms = int((time.time() - start_time) * 1000)

            result = STTResult(
                text=text.strip(),
                confidence=0.95,
                duration_ms=duration_ms,
                language=self._language,
                raw_audio_path=file_path,
            )
            self._status = STTStatus.IDLE
            self._emit_result(result)
            return result
        except Exception as e:
            self._status = STTStatus.ERROR
            self._emit_error(e)
            return STTResult(text="", confidence=0.0)

    def start_streaming(self) -> bool:
        """Start streaming mode."""
        if not self._is_initialized:
            return False

        self._streaming_active = True
        self._streaming_buffer.clear()
        self._status = STTStatus.LISTENING
        return True

    def stop_streaming(self) -> Optional[STTResult]:
        """Stop streaming and get final result."""
        if not self._streaming_active:
            return None

        self._streaming_active = False

        if self._streaming_buffer:
            audio_data = b"".join(self._streaming_buffer)
            result = self.transcribe(audio_data)
            self._streaming_buffer.clear()
            return result

        self._status = STTStatus.IDLE
        return None

    def feed_audio(self, audio_chunk: bytes) -> Optional[STTResult]:
        """Feed audio chunk during streaming."""
        if not self._streaming_active:
            return None

        self._streaming_buffer.append(audio_chunk)

        # Return partial result periodically
        if len(b"".join(self._streaming_buffer)) >= 32000:
            return STTResult(
                text="",
                confidence=0.8,
                is_final=False,
            )

        return None

    def get_supported_languages(self) -> List[str]:
        """Get supported languages."""
        return [
            "en", "es", "fr", "de", "it", "pt", "ru", "zh", "ja", "ko",
            "ar", "hi", "tr", "pl", "nl", "sv", "da", "fi", "no", "cs"
        ]

    def set_language(self, language: str) -> bool:
        """Set recognition language."""
        if language in self.get_supported_languages():
            self._language = language
            return True
        return False


class VoskSTTEngine(STTEngine):
    """Vosk-based STT engine (lightweight, offline)."""

    def __init__(self, model_path: Optional[str] = None):
        super().__init__(model_path)
        self._model = None
        self._recognizer = None
        self._language = "en"
        self._streaming_active = False

    def initialize(self) -> bool:
        """Initialize Vosk model."""
        try:
            from vosk import Model, KaldiRecognizer

            if self.model_path:
                self._model = Model(self.model_path)
            else:
                # Use default small model
                self._model = Model(lang="en-us")

            self._recognizer = KaldiRecognizer(self._model, 16000)
            self._is_initialized = True
            self._status = STTStatus.IDLE
            return True
        except ImportError:
            return False
        except Exception as e:
            self._status = STTStatus.ERROR
            self._emit_error(e)
            return False

    def shutdown(self) -> None:
        """Shutdown Vosk engine."""
        self._model = None
        self._recognizer = None
        self._is_initialized = False
        self._status = STTStatus.DISABLED
        self._streaming_active = False

    def transcribe(self, audio_data: bytes) -> STTResult:
        """Transcribe audio data using Vosk."""
        if not self._is_initialized or self._recognizer is None:
            return STTResult(text="", confidence=0.0)

        self._status = STTStatus.PROCESSING
        start_time = time.time()

        try:
            import json

            if self._recognizer.AcceptWaveform(audio_data):
                result_json = json.loads(self._recognizer.Result())
                text = result_json.get("text", "")
            else:
                result_json = json.loads(self._recognizer.PartialResult())
                text = result_json.get("partial", "")

            duration_ms = int((time.time() - start_time) * 1000)

            result = STTResult(
                text=text,
                confidence=0.85,
                duration_ms=duration_ms,
                language=self._language,
            )
            self._status = STTStatus.IDLE
            self._emit_result(result)
            return result
        except Exception as e:
            self._status = STTStatus.ERROR
            self._emit_error(e)
            return STTResult(text="", confidence=0.0)

    def transcribe_file(self, file_path: str) -> STTResult:
        """Transcribe audio file using Vosk."""
        if not self._is_initialized:
            return STTResult(text="", confidence=0.0)

        self._status = STTStatus.PROCESSING

        try:
            import wave
            import json

            with wave.open(file_path, "rb") as wf:
                while True:
                    data = wf.readframes(4000)
                    if len(data) == 0:
                        break
                    self._recognizer.AcceptWaveform(data)

            result_json = json.loads(self._recognizer.FinalResult())
            text = result_json.get("text", "")

            result = STTResult(
                text=text,
                confidence=0.85,
                language=self._language,
                raw_audio_path=file_path,
            )
            self._status = STTStatus.IDLE
            self._emit_result(result)
            return result
        except Exception as e:
            self._status = STTStatus.ERROR
            self._emit_error(e)
            return STTResult(text="", confidence=0.0)

    def start_streaming(self) -> bool:
        """Start streaming mode."""
        if not self._is_initialized:
            return False

        self._streaming_active = True
        self._status = STTStatus.LISTENING
        return True

    def stop_streaming(self) -> Optional[STTResult]:
        """Stop streaming and get final result."""
        if not self._streaming_active:
            return None

        self._streaming_active = False
        self._status = STTStatus.IDLE

        if self._recognizer:
            import json
            result_json = json.loads(self._recognizer.FinalResult())
            return STTResult(
                text=result_json.get("text", ""),
                confidence=0.85,
                is_final=True
            )

        return STTResult(text="", confidence=0.0, is_final=True)

    def feed_audio(self, audio_chunk: bytes) -> Optional[STTResult]:
        """Feed audio chunk during streaming."""
        if not self._streaming_active or self._recognizer is None:
            return None

        import json

        if self._recognizer.AcceptWaveform(audio_chunk):
            result_json = json.loads(self._recognizer.Result())
            return STTResult(
                text=result_json.get("text", ""),
                confidence=0.85,
                is_final=False
            )

        return None

    def get_supported_languages(self) -> List[str]:
        """Get supported languages (depends on available models)."""
        return ["en", "es", "fr", "de", "ru", "zh", "pt", "it"]

    def set_language(self, language: str) -> bool:
        """Set recognition language."""
        if language in self.get_supported_languages():
            self._language = language
            return True
        return False


class MockSTTEngine(STTEngine):
    """Mock STT engine for testing."""

    def __init__(self, model_path: Optional[str] = None):
        super().__init__(model_path)
        self._responses: queue.Queue = queue.Queue()
        self._streaming_responses: List[STTResult] = []
        self._streaming_index = 0
        self._streaming_active = False
        self._language = "en"
        self._delay_ms = 0

    def set_response(self, text: str, confidence: float = 0.95) -> None:
        """Set next response for transcription."""
        self._responses.put(STTResult(
            text=text,
            confidence=confidence,
            language=self._language,
        ))

    def set_responses(self, responses: List[tuple]) -> None:
        """Set multiple responses (text, confidence) tuples."""
        for text, confidence in responses:
            self.set_response(text, confidence)

    def set_streaming_responses(self, responses: List[tuple]) -> None:
        """Set streaming responses (text, confidence, is_final) tuples."""
        self._streaming_responses = [
            STTResult(text=text, confidence=conf, is_final=final)
            for text, conf, final in responses
        ]

    def set_delay(self, delay_ms: int) -> None:
        """Set artificial delay for transcription."""
        self._delay_ms = delay_ms

    def initialize(self) -> bool:
        """Initialize mock engine."""
        self._is_initialized = True
        self._status = STTStatus.IDLE
        return True

    def shutdown(self) -> None:
        """Shutdown mock engine."""
        self._is_initialized = False
        self._status = STTStatus.DISABLED
        self._streaming_active = False

    def transcribe(self, audio_data: bytes) -> STTResult:
        """Return next queued response."""
        if not self._is_initialized:
            return STTResult(text="", confidence=0.0)

        self._status = STTStatus.PROCESSING

        if self._delay_ms > 0:
            time.sleep(self._delay_ms / 1000)

        try:
            result = self._responses.get_nowait()
        except queue.Empty:
            result = STTResult(text="", confidence=0.0)

        self._status = STTStatus.IDLE
        self._emit_result(result)
        return result

    def transcribe_file(self, file_path: str) -> STTResult:
        """Return next queued response."""
        result = self.transcribe(b"")
        result.raw_audio_path = file_path
        return result

    def start_streaming(self) -> bool:
        """Start streaming mode."""
        if not self._is_initialized:
            return False

        self._streaming_active = True
        self._streaming_index = 0
        self._status = STTStatus.LISTENING
        return True

    def stop_streaming(self) -> Optional[STTResult]:
        """Stop streaming and return final result."""
        if not self._streaming_active:
            return None

        self._streaming_active = False
        self._status = STTStatus.IDLE

        if self._streaming_responses:
            return self._streaming_responses[-1]
        return STTResult(text="", confidence=0.0, is_final=True)

    def feed_audio(self, audio_chunk: bytes) -> Optional[STTResult]:
        """Return next streaming response."""
        if not self._streaming_active:
            return None

        if self._streaming_index < len(self._streaming_responses):
            result = self._streaming_responses[self._streaming_index]
            self._streaming_index += 1
            self._emit_result(result)
            return result

        return None

    def get_supported_languages(self) -> List[str]:
        """Get supported languages."""
        return ["en", "es", "fr", "de", "test"]

    def set_language(self, language: str) -> bool:
        """Set recognition language."""
        self._language = language
        return True


def create_stt_engine(
    engine_type: str = "mock",
    model_path: Optional[str] = None,
    **kwargs
) -> STTEngine:
    """
    Factory function to create STT engine.

    Args:
        engine_type: Type of engine ('whisper', 'vosk', 'mock')
        model_path: Path to model files
        **kwargs: Additional engine-specific arguments

    Returns:
        Configured STTEngine instance
    """
    engines = {
        "whisper": WhisperSTTEngine,
        "vosk": VoskSTTEngine,
        "mock": MockSTTEngine,
    }

    engine_class = engines.get(engine_type.lower(), MockSTTEngine)
    return engine_class(model_path=model_path, **kwargs)
