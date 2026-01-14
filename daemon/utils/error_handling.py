"""
Robust Error Handling Utilities for Boundary Daemon

Provides consistent, verbose error handling across all modules with:
1. Detailed error logging with context
2. Error categorization and severity levels
3. Stack trace preservation
4. Retry logic with exponential backoff
5. Error aggregation and reporting
6. Cross-platform error normalization

USAGE:
    from daemon.utils.error_handling import (
        handle_error,
        ErrorCategory,
        safe_execute,
        with_error_handling,
    )

    # Decorator usage
    @with_error_handling(category=ErrorCategory.SECURITY)
    def my_function():
        ...

    # Context manager usage
    with safe_execute("operation_name", ErrorCategory.NETWORK):
        ...

    # Direct error handling
    try:
        risky_operation()
    except Exception as e:
        handle_error(e, "operation_name", ErrorCategory.SYSTEM)
"""

import functools
import logging
import sys
import time
import threading
import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
)

logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = sys.platform == 'win32'

# Type variable for generic return types
T = TypeVar('T')


class ErrorCategory(Enum):
    """Categories of errors for proper handling and reporting."""
    # Security-related errors (highest priority)
    SECURITY = "security"

    # Authentication/authorization errors
    AUTH = "authentication"

    # Network-related errors
    NETWORK = "network"

    # File system errors
    FILESYSTEM = "filesystem"

    # Process/system errors
    SYSTEM = "system"

    # Configuration errors
    CONFIG = "configuration"

    # Platform-specific errors
    PLATFORM = "platform"

    # Resource exhaustion
    RESOURCE = "resource"

    # External service errors
    EXTERNAL = "external"

    # Unknown/uncategorized
    UNKNOWN = "unknown"


class ErrorSeverity(Enum):
    """Severity levels for errors."""
    # Informational - operation can continue
    INFO = "info"

    # Warning - something unexpected but not critical
    WARNING = "warning"

    # Error - operation failed but system stable
    ERROR = "error"

    # Critical - system integrity at risk
    CRITICAL = "critical"

    # Fatal - system must shut down
    FATAL = "fatal"


@dataclass
class ErrorContext:
    """Detailed context information for an error."""
    error: Exception
    category: ErrorCategory
    severity: ErrorSeverity
    operation: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    thread_name: str = field(default_factory=lambda: threading.current_thread().name)
    stack_trace: str = ""
    additional_context: Dict[str, Any] = field(default_factory=dict)
    platform: str = field(default_factory=lambda: sys.platform)
    python_version: str = field(default_factory=lambda: sys.version)

    def __post_init__(self):
        if not self.stack_trace:
            self.stack_trace = traceback.format_exc()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/serialization."""
        return {
            'error_type': type(self.error).__name__,
            'error_message': str(self.error),
            'category': self.category.value,
            'severity': self.severity.value,
            'operation': self.operation,
            'timestamp': self.timestamp,
            'thread_name': self.thread_name,
            'stack_trace': self.stack_trace,
            'additional_context': self.additional_context,
            'platform': self.platform,
            'python_version': self.python_version,
        }

    def format_log_message(self) -> str:
        """Format a detailed log message."""
        lines = [
            f"ERROR [{self.severity.value.upper()}] in {self.operation}",
            f"  Category: {self.category.value}",
            f"  Type: {type(self.error).__name__}",
            f"  Message: {self.error}",
            f"  Thread: {self.thread_name}",
            f"  Timestamp: {self.timestamp}",
        ]

        if self.additional_context:
            lines.append("  Context:")
            for key, value in self.additional_context.items():
                lines.append(f"    {key}: {value}")

        lines.append("  Stack Trace:")
        for line in self.stack_trace.split('\n'):
            if line.strip():
                lines.append(f"    {line}")

        return '\n'.join(lines)


class ErrorAggregator:
    """
    Aggregates and tracks errors for reporting and analysis.

    Thread-safe error collection with rate limiting and deduplication.
    """

    def __init__(self, max_errors: int = 1000, dedup_window_seconds: int = 60):
        self._errors: List[ErrorContext] = []
        self._lock = threading.Lock()
        self._max_errors = max_errors
        self._dedup_window = dedup_window_seconds
        self._error_counts: Dict[str, int] = {}
        self._last_error_times: Dict[str, float] = {}

    def add_error(self, context: ErrorContext) -> bool:
        """
        Add an error to the aggregator.

        Returns True if error was added, False if deduplicated.
        """
        error_key = f"{context.category.value}:{type(context.error).__name__}:{context.operation}"
        current_time = time.time()

        with self._lock:
            # Check for deduplication
            last_time = self._last_error_times.get(error_key, 0)
            if current_time - last_time < self._dedup_window:
                self._error_counts[error_key] = self._error_counts.get(error_key, 0) + 1
                return False

            # Add the error
            self._errors.append(context)
            self._last_error_times[error_key] = current_time
            self._error_counts[error_key] = 1

            # Trim if too many errors
            if len(self._errors) > self._max_errors:
                self._errors = self._errors[-self._max_errors:]

            return True

    def get_error_summary(self) -> Dict[str, Any]:
        """Get a summary of aggregated errors."""
        with self._lock:
            by_category = {}
            by_severity = {}

            for ctx in self._errors:
                cat = ctx.category.value
                sev = ctx.severity.value
                by_category[cat] = by_category.get(cat, 0) + 1
                by_severity[sev] = by_severity.get(sev, 0) + 1

            return {
                'total_errors': len(self._errors),
                'by_category': by_category,
                'by_severity': by_severity,
                'deduplicated_counts': dict(self._error_counts),
            }

    def get_recent_errors(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get the most recent errors."""
        with self._lock:
            return [e.to_dict() for e in self._errors[-count:]]

    def clear(self):
        """Clear all aggregated errors."""
        with self._lock:
            self._errors.clear()
            self._error_counts.clear()
            self._last_error_times.clear()


# Global error aggregator
_global_aggregator = ErrorAggregator()


def get_error_aggregator() -> ErrorAggregator:
    """Get the global error aggregator instance."""
    return _global_aggregator


def determine_severity(
    error: Exception,
    category: ErrorCategory,
) -> ErrorSeverity:
    """
    Determine the severity level for an error based on type and category.
    """
    error_type = type(error).__name__

    # Fatal errors
    if isinstance(error, (SystemExit, KeyboardInterrupt)):
        return ErrorSeverity.FATAL

    # Critical security errors
    if category == ErrorCategory.SECURITY:
        if 'tamper' in str(error).lower() or 'integrity' in str(error).lower():
            return ErrorSeverity.CRITICAL
        return ErrorSeverity.ERROR

    # Critical auth errors
    if category == ErrorCategory.AUTH:
        if 'bypass' in str(error).lower() or 'violation' in str(error).lower():
            return ErrorSeverity.CRITICAL
        return ErrorSeverity.ERROR

    # Resource exhaustion is critical
    if category == ErrorCategory.RESOURCE:
        return ErrorSeverity.CRITICAL

    # Permission errors
    if isinstance(error, PermissionError):
        return ErrorSeverity.ERROR

    # File not found is usually a warning
    if isinstance(error, FileNotFoundError):
        return ErrorSeverity.WARNING

    # Network timeouts are warnings
    if 'timeout' in error_type.lower() or 'timeout' in str(error).lower():
        return ErrorSeverity.WARNING

    # Default to ERROR
    return ErrorSeverity.ERROR


def handle_error(
    error: Exception,
    operation: str,
    category: ErrorCategory = ErrorCategory.UNKNOWN,
    severity: Optional[ErrorSeverity] = None,
    additional_context: Optional[Dict[str, Any]] = None,
    reraise: bool = False,
    log_level: Optional[int] = None,
) -> ErrorContext:
    """
    Handle an error with comprehensive logging and tracking.

    Args:
        error: The exception that occurred
        operation: Name of the operation that failed
        category: Category of the error
        severity: Severity level (auto-determined if not provided)
        additional_context: Additional context information
        reraise: Whether to re-raise the exception after handling
        log_level: Override the log level (auto-determined if not provided)

    Returns:
        ErrorContext with full error details
    """
    # Determine severity if not provided
    if severity is None:
        severity = determine_severity(error, category)

    # Create error context
    context = ErrorContext(
        error=error,
        category=category,
        severity=severity,
        operation=operation,
        additional_context=additional_context or {},
    )

    # Add to aggregator
    was_added = _global_aggregator.add_error(context)

    # Determine log level
    if log_level is None:
        log_level_map = {
            ErrorSeverity.INFO: logging.INFO,
            ErrorSeverity.WARNING: logging.WARNING,
            ErrorSeverity.ERROR: logging.ERROR,
            ErrorSeverity.CRITICAL: logging.CRITICAL,
            ErrorSeverity.FATAL: logging.CRITICAL,
        }
        log_level = log_level_map.get(severity, logging.ERROR)

    # Log the error
    if was_added:
        logger.log(log_level, context.format_log_message())
    else:
        # Just log a brief message for deduplicated errors
        logger.log(
            log_level,
            f"[DEDUPLICATED] {operation}: {type(error).__name__}: {error}"
        )

    # Re-raise if requested
    if reraise:
        raise error

    return context


@contextmanager
def safe_execute(
    operation: str,
    category: ErrorCategory = ErrorCategory.UNKNOWN,
    default_return: Any = None,
    reraise: bool = False,
    additional_context: Optional[Dict[str, Any]] = None,
):
    """
    Context manager for safe execution with error handling.

    Usage:
        with safe_execute("loading config", ErrorCategory.CONFIG) as result:
            result.value = load_config()

    Args:
        operation: Name of the operation
        category: Error category
        default_return: Default value to return on error
        reraise: Whether to re-raise exceptions
        additional_context: Additional context information
    """
    class Result:
        def __init__(self):
            self.value = default_return
            self.error: Optional[ErrorContext] = None
            self.success = True

    result = Result()

    try:
        yield result
    except Exception as e:
        result.success = False
        result.error = handle_error(
            e,
            operation,
            category=category,
            additional_context=additional_context,
            reraise=reraise,
        )
        result.value = default_return


def with_error_handling(
    category: ErrorCategory = ErrorCategory.UNKNOWN,
    operation: Optional[str] = None,
    default_return: Any = None,
    reraise: bool = False,
    log_args: bool = False,
    retry_count: int = 0,
    retry_delay: float = 1.0,
    retry_backoff: float = 2.0,
    retry_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
):
    """
    Decorator for functions with automatic error handling.

    Args:
        category: Error category for this function
        operation: Operation name (defaults to function name)
        default_return: Value to return on error
        reraise: Whether to re-raise exceptions
        log_args: Whether to log function arguments on error
        retry_count: Number of retries on failure
        retry_delay: Initial delay between retries
        retry_backoff: Multiplier for delay on each retry
        retry_exceptions: Exception types to retry on (defaults to all)

    Usage:
        @with_error_handling(category=ErrorCategory.NETWORK, retry_count=3)
        def fetch_data():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            op_name = operation or func.__name__
            attempts = 0
            current_delay = retry_delay
            last_error: Optional[Exception] = None

            while attempts <= retry_count:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_error = e
                    attempts += 1

                    # Check if we should retry
                    should_retry = (
                        attempts <= retry_count and
                        (retry_exceptions is None or isinstance(e, retry_exceptions))
                    )

                    # Build additional context
                    additional_context = {
                        'attempt': attempts,
                        'max_attempts': retry_count + 1,
                        'will_retry': should_retry,
                    }

                    if log_args:
                        additional_context['args'] = repr(args)[:500]
                        additional_context['kwargs'] = repr(kwargs)[:500]

                    # Handle the error
                    handle_error(
                        e,
                        op_name,
                        category=category,
                        additional_context=additional_context,
                        reraise=False,
                    )

                    if should_retry:
                        logger.info(
                            f"Retrying {op_name} in {current_delay:.1f}s "
                            f"(attempt {attempts}/{retry_count + 1})"
                        )
                        time.sleep(current_delay)
                        current_delay *= retry_backoff
                    else:
                        break

            # All retries exhausted
            if reraise and last_error:
                raise last_error

            return default_return

        return wrapper
    return decorator


def normalize_platform_error(error: Exception) -> Tuple[str, str]:
    """
    Normalize platform-specific errors to a common format.

    Returns:
        Tuple of (normalized_type, normalized_message)
    """
    error_type = type(error).__name__
    error_msg = str(error)

    # Windows-specific error normalization
    if IS_WINDOWS:
        # Windows error codes
        if 'WinError' in error_type or 'WinError' in error_msg:
            import re
            match = re.search(r'\[WinError (\d+)\]', error_msg)
            if match:
                code = int(match.group(1))
                # Map common Windows error codes
                win_errors = {
                    2: ('FileNotFoundError', 'File not found'),
                    3: ('FileNotFoundError', 'Path not found'),
                    5: ('PermissionError', 'Access denied'),
                    32: ('PermissionError', 'File in use'),
                    87: ('ValueError', 'Invalid parameter'),
                    1314: ('PermissionError', 'Privilege not held'),
                }
                if code in win_errors:
                    return win_errors[code]
    else:
        # Unix-specific error normalization
        if hasattr(error, 'errno'):
            import errno
            errno_map = {
                errno.ENOENT: ('FileNotFoundError', 'No such file or directory'),
                errno.EACCES: ('PermissionError', 'Permission denied'),
                errno.EPERM: ('PermissionError', 'Operation not permitted'),
                errno.EEXIST: ('FileExistsError', 'File exists'),
                errno.ENOTDIR: ('NotADirectoryError', 'Not a directory'),
                errno.EISDIR: ('IsADirectoryError', 'Is a directory'),
            }
            if error.errno in errno_map:
                return errno_map[error.errno]

    return error_type, error_msg


class ErrorRecoveryAction(Enum):
    """Actions to take for error recovery."""
    IGNORE = "ignore"           # Ignore and continue
    RETRY = "retry"             # Retry the operation
    FALLBACK = "fallback"       # Use fallback method
    ABORT = "abort"             # Abort the operation
    RESTART = "restart"         # Restart the component
    SHUTDOWN = "shutdown"       # Shut down gracefully


def suggest_recovery_action(
    error: Exception,
    category: ErrorCategory,
) -> ErrorRecoveryAction:
    """
    Suggest a recovery action based on the error type and category.
    """
    error_type = type(error).__name__

    # Transient errors - retry
    transient_types = {'TimeoutError', 'ConnectionError', 'BrokenPipeError'}
    if error_type in transient_types or 'timeout' in str(error).lower():
        return ErrorRecoveryAction.RETRY

    # Permission errors - might need fallback
    if isinstance(error, PermissionError):
        return ErrorRecoveryAction.FALLBACK

    # File not found - might be ignorable
    if isinstance(error, FileNotFoundError):
        if category in {ErrorCategory.CONFIG, ErrorCategory.FILESYSTEM}:
            return ErrorRecoveryAction.FALLBACK
        return ErrorRecoveryAction.IGNORE

    # Security violations - abort
    if category == ErrorCategory.SECURITY:
        if 'tamper' in str(error).lower() or 'violation' in str(error).lower():
            return ErrorRecoveryAction.SHUTDOWN
        return ErrorRecoveryAction.ABORT

    # Resource exhaustion - restart might help
    if category == ErrorCategory.RESOURCE:
        return ErrorRecoveryAction.RESTART

    # Default to abort for unknown errors
    return ErrorRecoveryAction.ABORT


# Convenience functions for common error types
def log_security_error(
    error: Exception,
    operation: str,
    **context,
) -> ErrorContext:
    """Log a security-related error with critical severity."""
    return handle_error(
        error,
        operation,
        category=ErrorCategory.SECURITY,
        severity=ErrorSeverity.CRITICAL,
        additional_context=context,
    )


def log_auth_error(
    error: Exception,
    operation: str,
    **context,
) -> ErrorContext:
    """Log an authentication/authorization error."""
    return handle_error(
        error,
        operation,
        category=ErrorCategory.AUTH,
        additional_context=context,
    )


def log_network_error(
    error: Exception,
    operation: str,
    **context,
) -> ErrorContext:
    """Log a network-related error."""
    return handle_error(
        error,
        operation,
        category=ErrorCategory.NETWORK,
        additional_context=context,
    )


def log_filesystem_error(
    error: Exception,
    operation: str,
    **context,
) -> ErrorContext:
    """Log a filesystem error."""
    return handle_error(
        error,
        operation,
        category=ErrorCategory.FILESYSTEM,
        additional_context=context,
    )


def log_platform_error(
    error: Exception,
    operation: str,
    **context,
) -> ErrorContext:
    """Log a platform-specific error with normalization."""
    norm_type, norm_msg = normalize_platform_error(error)
    context['normalized_type'] = norm_type
    context['normalized_message'] = norm_msg
    return handle_error(
        error,
        operation,
        category=ErrorCategory.PLATFORM,
        additional_context=context,
    )


# === SIEM Integration ===

# Optional SIEM integration - import only if available
_siem_integration = None


def set_siem_integration(siem):
    """
    Set the SIEM integration instance for automatic security event forwarding.

    Args:
        siem: SIEMIntegration instance from daemon.security.siem_integration
    """
    global _siem_integration
    _siem_integration = siem


def _forward_to_siem(context: ErrorContext):
    """Forward error to SIEM if integration is configured."""
    if _siem_integration is None:
        return

    try:
        # Map error severity to SIEM severity
        from daemon.security.siem_integration import SecurityEventSeverity

        severity_map = {
            ErrorSeverity.INFO: SecurityEventSeverity.LOW,
            ErrorSeverity.WARNING: SecurityEventSeverity.MEDIUM,
            ErrorSeverity.ERROR: SecurityEventSeverity.HIGH,
            ErrorSeverity.CRITICAL: SecurityEventSeverity.CRITICAL,
            ErrorSeverity.FATAL: SecurityEventSeverity.EMERGENCY,
        }
        siem_severity = severity_map.get(context.severity, SecurityEventSeverity.MEDIUM)

        # Forward based on category
        if context.category == ErrorCategory.SECURITY:
            _siem_integration.log_security_error(
                error_type=type(context.error).__name__,
                error_message=str(context.error),
                component=context.operation,
                details=context.additional_context,
            )
        elif context.category == ErrorCategory.AUTH:
            _siem_integration.log_authentication_failure(
                reason=str(context.error),
                details={
                    'operation': context.operation,
                    **context.additional_context,
                },
            )
        elif context.severity in (ErrorSeverity.CRITICAL, ErrorSeverity.FATAL):
            _siem_integration.log_security_error(
                error_type=context.category.value,
                error_message=str(context.error),
                component=context.operation,
                details=context.additional_context,
            )
    except ImportError:
        pass  # SIEM module not available
    except Exception as e:
        # Don't let SIEM forwarding errors propagate
        logger.debug(f"SIEM forwarding failed: {e}")


# === Circuit Breaker Pattern ===

class CircuitBreakerState(Enum):
    """States for the circuit breaker."""
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Failing, rejecting calls
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """
    Circuit breaker pattern implementation for resilient service calls.

    Prevents cascading failures by temporarily stopping calls to failing services.

    Usage:
        breaker = CircuitBreaker("external_service", failure_threshold=5)

        @breaker.protect
        def call_external_service():
            ...

        # Or manual usage
        if breaker.can_execute():
            try:
                result = call_service()
                breaker.record_success()
            except Exception as e:
                breaker.record_failure(e)
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        success_threshold: int = 2,
        timeout: float = 60.0,
        excluded_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
    ):
        """
        Initialize circuit breaker.

        Args:
            name: Name for logging/identification
            failure_threshold: Failures before opening circuit
            success_threshold: Successes needed to close from half-open
            timeout: Seconds before half-open transition
            excluded_exceptions: Exceptions that don't count as failures
        """
        self.name = name
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.timeout = timeout
        self.excluded_exceptions = excluded_exceptions or ()

        self._state = CircuitBreakerState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitBreakerState:
        """Get current circuit state."""
        with self._lock:
            self._check_state_transition()
            return self._state

    def _check_state_transition(self):
        """Check if state should transition based on timeout."""
        if self._state == CircuitBreakerState.OPEN:
            if self._last_failure_time:
                elapsed = time.time() - self._last_failure_time
                if elapsed >= self.timeout:
                    self._state = CircuitBreakerState.HALF_OPEN
                    self._success_count = 0
                    logger.info(f"Circuit breaker '{self.name}' -> HALF_OPEN")

    def can_execute(self) -> bool:
        """Check if execution is allowed."""
        state = self.state
        return state in (CircuitBreakerState.CLOSED, CircuitBreakerState.HALF_OPEN)

    def record_success(self):
        """Record a successful execution."""
        with self._lock:
            if self._state == CircuitBreakerState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = CircuitBreakerState.CLOSED
                    self._failure_count = 0
                    logger.info(f"Circuit breaker '{self.name}' -> CLOSED")
            elif self._state == CircuitBreakerState.CLOSED:
                # Reset failure count on success
                self._failure_count = 0

    def record_failure(self, error: Exception):
        """Record a failed execution."""
        # Check if this exception is excluded
        if isinstance(error, self.excluded_exceptions):
            return

        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()

            if self._state == CircuitBreakerState.HALF_OPEN:
                # Single failure in half-open goes back to open
                self._state = CircuitBreakerState.OPEN
                logger.warning(f"Circuit breaker '{self.name}' -> OPEN (half-open failure)")
            elif self._state == CircuitBreakerState.CLOSED:
                if self._failure_count >= self.failure_threshold:
                    self._state = CircuitBreakerState.OPEN
                    logger.warning(
                        f"Circuit breaker '{self.name}' -> OPEN "
                        f"(threshold {self.failure_threshold} reached)"
                    )

    def protect(self, func: Callable[..., T]) -> Callable[..., T]:
        """
        Decorator to protect a function with this circuit breaker.

        Raises:
            CircuitBreakerOpenError: When circuit is open
        """
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            if not self.can_execute():
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{self.name}' is OPEN"
                )

            try:
                result = func(*args, **kwargs)
                self.record_success()
                return result
            except Exception as e:
                self.record_failure(e)
                raise

        return wrapper

    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status."""
        with self._lock:
            return {
                'name': self.name,
                'state': self._state.value,
                'failure_count': self._failure_count,
                'success_count': self._success_count,
                'failure_threshold': self.failure_threshold,
                'last_failure': self._last_failure_time,
            }

    def reset(self):
        """Manually reset the circuit breaker to closed state."""
        with self._lock:
            self._state = CircuitBreakerState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            logger.info(f"Circuit breaker '{self.name}' manually reset -> CLOSED")


class CircuitBreakerOpenError(Exception):
    """Raised when trying to execute through an open circuit breaker."""
    pass


# Registry for circuit breakers
_circuit_breakers: Dict[str, CircuitBreaker] = {}
_breaker_lock = threading.Lock()


def get_circuit_breaker(
    name: str,
    failure_threshold: int = 5,
    success_threshold: int = 2,
    timeout: float = 60.0,
) -> CircuitBreaker:
    """
    Get or create a named circuit breaker.

    Args:
        name: Unique name for the circuit breaker
        failure_threshold: Failures before opening
        success_threshold: Successes to close from half-open
        timeout: Seconds before half-open

    Returns:
        CircuitBreaker instance
    """
    with _breaker_lock:
        if name not in _circuit_breakers:
            _circuit_breakers[name] = CircuitBreaker(
                name=name,
                failure_threshold=failure_threshold,
                success_threshold=success_threshold,
                timeout=timeout,
            )
        return _circuit_breakers[name]


def get_all_circuit_breaker_status() -> Dict[str, Dict[str, Any]]:
    """Get status of all circuit breakers."""
    with _breaker_lock:
        return {name: cb.get_status() for name, cb in _circuit_breakers.items()}


# Update handle_error to forward to SIEM
_original_handle_error = handle_error


def handle_error(
    error: Exception,
    operation: str,
    category: ErrorCategory = ErrorCategory.UNKNOWN,
    severity: Optional[ErrorSeverity] = None,
    additional_context: Optional[Dict[str, Any]] = None,
    reraise: bool = False,
    log_level: Optional[int] = None,
    forward_to_siem: bool = True,
) -> ErrorContext:
    """
    Handle an error with comprehensive logging, tracking, and SIEM forwarding.

    Args:
        error: The exception that occurred
        operation: Name of the operation that failed
        category: Category of the error
        severity: Severity level (auto-determined if not provided)
        additional_context: Additional context information
        reraise: Whether to re-raise the exception after handling
        log_level: Override the log level (auto-determined if not provided)
        forward_to_siem: Whether to forward to SIEM (default True)

    Returns:
        ErrorContext with full error details
    """
    # Determine severity if not provided
    if severity is None:
        severity = determine_severity(error, category)

    # Create error context
    context = ErrorContext(
        error=error,
        category=category,
        severity=severity,
        operation=operation,
        additional_context=additional_context or {},
    )

    # Add to aggregator
    was_added = _global_aggregator.add_error(context)

    # Determine log level
    if log_level is None:
        log_level_map = {
            ErrorSeverity.INFO: logging.INFO,
            ErrorSeverity.WARNING: logging.WARNING,
            ErrorSeverity.ERROR: logging.ERROR,
            ErrorSeverity.CRITICAL: logging.CRITICAL,
            ErrorSeverity.FATAL: logging.CRITICAL,
        }
        log_level = log_level_map.get(severity, logging.ERROR)

    # Log the error
    if was_added:
        logger.log(log_level, context.format_log_message())
    else:
        # Just log a brief message for deduplicated errors
        logger.log(
            log_level,
            f"[DEDUPLICATED] {operation}: {type(error).__name__}: {error}"
        )

    # Forward to SIEM for security-relevant errors
    if forward_to_siem and severity in (
        ErrorSeverity.ERROR, ErrorSeverity.CRITICAL, ErrorSeverity.FATAL
    ):
        _forward_to_siem(context)

    # Re-raise if requested
    if reraise:
        raise error

    return context


# Export all public symbols
__all__ = [
    'ErrorCategory',
    'ErrorSeverity',
    'ErrorContext',
    'ErrorAggregator',
    'ErrorRecoveryAction',
    'get_error_aggregator',
    'handle_error',
    'safe_execute',
    'with_error_handling',
    'determine_severity',
    'normalize_platform_error',
    'suggest_recovery_action',
    'log_security_error',
    'log_auth_error',
    'log_network_error',
    'log_filesystem_error',
    'log_platform_error',
    # SIEM integration
    'set_siem_integration',
    # Circuit breaker
    'CircuitBreaker',
    'CircuitBreakerState',
    'CircuitBreakerOpenError',
    'get_circuit_breaker',
    'get_all_circuit_breaker_status',
]
