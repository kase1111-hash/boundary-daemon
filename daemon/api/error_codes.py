"""
Error codes for Boundary Daemon API.

Provides a central registry of machine-readable error codes used across
HTTP endpoints and CLI tools.
"""

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class ErrorCode:
    """A single API error code with metadata."""
    code: str
    message: str
    hint: str = ""


# Authentication & authorization
AUTH_FAILED = ErrorCode("E001", "Authentication failed", "Check API token or credentials.")
RATE_LIMIT_EXCEEDED = ErrorCode("E002", "Rate limit exceeded", "Wait and retry after the cooldown window.")

# Request validation
INVALID_REQUEST = ErrorCode("E003", "Invalid request format", "Check the request body against the API docs.")

# Policy engine
POLICY_EVAL_FAILED = ErrorCode("E004", "Policy evaluation failed", "Review policy configuration.")
MODE_TRANSITION_DENIED = ErrorCode(
    "E005",
    "Mode transition denied",
    "Transition may require a ceremony. Run: boundaryctl ceremony mode_override",
)

# Ceremony & lockdown
CEREMONY_REQUIRED = ErrorCode("E006", "Ceremony required", "Start a ceremony with: boundaryctl ceremony <type>")
SYSTEM_IN_LOCKDOWN = ErrorCode("E007", "System in LOCKDOWN", "Exit LOCKDOWN via operator ceremony first.")
TRIPWIRE_LOCKED = ErrorCode("E008", "Tripwire locked", "A tripwire has been triggered; manual investigation required.")

# Configuration & internal
CONFIG_ERROR = ErrorCode("E009", "Configuration error", "Run: boundaryctl config validate")
INTERNAL_ERROR = ErrorCode("E010", "Internal error", "Check daemon logs for details.")

# Resource lookup
NOT_FOUND = ErrorCode("E011", "Resource not found", "Verify the resource ID and try again.")

# Registry for code-based lookup
_ALL: Dict[str, ErrorCode] = {
    ec.code: ec
    for ec in [
        AUTH_FAILED, RATE_LIMIT_EXCEEDED, INVALID_REQUEST, POLICY_EVAL_FAILED,
        MODE_TRANSITION_DENIED, CEREMONY_REQUIRED, SYSTEM_IN_LOCKDOWN,
        TRIPWIRE_LOCKED, CONFIG_ERROR, INTERNAL_ERROR, NOT_FOUND,
    ]
}


def lookup(code: str) -> ErrorCode:
    """Look up an error code by its string code (e.g. 'E001')."""
    return _ALL.get(code, INTERNAL_ERROR)
