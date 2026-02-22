"""
Shared API response envelope for all Boundary Daemon HTTP endpoints.

Provides a consistent JSON response format across health, verification,
and metrics APIs.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, Optional, Any


@dataclass
class APIResponse:
    """Standard response envelope for all API endpoints."""
    status: str  # "ok" | "error"
    data: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None  # {"code": "E001", "message": "..."}
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_json(self) -> str:
        result = {"status": self.status, "timestamp": self.timestamp}
        if self.data is not None:
            result["data"] = self.data
        if self.error is not None:
            result["error"] = self.error
        return json.dumps(result, default=str)

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"status": self.status, "timestamp": self.timestamp}
        if self.data is not None:
            result["data"] = self.data
        if self.error is not None:
            result["error"] = self.error
        return result


def ok_response(data: Optional[Dict[str, Any]] = None) -> APIResponse:
    """Create a successful response."""
    return APIResponse(status="ok", data=data)


def error_response(code: str, message: str, details: Optional[Dict[str, Any]] = None) -> APIResponse:
    """Create an error response with structured error info."""
    error_body: Dict[str, Any] = {"code": code, "message": message}
    if details:
        error_body["details"] = details
    return APIResponse(status="error", error=error_body)
