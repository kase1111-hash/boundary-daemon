"""
API Module for Boundary Daemon

Provides HTTP and health check endpoints:
- Health Check API for Kubernetes/systemd probes
- TLS helper utilities for HTTP servers
- Shared response envelope and error codes
"""

from .health import (
    HealthCheckServer,
    HealthChecker,
    HealthCheckResult,
    ComponentHealth,
    HealthStatus,
    get_health_server,
    create_health_server,
)

from .tls import (
    create_ssl_context,
    generate_self_signed_cert,
)

from .response import (
    APIResponse,
    ok_response,
    error_response,
)

from .error_codes import (
    ErrorCode,
    lookup as lookup_error,
)

__all__ = [
    'HealthCheckServer',
    'HealthChecker',
    'HealthCheckResult',
    'ComponentHealth',
    'HealthStatus',
    'get_health_server',
    'create_health_server',
    'create_ssl_context',
    'generate_self_signed_cert',
    'APIResponse',
    'ok_response',
    'error_response',
    'ErrorCode',
    'lookup_error',
]
