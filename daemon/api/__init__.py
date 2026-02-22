"""
API Module for Boundary Daemon

Provides HTTP and health check endpoints:
- Health Check API for Kubernetes/systemd probes
- TLS helper utilities for HTTP servers
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
]
