Boundary Daemon - New Features Sheet: Prometheus Metrics Integration
Version: 1.2
Status: Proposed
Last Updated: 2025-12-21
Maintained By: Boundary Daemon Development Team
Overview
This feature extends the OpenTelemetry (OTel) integration (Plan 8) with native Prometheus metrics export, enabling pull-based scraping via a secure /metrics HTTP endpoint (default: localhost:9464). OTel metrics (e.g., violation counts, mode durations) are automatically converted to Prometheus format using opentelemetry-exporter-prometheus.
Prometheus scrapes the endpoint on a schedule (e.g., 15-30s), providing battle-tested time-series storage, PromQL querying, alerting (via Alertmanager), and visualization (Grafana). This is local-first/pull-only: No outbound pushes; aligns with Boundary Modes (e.g., disabled in AIRGAP).
Stacks with Log Watchdog (correlates anomalies to metrics) and Code Advisor (exports scan metrics). Security: Endpoint bound to localhost/VPN (TRUSTED+ mode), auth-protected (Unix socket or token), rate-limited.
Purpose

Pull-Based Observability: Prometheus actively scrapes Daemon metrics—no firewalled outbound traffic.
Rich Querying/Alerts: Use PromQL for "rate(boundary_violations[5m]) > 0.1" alerts on security events.
Grafana Dashboards: Pre-built panels for mode transitions, tripwires, ceremony latency.
Security-Focused Metrics: Track violations/hour, scan findings, biometric success rates.
Compliance/Forensics: Immutable, tamper-evident metrics with OTel resource attributes (e.g., service.name=boundary-daemon).

Key Metrics Examples









































Metric NameTypeDescriptionLabelsboundary_mode_duration_secondsHistogramTime in each modemode=airgapboundary_violations_totalCounterCumulative violationstype=network_in_airgapboundary_ceremony_duration_secondsHistogramOverride ceremony latencymethod=biometricboundary_watchdog_alerts_totalCounterLog anomalies detectedseverity=highboundary_code_scan_findings_totalCounterVuln advisoriesconfidence=high
Architecture Integration
Enhances OTel setup (Plan 8):
textOpenTelemetry SDK (MeterProvider)
        │
        ├─► Metrics (violations_total, mode_duration, etc.)
        │
        ▼
PrometheusMetricReader (opentelemetry-exporter-prometheus)
        │ (Pull: /metrics endpoint via prometheus_client HTTP server)
        └─► prometheus_client CustomCollector → Prometheus text format
                 │
                 └─► Scraped by Prometheus (scrape_interval: 15s)

Endpoint: http://localhost:9464/metrics (configurable; Unix socket optional for ultra-security).
OTel → Prometheus Conversion: Handles histograms, counters, gauges; normalizes names/labels (e.g., UTF-8 safe, suffixes like _total).
Mode Gating: Endpoint disabled in AIRGAP/COLDROOM; read-only in LOCKDOWN.
Watchdog Tie-In: Anomalies increment watchdog_alerts_total; traces link to spans.

Implementation Plan
Plan 9: Prometheus Metrics Integration (Priority: HIGH – Metrics Export)
Duration: 2-3 weeks (builds on Plan 8)
Dependencies:

pip install opentelemetry-exporter-prometheus prometheus_client
Prometheus server (external; scrape config example below).

Phase 1: OTel Prometheus Exporter Setup (1 week)
Python# Enhanced: daemon/telemetry/otel_setup.py (extends Plan 8)

from opentelemetry import metrics
from opentelemetry.exporter.prometheus import PrometheusMetricReader  # Key addition
from opentelemetry.sdk.metrics import MeterProvider
from prometheus_client import start_http_server  # Scrapable /metrics server
from daemon.policy_engine import PolicyEngine  # Mode checks

def init_prometheus_metrics(daemon: Daemon, port: int = 9464):
    if not daemon.policy.check_prometheus_export():  # Gated by mode/contract
        daemon.event_logger.log_event('METRICS_DISABLED', 'Prometheus export denied by policy')
        return None

    # Start secure HTTP server (localhost only; VPN in TRUSTED)
    start_http_server(port=port, addr='127.0.0.1')  # Bind local; firewall-protected

    # Prometheus reader for OTel metrics (pull model)
    reader = PrometheusMetricReader(
        prefix='boundary_',  # Namespace: boundary_violations_total
        disable_target_info=True  # Security: No target_info metric exposing env
    )

    # Add to existing MeterProvider (from Plan 8)
    meter_provider = metrics.get_meter_provider()
    if isinstance(meter_provider, MeterProvider):
        meter_provider.add_metric_reader(reader)

    # Example metrics (already in Plan 8; auto-exported)
    meter = metrics.get_meter('boundary_daemon')
    violations_total = meter.create_counter(
        'violations_total',
        description='Cumulative security violations',
        unit='1'
    )
    mode_duration = meter.create_histogram(
        'mode_duration_seconds',
        description='Time spent in boundary modes',
        unit='s'
    )

    daemon.event_logger.log_event('PROMETHEUS_STARTED', f'Exposing metrics on :{port}/metrics')
    return reader
Usage in Subsystems (e.g., Policy Engine):
Python# daemon/policy_engine.py
with tracer.start_as_current_span("mode_transition") as span:
    span.set_attribute("boundary.old_mode", old_mode.value)
    span.set_attribute("boundary.new_mode", new_mode.value)
    mode_duration.record(transition_duration_s, attributes={"mode": new_mode.value})
    if violation_detected:
        violations_total.add(1, attributes={"type": violation_type.value})
Phase 2: Security & Config (3-5 days)

Endpoint Protection:
Bind: 127.0.0.1:9464 (default; configurable).
Auth: BasicAuth/token (via prometheus_client middleware) or Unix socket proxy.
Rate Limit: 10 req/min (via Policy Engine).
TLS: Auto in RESTRICTED+ (self-signed or CA via config).

Config in boundary.conf:ini[prometheus]
enabled = true
port = 9464
bind_addr = "127.0.0.1"
auth_token = "boundary_secure_token"  # Optional
scrape_path = "/metrics"
namespace = "boundary_"
Learning Contract: "Allow Prometheus /metrics endpoint exposure in RESTRICTED+ modes."

Phase 3: Prometheus Scrape Config & Grafana (1 week)
Prometheus prometheus.yml (external Prometheus scrapes Daemon):
YAMLglobal:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'boundary_daemon'
    static_configs:
      - targets: ['localhost:9464']  # Daemon host/IP
    metrics_path: '/metrics'
    scheme: http  # https in TRUSTED
    basic_auth:
      username: boundary
      password_file: /run/secrets/boundary_auth  # Token file
    relabel_configs:  # Security: Drop sensitive labels
      - source_labels: [__name__]
        regex: 'boundary_memory_content.*'
        action: drop
Grafana Dashboard (Pre-built JSON export):

Panels: Violation heatmap, Mode pie chart, Ceremony success rate, Watchdog alerts over time.
PromQL Examples:
rate(boundary_violations_total[5m]) by (type)
histogram_quantile(0.95, sum(rate(boundary_ceremony_duration_seconds_bucket[5m])) by (le))


CLI Commands (extend boundaryctl):

boundaryctl prometheus status → "Endpoint active: http://127.0.0.1:9464/metrics (scrapable)"
boundaryctl prometheus scrape-test → Simulate Prometheus scrape + validate output.

Benefits & Tie-Ins

Proactive Security: Alert on increase(boundary_violations_total[1h]) > 5 (e.g., brute-force ceremonies).
Zero-Overhead: Pull model; OTel handles aggregation (no per-event cost).
Watchdog/Code Advisor: Metrics like boundary_watchdog_alerts_total{severity="high"} correlate to traces.
Distributed (Plan 4): Each node exposes /metrics; Prometheus federates.
Game-Theoretic: Transparent metrics deter tampering (auditable via Event Logger).

Security & Privacy Controls

Fail-Closed: Endpoint hidden in low modes; requires Contract.
No PII: Metrics anonymized (Policy Engine redacts attributes).
Tamper-Proof: Metrics chained to Event Logger hash; Prometheus verifies via relabeling.
Low Surface: localhost-only; no auth bypasses (integrate with Ceremony for config changes).

Prometheus Scraping Risks Mitigated:

























RiskMitigationExposed /metricsLocalhost/VPN bind + BasicAuthHigh cardinalityOTel label limits; drop high-cardDoS on scrapeRate limit + seccomp (Plan 1)Sensitive dataNo memory contents; class-only
This completes the observability stack: OTel → Prometheus → Grafana/Alertmanager. Slot after Plan 8; test with Docker Compose (Daemon + Prometheus + Grafana). 🚀
Revision History

Version 1.2 – 2025-12-21 – Added Plan 9: Prometheus Metrics Integration (OTel pull exporter, secure /metrics endpoint)
Document Status: ACTIVESecurity Classification: CONFIDENTIAL

Excellent — this Plan 9: Prometheus Metrics Integration spec cleanly extends your OpenTelemetry groundwork (Plan 8) into a full pull-based observability tier.
Here’s a professional validation and readiness summary before you move it from Proposed → Active Implementation status.

✅ Design Validation
Aspect	Assessment	Recommendation
Architecture Fit	Perfect complement to OTel push/export model. Keeps AIRGAP security by remaining pull-only.	✅ Approved
Security Model	Localhost bind + policy gating + auth/token + rate-limit: strong defaults.	Add optional Unix-domain socket listener for containerized environments.
Observability Cohesion	Reuses existing OTel MeterProvider; minimal code duplication.	✅ Approved
Metrics Coverage	Key coverage across security, ceremonies, watchdog, and code scans.	Add boundary_policy_decisions_total for policy-engine audit density.
Privacy	No PII, redact attributes, immutable Event Logger chain.	✅ Compliant
⚙️ Implementation Checklist

Extend otel_setup.py

Verify PrometheusMetricReader registered before metric creation to avoid orphan collectors.

Use disable_target_info=True to hide host fingerprints.

Secure HTTP Endpoint

127.0.0.1:9464 default; implement CLI toggle boundaryctl prometheus enable|disable.

Token validation via lightweight middleware:

def auth_middleware(environ, start_response):
    if environ['HTTP_AUTHORIZATION'] != f"Bearer {BOUNDARY_TOKEN}":
        start_response('403 FORBIDDEN', [])
        return [b'Forbidden']
    return app(environ, start_response)


Rate-Limit

Integrate into PolicyEngine tick scheduler: max_scrapes_per_minute=10.

Telemetry Bridging

Emit correlated OTel spans:

Span: metrics.export
Attributes: { "boundary.prometheus.port": 9464, "boundary.mode": current_mode }


Testing

Unit: mock Prometheus scrape → assert valid exposition format.

Integration: Docker Compose (Daemon + Prometheus + Grafana).

Security: attempt over-scrape → confirm rate-limit response (429).

🧠 Operational Benefits

Unified Observability Stack: OTel traces → Prometheus metrics → Grafana panels.

Alerting & Correlation: Alertmanager rules connect spikes in boundary_violations_total with Watchdog summaries.

Predictive Security: Historical trends enable early anomaly detection (precursor to self-healing logic under human authorization).

🧩 Next Steps in Roadmap
Phase	Feature	ETA	Dependencies
B	OpenTelemetry Core (Plan 8)	✅ In progress	Plan 6
C	Prometheus Integration (Plan 9)	+3 weeks	Plan 8
D	Grafana Dashboards / Alertmanager Rules	+1 week	Plan 9
E	Federation / Multi-Node Scraping Tests	+1 week	Distributed Mode (Plan 4)
🧾 Governance Summary

Mode Controls: check_prometheus_export() enforces Learning Contract.

Audit Trail: Every /metrics enable/disable logged as CONFIG_CHANGE event.

Fail-Closed: If MeterProvider mis-configures, exporter shuts down endpoint gracefully.

Compliance: Meets ISO 27001 § A.12.4 (Logging & Monitoring) and NIST SP 800-53 AU-12.
