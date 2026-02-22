"""
OpenTelemetry integration tests for Boundary Daemon.

Verifies that the TelemetryManager produces correct spans and metrics
using the fallback in-memory recording (no real OTel SDK required).
"""

import time
from unittest.mock import MagicMock

import pytest

from daemon.telemetry.otel_setup import (
    TelemetryManager,
    TelemetryConfig,
    ExportMode,
    RedactionProcessor,
    MockSpan,
)


@pytest.fixture
def telemetry_manager():
    """Create a TelemetryManager with in-memory fallback (no OTel SDK)."""
    config = TelemetryConfig()
    config.enabled = True
    config.console_export = False
    config.file_export = False
    config.remote_export = False
    config.export_mode = ExportMode.DISABLED
    manager = TelemetryManager(config=config)
    manager.initialize()
    yield manager
    manager.shutdown()


class TestSpanCreation:
    """Verify that spans are recorded with correct structure."""

    def test_span_records_name_and_attributes(self, telemetry_manager):
        with telemetry_manager.start_span("test.operation", {"host": "localhost"}) as span:
            span.set_attribute("extra", "data")

        spans = telemetry_manager.get_recent_spans()
        assert len(spans) == 1
        assert spans[0]["name"] == "test.operation"
        assert spans[0]["attributes"]["host"] == "localhost"
        assert spans[0]["attributes"]["extra"] == "data"

    def test_span_records_start_and_end_times(self, telemetry_manager):
        before = time.time()
        with telemetry_manager.start_span("timed.op"):
            time.sleep(0.01)
        after = time.time()

        spans = telemetry_manager.get_recent_spans()
        assert len(spans) == 1
        assert spans[0]["start_time"] >= before
        assert spans[0]["end_time"] <= after
        assert spans[0]["end_time"] > spans[0]["start_time"]

    def test_span_events_recorded(self, telemetry_manager):
        with telemetry_manager.start_span("with.events") as span:
            span.add_event("checkpoint_a", {"step": "1"})
            span.add_event("checkpoint_b", {"step": "2"})

        spans = telemetry_manager.get_recent_spans()
        events = spans[0]["events"]
        assert len(events) == 2
        assert events[0]["name"] == "checkpoint_a"
        assert events[1]["name"] == "checkpoint_b"
        assert events[0]["attributes"]["step"] == "1"


class TestParentChildSpans:
    """Verify parent-child span relationships via nesting."""

    def test_nested_spans_both_recorded(self, telemetry_manager):
        with telemetry_manager.start_span("parent.op") as parent:
            parent.set_attribute("role", "parent")
            with telemetry_manager.start_span("child.op") as child:
                child.set_attribute("role", "child")

        spans = telemetry_manager.get_recent_spans()
        assert len(spans) == 2
        names = [s["name"] for s in spans]
        assert "child.op" in names
        assert "parent.op" in names

    def test_child_span_completes_before_parent(self, telemetry_manager):
        with telemetry_manager.start_span("parent"):
            with telemetry_manager.start_span("child"):
                pass

        spans = telemetry_manager.get_recent_spans()
        child = next(s for s in spans if s["name"] == "child")
        parent = next(s for s in spans if s["name"] == "parent")
        assert child["end_time"] <= parent["end_time"]


class TestPolicyEvaluationSpans:
    """Verify spans are created for policy-related operations."""

    def test_policy_decision_recorded(self, telemetry_manager):
        with telemetry_manager.start_span("policy.evaluate", {
            "request_type": "recall",
            "mode": "RESTRICTED",
        }) as span:
            span.add_event("decision", {"result": "DENY", "reason": "airgap_violation"})
            span.set_attribute("decision", "DENY")

        spans = telemetry_manager.get_recent_spans()
        assert len(spans) == 1
        assert spans[0]["attributes"]["decision"] == "DENY"
        assert spans[0]["attributes"]["request_type"] == "recall"
        assert spans[0]["events"][0]["attributes"]["result"] == "DENY"

    def test_mode_transition_spans(self, telemetry_manager):
        with telemetry_manager.start_span("mode.transition", {
            "from_mode": "OPEN",
            "to_mode": "RESTRICTED",
        }) as span:
            span.add_event("ceremony_started")
            span.add_event("ceremony_completed")

        spans = telemetry_manager.get_recent_spans()
        assert spans[0]["attributes"]["from_mode"] == "OPEN"
        assert spans[0]["attributes"]["to_mode"] == "RESTRICTED"
        assert len(spans[0]["events"]) == 2


class TestMetricRecording:
    """Verify metrics are recorded via the fallback path."""

    def test_violation_counter(self, telemetry_manager):
        telemetry_manager.record_violation("network", "AIRGAP", "outbound blocked")
        telemetry_manager.record_violation("process", "RESTRICTED")

        snapshot = telemetry_manager.get_metrics_snapshot()
        assert "violations" in snapshot
        assert len(snapshot["violations"]) == 2
        assert snapshot["violations"][0]["attributes"]["violation_type"] == "network"

    def test_mode_transition_counter(self, telemetry_manager):
        telemetry_manager.record_mode_transition("OPEN", "RESTRICTED", "operator request")

        snapshot = telemetry_manager.get_metrics_snapshot()
        assert "mode_transitions" in snapshot
        entry = snapshot["mode_transitions"][0]
        assert entry["attributes"]["from_mode"] == "OPEN"
        assert entry["attributes"]["to_mode"] == "RESTRICTED"

    def test_ceremony_histogram(self, telemetry_manager):
        telemetry_manager.record_ceremony("override", True, 2.5)

        snapshot = telemetry_manager.get_metrics_snapshot()
        assert "ceremonies" in snapshot
        assert "ceremony_latency" in snapshot

    def test_policy_decision_counter(self, telemetry_manager):
        telemetry_manager.record_policy_decision("DENY", "AI_ASSISTANT", 3)
        telemetry_manager.record_policy_decision("ALLOW", "AI_ASSISTANT", 1)

        snapshot = telemetry_manager.get_metrics_snapshot()
        assert "policy_decisions" in snapshot
        assert len(snapshot["policy_decisions"]) == 2

    def test_gauge_values(self, telemetry_manager):
        telemetry_manager.set_gauge("test.active_sandboxes", 5)
        telemetry_manager.set_gauge("test.active_sandboxes", 3)

        stats = telemetry_manager.get_summary_stats()
        assert stats["gauges"]["test.active_sandboxes"] == 3


class TestSensitiveDataRedaction:
    """Verify sensitive attributes are redacted."""

    def test_redaction_in_spans(self, telemetry_manager):
        with telemetry_manager.start_span("auth.check", {
            "user": "alice",
            "auth_token": "secret-abc-123",
        }) as span:
            pass

        spans = telemetry_manager.get_recent_spans()
        assert spans[0]["attributes"]["user"] == "alice"
        assert spans[0]["attributes"]["auth_token"] == "[REDACTED]"

    def test_redaction_in_span_events(self, telemetry_manager):
        with telemetry_manager.start_span("op") as span:
            span.add_event("login", {"username": "bob", "password": "hunter2"})

        spans = telemetry_manager.get_recent_spans()
        event_attrs = spans[0]["events"][0]["attributes"]
        assert event_attrs["username"] == "bob"
        assert event_attrs["password"] == "[REDACTED]"

    def test_redaction_processor_standalone(self):
        attrs = {
            "host": "example.com",
            "api_key": "sk-abc",
            "secret_value": "hidden",
            "normal": "visible",
        }
        redacted = RedactionProcessor.redact_attributes(attrs)
        assert redacted["host"] == "example.com"
        assert redacted["api_key"] == "[REDACTED]"
        assert redacted["secret_value"] == "[REDACTED]"
        assert redacted["normal"] == "visible"


class TestMockSpanBehavior:
    """Verify MockSpan implements the required span interface."""

    def test_set_attribute(self, telemetry_manager):
        with telemetry_manager.start_span("test") as span:
            assert isinstance(span, MockSpan)
            span.set_attribute("operation", "verify")

        assert telemetry_manager.get_recent_spans()[0]["attributes"]["operation"] == "verify"

    def test_record_exception(self, telemetry_manager):
        with telemetry_manager.start_span("test") as span:
            span.record_exception(ValueError("bad input"))

        events = telemetry_manager.get_recent_spans()[0]["events"]
        assert len(events) == 1
        assert events[0]["name"] == "exception"
        assert events[0]["attributes"]["exception.type"] == "ValueError"
        assert events[0]["attributes"]["exception.message"] == "bad input"

    def test_set_status(self, telemetry_manager):
        with telemetry_manager.start_span("test") as span:
            span.set_status("ERROR", "something failed")

        span_data = telemetry_manager.get_recent_spans()[0]
        assert span_data["status"]["code"] == "ERROR"
        assert span_data["status"]["description"] == "something failed"


class TestTelemetryManagerLifecycle:
    """Verify TelemetryManager lifecycle operations."""

    def test_disabled_telemetry_skips_recording(self):
        config = TelemetryConfig()
        config.enabled = False
        manager = TelemetryManager(config=config)
        result = manager.initialize()
        assert result is False

    def test_summary_stats(self, telemetry_manager):
        stats = telemetry_manager.get_summary_stats()
        assert stats["enabled"] is True
        assert stats["initialized"] is True
        assert "instance_id" in stats
        assert "hostname" in stats

    def test_span_buffer_limit(self, telemetry_manager):
        for i in range(1100):
            with telemetry_manager.start_span(f"span_{i}"):
                pass

        spans = telemetry_manager.get_recent_spans(limit=2000)
        assert len(spans) <= 1000

    def test_double_initialize_is_idempotent(self, telemetry_manager):
        assert telemetry_manager.initialize() is True
        assert telemetry_manager.initialize() is True
