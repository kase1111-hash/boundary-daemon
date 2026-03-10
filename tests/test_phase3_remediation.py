"""
Tests for Phase 3 remediation — Findings #7, #9, #10.

Covers:
- Finding #7: SIEM ingestion rejects http:// endpoints
- Finding #9: Dev dependencies are exact-pinned
- Finding #10: GitHub Actions use commit SHAs
"""

import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Finding #7: SIEM ingestion enforces HTTPS
# ---------------------------------------------------------------------------

class TestSIEMHttpsEnforcement:
    """_send_http must reject non-HTTPS endpoints."""

    def _make_forwarder(self, endpoint: str):
        """Create an SIEMForwarder with a given http_endpoint."""
        import sys
        # The integration module is not installed as a package, so import by path
        siem_src = Path(__file__).resolve().parent.parent / "integrations" / "boundary-siem" / "src"
        if str(siem_src) not in sys.path:
            sys.path.insert(0, str(siem_src))

        from boundary_ingestion import SIEMForwarder, EventIngestionPipeline, EventFormat

        pipeline = EventIngestionPipeline(output_format=EventFormat.JSON)
        return SIEMForwarder(
            pipeline=pipeline,
            http_endpoint=endpoint,
        )

    def _make_event(self):
        from boundary_ingestion import BoundaryEvent, Severity
        from datetime import datetime
        return BoundaryEvent(
            event_id="e1",
            timestamp=datetime.utcnow(),
            event_type="TEST",
            severity=Severity.LOW,
            mode="OPEN",
            description="test event",
            source_component="test",
        )

    def test_http_endpoint_raises_valueerror(self):
        fwd = self._make_forwarder("http://insecure.example.com/events")
        event = self._make_event()
        with pytest.raises(ValueError, match="HTTPS"):
            fwd._send_http(event)

    def test_https_endpoint_accepted(self):
        """HTTPS endpoint should not raise ValueError (may fail on
        network, but the scheme check passes)."""
        fwd = self._make_forwarder("https://secure.example.com/events")
        event = self._make_event()
        # Will raise a network error (can't connect), but NOT ValueError
        try:
            fwd._send_http(event)
        except ValueError:
            pytest.fail("HTTPS endpoint should not raise ValueError")
        except Exception:
            pass  # network errors are expected


# ---------------------------------------------------------------------------
# Finding #9: Dev dependencies pinned
# ---------------------------------------------------------------------------

class TestDevDependenciesPinned:
    """requirements-dev.txt must use exact version pins (==)."""

    def test_no_floating_ranges(self):
        req_file = Path(__file__).resolve().parent.parent / "requirements-dev.txt"
        content = req_file.read_text()

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-r"):
                continue
            # Must contain == and NOT >= or >
            assert ">=" not in line, f"Floating range found: {line}"
            assert "==" in line, f"Missing exact pin: {line}"


# ---------------------------------------------------------------------------
# Finding #10: GitHub Actions pinned to SHAs
# ---------------------------------------------------------------------------

class TestGitHubActionsPinned:
    """CI and publish workflows must pin actions to commit SHAs."""

    @pytest.fixture(params=["ci.yml", "publish.yml"])
    def workflow_content(self, request):
        wf_path = (
            Path(__file__).resolve().parent.parent
            / ".github" / "workflows" / request.param
        )
        return wf_path.read_text()

    def test_no_version_tags(self, workflow_content):
        """No action should use @v<N> or @release/v<N> tags."""
        # Match patterns like @v4, @v5, @release/v1 that are NOT followed by
        # a hex SHA (which our pinned format uses)
        tag_pattern = re.compile(r"uses:\s+[\w\-/]+@(v\d+|release/v\d+)\s*$", re.MULTILINE)
        matches = tag_pattern.findall(workflow_content)
        assert not matches, f"Unpinned action tags found: {matches}"

    def test_sha_format(self, workflow_content):
        """All 'uses:' lines should reference a 40-char hex SHA."""
        for line in workflow_content.splitlines():
            if "uses:" not in line:
                continue
            # Extract the ref after @
            match = re.search(r"@([a-f0-9]{40})", line)
            assert match, f"No SHA pin found in: {line.strip()}"
