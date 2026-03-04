"""Unit tests for clawcheck.models."""

import pytest
from datetime import datetime

from clawcheck.models import (
    ExitCode,
    OpenClawInstance,
    ProbeIndicator,
    ProbeResult,
    Remediation,
    Finding,
    ScanSummary,
    ScanResult,
)


class TestExitCode:
    """Test ExitCode enum."""

    def test_values(self):
        """Test exit code values."""
        assert ExitCode.SECURE == 0
        assert ExitCode.VULNERABLE == 1
        assert ExitCode.ERROR == 2
        assert ExitCode.NOT_FOUND == 3


class TestOpenClawInstance:
    """Test OpenClawInstance model."""

    def test_defaults(self):
        """Test default values."""
        instance = OpenClawInstance()
        assert instance.config_path is None
        assert instance.version is None
        assert instance.gateway_running is False
        assert instance.gateway_port == 18789
        assert instance.gateway_host == "127.0.0.1"
        assert instance.instance_type == "local"

    def test_gateway_url(self):
        """Test gateway_url property."""
        instance = OpenClawInstance(
            gateway_host="localhost",
            gateway_port=8080,
        )
        assert instance.gateway_url == "ws://localhost:8080"

    def test_is_running(self):
        """Test is_running method."""
        instance = OpenClawInstance(gateway_running=True)
        assert instance.is_running() is True

        instance.gateway_running = False
        assert instance.is_running() is False


class TestProbeIndicator:
    """Test ProbeIndicator model."""

    def test_defaults(self):
        """Test default values."""
        indicator = ProbeIndicator(
            name="test",
            status="PASS",
            description="Test indicator",
        )
        assert indicator.confidence == "HIGH"


class TestProbeResult:
    """Test ProbeResult model."""

    def test_is_vulnerable(self):
        """Test is_vulnerable property."""
        result = ProbeResult()

        # No indicators
        assert result.is_vulnerable is False

        # All SKIP
        result.origin_validation = ProbeIndicator("test", "SKIP", "test")
        result.rate_limiting = ProbeIndicator("test", "SKIP", "test")
        result.trust_registration = ProbeIndicator("test", "SKIP", "test")
        assert result.is_vulnerable is False

        # One FAIL
        result.origin_validation = ProbeIndicator("test", "FAIL", "test")
        assert result.is_vulnerable is True

    def test_indicators(self):
        """Test indicators property."""
        result = ProbeResult(
            origin_validation=ProbeIndicator("test", "PASS", "test"),
            rate_limiting=ProbeIndicator("test", "FAIL", "test"),
        )

        indicators = result.indicators
        assert indicators["origin_validation"] == "PASS"
        assert indicators["rate_limiting"] == "FAIL"
        assert indicators["trust_registration"] == "SKIP"


class TestFinding:
    """Test Finding model."""

    def test_defaults(self):
        """Test default values."""
        finding = Finding(
            vulnerability_id="test",
            cve_id="CVE-2026-TEST",
            severity="HIGH",
            status="VULNERABLE",
        )
        assert finding.confidence == "HIGH"
        assert finding.indicators == {}
        assert finding.remediation is None


class TestScanSummary:
    """Test ScanSummary model."""

    def test_empty_summary(self):
        """Test summary with no findings."""
        summary = ScanSummary()
        assert summary.total_vulnerabilities == 0
        assert summary.critical == 0
        assert summary.high == 0
        assert summary.medium == 0
        assert summary.low == 0

    def test_from_findings(self):
        """Test creating summary from findings."""
        findings = [
            Finding("vuln1", "CVE-1", "HIGH", "VULNERABLE"),
            Finding("vuln2", "CVE-2", "CRITICAL", "VULNERABLE"),
            Finding("vuln3", "CVE-3", "LOW", "SECURE"),
        ]

        summary = ScanSummary.from_findings(findings)

        assert summary.total_vulnerabilities == 2  # Only VULNERABLE count
        assert summary.critical == 1
        assert summary.high == 1
        assert summary.low == 0


class TestScanResult:
    """Test ScanResult model."""

    def test_empty_result(self):
        """Test result with no findings."""
        result = ScanResult(
            scan_id="test",
            scan_time=datetime.now(),
            scan_duration_ms=100,
        )

        assert result.exit_code == ExitCode.SECURE
        assert result.summary.total_vulnerabilities == 0

    def test_vulnerable_result(self):
        """Test result with vulnerability."""
        finding = Finding(
            vulnerability_id="test",
            cve_id="CVE-TEST",
            severity="HIGH",
            status="VULNERABLE",
        )

        result = ScanResult(
            scan_id="test",
            scan_time=datetime.now(),
            scan_duration_ms=100,
            findings=[finding],
        )

        assert result.exit_code == ExitCode.VULNERABLE
        assert result.summary.total_vulnerabilities == 1
        assert result.summary.high == 1

    def test_error_result(self):
        """Test result with error."""
        result = ScanResult(
            scan_id="test",
            scan_time=datetime.now(),
            scan_duration_ms=100,
            error="OpenClaw not found",
        )

        assert result.exit_code == ExitCode.NOT_FOUND

    def test_generic_error_result(self):
        """Test result with generic error."""
        result = ScanResult(
            scan_id="test",
            scan_time=datetime.now(),
            scan_duration_ms=100,
            error="Permission denied",
        )

        assert result.exit_code == ExitCode.ERROR

    def test_to_dict(self):
        """Test to_dict serialization."""
        instance = OpenClawInstance(
            version="2026.2.12",
            gateway_running=True,
        )

        result = ScanResult(
            scan_id="test-id",
            scan_time=datetime(2026, 3, 4, 12, 0, 0),
            scan_duration_ms=500,
            target=instance,
        )

        data = result.to_dict()

        assert data["scan_id"] == "test-id"
        assert data["scan_time"] == "2026-03-04T12:00:00"
        assert data["tool"]["name"] == "clawcheck"
        assert data["target"]["openclaw_version"] == "2026.2.12"
        assert data["target"]["gateway_running"] is True
