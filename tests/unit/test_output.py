"""Unit tests for clawcheck.output."""

import json
from datetime import datetime

import pytest

from clawcheck.models import (
    OpenClawInstance,
    ScanResult,
    ExitCode,
    Finding,
)
from clawcheck.output import OutputFormatter, create_scan_result


class TestOutputFormatter:
    """Test OutputFormatter class."""

    def test_init(self):
        """Test formatter initialization."""
        formatter = OutputFormatter()
        assert formatter.console is not None

    def test_format_json(self):
        """Test JSON formatting."""
        instance = OpenClawInstance(version="2026.2.12")
        finding = Finding(
            "test",
            "CVE-TEST",
            "HIGH",
            "VULNERABLE",
        )

        result = ScanResult(
            scan_id="test",
            scan_time=datetime(2026, 3, 4, 12, 0, 0),
            scan_duration_ms=100,
            target=instance,
            findings=[finding],
        )

        formatter = OutputFormatter()
        output = formatter.format_json(result)

        data = json.loads(output)
        assert data["scan_id"] == "test"
        assert data["target"]["openclaw_version"] == "2026.2.12"
        assert data["summary"]["total_vulnerabilities"] == 1

    def test_format_sarif(self):
        """Test SARIF formatting."""
        instance = OpenClawInstance(
            version="2026.2.12",
            config_path=None,
        )
        finding = Finding(
            "clawjacked",
            "CVE-2026-CLAW",
            "HIGH",
            "VULNERABLE",
            description="Test vulnerability",
            indicators={"test": "FAIL"},
        )

        result = ScanResult(
            scan_id="test",
            scan_time=datetime.now(),
            scan_duration_ms=100,
            target=instance,
            findings=[finding],
        )

        formatter = OutputFormatter()
        output = formatter.format_sarif(result)

        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["tool"]["driver"]["name"] == "clawcheck"
        assert len(data["runs"][0]["results"]) == 1

    def test_format_sarif_secure(self):
        """Test SARIF with secure (no findings) result."""
        result = ScanResult(
            scan_id="test",
            scan_time=datetime.now(),
            scan_duration_ms=100,
            findings=[],
        )

        formatter = OutputFormatter()
        output = formatter.format_sarif(result)

        data = json.loads(output)
        assert len(data["runs"][0]["results"]) == 0


class TestCreateScanResult:
    """Test create_scan_result function."""

    def test_basic_result(self):
        """Test creating basic scan result."""
        result = create_scan_result()

        assert result.scan_id is not None
        assert isinstance(result.scan_id, str)
        assert result.scan_time is not None
        assert isinstance(result.scan_time, datetime)
        assert result.target is None
        assert result.findings == []
        assert result.probe_result is None
        assert result.error is None

    def test_result_with_target(self):
        """Test creating result with target."""
        instance = OpenClawInstance(version="2026.2.12")
        result = create_scan_result(target=instance)

        assert result.target == instance
        assert result.target.version == "2026.2.12"

    def test_result_with_findings(self):
        """Test creating result with findings."""
        findings = [
            Finding("test", "CVE-TEST", "HIGH", "VULNERABLE"),
        ]
        result = create_scan_result(findings=findings)

        assert result.findings == findings
        assert result.exit_code == ExitCode.VULNERABLE

    def test_result_with_error(self):
        """Test creating result with error."""
        result = create_scan_result(error="Test error")

        assert result.error == "Test error"
        assert result.exit_code == ExitCode.ERROR
