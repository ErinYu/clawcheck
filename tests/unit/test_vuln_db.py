"""Unit tests for clawcheck.vuln_db."""

import pytest

from clawcheck.vuln_db import (
    parse_version,
    compare_versions,
    is_vulnerable,
    get_vulnerability_info,
    create_finding,
    VULNERABILITY_DATABASE,
)


class TestParseVersion:
    """Test version parsing."""

    def test_standard_version(self):
        """Test parsing standard version strings."""
        assert parse_version("2026.2.25") == (2026, 2, 25)
        assert parse_version("2026.2.12") == (2026, 2, 12)

    def test_version_with_v_prefix(self):
        """Test parsing version with v prefix."""
        assert parse_version("v2026.2.25") == (2026, 2, 25)

    def test_partial_version(self):
        """Test parsing partial versions."""
        assert parse_version("2026.2") == (2026, 2, 0)
        assert parse_version("2026") == (2026, 0, 0)

    def test_invalid_version(self):
        """Test parsing invalid versions."""
        assert parse_version("") == (0, 0, 0)
        assert parse_version("invalid") == (0, 0, 0)
        assert parse_version(None) == (0, 0, 0)


class TestCompareVersions:
    """Test version comparison."""

    def test_less_than(self):
        """Test less than comparison."""
        v1 = (2026, 2, 12)
        v2 = (2026, 2, 25)
        assert compare_versions(v1, v2) == -1

    def test_equal(self):
        """Test equal comparison."""
        v1 = (2026, 2, 25)
        v2 = (2026, 2, 25)
        assert compare_versions(v1, v2) == 0

    def test_greater_than(self):
        """Test greater than comparison."""
        v1 = (2026, 3, 0)
        v2 = (2026, 2, 25)
        assert compare_versions(v1, v2) == 1


class TestIsVulnerable:
    """Test vulnerability checking."""

    def test_vulnerable_version(self):
        """Test versions before fix."""
        assert is_vulnerable("2026.2.12") is True
        assert is_vulnerable("2026.2.24") is True
        assert is_vulnerable("2025.1.0") is True

    def test_secure_version(self):
        """Test versions at or after fix."""
        assert is_vulnerable("2026.2.25") is False
        assert is_vulnerable("2026.2.26") is False
        assert is_vulnerable("2026.3.0") is False
        assert is_vulnerable("2027.0.0") is False

    def test_unknown_version(self):
        """Test unknown/invalid versions."""
        # Unknown versions assume vulnerable for safety
        assert is_vulnerable("") is True
        assert is_vulnerable("unknown") is True

    def test_invalid_vuln_id(self):
        """Test with non-existent vulnerability ID."""
        assert is_vulnerable("2026.2.12", "nonexistent") is False


class TestGetVulnerabilityInfo:
    """Test vulnerability info retrieval."""

    def test_clawjacked_info(self):
        """Test getting ClawJacked vulnerability info."""
        info = get_vulnerability_info("clawjacked")

        assert info is not None
        assert info["cve_id"] == "CVE-2026-CLAW"
        assert info["severity"] == "HIGH"
        assert info["fixed_version"] == "2026.2.25"
        assert "no_origin_validation" in info["indicators"]

    def test_nonexistent_vuln(self):
        """Test getting non-existent vulnerability."""
        info = get_vulnerability_info("nonexistent")
        assert info is None


class TestCreateFinding:
    """Test finding creation."""

    def test_vulnerable_finding(self):
        """Test creating a vulnerable finding."""
        finding = create_finding(
            vuln_id="clawjacked",
            status="VULNERABLE",
        )

        assert finding.vulnerability_id == "clawjacked"
        assert finding.cve_id == "CVE-2026-CLAW"
        assert finding.severity == "HIGH"
        assert finding.status == "VULNERABLE"
        assert finding.confidence == "HIGH"
        assert finding.remediation is not None
        assert finding.remediation.automatic is True
        assert finding.remediation.command == "openclaw upgrade"

    def test_secure_finding(self):
        """Test creating a secure finding."""
        finding = create_finding(
            vuln_id="clawjacked",
            status="SECURE",
        )

        assert finding.status == "SECURE"
        assert finding.severity == "HIGH"

    def test_with_indicators(self):
        """Test creating finding with probe indicators."""
        indicators = {
            "version_check": "VULNERABLE",
            "origin_validation": "FAIL",
            "rate_limiting": "FAIL",
        }

        finding = create_finding(
            vuln_id="clawjacked",
            status="VULNERABLE",
            indicators=indicators,
        )

        assert finding.indicators == indicators

    def test_nonexistent_vuln_finding(self):
        """Test creating finding for non-existent vulnerability."""
        finding = create_finding(
            vuln_id="nonexistent",
            status="VULNERABLE",
        )

        assert finding.vulnerability_id == "nonexistent"
        assert finding.cve_id is None
        assert finding.severity == "UNKNOWN"
        assert finding.confidence == "LOW"


class TestVulnerabilityDatabase:
    """Test vulnerability database structure."""

    def test_database_structure(self):
        """Test that database has required fields."""
        assert "clawjacked" in VULNERABILITY_DATABASE

        vuln = VULNERABILITY_DATABASE["clawjacked"]
        required_fields = [
            "cve_id",
            "disclosed",
            "affected_versions",
            "fixed_version",
            "severity",
            "description",
            "indicators",
        ]

        for field in required_fields:
            assert field in vuln
