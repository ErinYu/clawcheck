"""Pytest configuration for ClawCheck tests."""

import pytest


@pytest.fixture
def sample_instance():
    """Create a sample OpenClawInstance for testing."""
    from clawcheck.models import OpenClawInstance
    return OpenClawInstance(
        version="2026.2.12",
        gateway_running=True,
        gateway_port=18789,
        instance_type="local",
    )


@pytest.fixture
def sample_finding():
    """Create a sample Finding for testing."""
    from clawcheck.models import Finding, Remediation
    return Finding(
        vulnerability_id="clawjacked",
        cve_id="CVE-2026-CLAW",
        severity="HIGH",
        status="VULNERABLE",
        description="Test vulnerability",
        indicators={"test": "FAIL"},
        remediation=Remediation(
            automatic=True,
            command="openclaw upgrade",
            manual_steps=["Update OpenClaw"],
        ),
    )
