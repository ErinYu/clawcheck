"""Data models for ClawCheck."""

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional
from datetime import datetime


class ExitCode(IntEnum):
    """Exit codes for ClawCheck."""

    SECURE = 0
    VULNERABLE = 1
    ERROR = 2
    NOT_FOUND = 3


@dataclass
class OpenClawInstance:
    """Represents a discovered OpenClaw instance."""

    config_path: Optional[Path] = None
    version: Optional[str] = None
    gateway_running: bool = False
    gateway_port: int = 18789
    gateway_host: str = "127.0.0.1"
    pid: Optional[int] = None
    instance_type: str = "local"  # local, docker, custom

    @property
    def gateway_url(self) -> str:
        """Get the WebSocket gateway URL."""
        return f"ws://{self.gateway_host}:{self.gateway_port}"

    def is_running(self) -> bool:
        """Check if the gateway is running."""
        return self.gateway_running


@dataclass
class ProbeIndicator:
    """Result of a single vulnerability probe test."""

    name: str
    status: str  # PASS, FAIL, SKIP, ERROR
    description: str
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW


@dataclass
class ProbeResult:
    """Result of WebSocket vulnerability probing."""

    origin_validation: Optional[ProbeIndicator] = None
    rate_limiting: Optional[ProbeIndicator] = None
    trust_registration: Optional[ProbeIndicator] = None
    error: Optional[str] = None
    scan_duration_ms: int = 0

    @property
    def is_vulnerable(self) -> bool:
        """Check if any probe indicates vulnerability."""
        for indicator in [self.origin_validation, self.rate_limiting, self.trust_registration]:
            if indicator and indicator.status == "FAIL":
                return True
        return False

    @property
    def indicators(self) -> dict[str, str]:
        """Get all indicator statuses as a dict."""
        return {
            "origin_validation": self.origin_validation.status if self.origin_validation else "SKIP",
            "rate_limiting": self.rate_limiting.status if self.rate_limiting else "SKIP",
            "trust_registration": self.trust_registration.status if self.trust_registration else "SKIP",
        }


@dataclass
class Remediation:
    """Remediation steps for a vulnerability."""

    automatic: bool = False
    command: Optional[str] = None
    manual_steps: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """A single vulnerability finding."""

    vulnerability_id: str
    cve_id: Optional[str]
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    status: str  # VULNERABLE, SECURE, ERROR
    confidence: str = "HIGH"
    description: str = ""
    indicators: dict[str, str] = field(default_factory=dict)
    remediation: Optional[Remediation] = None


@dataclass
class ScanSummary:
    """Summary of scan results."""

    total_vulnerabilities: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "ScanSummary":
        """Create summary from list of findings."""
        summary = cls()
        for finding in findings:
            if finding.status == "VULNERABLE":
                summary.total_vulnerabilities += 1
                severity = finding.severity.lower()
                if severity == "critical":
                    summary.critical += 1
                elif severity == "high":
                    summary.high += 1
                elif severity == "medium":
                    summary.medium += 1
                elif severity == "low":
                    summary.low += 1
        return summary


@dataclass
class ScanResult:
    """Complete scan result."""

    scan_id: str
    scan_time: datetime
    scan_duration_ms: int
    tool_name: str = "clawcheck"
    tool_version: str = "1.0.0"
    vuln_db_version: str = "2026-03-04"
    target: Optional[OpenClawInstance] = None
    findings: list[Finding] = field(default_factory=list)
    probe_result: Optional[ProbeResult] = None
    error: Optional[str] = None

    @property
    def summary(self) -> ScanSummary:
        """Get scan summary."""
        return ScanSummary.from_findings(self.findings)

    @property
    def exit_code(self) -> ExitCode:
        """Determine the appropriate exit code."""
        if self.error:
            # Check if it's a "not found" error
            if "not found" in self.error.lower() or "no openclaw" in self.error.lower():
                return ExitCode.NOT_FOUND
            return ExitCode.ERROR
        if any(f.status == "VULNERABLE" for f in self.findings):
            return ExitCode.VULNERABLE
        return ExitCode.SECURE

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "scan_id": self.scan_id,
            "scan_time": self.scan_time.isoformat(),
            "scan_duration_ms": self.scan_duration_ms,
            "tool": {
                "name": self.tool_name,
                "version": self.tool_version,
                "vulnerability_db_version": self.vuln_db_version,
            },
            "target": {
                "openclaw_version": self.target.version if self.target else None,
                "gateway_running": self.target.gateway_running if self.target else False,
                "gateway_port": self.target.gateway_port if self.target else 18789,
                "config_path": str(self.target.config_path) if self.target and self.target.config_path else None,
                "instance_type": self.target.instance_type if self.target else None,
            } if self.target else None,
            "findings": [
                {
                    "vulnerability_id": f.vulnerability_id,
                    "cve_id": f.cve_id,
                    "severity": f.severity,
                    "status": f.status,
                    "confidence": f.confidence,
                    "description": f.description,
                    "indicators": f.indicators,
                    "remediation": {
                        "automatic": f.remediation.automatic,
                        "command": f.remediation.command,
                        "manual_steps": f.remediation.manual_steps,
                    } if f.remediation else None,
                }
                for f in self.findings
            ],
            "probe_result": {
                "indicators": self.probe_result.indicators,
                "error": self.probe_result.error,
                "scan_duration_ms": self.probe_result.scan_duration_ms,
            } if self.probe_result else None,
            "error": self.error,
            "summary": {
                "total_vulnerabilities": self.summary.total_vulnerabilities,
                "critical": self.summary.critical,
                "high": self.summary.high,
                "medium": self.summary.medium,
                "low": self.summary.low,
            },
        }
