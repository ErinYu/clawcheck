"""Vulnerability database for OpenClaw."""

from clawcheck.models import Finding, Remediation

# Vulnerability database - bundled with the tool
# Update via tool releases for offline capability
VULNERABILITY_DATABASE = {
    "clawjacked": {
        "cve_id": "CVE-2026-CLAW",
        "disclosed": "2026-02-26",
        "affected_versions": "< 2026.2.25",
        "fixed_version": "2026.2.25",
        "severity": "HIGH",
        "description": "WebSocket hijacking via localhost origin bypass. Any website can silently hijack OpenClaw agents through malicious JavaScript.",
        "indicators": [
            "no_origin_validation",
            "no_localhost_rate_limit",
            "auto_trust_localhost_devices"
        ],
        "references": [
            "https://www.oasis.security/blog/openclaw-vulnerability"
        ]
    }
}


def parse_version(version: str) -> tuple[int, int, int]:
    """Parse OpenClaw version string to tuple.

    Args:
        version: Version string like "2026.2.25" or "v2026.2.25"

    Returns:
        Tuple of (year, month, patch) or (0, 0, 0) if invalid
    """
    if not version:
        return (0, 0, 0)

    # Remove 'v' or 'OpenClaw' prefix if present
    version = version.strip().lower()
    version = version.removeprefix("v")
    version = version.removeprefix("openclaw")

    try:
        parts = version.split(".")
        if len(parts) >= 3:
            return (int(parts[0]), int(parts[1]), int(parts[2]))
        elif len(parts) == 2:
            return (int(parts[0]), int(parts[1]), 0)
        else:
            return (int(parts[0]), 0, 0)
    except (ValueError, AttributeError):
        return (0, 0, 0)


def compare_versions(v1: tuple[int, int, int], v2: tuple[int, int, int]) -> int:
    """Compare two version tuples.

    Args:
        v1: First version tuple
        v2: Second version tuple

    Returns:
        -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    """
    if v1 < v2:
        return -1
    elif v1 > v2:
        return 1
    return 0


def is_vulnerable(version: str, vuln_id: str = "clawjacked") -> bool:
    """Check if a version is vulnerable to a specific vulnerability.

    Args:
        version: Version string to check
        vuln_id: Vulnerability ID (default: clawjacked)

    Returns:
        True if version is vulnerable
    """
    vuln = VULNERABILITY_DATABASE.get(vuln_id)
    if not vuln:
        return False

    affected_spec = vuln["affected_versions"]
    fixed_spec = vuln.get("fixed_version", "")

    if not affected_spec and not fixed_spec:
        return False

    parsed_version = parse_version(version)
    if parsed_version == (0, 0, 0):
        # Unknown version - assume vulnerable for safety
        return True

    # Parse "X.Y.Z" comparison operators
    if affected_spec.startswith("< "):
        fixed_version = parse_version(affected_spec[2:].strip())
        return compare_versions(parsed_version, fixed_version) < 0
    elif affected_spec.startswith("<="):
        fixed_version = parse_version(affected_spec[3:].strip())
        return compare_versions(parsed_version, fixed_version) <= 0
    elif affected_spec.startswith("> "):
        fixed_version = parse_version(affected_spec[2:].strip())
        return compare_versions(parsed_version, fixed_version) > 0
    elif affected_spec.startswith(">="):
        fixed_version = parse_version(affected_spec[3:].strip())
        return compare_versions(parsed_version, fixed_version) >= 0
    elif affected_spec.startswith("=="):
        fixed_version = parse_version(affected_spec[2:].strip())
        return compare_versions(parsed_version, fixed_version) == 0

    # If fixed_version is specified, check if version is before fix
    if fixed_spec:
        fixed_version = parse_version(fixed_spec)
        return compare_versions(parsed_version, fixed_version) < 0

    return False


def get_vulnerability_info(vuln_id: str = "clawjacked") -> dict | None:
    """Get complete vulnerability information.

    Args:
        vuln_id: Vulnerability ID

    Returns:
        Vulnerability dict or None if not found
    """
    return VULNERABILITY_DATABASE.get(vuln_id)


def create_finding(
    vuln_id: str = "clawjacked",
    status: str = "VULNERABLE",
    indicators: dict | None = None,
) -> Finding:
    """Create a Finding object from vulnerability database.

    Args:
        vuln_id: Vulnerability ID
        status: Status (VULNERABLE, SECURE, ERROR)
        indicators: Probe test results

    Returns:
        Finding object
    """
    vuln = get_vulnerability_info(vuln_id)
    if not vuln:
        # Return a generic finding if vuln not found
        return Finding(
            vulnerability_id=vuln_id,
            cve_id=None,
            severity="UNKNOWN",
            status=status,
            confidence="LOW",
            indicators=indicators or {},
        )

    remediation = Remediation(
        automatic=True,
        command="openclaw upgrade",
        manual_steps=[
            f"Update to OpenClaw {vuln['fixed_version']} or later",
            "Verify gateway configuration has rate limiting enabled",
            "Review trusted devices list in OpenClaw dashboard",
        ],
    )

    return Finding(
        vulnerability_id=vuln_id,
        cve_id=vuln["cve_id"],
        severity=vuln["severity"],
        status=status,
        confidence="HIGH",
        description=vuln["description"],
        indicators=indicators or {},
        remediation=remediation,
    )


def list_vulnerabilities() -> list[str]:
    """List all known vulnerability IDs.

    Returns:
        List of vulnerability IDs
    """
    return list(VULNERABILITY_DATABASE.keys())
