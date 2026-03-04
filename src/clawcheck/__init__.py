"""ClawCheck - OpenClaw vulnerability scanner."""

__version__ = "1.0.0"
__author__ = "ClawCheck Contributors"
__license__ = "MIT"

from clawcheck.models import (
    OpenClawInstance,
    ScanResult,
    ProbeResult,
    Finding,
    ExitCode,
)

__all__ = [
    "__version__",
    "OpenClawInstance",
    "ScanResult",
    "ProbeResult",
    "Finding",
    "ExitCode",
]
