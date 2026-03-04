"""Output formatter for scan results."""

import json
import uuid
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from clawcheck.models import ScanResult, ExitCode


class OutputFormatter:
    """Format scan results for different output modes."""

    def __init__(self, console: Optional[Console] = None):
        """Initialize formatter.

        Args:
            console: Rich console instance (creates default if None)
        """
        self.console = console or Console()

    def format_terminal(self, result: ScanResult) -> str:
        """Format result as human-readable terminal output.

        Args:
            result: Scan result to format

        Returns:
            Formatted string
        """
        lines = []

        # Header
        if result.error:
            self.console.print(
                f"[red]✗[/red] Scan Error: {result.error}",
                highlight=False,
            )
        elif result.exit_code == ExitCode.VULNERABLE:
            self.console.print(
                f"[red]✗ VULNERABLE[/red]: {result.summary.total_vulnerabilities} vulnerability(ies) found",
                highlight=False,
            )
        elif result.exit_code == ExitCode.NOT_FOUND:
            self.console.print(
                "[yellow]○ OpenClaw not found[/yellow]",
                highlight=False,
            )
        else:
            self.console.print(
                "[green]✓ SECURE[/green]: No vulnerabilities detected",
                highlight=False,
            )

        self.console.print("")

        # Target info
        if result.target:
            target_table = Table(show_header=False, box=None, padding=(0, 2))
            target_table.add_column("Property", style="cyan")
            target_table.add_column("Value")

            target_table.add_row("OpenClaw Version", result.target.version or "Unknown")
            target_table.add_row("Gateway Status", "Running" if result.target.gateway_running else "Stopped")
            target_table.add_row("Config Path", str(result.target.config_path) if result.target.config_path else "Not found")
            target_table.add_row("Instance Type", result.target.instance_type)

            self.console.print(Panel(target_table, title="[bold]Target Information[/bold]"))
            self.console.print("")

        # Findings
        if result.findings:
            for finding in result.findings:
                color = {
                    "CRITICAL": "red",
                    "HIGH": "red",
                    "MEDIUM": "yellow",
                    "LOW": "blue",
                }.get(finding.severity, "white")

                status_color = "red" if finding.status == "VULNERABLE" else "green"

                finding_table = Table(show_header=True, box=None)
                finding_table.add_column("Indicator", style="cyan")
                finding_table.add_column("Status")
                finding_table.add_column("Description")

                for indicator_name, status in finding.indicators.items():
                    status_color = "red" if status == "FAIL" else "green" if status == "PASS" else "yellow"
                    indicator_display = indicator_name.replace("_", " ").title()
                    finding_table.add_row(indicator_display, f"[{status_color}]{status}[/{status_color}]", "")

                panel_content = finding_table
                self.console.print(
                    Panel(
                        panel_content,
                        title=f"[bold][{color}] {finding.vulnerability_id.upper()} [/{color}][/bold] [{status_color}]{finding.status}[/{status_color}]",
                        subtitle=finding.description,
                    )
                )

                # Remediation
                if finding.remediation:
                    if finding.remediation.automatic and finding.remediation.command:
                        self.console.print(f"[green]  Auto-fix:[/green] {finding.remediation.command}")

                    if finding.remediation.manual_steps:
                        self.console.print("[cyan]  Manual steps:[/cyan]")
                        for step in finding.remediation.manual_steps:
                            self.console.print(f"    • {step}")

                self.console.print("")

        # Probe results
        if result.probe_result and result.probe_result.indicators:
            probe_table = Table(title="Probe Results")
            probe_table.add_column("Test", style="cyan")
            probe_table.add_column("Result")

            for test_name, status in result.probe_result.indicators.items():
                status_color = "red" if status == "FAIL" else "green" if status == "PASS" else "yellow"
                test_display = test_name.replace("_", " ").title()
                probe_table.add_row(test_display, f"[{status_color}]{status}[/{status_color}]")

            self.console.print(probe_table)
            self.console.print("")

        # Summary
        summary_table = Table(show_header=False, box=None)
        summary_table.add_column("", style="cyan")
        summary_table.add_column("")
        summary_table.add_row("Scan Duration", f"{result.scan_duration_ms}ms")
        summary_table.add_row("Total Vulnerabilities", str(result.summary.total_vulnerabilities))

        if result.summary.high > 0:
            summary_table.add_row("High Severity", str(result.summary.high))

        self.console.print(Panel(summary_table, title="[bold]Summary[/bold]"))

        return ""  # Console output already printed

    def format_json(self, result: ScanResult) -> str:
        """Format result as machine-readable JSON.

        Args:
            result: Scan result to format

        Returns:
            JSON string
        """
        return json.dumps(result.to_dict(), indent=2)

    def format_sarif(self, result: ScanResult) -> str:
        """Format result as SARIF v2.1.0 for CI/CD integration.

        Args:
            result: Scan result to format

        Returns:
            SARIF JSON string
        """
        # SARIF v2.1.0 format
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": result.tool_name,
                            "version": result.tool_version,
                            "informationUri": "https://github.com/yourusername/clawcheck",
                            "rules": [
                                {
                                    "id": finding.vulnerability_id,
                                    "name": finding.vulnerability_id,
                                    "shortDescription": {
                                        "text": finding.description,
                                    },
                                    "fullDescription": {
                                        "text": finding.description,
                                    },
                                    "help": {
                                        "text": "\n".join(finding.remediation.manual_steps) if finding.remediation else "",
                                    },
                                    "defaultConfiguration": {
                                        "level": {
                                            "CRITICAL": "error",
                                            "HIGH": "error",
                                            "MEDIUM": "warning",
                                            "LOW": "note",
                                        }.get(finding.severity, "warning"),
                                    },
                                }
                                for finding in result.findings
                            ],
                        }
                    },
                    "results": [],
                    "invocations": [
                        {
                            "endTimeUtc": result.scan_time.isoformat() + "Z",
                            "machine": result.target.config_path.as_posix() if result.target and result.target.config_path else "unknown",
                            "account": "local",
                        }
                    ],
                }
            ],
        }

        # Add results for each vulnerability
        for finding in result.findings:
            if finding.status == "VULNERABLE":
                result_obj = {
                    "ruleId": finding.vulnerability_id,
                    "level": {
                        "CRITICAL": "error",
                        "HIGH": "error",
                        "MEDIUM": "warning",
                        "LOW": "note",
                    }.get(finding.severity, "warning"),
                    "message": {
                        "text": finding.description,
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": str(result.target.config_path) if result.target and result.target.config_path else "unknown",
                                },
                            },
                        }
                    ],
                    "fixes": (
                        [
                            {
                                "description": {
                                    "text": finding.remediation.command,
                                }
                            }
                        ]
                        if finding.remediation and finding.remediation.automatic
                        else []
                    ),
                }
                sarif["runs"][0]["results"].append(result_obj)

        return json.dumps(sarif, indent=2)

    def print_exit_code_info(self) -> None:
        """Print exit code reference."""
        table = Table(title="Exit Codes")
        table.add_column("Code", style="cyan")
        table.add_column("Meaning")
        table.add_column("Use Case")

        table.add_row("0", "SECURE", "No vulnerabilities found")
        table.add_row("1", "VULNERABLE", "Vulnerabilities detected")
        table.add_row("2", "ERROR", "Scan error")
        table.add_row("3", "NOT_FOUND", "OpenClaw not installed")

        self.console.print(table)


def create_scan_result(
    target=None,
    findings=None,
    probe_result=None,
    error: Optional[str] = None,
) -> ScanResult:
    """Create a new ScanResult with generated ID and timestamp.

    Args:
        target: OpenClawInstance
        findings: List of findings
        probe_result: ProbeResult
        error: Error message

    Returns:
        ScanResult with populated fields
    """
    return ScanResult(
        scan_id=str(uuid.uuid4()),
        scan_time=datetime.now(),
        scan_duration_ms=0,
        target=target,
        findings=findings or [],
        probe_result=probe_result,
        error=error,
    )
