"""CLI interface for ClawCheck."""

import json
import sys
from pathlib import Path

import click
from rich.panel import Panel

from clawcheck.discovery import OpenClawDiscovery
from clawcheck.models import ExitCode
from clawcheck.output import OutputFormatter, create_scan_result
from clawcheck.probe import WebSocketProbe
from clawcheck.vuln_db import (
    create_finding,
    get_vulnerability_info,
    is_vulnerable,
)


@click.group()
@click.version_option(version="1.0.0")
def cli() -> None:
    """ClawCheck - OpenClaw vulnerability scanner.

    Detect the ClawJacked vulnerability (CVE-2026-CLAW) in OpenClaw installations.
    """
    pass


@cli.command()
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    help="Output as machine-readable JSON",
)
@click.option(
    "--sarif",
    "output_sarif",
    is_flag=True,
    help="Output as SARIF v2.1.0 format",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(),
    help="Write output to file",
)
@click.option(
    "--verbose",
    "-v",
    count=True,
    help="Increase verbosity (-v, -vv)",
)
@click.option(
    "--timeout",
    default=30,
    type=int,
    help="Connection timeout in seconds (default: 30)",
)
@click.option(
    "--config-path",
    type=click.Path(),
    help="Custom path to OpenClaw config",
)
def scan(
    output_json: bool,
    output_sarif: bool,
    output_file: str | None,
    verbose: int,
    timeout: int,
    config_path: str | None,
) -> None:
    """Scan for OpenClaw vulnerabilities."""
    formatter = OutputFormatter()

    # Discovery
    discovery = OpenClawDiscovery(config_path=config_path)
    instance = discovery.find_installation()

    if not instance:
        result = create_scan_result(error="OpenClaw not found")
        _output_result(result, formatter, output_json, output_sarif, output_file)
        sys.exit(ExitCode.NOT_FOUND)

    if verbose:
        click.echo(f"Found OpenClaw {instance.version or 'unknown'} at {instance.config_path or 'unknown path'}")
        click.echo(f"Gateway running: {instance.gateway_running}")

    # Version check
    vuln_info = get_vulnerability_info("clawjacked")
    findings = []

    if instance.version and is_vulnerable(instance.version):
        # Vulnerable by version
        finding = create_finding(
            status="VULNERABLE",
            indicators={
                "version_check": "VULNERABLE",
                "origin_validation": "UNKNOWN",
                "rate_limiting": "UNKNOWN",
                "trust_registration": "UNKNOWN",
            },
        )
        findings.append(finding)
    elif not instance.version:
        # Unknown version - assume vulnerable for safety
        finding = create_finding(
            status="VULNERABLE",
            indicators={
                "version_check": "UNKNOWN",
                "origin_validation": "UNKNOWN",
                "rate_limiting": "UNKNOWN",
                "trust_registration": "UNKNOWN",
            },
        )
        findings.append(finding)
    else:
        # Version indicates secure
        finding = create_finding(
            status="SECURE",
            indicators={
                "version_check": "SECURE",
                "origin_validation": "UNKNOWN",
                "rate_limiting": "UNKNOWN",
                "trust_registration": "UNKNOWN",
            },
        )
        findings.append(finding)

    # Active probing if gateway is running
    probe_result = None
    if instance.gateway_running and verbose > 0:
        click.echo("Running WebSocket probe tests...")
        probe = WebSocketProbe(instance)
        probe_result = probe.run_all_tests_sync()

        # Update finding with probe results
        if findings and probe_result.indicators:
            findings[0].indicators.update(probe_result.indicators)

    # Create result
    result = create_scan_result(
        target=instance,
        findings=findings,
        probe_result=probe_result,
    )

    _output_result(result, formatter, output_json, output_sarif, output_file)
    sys.exit(result.exit_code)


@cli.command()
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be done without making changes",
)
@click.option(
    "--force",
    is_flag=True,
    help="Apply fixes without confirmation",
)
@click.option(
    "--config-path",
    type=click.Path(),
    help="Custom path to OpenClaw config",
)
def fix(dry_run: bool, force: bool, config_path: str | None) -> None:
    """Fix detected vulnerabilities."""
    formatter = OutputFormatter()

    # First, run a scan
    discovery = OpenClawDiscovery(config_path=config_path)
    instance = discovery.find_installation()

    if not instance:
        formatter.console.print("[red]Error: OpenClaw not found[/red]")
        sys.exit(ExitCode.NOT_FOUND)

    if not instance.version:
        formatter.console.print("[yellow]Warning: Could not determine OpenClaw version[/yellow]")

    # Check for vulnerabilities
    if instance.version and not is_vulnerable(instance.version):
        formatter.console.print("[green]✓ OpenClaw is not vulnerable[/green]")
        sys.exit(ExitCode.SECURE)

    # Vulnerable - propose fix
    vuln_info = get_vulnerability_info("clawjacked")

    formatter.console.print(Panel(
        f"[bold red]VULNERABILITY DETECTED[/bold red]\n\n"
        f"{vuln_info['description']}\n\n"
        f"[yellow]Affected versions:[/yellow] {vuln_info['affected_versions']}\n"
        f"[green]Fixed version:[/green] {vuln_info['fixed_version']}\n\n"
        f"[bold]Recommended fix:[/bold]\n"
        f"  [cyan]{vuln_info['fixed_version']}[/cyan]"
    ))

    if dry_run:
        formatter.console.print("\n[yellow]Dry run mode - no changes made[/yellow]")
        sys.exit(ExitCode.VULNERABLE)

    if not force:
        click.confirm("\nApply fix now?", abort=True)

    # Apply fix (run openclaw upgrade)
    formatter.console.print("\n[cyan]Running: openclaw upgrade[/cyan]")

    import subprocess
    try:
        result = subprocess.run(
            ["openclaw", "upgrade"],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            formatter.console.print("[green]✓ Upgrade completed successfully[/green]")

            # Verify the fix
            formatter.console.print("\n[cyan]Verifying fix...[/cyan]")
            instance.version = discovery.get_version()

            if instance.version and not is_vulnerable(instance.version):
                formatter.console.print(f"[green]✓ Verified: Now running {instance.version}[/green]")
                sys.exit(ExitCode.SECURE)
            else:
                formatter.console.print("[yellow]⚠ Could not verify fix - please check manually[/yellow]")
                sys.exit(ExitCode.ERROR)
        else:
            formatter.console.print(f"[red]✗ Upgrade failed:[/red] {result.stderr}")
            sys.exit(ExitCode.ERROR)

    except FileNotFoundError:
        formatter.console.print("[red]✗ OpenClaw CLI not found - cannot apply automatic fix[/red]")
        formatter.console.print("\n[cyan]Manual fix steps:[/cyan]")
        formatter.console.print("  1. Update OpenClaw: openclaw upgrade")
        formatter.console.print("  2. Or reinstall: curl -sSL https://install.openclaw.dev | sh")
        sys.exit(ExitCode.ERROR)
    except Exception as e:
        formatter.console.print(f"[red]✗ Error:[/red] {e}")
        sys.exit(ExitCode.ERROR)


@cli.command()
@click.option(
    "--interval",
    default=60,
    type=int,
    help="Monitoring interval in seconds (default: 60)",
)
@click.option(
    "--log-file",
    type=click.Path(),
    help="Write monitoring logs to file",
)
@click.option(
    "--config-path",
    type=click.Path(),
    help="Custom path to OpenClaw config",
)
def monitor(interval: int, log_file: str | None, config_path: str | None) -> None:
    """Continuously monitor for vulnerability state changes."""
    formatter = OutputFormatter()

    formatter.console.print(f"[cyan]Starting ClawCheck monitor (interval: {interval}s)[/cyan]")
    formatter.console.print("Press Ctrl+C to stop\n")

    import signal
    import time

    running = True

    def signal_handler(sig, frame):
        nonlocal running
        running = False
        formatter.console.print("\n[yellow]Stopping monitor...[/yellow]")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    discovery = OpenClawDiscovery(config_path=config_path)
    last_status = None

    while running:
        try:
            instance = discovery.find_installation()
            current_status = {
                "found": instance is not None,
                "version": instance.version if instance else None,
                "running": instance.gateway_running if instance else None,
            }

            # Check for changes
            if current_status != last_status:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                status_str = json.dumps(current_status)

                log_msg = f"[{timestamp}] Status change: {status_str}"
                formatter.console.print(log_msg)

                if log_file:
                    with open(log_file, "a") as f:
                        f.write(log_msg + "\n")

                # Check vulnerability
                if instance and instance.version:
                    if is_vulnerable(instance.version):
                        formatter.console.print(f"[red]⚠ VULNERABLE: OpenClaw {instance.version} detected[/red]")
                    else:
                        formatter.console.print(f"[green]✓ SECURE: OpenClaw {instance.version}[/green]")

                last_status = current_status

        except Exception as e:
            formatter.console.print(f"[red]Error: {e}[/red]")

        # Wait for next interval or interrupt
        for _ in range(interval * 10):
            if not running:
                break
            time.sleep(0.1)

    formatter.console.print("[cyan]Monitor stopped[/cyan]")
    sys.exit(ExitCode.SECURE)


@cli.command()
def exit_codes() -> None:
    """Show exit code reference."""
    formatter = OutputFormatter()
    formatter.print_exit_code_info()


def _output_result(
    result,
    formatter,
    output_json: bool,
    output_sarif: bool,
    output_file: str | None,
) -> None:
    """Output scan result in the specified format.

    Args:
        result: ScanResult
        formatter: OutputFormatter
        output_json: Use JSON format
        output_sarif: Use SARIF format
        output_file: Write to file instead of stdout
    """
    if output_sarif:
        output = formatter.format_sarif(result)
    elif output_json:
        output = formatter.format_json(result)
    else:
        output = formatter.format_terminal(result)

    if output_file:
        with open(output_file, "w") as f:
            f.write(output)
        if not output_json and not output_sarif:
            click.echo(f"\nOutput written to {output_file}")
    else:
        if output_json or output_sarif:
            click.echo(output)


def main() -> None:
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
