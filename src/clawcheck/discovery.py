"""OpenClaw discovery module."""

import asyncio
import json
import os
import socket
import subprocess
from pathlib import Path
from typing import Optional

from clawcheck.models import OpenClawInstance


class OpenClawDiscovery:
    """Detect OpenClaw installation and running instances."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize discovery.

        Args:
            config_path: Custom path to OpenClaw config
        """
        self.config_paths = self._get_config_paths(config_path)

    def _get_config_paths(self, custom_path: Optional[str]) -> list[Path]:
        """Get list of config paths to check.

        Args:
            custom_path: User-specified config path

        Returns:
            List of potential config file paths
        """
        paths = []

        if custom_path:
            paths.append(Path(custom_path))

        # Standard paths
        paths.append(Path.home() / ".openclaw" / "openclaw.json")
        paths.append(Path("/root/.openclaw/openclaw.json"))  # WSL/root

        return [p for p in paths if p]

    def find_installation(self) -> Optional[OpenClawInstance]:
        """Locate OpenClaw config and create instance.

        Returns:
            OpenClawInstance if found, None otherwise
        """
        for config_path in self.config_paths:
            if config_path.exists():
                try:
                    with open(config_path) as f:
                        config = json.load(f)

                    instance = OpenClawInstance(
                        config_path=config_path,
                        instance_type="local",
                    )

                    # Extract version from config if available
                    if isinstance(config, dict):
                        version = config.get("version")
                        if version:
                            instance.version = str(version)

                        # Check gateway config
                        gateway = config.get("gateway", {})
                        if isinstance(gateway, dict):
                            instance.gateway_port = gateway.get("port", 18789)
                            instance.gateway_host = gateway.get("bind", "127.0.0.1")

                    # Try to get version from CLI if not in config
                    if not instance.version:
                        instance.version = self.get_version()

                    # Check if gateway is running
                    instance.gateway_running = self.check_gateway_status(instance)

                    return instance

                except (json.JSONDecodeError, IOError, OSError):
                    continue

        # No config found, try to detect via CLI
        version = self.get_version()
        if version:
            instance = OpenClawInstance(
                version=version,
                instance_type="local",
            )
            instance.gateway_running = self.check_gateway_status(instance)
            return instance

        return None

    def get_version(self) -> Optional[str]:
        """Parse OpenClaw version via CLI.

        Returns:
            Version string or None if OpenClaw not found
        """
        try:
            result = subprocess.run(
                ["openclaw", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            output = result.stdout.strip()
            # Parse output like "OpenClaw 2026.2.12 (f9e444d)"
            # or "openclaw 2026.2.12"
            for part in output.split():
                part = part.strip("(),")
                if part.count(".") >= 2 and part[0].isdigit():
                    return part

            # Try parsing as "OpenClaw X.Y.Z"
            if "OpenClaw" in output:
                for word in output.split():
                    if word.replace(".", "").isdigit():
                        return word

        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass

        return None

    def check_gateway_status(
        self,
        instance: Optional[OpenClawInstance] = None,
        timeout: float = 1.0,
    ) -> bool:
        """Check if gateway is running on port 18789.

        Args:
            instance: OpenClaw instance (uses defaults if None)
            timeout: Connection timeout in seconds

        Returns:
            True if gateway is running
        """
        if instance is None:
            instance = OpenClawInstance()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((instance.gateway_host, instance.gateway_port))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False

    async def check_gateway_status_async(
        self,
        instance: Optional[OpenClawInstance] = None,
        timeout: float = 1.0,
    ) -> bool:
        """Async check if gateway is running.

        Args:
            instance: OpenClaw instance
            timeout: Connection timeout

        Returns:
            True if gateway is running
        """
        if instance is None:
            instance = OpenClawInstance()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    instance.gateway_host,
                    instance.gateway_port,
                ),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    def find_all_instances(self) -> list[OpenClawInstance]:
        """Find all OpenClaw instances.

        Returns:
            List of discovered instances
        """
        instances = []

        # Find local instance
        local = self.find_installation()
        if local:
            instances.append(local)

        # TODO: Add Docker detection in Phase 2
        # TODO: Add Kubernetes detection in Phase 2

        return instances

    def get_pid(self) -> Optional[int]:
        """Get PID of running OpenClaw gateway process.

        Returns:
            PID or None if not found
        """
        try:
            # Try pgrep first (more reliable)
            result = subprocess.run(
                ["pgrep", "-f", "openclaw"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode == 0 and result.stdout.strip():
                pids = result.stdout.strip().split("\n")
                return int(pids[0])
        except (FileNotFoundError, ValueError, subprocess.SubprocessError):
            pass

        try:
            # Fallback to ps
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=2,
            )

            for line in result.stdout.split("\n"):
                if "openclaw" in line.lower() and "grep" not in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            return int(parts[1])
                        except ValueError:
                            continue
        except (FileNotFoundError, subprocess.SubprocessError):
            pass

        return None
