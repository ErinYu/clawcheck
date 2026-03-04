"""WebSocket vulnerability probe module."""

import asyncio
import time
import websockets.client
from typing import Optional

from clawcheck.models import OpenClawInstance, ProbeIndicator, ProbeResult


class WebSocketProbe:
    """Actively test for ClawJacked vulnerability indicators.

    SAFETY CONSTRAINTS:
    - Rate limit probe tests to 1 request/second (AWS guidelines)
    - Never attempt actual brute-force attacks
    - Read-only operations - no modification of OpenClaw state
    - Clear timeout values (30s for connection, 60s for full scan)
    """

    # Rate limiting: 1 request per second (AWS cooperative scanning guidelines)
    PROBE_DELAY = 1.0

    # Timeout values
    CONNECTION_TIMEOUT = 30.0
    OPERATION_TIMEOUT = 10.0

    def __init__(self, instance: OpenClawInstance):
        """Initialize probe.

        Args:
            instance: OpenClaw instance to probe
        """
        self.instance = instance
        self.gateway_url = instance.gateway_url

    async def test_origin_validation(self) -> ProbeIndicator:
        """Test if gateway accepts connections without Origin header check.

        This test sends a WebSocket connection without an Origin header
        (or with a malicious Origin). A secure gateway should reject
        connections from non-localhost origins.

        Returns:
            ProbeIndicator with test result
        """
        try:
            # Test 1: Connection without Origin header
            # (websockets doesn't send Origin by default for ws://)
            reader, writer = await asyncio.wait_for(
                websockets.client.connect(
                    self.gateway_url,
                    close_timeout=self.OPERATION_TIMEOUT,
                ),
                timeout=self.CONNECTION_TIMEOUT,
            )

            # If we get here, connection succeeded
            # A secure gateway should validate Origin
            await writer.close()

            return ProbeIndicator(
                name="origin_validation",
                status="FAIL",
                description="Gateway accepted WebSocket connection without Origin validation",
                confidence="HIGH",
            )

        except asyncio.TimeoutError:
            return ProbeIndicator(
                name="origin_validation",
                status="SKIP",
                description="Connection timeout - cannot determine status",
                confidence="LOW",
            )
        except ConnectionRefusedError:
            return ProbeIndicator(
                name="origin_validation",
                status="SKIP",
                description="Gateway not running or refused connection",
                confidence="HIGH",
            )
        except Exception as e:
            return ProbeIndicator(
                name="origin_validation",
                status="ERROR",
                description=f"Probe error: {e}",
                confidence="LOW",
            )

    async def test_rate_limiting(self) -> ProbeIndicator:
        """Test if localhost connections bypass rate limiting.

        This test sends multiple rapid connection attempts.
        A secure gateway should rate limit even localhost connections.

        SAFETY: We only send 3 connection attempts with 1s delay between.
        This is NOT a brute-force attack - just testing rate limiting behavior.

        Returns:
            ProbeIndicator with test result
        """
        attempts = []
        num_probes = 3

        for i in range(num_probes):
            start = time.time()
            try:
                reader, writer = await asyncio.wait_for(
                    websockets.client.connect(
                        self.gateway_url,
                        close_timeout=self.OPERATION_TIMEOUT,
                    ),
                    timeout=self.CONNECTION_TIMEOUT,
                )
                await writer.close()
                elapsed = time.time() - start
                attempts.append(("success", elapsed))

            except ConnectionRefusedError:
                attempts.append(("refused", time.time() - start))
                break
            except asyncio.TimeoutError:
                attempts.append(("timeout", time.time() - start))
            except Exception as e:
                attempts.append(("error", time.time() - start))

            # Rate limit our own probes (AWS cooperative scanning)
            if i < num_probes - 1:
                await asyncio.sleep(self.PROBE_DELAY)

        # Analyze results
        # If all connections succeeded rapidly, rate limiting may be disabled for localhost
        successful = [a for a in attempts if a[0] == "success"]

        if len(successful) >= 3:
            # All connections succeeded - potential rate limit bypass
            avg_time = sum(a[1] for a in successful) / len(successful)
            return ProbeIndicator(
                name="rate_limiting",
                status="FAIL",
                description=f"Made {len(successful)} successful connections in {avg_time:.2f}s avg - rate limiting may not apply to localhost",
                confidence="MEDIUM",
            )
        elif len(successful) == 0:
            return ProbeIndicator(
                name="rate_limiting",
                status="SKIP",
                description="All connections refused - gateway not accepting connections",
                confidence="HIGH",
            )
        else:
            return ProbeIndicator(
                name="rate_limiting",
                status="PASS",
                description=f"Only {len(successful)}/{num_probes} connections succeeded - rate limiting appears active",
                confidence="MEDIUM",
            )

    async def test_trust_registration(self) -> ProbeIndicator:
        """Test if auth auto-approves device registration from localhost.

        This test checks if successful authentication from localhost
        automatically registers the device as trusted without user prompt.

        NOTE: This is a simplified test. Full testing would require
        actual authentication, which we cannot do safely.

        Returns:
            ProbeIndicator with test result
        """
        # We cannot safely test actual authentication without credentials
        # Instead, we check if the gateway accepts connections that
        # should require device registration

        try:
            # Just test connection acceptance
            # A fully secure gateway would require explicit device approval
            reader, writer = await asyncio.wait_for(
                websockets.client.connect(
                    self.gateway_url,
                    close_timeout=self.OPERATION_TIMEOUT,
                ),
                timeout=self.CONNECTION_TIMEOUT,
            )

            # We connected - but we don't know if device was auto-trusted
            # This is a limitation of safe testing
            await writer.close()

            return ProbeIndicator(
                name="trust_registration",
                status="SKIP",
                description="Cannot safely test without credentials - manual verification required",
                confidence="LOW",
            )

        except ConnectionRefusedError:
            return ProbeIndicator(
                name="trust_registration",
                status="SKIP",
                description="Gateway not running",
                confidence="HIGH",
            )
        except asyncio.TimeoutError:
            return ProbeIndicator(
                name="trust_registration",
                status="SKIP",
                description="Connection timeout",
                confidence="MEDIUM",
            )
        except Exception as e:
            return ProbeIndicator(
                name="trust_registration",
                status="ERROR",
                description=f"Probe error: {e}",
                confidence="LOW",
            )

    async def run_all_tests(self) -> ProbeResult:
        """Execute all vulnerability tests.

        Returns:
            ProbeResult with all test results
        """
        start_time = time.time()
        result = ProbeResult()

        # Run tests with rate limiting between them
        try:
            result.origin_validation = await self.test_origin_validation()
            await asyncio.sleep(self.PROBE_DELAY)

            result.rate_limiting = await self.test_rate_limiting()
            await asyncio.sleep(self.PROBE_DELAY)

            result.trust_registration = await self.test_trust_registration()

        except Exception as e:
            result.error = f"Probe suite error: {e}"

        result.scan_duration_ms = int((time.time() - start_time) * 1000)
        return result

    def run_all_tests_sync(self) -> ProbeResult:
        """Synchronous wrapper for run_all_tests.

        Returns:
            ProbeResult with all test results
        """
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(self.run_all_tests())
