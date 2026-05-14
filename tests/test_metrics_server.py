"""Tests for the Prometheus metrics HTTP server."""

import asyncio
import socket

import pytest

from mcp_witness.metrics_server import _handle, _render_prometheus, start_metrics_server


def _free_port() -> int:
    """Return an OS-assigned free TCP port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestRenderPrometheus:
    def test_all_metric_names_present(self):
        output = _render_prometheus()
        expected = [
            "mcp_witness_chain_breaks_total",
            "mcp_witness_signature_failures_total",
            "mcp_witness_anchor_verification_failures_total",
            "mcp_witness_rate_limit_hits_total",
            "mcp_witness_idempotency_duplicates_total",
            "mcp_witness_records_written_total",
            "mcp_witness_records_read_total",
        ]
        for name in expected:
            assert name in output, f"Missing metric: {name}"

    def test_help_and_type_line_counts(self):
        lines = _render_prometheus().strip().splitlines()
        assert sum(1 for line in lines if line.startswith("# HELP ")) == 7
        assert sum(1 for line in lines if line.startswith("# TYPE ")) == 7

    def test_all_type_lines_declare_counter(self):
        for line in _render_prometheus().splitlines():
            if line.startswith("# TYPE "):
                assert line.endswith("counter"), f"Unexpected metric type: {line}"

    def test_value_lines_are_numeric(self):
        for line in _render_prometheus().strip().splitlines():
            if line.startswith("#"):
                continue
            _, value = line.rsplit(" ", 1)
            float(value)  # Raises ValueError if not a valid number

    def test_output_ends_with_newline(self):
        assert _render_prometheus().endswith("\n")


class TestStartMetricsServer:
    @pytest.mark.asyncio
    async def test_disabled_when_port_zero(self):
        result = await start_metrics_server(port=0)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_server_object_on_valid_port(self):
        port = _free_port()
        server = await start_metrics_server(host="127.0.0.1", port=port)
        assert server is not None
        server.close()
        await server.wait_closed()

    @pytest.mark.asyncio
    async def test_returns_none_when_port_already_bound(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
            blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            blocker.bind(("127.0.0.1", 0))
            blocker.listen(1)
            occupied_port = blocker.getsockname()[1]
            result = await start_metrics_server(host="127.0.0.1", port=occupied_port)
        assert result is None

    @pytest.mark.asyncio
    async def test_default_host_is_loopback(self):
        """Verify the default host is loopback, not 0.0.0.0."""
        import inspect

        sig = inspect.signature(start_metrics_server)
        default_host = sig.parameters["host"].default
        assert default_host == "127.0.0.1", (
            f"Default host must be 127.0.0.1 (got {default_host!r}). "
            "Binding to 0.0.0.0 exposes metrics to the network."
        )


class TestHandleHTTP:
    @pytest.mark.asyncio
    async def test_responds_200_with_prometheus_body(self):
        server = await asyncio.start_server(_handle, "127.0.0.1", 0)
        host, port = server.sockets[0].getsockname()[:2]

        async with server:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(8192), timeout=5.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        text = response.decode()
        assert "200 OK" in text
        assert "Content-Type: text/plain" in text
        assert "mcp_witness_" in text
        assert "# HELP" in text
        assert "# TYPE" in text

    @pytest.mark.asyncio
    async def test_connection_closes_after_response(self):
        """Server closes connection after each response (no keep-alive)."""
        server = await asyncio.start_server(_handle, "127.0.0.1", 0)
        host, port = server.sockets[0].getsockname()[:2]

        async with server:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            # Drain full response
            await asyncio.wait_for(reader.read(8192), timeout=5.0)
            # Server sends Connection: close — next read must be EOF
            eof = await asyncio.wait_for(reader.read(1), timeout=2.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        assert eof == b""

    @pytest.mark.asyncio
    async def test_content_length_matches_body(self):
        """Content-Length header must equal the actual body length."""
        server = await asyncio.start_server(_handle, "127.0.0.1", 0)
        host, port = server.sockets[0].getsockname()[:2]

        async with server:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(8192), timeout=5.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        # Split headers from body at the blank line
        header_part, _, body = raw.partition(b"\r\n\r\n")
        headers = header_part.decode()
        content_length = None
        for line in headers.splitlines():
            if line.lower().startswith("content-length:"):
                content_length = int(line.split(":", 1)[1].strip())
                break

        assert content_length is not None, "Content-Length header missing"
        assert content_length == len(body)
