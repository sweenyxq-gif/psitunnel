"""
Local HTTP / HTTPS CONNECT proxy server for PsiTunnel.
Allows standard browsers and tools to route traffic through the encrypted tunnel.
"""

import asyncio
import logging
from urllib.parse import urlparse
from typing import Optional

from psitunnel.client.fallback_mgr import FallbackManager
from psitunnel.common.logger import setup_logger


MAX_HEADER_SIZE = 64 * 1024
MAX_HEADER_LINES = 100


def parse_connect_target(target: str) -> tuple[str, int]:
    """Parse an HTTP CONNECT authority, including bracketed IPv6 literals."""
    parsed = urlparse(f"//{target}")
    if not parsed.hostname:
        raise ValueError("CONNECT target is missing a host")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ValueError("CONNECT target contains an invalid port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("CONNECT target port is outside the valid range")
    return parsed.hostname, port


class LocalHttpProxyServer:
    def __init__(self, fallback_mgr: FallbackManager, host: str = "127.0.0.1", port: int = 8080):
        self.fallback_mgr = fallback_mgr
        self.host = host
        self.port = port
        self.logger = setup_logger("psitunnel.http")
        self.server: Optional[asyncio.Server] = None

    async def start(self):
        self.server = await asyncio.start_server(
            self._handle_client,
            host=self.host,
            port=self.port,
        )
        self.logger.info(f"HTTP CONNECT proxy listening on {self.host}:{self.port}")

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.logger.info("HTTP proxy stopped")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        from psitunnel.common.socket_utils import tune_socket
        tune_socket(writer)
        try:
            # Read request line
            request_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not request_line:
                writer.close()
                return

            req_parts = request_line.decode("latin1").strip().split()
            if len(req_parts) < 2:
                writer.close()
                return

            method, target = req_parts[0].upper(), req_parts[1]

            if method == "CONNECT":
                # HTTPS Tunneling
                dest_host, dest_port = parse_connect_target(target)

                # Read and discard remaining headers
                await self._read_headers(reader)

                self.logger.info(f"HTTP CONNECT for {dest_host}:{dest_port}")

                async def send_connect_success():
                    writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: PsiTunnel/1.0\r\n\r\n")
                    await writer.drain()

                # Delegate to fallback manager
                success = await self.fallback_mgr.open_channel(
                    dest_host, dest_port, reader, writer, on_connected=send_connect_success
                )
                if not success:
                    try:
                        writer.write(b"HTTP/1.1 502 Bad Gateway\r\nProxy-Agent: PsiTunnel/1.0\r\n\r\n")
                        await writer.drain()
                    except Exception:
                        pass
                    finally:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass

            else:
                # Plain HTTP proxy request (e.g. GET http://example.com/path)
                parsed = urlparse(target)
                dest_host = parsed.hostname or ""
                dest_port = parsed.port or 80
                path = parsed.path or "/"
                if parsed.query:
                    path += f"?{parsed.query}"

                if not dest_host:
                    writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    await writer.drain()
                    writer.close()
                    return

                self.logger.info(f"HTTP {method} for {dest_host}:{dest_port}")

                # Forward initial request line with relative path
                version = req_parts[2] if len(req_parts) > 2 else "HTTP/1.1"
                initial_data = f"{method} {path} {version}\r\n".encode("latin1")

                # Read remaining headers
                headers = []
                for line in await self._read_headers(reader, include_terminator=True):
                    # Strip Proxy-Connection header
                    if line.lower().startswith(b"proxy-connection:"):
                        continue
                    headers.append(line)

                initial_data += b"".join(headers)

                # Open channel and send initial request
                async def pipe_with_initial():
                    # We inject initial_data before reading remainder from reader
                    class PrefixedReader:
                        def __init__(self, prefix: bytes, orig_reader: asyncio.StreamReader):
                            self.prefix = prefix
                            self.orig = orig_reader

                        async def read(self, n: int) -> bytes:
                            if self.prefix:
                                chunk = self.prefix[:n]
                                self.prefix = self.prefix[n:]
                                return chunk
                            return await self.orig.read(n)

                    prefixed_reader = PrefixedReader(initial_data, reader)
                    success = await self.fallback_mgr.open_channel(dest_host, dest_port, prefixed_reader, writer)
                    if not success and not writer.is_closing():
                        try:
                            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nProxy-Agent: PsiTunnel/1.0\r\n\r\n")
                            await writer.drain()
                        except Exception:
                            pass

                await pipe_with_initial()

        except Exception as e:
            self.logger.debug(f"HTTP client error: {e}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _read_headers(
        self,
        reader: asyncio.StreamReader,
        include_terminator: bool = False,
    ) -> list[bytes]:
        async def read_block() -> list[bytes]:
            lines = []
            total_size = 0
            while True:
                line = await reader.readline()
                if not line:
                    raise ConnectionError("Client closed while sending HTTP headers")
                total_size += len(line)
                if total_size > MAX_HEADER_SIZE or len(lines) >= MAX_HEADER_LINES:
                    raise ValueError("HTTP header block exceeds maximum size")
                if line in (b"\r\n", b"\n"):
                    if include_terminator:
                        lines.append(line)
                    return lines
                lines.append(line)

        return await asyncio.wait_for(read_block(), timeout=10.0)
