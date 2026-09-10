"""
RFC 1928 compliant SOCKS5 local proxy server for PsiTunnel.
Supports domain name resolution (preventing DNS leaks) and IPv4/IPv6 addressing.
"""

import asyncio
import logging
import socket
import struct
from typing import Optional, Tuple

from psitunnel.client.fallback_mgr import FallbackManager
from psitunnel.common.logger import setup_logger

SOCKS_VERSION = 0x05
CMD_CONNECT = 0x01

ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

REP_SUCCESS = 0x00
REP_GEN_FAILURE = 0x01
REP_CONN_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CMD_NOT_SUPPORTED = 0x07


class LocalSocks5Server:
    def __init__(self, fallback_mgr: FallbackManager, host: str = "127.0.0.1", port: int = 1080):
        self.fallback_mgr = fallback_mgr
        self.host = host
        self.port = port
        self.logger = setup_logger("psitunnel.socks5")
        self.server: Optional[asyncio.Server] = None

    async def start(self):
        self.server = await asyncio.start_server(
            self._handle_client,
            host=self.host,
            port=self.port,
        )
        self.logger.info(f"SOCKS5 proxy listening on {self.host}:{self.port}")

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.logger.info("SOCKS5 proxy stopped")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        from psitunnel.common.socket_utils import tune_socket
        tune_socket(writer)
        try:
            # 1. Version and Authentication Method Negotiation
            greeting = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
            ver, nmethods = greeting[0], greeting[1]
            if ver != SOCKS_VERSION:
                writer.close()
                return

            methods = await asyncio.wait_for(reader.readexactly(nmethods), timeout=10.0)
            if 0x00 not in methods:  # 0x00 = NO AUTHENTICATION REQUIRED
                writer.write(bytes([SOCKS_VERSION, 0xFF]))  # 0xFF = NO ACCEPTABLE METHODS
                await writer.drain()
                writer.close()
                return

            # Reply: NO AUTH
            writer.write(bytes([SOCKS_VERSION, 0x00]))
            await writer.drain()

            # 2. SOCKS5 Request
            req_header = await asyncio.wait_for(reader.readexactly(4), timeout=10.0)
            ver, cmd, rsv, atyp = req_header[0], req_header[1], req_header[2], req_header[3]

            if ver != SOCKS_VERSION or cmd != CMD_CONNECT:
                writer.write(self._make_reply(REP_CMD_NOT_SUPPORTED))
                await writer.drain()
                writer.close()
                return

            # Parse destination address
            dest_host: str = ""
            if atyp == ATYP_IPV4:
                addr_bytes = await reader.readexactly(4)
                dest_host = socket.inet_ntoa(addr_bytes)
            elif atyp == ATYP_DOMAIN:
                domain_len = (await reader.readexactly(1))[0]
                domain_bytes = await reader.readexactly(domain_len)
                dest_host = domain_bytes.decode("utf-8", errors="replace")
            elif atyp == ATYP_IPV6:
                addr_bytes = await reader.readexactly(16)
                dest_host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                writer.write(self._make_reply(REP_GEN_FAILURE))
                await writer.drain()
                writer.close()
                return

            dest_port_bytes = await reader.readexactly(2)
            dest_port = struct.unpack(">H", dest_port_bytes)[0]

            self.logger.info(f"SOCKS5 request for {dest_host}:{dest_port}")

            async def send_success_reply():
                reply = self._make_reply(REP_SUCCESS)
                writer.write(reply)
                await writer.drain()

            # Delegate proxying to fallback manager
            success = await self.fallback_mgr.open_channel(
                dest_host, dest_port, reader, writer, on_connected=send_success_reply
            )
            if not success:
                try:
                    writer.write(self._make_reply(REP_HOST_UNREACHABLE))
                    await writer.drain()
                except Exception:
                    pass
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

        except Exception as e:
            self.logger.debug(f"SOCKS5 client handler error: {e}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _make_reply(self, rep_code: int) -> bytes:
        return bytes([SOCKS_VERSION, rep_code, 0x00, ATYP_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

