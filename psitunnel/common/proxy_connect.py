"""
Upstream proxy connection helper for traversing corporate / company firewalls.
Supports:
  - HTTP/HTTPS forward proxies (CONNECT method)
  - SOCKS5 upstream proxies (username/password or no-auth)
  - Direct connections (no upstream proxy)
"""

import asyncio
import base64
import socket
import ssl
import struct
from typing import Optional, Tuple
from urllib.parse import urlparse


async def _connect_via_socks5(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
    username: Optional[str],
    password: Optional[str],
    timeout: float,
) -> None:
    """Perform SOCKS5 handshake to tunnel through to target_host:target_port."""

    # --- Auth negotiation ---
    # Offer no-auth (0x00) and username/password auth (0x02) if credentials supplied
    if username and password:
        writer.write(b"\x05\x02\x00\x02")  # VER=5, NMETHODS=2, NO_AUTH, USER/PASS
    else:
        writer.write(b"\x05\x01\x00")      # VER=5, NMETHODS=1, NO_AUTH
    await writer.drain()

    # Server picks one method
    method_resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
    if method_resp[0] != 0x05:
        raise ConnectionError("SOCKS5: unexpected version in server response")
    chosen = method_resp[1]

    if chosen == 0xFF:
        raise ConnectionError("SOCKS5: server rejected all authentication methods")

    if chosen == 0x02:
        # Username/password sub-negotiation (RFC 1929)
        if not username or not password:
            raise ConnectionError("SOCKS5: server requires username/password but none supplied")
        ulen = len(username.encode("utf-8"))
        plen = len(password.encode("utf-8"))
        auth_pkt = bytes([0x01, ulen]) + username.encode("utf-8") + bytes([plen]) + password.encode("utf-8")
        writer.write(auth_pkt)
        await writer.drain()
        auth_resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if auth_resp[1] != 0x00:
            raise ConnectionError("SOCKS5: authentication failed (wrong username/password)")

    # --- CONNECT request ---
    # Try domain name first (ATYP_DOMAIN=0x03)
    host_bytes = target_host.encode("utf-8")
    request = (
        b"\x05\x01\x00"           # VER CMD(CONNECT) RSV
        + b"\x03"                  # ATYP: domain name
        + bytes([len(host_bytes)]) # domain length
        + host_bytes               # domain
        + struct.pack(">H", target_port)  # port (big-endian)
    )
    writer.write(request)
    await writer.drain()

    # Read SOCKS5 response (VER REP RSV ATYP ...)
    resp_header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    if resp_header[0] != 0x05:
        raise ConnectionError("SOCKS5: unexpected version in CONNECT response")
    rep = resp_header[1]
    if rep != 0x00:
        errors = {
            0x01: "General SOCKS5 failure",
            0x02: "Connection not allowed by ruleset",
            0x03: "Network unreachable",
            0x04: "Host unreachable",
            0x05: "Connection refused",
            0x06: "TTL expired",
            0x07: "Command not supported",
            0x08: "Address type not supported",
        }
        raise ConnectionError(f"SOCKS5 CONNECT refused: {errors.get(rep, f'error 0x{rep:02X}')}")

    # Drain the bound address field
    atyp = resp_header[3]
    if atyp == 0x01:        # IPv4
        await asyncio.wait_for(reader.readexactly(4 + 2), timeout=timeout)
    elif atyp == 0x03:      # domain
        dlen = (await asyncio.wait_for(reader.readexactly(1), timeout=timeout))[0]
        await asyncio.wait_for(reader.readexactly(dlen + 2), timeout=timeout)
    elif atyp == 0x04:      # IPv6
        await asyncio.wait_for(reader.readexactly(16 + 2), timeout=timeout)
    else:
        raise ConnectionError(f"SOCKS5: unknown address type 0x{atyp:02X} in reply")


async def open_connection_with_upstream_proxy(
    target_host: str,
    target_port: int,
    upstream_proxy: Optional[str] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
    server_hostname: Optional[str] = None,
    timeout: float = 10.0,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """
    Establishes a TCP/TLS connection to target_host:target_port, optionally
    tunneling through an upstream proxy:

      - http://[user:pass@]host:port  — HTTP CONNECT (corporate firewall)
      - https://[user:pass@]host:port — HTTPS CONNECT
      - socks5://[user:pass@]host:port — SOCKS5 proxy (e.g. Tor: socks5://127.0.0.1:9050)
    """
    from psitunnel.common.socket_utils import tune_socket

    if not upstream_proxy:
        # Direct connection — no chain
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                target_host,
                target_port,
                ssl=ssl_context,
                server_hostname=server_hostname,
            ),
            timeout=timeout,
        )
        tune_socket(writer)
        return reader, writer

    # Normalise URL
    if "://" not in upstream_proxy:
        upstream_proxy = f"http://{upstream_proxy}"

    parsed = urlparse(upstream_proxy)
    scheme     = (parsed.scheme or "http").lower()
    proxy_host = parsed.hostname or "127.0.0.1"
    proxy_port = parsed.port
    username   = parsed.username or None
    password   = parsed.password or None

    # Default ports per scheme
    if proxy_port is None:
        proxy_port = 1080 if scheme.startswith("socks") else 8080

    # Open TCP connection to the proxy
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_host, proxy_port),
        timeout=timeout,
    )

    try:
        if scheme == "socks5":
            # ── SOCKS5 upstream ──────────────────────────────────────────────
            await _connect_via_socks5(
                reader, writer, target_host, target_port,
                username, password, timeout,
            )
        else:
            # ── HTTP / HTTPS CONNECT upstream ────────────────────────────────
            connect_req = (
                f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                f"Host: {target_host}:{target_port}\r\n"
            )
            if username and password:
                auth_str = f"{username}:{password}"
                b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("ascii")
                connect_req += f"Proxy-Authorization: Basic {b64_auth}\r\n"
            connect_req += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) PsiTunnel/1.0\r\n\r\n"
            writer.write(connect_req.encode("latin1"))
            await writer.drain()

            # Validate proxy CONNECT response
            status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not status_line or b" 200 " not in status_line:
                status_text = status_line.decode("latin1", errors="replace").strip()
                raise ConnectionError(f"Upstream proxy rejected CONNECT: {status_text}")

            # Drain remaining proxy response headers
            async def _read_proxy_headers():
                total = 0
                for _ in range(100):
                    line = await reader.readline()
                    total += len(line)
                    if total > 64 * 1024:
                        raise ValueError("Upstream proxy headers too large")
                    if not line or line in (b"\r\n", b"\n"):
                        return
                raise ValueError("Upstream proxy sent too many headers")

            await asyncio.wait_for(_read_proxy_headers(), timeout=timeout)

        # Optional TLS upgrade over the established tunnel
        if ssl_context:
            loop = asyncio.get_running_loop()
            protocol = writer._protocol
            transport = await loop.start_tls(
                writer._transport, protocol, ssl_context,
                server_hostname=server_hostname or target_host,
            )
            writer._transport = transport
            reader.set_transport(transport)

        tune_socket(writer)
        return reader, writer

    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise
