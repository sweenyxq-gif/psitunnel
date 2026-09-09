"""
Upstream proxy connection helper for traversing corporate / company firewalls.
"""

import asyncio
import base64
from typing import Optional, Tuple
from urllib.parse import urlparse


async def open_connection_with_upstream_proxy(
    target_host: str,
    target_port: int,
    upstream_proxy: Optional[str] = None,
    timeout: float = 10.0,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """
    Establishes a TCP connection to target_host:target_port, optionally tunneling
    through a corporate/company HTTP forward proxy via the HTTP CONNECT method.
    """
    if not upstream_proxy:
        return await asyncio.wait_for(
            asyncio.open_connection(target_host, target_port),
            timeout=timeout,
        )

    # Parse upstream proxy URL, e.g. "http://corp-proxy.local:8080" or "corp-proxy.local:8080"
    if "://" not in upstream_proxy:
        upstream_proxy = f"http://{upstream_proxy}"

    parsed = urlparse(upstream_proxy)
    proxy_host = parsed.hostname or "127.0.0.1"
    proxy_port = parsed.port or 8080

    # Connect to the corporate firewall / proxy
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_host, proxy_port),
        timeout=timeout,
    )

    try:
        # Issue HTTP CONNECT to tunnel through the company firewall
        connect_req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"

        if parsed.username and parsed.password:
            auth_str = f"{parsed.username}:{parsed.password}"
            b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("ascii")
            connect_req += f"Proxy-Authorization: Basic {b64_auth}\r\n"

        connect_req += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) PsiTunnel/1.0\r\n\r\n"
        writer.write(connect_req.encode("latin1"))
        await writer.drain()

        # Read response status line
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not status_line or b" 200 " not in status_line:
            status_text = status_line.decode("latin1", errors="replace").strip()
            raise ConnectionError(f"Upstream corporate proxy rejected CONNECT: {status_text}")

        # Read remaining proxy headers
        while True:
            line = await reader.readline()
            if not line or line == b"\r\n" or line == b"\n":
                break

        return reader, writer

    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise

