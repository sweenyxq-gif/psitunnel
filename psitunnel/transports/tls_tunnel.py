"""
TLS-masked transport for PsiTunnel.
Encapsulates tunnel traffic inside standard TLS 1.2/1.3 with customizable SNI and ALPN.
"""

import asyncio
import ssl
import tempfile
import os
from typing import Optional, Tuple

from psitunnel.common.cert_utils import generate_self_signed_cert
from psitunnel.transports.base import BaseTransportConnection
from psitunnel.transports.obfs_stream import (
    accept_obfs,
    connect_obfs,
    ObfsConnection,
)


class TlsConnection(BaseTransportConnection):
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        obfs_conn: ObfsConnection,
    ):
        super().__init__(
            reader=reader,
            writer=writer,
            sender_session=obfs_conn.sender_session,
            receiver_session=obfs_conn.receiver_session,
            name="tls",
        )


def create_server_ssl_context(
    cert_path: Optional[str] = None,
    key_path: Optional[str] = None,
) -> Tuple[ssl.SSLContext, Optional[str], Optional[str]]:
    """
    Creates an SSLContext for the relay server. Generates temporary self-signed cert if none provided.
    Returns: (ssl_context, cert_file_to_clean, key_file_to_clean)
    """
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
    ctx.set_alpn_protocols(["http/1.1", "h2"])

    temp_cert, temp_key = None, None
    if not cert_path or not key_path:
        cert_pem, key_pem = generate_self_signed_cert()
        f_cert = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
        f_cert.write(cert_pem)
        f_cert.close()
        temp_cert = f_cert.name

        f_key = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
        f_key.write(key_pem)
        f_key.close()
        temp_key = f_key.name

        ctx.load_cert_chain(certfile=temp_cert, keyfile=temp_key)
    else:
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    return ctx, temp_cert, temp_key


def create_client_ssl_context(
    ca_cert_path: Optional[str] = None,
    verify_cert: bool = False,
) -> ssl.SSLContext:
    """
    Creates an SSLContext for the client.
    """
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.set_alpn_protocols(["http/1.1", "h2"])

    if not verify_cert:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif ca_cert_path:
        ctx.load_verify_locations(cafile=ca_cert_path)

    return ctx


from psitunnel.common.proxy_connect import open_connection_with_upstream_proxy


async def connect_tls(
    host: str,
    port: int,
    psk: str,
    server_hostname: Optional[str] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
    upstream_proxy: Optional[str] = None,
    timeout: float = 10.0,
) -> TlsConnection:
    """
    Connects to relay over TLS transport, optionally traversing an upstream corporate proxy.
    """
    if ssl_context is None:
        ssl_context = create_client_ssl_context(verify_cert=False)

    sni = server_hostname or host

    if upstream_proxy:
        reader, writer = await open_connection_with_upstream_proxy(
            target_host=host,
            target_port=port,
            upstream_proxy=upstream_proxy,
            timeout=timeout,
        )
        loop = asyncio.get_running_loop()
        protocol = writer._protocol
        transport = await loop.start_tls(writer._transport, protocol, ssl_context, server_hostname=sni)
        writer._transport = transport
        reader.set_transport(transport)
    else:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host,
                port,
                ssl=ssl_context,
                server_hostname=sni,
            ),
            timeout=timeout,
        )

    try:
        # Run authenticated handshake over the established TLS stream
        # (reusing the handshake logic from obfs_stream)
        from psitunnel.transports.obfs_stream import AUTH_TOKEN_LEN
        import struct
        from psitunnel.common.crypto import (
            derive_keys,
            generate_handshake_auth,
            TunnelCryptoSession,
        )

        salt = os.urandom(32)
        c2s_key, s2c_key = derive_keys(psk, salt)
        auth_token = generate_handshake_auth(psk, salt)

        pad_len = os.urandom(1)[0] % 32
        pad_bytes = os.urandom(pad_len)

        handshake = salt + struct.pack(">B", pad_len) + pad_bytes + auth_token
        writer.write(handshake)
        await writer.drain()

        server_crypto = TunnelCryptoSession(s2c_key)
        len_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        frame_len = struct.unpack(">I", len_bytes)[0]
        ciphertext = await asyncio.wait_for(reader.readexactly(frame_len), timeout=timeout)
        server_conf = server_crypto.decrypt_frame(ciphertext)
        if server_conf != b"SERVER_OK":
            raise PermissionError("Server authentication verification failed over TLS")

        client_crypto = TunnelCryptoSession(c2s_key)
        return TlsConnection(
            reader=reader,
            writer=writer,
            obfs_conn=ObfsConnection(reader, writer, client_crypto, server_crypto),
        )
    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise


async def accept_tls(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    psk: str,
    timeout: float = 10.0,
) -> Optional[TlsConnection]:
    """
    Accepts inbound connection that has already completed TLS handshake.
    """
    try:
        obfs_conn = await accept_obfs(reader, writer, psk, timeout=timeout)
        if not obfs_conn:
            return None
        return TlsConnection(reader, writer, obfs_conn)
    except Exception:
        return None

