"""
Obfuscated raw TCP stream transport with random padding and pre-shared key AEAD authentication.
"""

import asyncio
import os
import struct
from typing import Optional

from psitunnel.common.crypto import (
    TunnelCryptoSession,
    derive_keys,
    derive_session_keys,
    generate_handshake_auth,
    verify_handshake_auth,
)
from psitunnel.transports.base import BaseTransportConnection

AUTH_TOKEN_LEN = 52  # 8 bytes ts + 12 bytes magic + 16 bytes rnd + 16 bytes tag
SERVER_NONCE_LEN = 32
SERVER_CONFIRMATION_PREFIX = b"SERVER_OK"
MAX_HANDSHAKE_FRAME_SIZE = 4096


class ObfsConnection(BaseTransportConnection):
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        sender_session: TunnelCryptoSession,
        receiver_session: TunnelCryptoSession,
    ):
        super().__init__(
            reader=reader,
            writer=writer,
            sender_session=sender_session,
            receiver_session=receiver_session,
            name="obfs",
        )


from psitunnel.common.proxy_connect import open_connection_with_upstream_proxy


async def connect_obfs(
    host: str,
    port: int,
    psk: str,
    upstream_proxy: Optional[str] = None,
    timeout: float = 10.0,
) -> ObfsConnection:
    """
    Connects to an obfuscated PsiTunnel relay, optionally traversing an upstream corporate proxy.
    """
    reader, writer = await open_connection_with_upstream_proxy(
        target_host=host,
        target_port=port,
        upstream_proxy=upstream_proxy,
        timeout=timeout,
    )

    try:
        salt = os.urandom(32)
        _, confirmation_key = derive_keys(psk, salt)
        auth_token = generate_handshake_auth(psk, salt)

        # Dynamic random padding (0-31 bytes) to disguise initial packet length
        pad_len = os.urandom(1)[0] % 32
        pad_bytes = os.urandom(pad_len)

        # Handshake payload
        handshake = salt + struct.pack(">B", pad_len) + pad_bytes + auth_token
        writer.write(handshake)
        await writer.drain()

        # The encrypted confirmation contributes fresh server randomness to the
        # final traffic keys, so replaying a captured client hello cannot replay
        # the captured traffic that followed it.
        confirmation_crypto = TunnelCryptoSession(confirmation_key)
        # 4 bytes frame len + 16 bytes tag + 2 bytes pad_len + 16 bytes token = 38 bytes
        len_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        frame_len = struct.unpack(">I", len_bytes)[0]
        if frame_len < 18 or frame_len > MAX_HANDSHAKE_FRAME_SIZE:
            raise ValueError("Invalid server confirmation frame length")
        ciphertext = await asyncio.wait_for(reader.readexactly(frame_len), timeout=timeout)
        server_conf = confirmation_crypto.decrypt_frame(ciphertext)
        if not server_conf.startswith(SERVER_CONFIRMATION_PREFIX) or len(server_conf) != len(SERVER_CONFIRMATION_PREFIX) + SERVER_NONCE_LEN:
            raise PermissionError("Server authentication verification failed")

        server_nonce = server_conf[len(SERVER_CONFIRMATION_PREFIX):]
        c2s_key, s2c_key = derive_session_keys(psk, salt, server_nonce)

        client_crypto = TunnelCryptoSession(c2s_key)
        return ObfsConnection(
            reader=reader,
            writer=writer,
            sender_session=client_crypto,
            receiver_session=TunnelCryptoSession(s2c_key),
        )
    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise


async def accept_obfs(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    psk: str,
    timeout: float = 10.0,
) -> Optional[ObfsConnection]:
    """
    Handles inbound obfuscated handshake on the relay server.
    """
    try:
        salt = await asyncio.wait_for(reader.readexactly(32), timeout=timeout)
        pad_len_byte = await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
        pad_len = struct.unpack(">B", pad_len_byte)[0]
        if pad_len > 0:
            await asyncio.wait_for(reader.readexactly(pad_len), timeout=timeout)

        auth_token = await asyncio.wait_for(reader.readexactly(AUTH_TOKEN_LEN), timeout=timeout)
        if not verify_handshake_auth(psk, salt, auth_token):
            # Anti-probing: Send garbage or close immediately
            writer.close()
            return None

        _, confirmation_key = derive_keys(psk, salt)
        confirmation_crypto = TunnelCryptoSession(confirmation_key)
        server_nonce = os.urandom(SERVER_NONCE_LEN)
        c2s_key, s2c_key = derive_session_keys(psk, salt, server_nonce)
        server_crypto = TunnelCryptoSession(s2c_key)
        client_crypto = TunnelCryptoSession(c2s_key)

        # Send confirmation frame
        conf_frame = confirmation_crypto.encrypt_frame(
            SERVER_CONFIRMATION_PREFIX + server_nonce,
            pad_len=8,
        )
        writer.write(conf_frame)
        await writer.drain()

        return ObfsConnection(
            reader=reader,
            writer=writer,
            sender_session=server_crypto,
            receiver_session=client_crypto,
        )
    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return None
