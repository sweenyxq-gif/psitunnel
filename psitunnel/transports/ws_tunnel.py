"""
WebSocket transport for PsiTunnel (RFC 6455).
Disguises proxy traffic as web browsing / WebSocket traffic.
Can traverse HTTP proxies, reverse proxies, and CDN edge nodes.
"""

import asyncio
import base64
import hashlib
import os
import struct
from typing import Optional

from psitunnel.common.crypto import (
    TunnelCryptoSession,
    derive_keys,
    generate_handshake_auth,
    verify_handshake_auth,
)
from psitunnel.transports.base import BaseTransportConnection

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def compute_accept_key(sec_key: str) -> str:
    combined = (sec_key.strip() + WS_GUID).encode("utf-8")
    return base64.b64encode(hashlib.sha1(combined).digest()).decode("ascii")


def create_ws_frame(data: bytes, mask: bool = False, opcode: int = 0x02) -> bytes:
    """
    Creates an RFC 6455 WebSocket binary frame (0x02).
    """
    first_byte = 0x80 | (opcode & 0x0F)  # FIN bit + Opcode
    length = len(data)

    if length <= 125:
        header = bytes([first_byte, (0x80 if mask else 0) | length])
    elif length <= 65535:
        header = bytes([first_byte, (0x80 if mask else 0) | 126]) + struct.pack(">H", length)
    else:
        header = bytes([first_byte, (0x80 if mask else 0) | 127]) + struct.pack(">Q", length)

    if mask and length > 0:
        mask_key = os.urandom(4)
        mask_repeated = (mask_key * ((length // 4) + 1))[:length]
        masked_data = (int.from_bytes(data, "big") ^ int.from_bytes(mask_repeated, "big")).to_bytes(length, "big")
        return header + mask_key + masked_data
    elif mask and length == 0:
        mask_key = os.urandom(4)
        return header + mask_key
    else:
        return header + data


async def read_ws_frame(
    reader: asyncio.StreamReader,
    writer: Optional[asyncio.StreamWriter] = None,
    is_client: bool = False,
) -> Optional[bytes]:
    """
    Reads next WebSocket frame from reader, handling masking and multi-byte lengths.
    Handles RFC 6455 Ping control frames (0x09) by replying with Pong (0x0A) and ignores Pong (0x0A).
    """
    while True:
        try:
            header = await reader.readexactly(2)
            fin_and_opcode = header[0]
            mask_and_len = header[1]

            opcode = fin_and_opcode & 0x0F
            if opcode == 0x08:  # CLOSE
                return None

            is_masked = (mask_and_len & 0x80) != 0
            payload_len = mask_and_len & 0x7F

            if payload_len == 126:
                ext_len = await reader.readexactly(2)
                payload_len = struct.unpack(">H", ext_len)[0]
            elif payload_len == 127:
                ext_len = await reader.readexactly(8)
                payload_len = struct.unpack(">Q", ext_len)[0]

            mask_key = b""
            if is_masked:
                mask_key = await reader.readexactly(4)

            data = await reader.readexactly(payload_len)
            if is_masked and payload_len > 0:
                mask_repeated = (mask_key * ((payload_len // 4) + 1))[:payload_len]
                data = (int.from_bytes(data, "big") ^ int.from_bytes(mask_repeated, "big")).to_bytes(payload_len, "big")

            if opcode == 0x09:  # PING
                if writer and not writer.is_closing():
                    pong_frame = create_ws_frame(data, mask=is_client, opcode=0x0A)
                    writer.write(pong_frame)
                    await writer.drain()
                continue
            elif opcode == 0x0A:  # PONG
                continue

            return data
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            return None


class WsStreamWrapper:
    """
    Wraps StreamReader/StreamWriter with WebSocket framing.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, is_client: bool):
        self.reader = reader
        self.writer = writer
        self.is_client = is_client

    async def readexactly(self, n: int) -> bytes:
        # Buffer frames as needed to satisfy readexactly
        # For our architecture, since BaseTransportConnection reads a frame at a time,
        # we can provide a stream adapter or custom connection.
        raise NotImplementedError()


class WsConnection(BaseTransportConnection):
    """
    WebSocket transport connection. Each send_message packs an AEAD encrypted
    frame inside an RFC 6455 binary frame.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        sender_session: TunnelCryptoSession,
        receiver_session: TunnelCryptoSession,
        is_client: bool,
    ):
        super().__init__(
            reader=reader,
            writer=writer,
            sender_session=sender_session,
            receiver_session=receiver_session,
            name="ws",
        )
        self.is_client = is_client

    async def send_message(self, msg, inject_padding: bool = True) -> None:
        if self.is_closed:
            raise ConnectionResetError("WebSocket connection is closed")

        import random
        payload = msg.encode()
        pad_len = random.randint(0, 32) if inject_padding else 0

        async with self._send_lock:
            aead_frame = self.sender_session.encrypt_frame(payload, pad_len=pad_len)
            ws_frame = create_ws_frame(aead_frame, mask=self.is_client, opcode=0x02)
            self.writer.write(ws_frame)
            await self.writer.drain()

    async def recv_message(self):
        if self.is_closed:
            return None

        async with self._recv_lock:
            try:
                ws_payload = await read_ws_frame(self.reader, self.writer, is_client=self.is_client)
                if ws_payload is None:
                    await self.close()
                    return None

                # Unpack AEAD frame from WebSocket payload
                # aead_frame starts with 4-byte frame length
                if len(ws_payload) < 4:
                    raise ValueError("WS payload smaller than AEAD frame length header")

                frame_len = struct.unpack(">I", ws_payload[:4])[0]
                ciphertext = ws_payload[4:4 + frame_len]
                plaintext = self.receiver_session.decrypt_frame(ciphertext)

                from psitunnel.common.protocol import TunnelMessage
                if len(plaintext) < TunnelMessage.HEADER_LEN:
                    raise ValueError("Decrypted frame is smaller than message header")

                cmd, conn_id, payload_len = TunnelMessage.decode_header(
                    plaintext[:TunnelMessage.HEADER_LEN]
                )
                payload = plaintext[TunnelMessage.HEADER_LEN:TunnelMessage.HEADER_LEN + payload_len]
                return TunnelMessage(cmd=cmd, conn_id=conn_id, payload=payload)
            except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
                await self.close()
                return None
            except Exception:
                await self.close()
                raise


from psitunnel.common.proxy_connect import open_connection_with_upstream_proxy


async def connect_ws(
    host: str,
    port: int,
    psk: str,
    path: str = "/ws",
    upstream_proxy: Optional[str] = None,
    timeout: float = 10.0,
) -> WsConnection:
    """
    Establishes a WebSocket transport connection to the relay server,
    optionally traversing an upstream corporate proxy.
    """
    reader, writer = await open_connection_with_upstream_proxy(
        target_host=host,
        target_port=port,
        upstream_proxy=upstream_proxy,
        timeout=timeout,
    )

    try:
        # Generate WebSocket key
        sec_key = base64.b64encode(os.urandom(16)).decode("ascii")
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {sec_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Origin: https://{host}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\n"
            f"Accept-Encoding: gzip, deflate, br\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
            f"\r\n"
        ).encode("utf-8")

        writer.write(req)
        await writer.drain()

        # Read HTTP response headers
        resp_lines = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not line:
                raise ConnectionError("Server closed connection during WebSocket upgrade")
            line_str = line.decode("latin1").rstrip("\r\n")
            if not line_str:
                break
            resp_lines.append(line_str)

        status_line = resp_lines[0] if resp_lines else ""
        if "101" not in status_line:
            raise ConnectionError(f"WebSocket upgrade rejected by server: {status_line}")

        # Now stream is upgraded. Perform AEAD handshake wrapped in WebSocket frames
        salt = os.urandom(32)
        c2s_key, s2c_key = derive_keys(psk, salt)
        auth_token = generate_handshake_auth(psk, salt)

        pad_len = os.urandom(1)[0] % 32
        pad_bytes = os.urandom(pad_len)
        handshake_payload = salt + struct.pack(">B", pad_len) + pad_bytes + auth_token

        # Send handshake as WS frame
        hs_frame = create_ws_frame(handshake_payload, mask=True, opcode=0x02)
        writer.write(hs_frame)
        await writer.drain()

        # Wait for server confirmation
        server_crypto = TunnelCryptoSession(s2c_key)
        resp_ws_data = await asyncio.wait_for(read_ws_frame(reader), timeout=timeout)
        if not resp_ws_data:
            raise ConnectionError("Empty handshake response from server")

        frame_len = struct.unpack(">I", resp_ws_data[:4])[0]
        server_conf = server_crypto.decrypt_frame(resp_ws_data[4:4 + frame_len])
        if server_conf != b"SERVER_OK":
            raise PermissionError("Server authentication verification failed over WebSocket")

        client_crypto = TunnelCryptoSession(c2s_key)
        return WsConnection(
            reader=reader,
            writer=writer,
            sender_session=client_crypto,
            receiver_session=server_crypto,
            is_client=True,
        )
    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise


async def accept_ws(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    psk: str,
    timeout: float = 10.0,
) -> Optional[WsConnection]:
    """
    Handles inbound WebSocket HTTP upgrade request and authentication.
    """
    try:
        # Read HTTP request
        req_lines = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not line:
                return None
            line_str = line.decode("latin1").rstrip("\r\n")
            if not line_str:
                break
            req_lines.append(line_str)

        if not req_lines:
            return None

        # Look for Sec-WebSocket-Key
        sec_key = None
        for line in req_lines:
            if line.lower().startswith("sec-websocket-key:"):
                sec_key = line.split(":", 1)[1].strip()
                break

        if not sec_key:
            # Not a WebSocket request; send 400 or anti-probing 404
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
            return None

        # Send 101 Switching Protocols
        accept_val = compute_accept_key(sec_key)
        resp = (
            f"HTTP/1.1 101 Switching Protocols\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept_val}\r\n"
            f"\r\n"
        ).encode("utf-8")
        writer.write(resp)
        await writer.drain()

        # Read handshake from first WS frame
        hs_data = await asyncio.wait_for(read_ws_frame(reader), timeout=timeout)
        if not hs_data or len(hs_data) < 33 + 52:
            writer.close()
            return None

        salt = hs_data[:32]
        pad_len = hs_data[32]
        idx = 33 + pad_len
        auth_token = hs_data[idx:idx + 52]

        if not verify_handshake_auth(psk, salt, auth_token):
            writer.close()
            return None

        c2s_key, s2c_key = derive_keys(psk, salt)
        server_crypto = TunnelCryptoSession(s2c_key)
        client_crypto = TunnelCryptoSession(c2s_key)

        # Send server confirmation frame
        conf_frame = server_crypto.encrypt_frame(b"SERVER_OK", pad_len=8)
        ws_conf = create_ws_frame(conf_frame, mask=False, opcode=0x02)
        writer.write(ws_conf)
        await writer.drain()

        return WsConnection(
            reader=reader,
            writer=writer,
            sender_session=server_crypto,
            receiver_session=client_crypto,
            is_client=False,
        )
    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return None

