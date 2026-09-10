"""
Abstract base transport definition for PsiTunnel.
"""

import abc
import asyncio
import random
import struct
from typing import Optional

from psitunnel.common.crypto import TunnelCryptoSession
from psitunnel.common.protocol import TunnelMessage


MAX_FRAME_SIZE = 10 * 1024 * 1024


class BaseTransportConnection(abc.ABC):
    """
    Abstract bidirectional connection between client and relay over an established transport stream.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        sender_session: TunnelCryptoSession,
        receiver_session: TunnelCryptoSession,
        name: str = "base",
    ):
        self.reader = reader
        self.writer = writer
        self.sender_session = sender_session
        self.receiver_session = receiver_session
        self.name = name
        self._closed = False
        self._send_lock = asyncio.Lock()
        self._recv_lock = asyncio.Lock()

    @property
    def is_closed(self) -> bool:
        return self._closed or self.writer.is_closing()

    async def send_message(self, msg: TunnelMessage, inject_padding: bool = True) -> None:
        """
        Serializes and AEAD-encrypts a TunnelMessage, then writes to the underlying stream.
        Guarantees frame encryption and socket writes are strictly atomic to preserve nonce order.
        """
        if self.is_closed:
            raise ConnectionResetError("Transport connection is closed")

        payload = msg.encode()
        pad_len = random.randint(0, 32) if inject_padding else 0

        async with self._send_lock:
            frame = self.sender_session.encrypt_frame(payload, pad_len=pad_len)
            self.writer.write(frame)
            await self.writer.drain()

    async def recv_message(self) -> Optional[TunnelMessage]:
        """
        Reads next AEAD frame from the stream and decodes the TunnelMessage.
        Returns None if the stream reached EOF.
        """
        if self.is_closed:
            return None

        async with self._recv_lock:
            try:
                # Read 4-byte frame length header
                len_bytes = await self.reader.readexactly(4)
                frame_len = struct.unpack(">I", len_bytes)[0]
                if frame_len < 18 or frame_len > MAX_FRAME_SIZE:
                    raise ValueError(f"Frame length {frame_len} exceeds maximum limit")

                ciphertext = await self.reader.readexactly(frame_len)
                plaintext = self.receiver_session.decrypt_frame(ciphertext)

                if len(plaintext) < TunnelMessage.HEADER_LEN:
                    raise ValueError("Decrypted frame is smaller than message header")

                cmd, conn_id, payload_len = TunnelMessage.decode_header(
                    plaintext[:TunnelMessage.HEADER_LEN]
                )
                actual_payload_len = len(plaintext) - TunnelMessage.HEADER_LEN
                if payload_len != actual_payload_len:
                    raise ValueError(
                        f"Message payload length mismatch: declared {payload_len}, actual {actual_payload_len}"
                    )
                payload = plaintext[TunnelMessage.HEADER_LEN:]
                return TunnelMessage(cmd=cmd, conn_id=conn_id, payload=payload)
            except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
                await self.close()
                return None
            except Exception:
                await self.close()
                raise

    async def close(self) -> None:
        """
        Closes the underlying stream.
        """
        if self._closed:
            return
        self._closed = True
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass
