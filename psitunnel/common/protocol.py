"""
Multiplexing protocol and message definitions for PsiTunnel.
"""

import enum
import struct
from typing import Tuple


class Command(enum.IntEnum):
    CMD_CONNECT = 0x01    # Client -> Relay: open connection to target
    CMD_CONNECTED = 0x02  # Relay -> Client: target connection established
    CMD_DATA = 0x03       # Bidirectional: proxied stream data
    CMD_CLOSE = 0x04      # Bidirectional: channel close
    CMD_PING = 0x05       # Client -> Relay: heartbeat
    CMD_PONG = 0x06       # Relay -> Client: heartbeat response
    CMD_ERROR = 0x07      # Relay -> Client: error notice
    CMD_WINDOW = 0x08     # Receiver grants consumed bytes back to sender
    CMD_SET_EXIT_PROXY = 0x09  # Client -> Relay: set session exit proxy URL


class AddressType(enum.IntEnum):
    IPV4 = 0x01
    DOMAIN = 0x03
    IPV6 = 0x04


class TunnelMessage:
    """
    Represents a multiplexed frame inside the encrypted tunnel.
    """

    # Header: [1 byte cmd] + [4 bytes conn_id] + [4 bytes payload_len]
    HEADER_STRUCT = struct.Struct(">BII")
    HEADER_LEN = HEADER_STRUCT.size  # 9 bytes

    def __init__(self, cmd: Command, conn_id: int, payload: bytes = b""):
        self.cmd = Command(cmd)
        self.conn_id = conn_id
        self.payload = payload

    def encode(self) -> bytes:
        header = self.HEADER_STRUCT.pack(self.cmd, self.conn_id, len(self.payload))
        return header + self.payload

    @classmethod
    def decode_header(cls, header_bytes: bytes) -> Tuple[Command, int, int]:
        """Returns (cmd, conn_id, payload_len)"""
        cmd_val, conn_id, payload_len = cls.HEADER_STRUCT.unpack(header_bytes)
        return Command(cmd_val), conn_id, payload_len

    def __repr__(self) -> str:
        return f"<TunnelMessage cmd={self.cmd.name} conn_id={self.conn_id} payload_len={len(self.payload)}>"


def encode_connect_payload(host: str, port: int) -> bytes:
    """
    Encodes target host and port into binary format.
    Format:
      [2 bytes port] + [1 byte addr_type] + [1 byte host_len] + [host_len bytes host]
    """
    host_bytes = host.encode("utf-8")
    if not host_bytes:
        raise ValueError("Target host cannot be empty")
    if not 1 <= port <= 65535:
        raise ValueError("Target port must be between 1 and 65535")
    if len(host_bytes) > 255:
        raise ValueError(f"Target host length {len(host_bytes)} exceeds maximum limit of 255 bytes")
    return struct.pack(">HBB", port, AddressType.DOMAIN, len(host_bytes)) + host_bytes


def decode_connect_payload(payload: bytes) -> Tuple[str, int]:
    """
    Decodes host and port from connect payload.
    """
    if len(payload) < 4:
        raise ValueError("Invalid connect payload: too short")
    port, addr_type, host_len = struct.unpack(">HBB", payload[:4])
    if addr_type not in (AddressType.IPV4, AddressType.DOMAIN, AddressType.IPV6):
        raise ValueError("Invalid connect payload: unsupported address type")
    if host_len == 0 or len(payload) != 4 + host_len:
        raise ValueError("Invalid connect payload: host length mismatch")
    if port == 0:
        raise ValueError("Invalid connect payload: port cannot be zero")
    try:
        host = payload[4:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Invalid connect payload: host is not valid UTF-8") from exc
    return host, port
