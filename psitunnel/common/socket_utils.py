import asyncio
import socket

def tune_socket(writer: asyncio.StreamWriter):
    """Configures TCP_NODELAY and expands socket buffer sizes for high-throughput streaming."""
    try:
        sock = writer.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
            except OSError:
                pass
    except Exception:
        pass
