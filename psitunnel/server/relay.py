"""
PsiTunnel Remote Relay Server.
Handles multi-transport ingress, channel multiplexing, and target internet egress.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Tuple

from psitunnel.common.logger import setup_logger
from psitunnel.common.flow import StreamFlow
from psitunnel.common.protocol import (
    Command,
    TunnelMessage,
    decode_connect_payload,
)
from psitunnel.transports.base import BaseTransportConnection
from psitunnel.transports.obfs_stream import accept_obfs
from psitunnel.transports.tls_tunnel import accept_tls, create_server_ssl_context
from psitunnel.transports.ws_tunnel import accept_ws


class Channel:
    def __init__(self, conn_id: int, host: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.conn_id = conn_id
        self.host = host
        self.port = port
        self.reader = reader
        self.writer = writer
        self.read_task: Optional[asyncio.Task] = None
        self.flow = None


class RelaySession:
    """
    Manages a single client connection over an established transport.
    """

    def __init__(self, transport: BaseTransportConnection, psk: str, logger: logging.Logger, max_channels=128, bandwidth=0):
        self.transport = transport
        self.max_channels, self.bandwidth = max_channels, bandwidth
        self.psk = psk
        self.logger = logger
        self.channels: Dict[int, Channel] = {}
        self._pending_connects: Dict[int, asyncio.Task] = {}
        self._running = True
        self._cleanup_lock = asyncio.Lock()
        self._cleaned = False

    async def run(self):
        self.logger.info(f"Relay session established via [{self.transport.name.upper()}] transport")
        try:
            while self._running:
                msg = await self.transport.recv_message()
                if msg is None:
                    break

                if msg.cmd == Command.CMD_CONNECT:
                    if len(self.channels) + len(self._pending_connects) >= self.max_channels:
                        await self.transport.send_message(TunnelMessage(Command.CMD_ERROR, msg.conn_id, b"Channel limit reached"))
                        await self.transport.send_message(TunnelMessage(Command.CMD_CLOSE, msg.conn_id))
                        continue
                    if msg.conn_id == 0 or msg.conn_id in self.channels or msg.conn_id in self._pending_connects:
                        err_msg = TunnelMessage(
                            Command.CMD_ERROR,
                            conn_id=msg.conn_id,
                            payload=b"Invalid or duplicate connection ID",
                        )
                        await self.transport.send_message(err_msg)
                        continue
                    task = asyncio.create_task(self._handle_connect(msg.conn_id, msg.payload))
                    self._pending_connects[msg.conn_id] = task
                elif msg.cmd == Command.CMD_DATA:
                    await self._handle_data(msg.conn_id, msg.payload)
                elif msg.cmd == Command.CMD_CLOSE:
                    await self._handle_close(msg.conn_id, notify_remote=False)
                elif msg.cmd == Command.CMD_WINDOW:
                    pass
                elif msg.cmd == Command.CMD_PING:
                    pong = TunnelMessage(Command.CMD_PONG, conn_id=0, payload=msg.payload)
                    await self.transport.send_message(pong, inject_padding=False)
        except Exception as e:
            self.logger.debug(f"Relay session loop error: {e}")
        finally:
            await self.cleanup()

    async def _handle_connect(self, conn_id: int, payload: bytes):
        try:
            host, port = decode_connect_payload(payload)
            self.logger.info(f"[Conn #{conn_id}] Connecting to target {host}:{port}")

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=15.0,
                )
            except Exception as e:
                self.logger.warning(f"[Conn #{conn_id}] Failed connecting to {host}:{port}: {e}")
                err_msg = TunnelMessage(
                    Command.CMD_ERROR,
                    conn_id=conn_id,
                    payload=f"Connection failed: {e}".encode("utf-8"),
                )
                await self.transport.send_message(err_msg)
                close_msg = TunnelMessage(Command.CMD_CLOSE, conn_id=conn_id)
                await self.transport.send_message(close_msg)
                return

            if not self._running:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return

            channel = Channel(conn_id, host, port, reader, writer)
            channel.flow = None
            self.channels[conn_id] = channel

            # Notify client that remote socket is connected
            connected_msg = TunnelMessage(Command.CMD_CONNECTED, conn_id=conn_id)
            await self.transport.send_message(connected_msg)

            # Start reading from target socket and forwarding back through tunnel
            channel.read_task = asyncio.create_task(self._forward_target_to_tunnel(channel))

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"[Conn #{conn_id}] Connect handler error: {e}")
        finally:
            self._pending_connects.pop(conn_id, None)

    async def _forward_target_to_tunnel(self, channel: Channel):
        """Reads target internet socket and sends CMD_DATA back to client."""
        try:
            while self._running and not self.transport.is_closed:
                data = await channel.reader.read(32768)
                if not data:
                    break
                data_msg = TunnelMessage(Command.CMD_DATA, conn_id=channel.conn_id, payload=data)
                await self.transport.send_message(data_msg)
        except Exception as e:
            self.logger.debug(f"[Conn #{channel.conn_id}] Target read error: {e}")
        finally:
            await self._handle_close(channel.conn_id, notify_remote=True)

    async def _handle_data(self, conn_id: int, payload: bytes):
        channel = self.channels.get(conn_id)
        if channel and not channel.writer.is_closing():
            try:
                channel.writer.write(payload)
                await channel.writer.drain()
            except Exception as e:
                self.logger.debug(f"[Conn #{conn_id}] Target write error: {e}")
                await self._handle_close(conn_id, notify_remote=True)

    async def _handle_close(self, conn_id: int, notify_remote: bool = False):
        pending_task = self._pending_connects.pop(conn_id, None)
        if pending_task and not pending_task.done():
            pending_task.cancel()

        channel = self.channels.pop(conn_id, None)
        if channel:
            if channel.flow:
                channel.flow.close()
            if channel.read_task and channel.read_task is not asyncio.current_task() and not channel.read_task.done():
                channel.read_task.cancel()
            try:
                channel.writer.close()
                await channel.writer.wait_closed()
            except Exception:
                pass

        if notify_remote:
            try:
                close_msg = TunnelMessage(Command.CMD_CLOSE, conn_id=conn_id)
                await self.transport.send_message(close_msg)
            except Exception:
                pass

    async def cleanup(self):
        async with self._cleanup_lock:
            if self._cleaned:
                return
            self._cleaned = True
            self._running = False
            pending_tasks = list(self._pending_connects.values())
            for task in pending_tasks:
                if not task.done():
                    task.cancel()
            self._pending_connects.clear()
            if pending_tasks:
                await asyncio.gather(*pending_tasks, return_exceptions=True)

            for conn_id in list(self.channels.keys()):
                await self._handle_close(conn_id, notify_remote=False)
            await self.transport.close()
            self.logger.info("Relay session terminated")


class PsiTunnelServer:
    """
    Main relay server capable of listening concurrently on multiple transport ports.
    """

    def __init__(self, psk: str, cert_path: Optional[str] = None, key_path: Optional[str] = None, max_channels=128, bandwidth=0, max_sessions=64):
        self.psk = psk
        if max_channels < 1 or max_sessions < 1 or bandwidth < 0:
            raise ValueError("Invalid resource limits")
        self.max_channels, self.bandwidth, self.max_sessions = max_channels, bandwidth, max_sessions
        self.cert_path = cert_path
        self.key_path = key_path
        self.logger = setup_logger("psitunnel.server")
        self.servers: List[asyncio.Server] = []
        self.active_sessions: List[RelaySession] = []
        self._temp_cert: Optional[str] = None
        self._temp_key: Optional[str] = None

    async def start(
        self,
        host: str = "0.0.0.0",
        obfs_port: Optional[int] = 9001,
        tls_port: Optional[int] = 9002,
        ws_port: Optional[int] = 9003,
    ):
        """Starts listeners for configured transports."""
        self.logger.info("Starting PsiTunnel Relay Server...")

        # 1. Obfuscated TCP listener
        if obfs_port:
            server_obfs = await asyncio.start_server(
                self._on_obfs_client,
                host=host,
                port=obfs_port,
            )
            self.servers.append(server_obfs)
            self.logger.info(f"Listening on {host}:{obfs_port} [OBFS]")

        # 2. TLS listener
        if tls_port:
            ssl_ctx, self._temp_cert, self._temp_key = create_server_ssl_context(
                self.cert_path, self.key_path
            )
            server_tls = await asyncio.start_server(
                self._on_tls_client,
                host=host,
                port=tls_port,
                ssl=ssl_ctx,
            )
            self.servers.append(server_tls)
            self.logger.info(f"Listening on {host}:{tls_port} [TLS]")

        # 3. WebSocket listener
        if ws_port:
            server_ws = await asyncio.start_server(
                self._on_ws_client,
                host=host,
                port=ws_port,
            )
            self.servers.append(server_ws)
            self.logger.info(f"Listening on {host}:{ws_port} [WS]")

    def _spawn_session(self, conn: BaseTransportConnection):
        if len(self.active_sessions) >= self.max_sessions:
            conn.writer.close()
            return
        session = RelaySession(conn, self.psk, self.logger, self.max_channels, self.bandwidth)
        self.active_sessions.append(session)
        task = asyncio.create_task(session.run())
        task.add_done_callback(
            lambda _: self.active_sessions.remove(session) if session in self.active_sessions else None
        )

    async def _on_obfs_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        conn = await accept_obfs(reader, writer, self.psk)
        if conn:
            self._spawn_session(conn)

    async def _on_tls_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        conn = await accept_tls(reader, writer, self.psk)
        if conn:
            self._spawn_session(conn)

    async def _on_ws_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        conn = await accept_ws(reader, writer, self.psk)
        if conn:
            self._spawn_session(conn)

    async def stop(self):
        self.logger.info("Stopping PsiTunnel Relay Server...")
        for s in self.servers:
            s.close()
            await s.wait_closed()
        self.servers.clear()

        # Cleanly shut down all active client sessions
        for session in list(self.active_sessions):
            await session.cleanup()
        self.active_sessions.clear()

        # Clean up temporary certs
        import os
        if self._temp_cert and os.path.exists(self._temp_cert):
            try:
                os.remove(self._temp_cert)
            except Exception:
                pass
        if self._temp_key and os.path.exists(self._temp_key):
            try:
                os.remove(self._temp_key)
            except Exception:
                pass
