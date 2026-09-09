"""
Psiphon-inspired Fallback Manager & Client Multiplexer.
Manages candidate endpoints, multi-transport fallback, and connection multiplexing.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

from psitunnel.common.logger import setup_logger
from psitunnel.common.protocol import (
    Command,
    TunnelMessage,
    encode_connect_payload,
)
from psitunnel.transports.base import BaseTransportConnection
from psitunnel.transports.obfs_stream import connect_obfs
from psitunnel.transports.tls_tunnel import connect_tls
from psitunnel.transports.ws_tunnel import connect_ws


class ClientChannel:
    def __init__(
        self,
        conn_id: int,
        host: str,
        port: int,
        local_reader: asyncio.StreamReader,
        local_writer: asyncio.StreamWriter,
    ):
        self.conn_id = conn_id
        self.host = host
        self.port = port
        self.local_reader = local_reader
        self.local_writer = local_writer
        self.connected_event = asyncio.Event()
        self.error_reason: Optional[str] = None
        self.is_connected = False
        self.forward_task: Optional[asyncio.Task] = None


class FallbackManager:
    """
    Maintains the tunnel connection to the relay server with automatic protocol fallback.
    Multiplexes local client connections over the active transport tunnel.
    """

    def __init__(self, psk: str, candidate_endpoints: List[Dict[str, Any]], upstream_proxy: Optional[str] = None):
        """
        candidate_endpoints: list of dicts:
          [
            {"transport": "ws", "host": "127.0.0.1", "port": 9003},
            {"transport": "tls", "host": "127.0.0.1", "port": 9002, "sni": "localhost"},
            {"transport": "obfs", "host": "127.0.0.1", "port": 9001},
          ]
        upstream_proxy: optional URL to corporate forward proxy (e.g. "http://corp-proxy:8080")
        """
        self.psk = psk
        self.candidates = candidate_endpoints
        self.upstream_proxy = upstream_proxy
        self.logger = setup_logger("psitunnel.client")
        self.active_transport: Optional[BaseTransportConnection] = None
        self.active_candidate: Optional[Dict[str, Any]] = None

        self._next_conn_id = 1
        self._conn_id_lock = asyncio.Lock()
        self.channels: Dict[int, ClientChannel] = {}

        self._running = False
        self._rx_task: Optional[asyncio.Task] = None
        self._ping_task: Optional[asyncio.Task] = None
        self._reconnect_lock = asyncio.Lock()

        # Stats
        self.bytes_sent = 0
        self.bytes_received = 0

    @property
    def is_connected(self) -> bool:
        return self.active_transport is not None and not self.active_transport.is_closed

    async def start(self) -> bool:
        """Connects to the best available relay transport."""
        self._running = True
        return await self._ensure_connected()

    async def _ensure_connected(self) -> bool:
        async with self._reconnect_lock:
            if self.is_connected:
                return True

            proxy_msg = f" (via upstream proxy {self.upstream_proxy})" if self.upstream_proxy else ""
            self.logger.info(f"Discovering and negotiating best transport protocol{proxy_msg}...")
            for cand in self.candidates:
                t_type = cand.get("transport", "obfs").lower()
                host = cand["host"]
                port = cand["port"]

                self.logger.info(f"Attempting connection via [{t_type.upper()}] to {host}:{port}...")
                try:
                    conn: Optional[BaseTransportConnection] = None
                    if t_type == "obfs":
                        conn = await connect_obfs(host, port, self.psk, upstream_proxy=self.upstream_proxy, timeout=4.0)
                    elif t_type == "tls":
                        sni = cand.get("sni", host)
                        conn = await connect_tls(host, port, self.psk, server_hostname=sni, upstream_proxy=self.upstream_proxy, timeout=4.0)
                    elif t_type == "ws":
                        conn = await connect_ws(host, port, self.psk, upstream_proxy=self.upstream_proxy, timeout=4.0)
                    else:
                        self.logger.warning(f"Unknown transport type: {t_type}")
                        continue

                    if conn:
                        self.active_transport = conn
                        self.active_candidate = cand
                        self.logger.info(f"Successfully established tunnel via [{t_type.upper()}] to {host}:{port}!")

                        # Start background reader and ping loop
                        self._rx_task = asyncio.create_task(self._tunnel_rx_loop())
                        self._ping_task = asyncio.create_task(self._heartbeat_loop())
                        return True
                except Exception as e:
                    self.logger.warning(f"Transport [{t_type.upper()}] failed ({e}), falling back to next...")

            self.logger.error("All candidate transports and endpoints failed!")
            return False

    async def _tunnel_rx_loop(self):
        """Processes multiplexed incoming messages from the relay."""
        transport = self.active_transport
        if not transport:
            return

        try:
            while self._running and not transport.is_closed:
                msg = await transport.recv_message()
                if msg is None:
                    break

                self.bytes_received += len(msg.payload)

                if msg.cmd == Command.CMD_CONNECTED:
                    ch = self.channels.get(msg.conn_id)
                    if ch:
                        ch.is_connected = True
                        ch.connected_event.set()

                elif msg.cmd == Command.CMD_DATA:
                    ch = self.channels.get(msg.conn_id)
                    if ch and not ch.local_writer.is_closing():
                        try:
                            ch.local_writer.write(msg.payload)
                            await ch.local_writer.drain()
                        except Exception:
                            await self._close_channel(msg.conn_id, notify_remote=True)

                elif msg.cmd == Command.CMD_CLOSE:
                    ch = self.channels.get(msg.conn_id)
                    if ch and not ch.is_connected:
                        ch.connected_event.set()
                        self.channels.pop(msg.conn_id, None)
                    else:
                        await self._close_channel(msg.conn_id, notify_remote=False)

                elif msg.cmd == Command.CMD_ERROR:
                    ch = self.channels.get(msg.conn_id)
                    if ch:
                        ch.error_reason = msg.payload.decode("utf-8", errors="replace")
                        ch.connected_event.set()

                elif msg.cmd == Command.CMD_PONG:
                    # Heartbeat reply received
                    pass

        except Exception as e:
            self.logger.debug(f"Tunnel RX loop error: {e}")
        finally:
            self.logger.warning("Active transport connection dropped!")
            if self.active_transport == transport:
                self.active_transport = None
            if self._ping_task and not self._ping_task.done():
                self._ping_task.cancel()

            # Notify and clean up all channels associated with the dropped transport
            for conn_id in list(self.channels.keys()):
                ch = self.channels.pop(conn_id, None)
                if ch:
                    ch.error_reason = "Active transport connection dropped"
                    ch.connected_event.set()
                    try:
                        ch.local_writer.close()
                    except Exception:
                        pass

    async def _heartbeat_loop(self):
        """Sends periodic PING messages to maintain NAT keepalive and detect drops."""
        while self._running and self.is_connected:
            try:
                await asyncio.sleep(20.0)
                if self.is_connected:
                    ping = TunnelMessage(Command.CMD_PING, conn_id=0, payload=b"PING")
                    await self.active_transport.send_message(ping, inject_padding=False)
            except Exception:
                break

    async def open_channel(
        self,
        dest_host: str,
        dest_port: int,
        local_reader: asyncio.StreamReader,
        local_writer: asyncio.StreamWriter,
        on_connected: Optional[Any] = None,
    ) -> bool:
        """
        Opens a multiplexed tunnel channel to dest_host:dest_port and relays bidirectional data.
        If on_connected callback is provided, it is invoked once the remote target connects.
        """
        if not self.is_connected:
            success = await self._ensure_connected()
            if not success:
                return False

        async with self._conn_id_lock:
            conn_id = self._next_conn_id
            self._next_conn_id += 1

        channel = ClientChannel(conn_id, dest_host, dest_port, local_reader, local_writer)
        self.channels[conn_id] = channel

        try:
            # Send CONNECT command
            connect_payload = encode_connect_payload(dest_host, dest_port)
            connect_msg = TunnelMessage(Command.CMD_CONNECT, conn_id=conn_id, payload=connect_payload)
            await self.active_transport.send_message(connect_msg)
            self.bytes_sent += len(connect_payload)

            # Await confirmation from relay
            try:
                await asyncio.wait_for(channel.connected_event.wait(), timeout=12.0)
            except asyncio.TimeoutError:
                self.logger.warning(f"[Conn #{conn_id}] Timed out waiting for relay connection to {dest_host}:{dest_port}")
                await self._close_channel(conn_id, notify_remote=True, close_local=False)
                return False

            if not channel.is_connected:
                self.logger.warning(f"[Conn #{conn_id}] Relay rejected connection to {dest_host}:{dest_port}: {channel.error_reason}")
                await self._close_channel(conn_id, notify_remote=False, close_local=False)
                return False

            if on_connected:
                res = on_connected()
                if asyncio.iscoroutine(res):
                    await res

            # Forward local reader data into the tunnel
            while self._running and self.is_connected and not local_writer.is_closing():
                data = await local_reader.read(32768)
                if not data:
                    break
                data_msg = TunnelMessage(Command.CMD_DATA, conn_id=conn_id, payload=data)
                await self.active_transport.send_message(data_msg)
                self.bytes_sent += len(data)

            return True

        except Exception as e:
            self.logger.debug(f"[Conn #{conn_id}] Forwarding error: {e}")
            return False
        finally:
            if channel.is_connected:
                await self._close_channel(conn_id, notify_remote=True, close_local=True)
            else:
                self.channels.pop(conn_id, None)

    async def _close_channel(self, conn_id: int, notify_remote: bool = False, close_local: bool = True):
        ch = self.channels.pop(conn_id, None)
        if ch and close_local:
            try:
                ch.local_writer.close()
                await ch.local_writer.wait_closed()
            except Exception:
                pass

        if notify_remote and self.is_connected:
            try:
                close_msg = TunnelMessage(Command.CMD_CLOSE, conn_id=conn_id)
                await self.active_transport.send_message(close_msg)
            except Exception:
                pass

    async def stop(self):
        self._running = False
        if self._rx_task and not self._rx_task.done():
            self._rx_task.cancel()
        if self._ping_task and not self._ping_task.done():
            self._ping_task.cancel()

        for conn_id in list(self.channels.keys()):
            await self._close_channel(conn_id, notify_remote=True)

        if self.active_transport:
            await self.active_transport.close()
            self.active_transport = None

