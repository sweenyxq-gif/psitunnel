"""
Psiphon-inspired Fallback Manager & Client Multiplexer.
Manages candidate endpoints, multi-transport fallback, and connection multiplexing.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from psitunnel.common.logger import setup_logger
from psitunnel.common.flow import StreamFlow
from psitunnel.common.protocol import (
    Command,
    TunnelMessage,
    encode_connect_payload,
)
from psitunnel.transports.base import BaseTransportConnection
from psitunnel.transports.obfs_stream import connect_obfs
from psitunnel.transports.tls_tunnel import connect_tls
from psitunnel.transports.ws_tunnel import connect_ws


@dataclass
class EndpointHealth:
    failures: int = 0
    retry_at: float = 0.0
    latency: float = float("inf")


class ClientChannel:
    def __init__(
        self,
        conn_id: int,
        host: str,
        port: int,
        local_reader: asyncio.StreamReader,
        local_writer: asyncio.StreamWriter,
        transport: BaseTransportConnection,
    ):
        self.conn_id = conn_id
        self.host = host
        self.port = port
        self.local_reader = local_reader
        self.local_writer = local_writer
        self.transport = transport
        self.flow = None
        self.connected_event = asyncio.Event()
        self.error_reason: Optional[str] = None
        self.is_connected = False
        self.forward_task: Optional[asyncio.Task] = None


class FallbackManager:
    """
    Maintains the tunnel connection to the relay server with automatic protocol fallback.
    Multiplexes local client connections over the active transport tunnel.
    """

    def __init__(self, psk: str, candidate_endpoints: List[Dict[str, Any]], upstream_proxy: Optional[str] = None, max_channels=1024, bandwidth=0):
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
        if max_channels < 1 or bandwidth < 0:
            raise ValueError("Invalid resource limits")
        self.max_channels, self.bandwidth = max_channels, bandwidth
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
        self._reconnect_task: Optional[asyncio.Task] = None
        self._reconnect_lock = asyncio.Lock()
        self.health = {self.endpoint_key(c): EndpointHealth() for c in self.candidates}
        self.heartbeat_interval = 20.0
        self.heartbeat_timeout = 10.0
        self._pong_events = {}

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
            if not self._running:
                return False
            if self.is_connected:
                return True

            proxy_msg = " (via upstream proxy)" if self.upstream_proxy else ""
            self.logger.info(f"Discovering and negotiating best transport protocol{proxy_msg}...")
            eligible = [c for c in self.candidates if self.health[self.endpoint_key(c)].retry_at <= time.monotonic()]
            if not eligible:
                self.logger.debug("All endpoints are in cooldown")
                return False
            eligible.sort(key=lambda c: (self.health[self.endpoint_key(c)].failures,
                                          self.health[self.endpoint_key(c)].latency))
            for cand in eligible:
                t_type = cand.get("transport", "obfs").lower()
                host = cand["host"]
                port = cand["port"]

                self.logger.info(f"Attempting connection via [{t_type.upper()}] to {host}:{port}...")
                try:
                    started = time.monotonic()
                    conn = await self.connect_endpoint(cand)

                    if conn:
                        health = self.health[self.endpoint_key(cand)]
                        health.latency = time.monotonic() - started
                        health.failures = 0
                        health.retry_at = 0
                        self.active_transport = conn
                        self.active_candidate = cand
                        self.logger.info(f"Successfully established tunnel via [{t_type.upper()}] to {host}:{port}!")

                        # Start background reader and ping loop
                        self._pong_events[conn] = asyncio.Event()
                        self._rx_task = asyncio.create_task(self._tunnel_rx_loop(conn, cand))
                        self._ping_task = asyncio.create_task(self._heartbeat_loop(conn))
                        return True
                except Exception as e:
                    self.record_failure(cand)
                    self.logger.warning(f"Transport [{t_type.upper()}] failed ({type(e).__name__}), falling back to next...")

            self.logger.error("All candidate transports and endpoints failed!")
            return False

    @staticmethod
    def endpoint_key(candidate):
        return tuple(candidate.get(k) for k in ("transport", "host", "port", "path", "sni", "use_ssl"))

    def record_failure(self, candidate):
        health = self.health[self.endpoint_key(candidate)]
        health.failures += 1
        health.retry_at = time.monotonic() + min(2 ** min(health.failures, 6), 60)

    async def connect_endpoint(self, candidate):
        """Shared connector for normal operation and doctor."""
        host, port = candidate["host"], candidate["port"]
        common = dict(upstream_proxy=self.upstream_proxy, timeout=15.0)
        kind = candidate["transport"]
        if kind == "obfs":
            return await connect_obfs(host, port, self.psk, **common)
        if kind == "tls":
            return await connect_tls(host, port, self.psk, server_hostname=candidate.get("sni", host), **common)
        if kind == "ws":
            return await connect_ws(host, port, self.psk, path=candidate.get("path", "/ws"),
                                    use_ssl=candidate.get("use_ssl"), **common)
        raise ValueError("Unknown transport")

    async def _tunnel_rx_loop(self, transport, candidate):
        """Processes multiplexed incoming messages from the relay."""
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
                            if ch.local_writer.transport and ch.local_writer.transport.get_write_buffer_size() > 131072:
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

                elif msg.cmd == Command.CMD_WINDOW:
                    pass

                elif msg.cmd == Command.CMD_ERROR:
                    ch = self.channels.get(msg.conn_id)
                    if ch:
                        ch.error_reason = msg.payload.decode("utf-8", errors="replace")
                        ch.connected_event.set()

                elif msg.cmd == Command.CMD_PONG:
                    if msg.payload == b"PING" and transport in self._pong_events:
                        self._pong_events[transport].set()

        except Exception as e:
            self.logger.warning(f"Tunnel RX loop error: {e}", exc_info=True)
        finally:
            if self._running:
                self.record_failure(candidate)
                self.logger.warning("Active transport connection dropped!")
            was_active_transport = self.active_transport is transport
            if was_active_transport:
                self.active_transport = None
                self.active_candidate = None
            if was_active_transport and self._ping_task and not self._ping_task.done():
                self._ping_task.cancel()

            # Notify only channels owned by the dropped transport. A replacement
            # transport may already be serving newer channels.
            for conn_id, existing_channel in list(self.channels.items()):
                if existing_channel.transport is transport:
                    ch = self.channels.pop(conn_id, None)
                    if ch.flow:
                        ch.flow.close()
                    ch.error_reason = "Active transport connection dropped"
                    ch.connected_event.set()
                    try:
                        ch.local_writer.close()
                    except Exception:
                        pass

            if self._running and not self.is_connected:
                self._schedule_reconnect()
            self._pong_events.pop(transport, None)
            await transport.close()

    async def _heartbeat_loop(self, transport: BaseTransportConnection):
        """Sends periodic PING messages to maintain NAT keepalive and detect drops."""
        while self._running and not transport.is_closed:
            try:
                await asyncio.sleep(self.heartbeat_interval)
                if self._running and not transport.is_closed:
                    event = self._pong_events[transport]
                    event.clear()
                    ping = TunnelMessage(Command.CMD_PING, conn_id=0, payload=b"PING")
                    await asyncio.wait_for(transport.send_message(ping, inject_padding=False), self.heartbeat_timeout)
                    await asyncio.wait_for(event.wait(), self.heartbeat_timeout)
            except Exception:
                await transport.close()
                break

    def _schedule_reconnect(self):
        if self._reconnect_task is None or self._reconnect_task.done():
            self._reconnect_task = asyncio.create_task(self._reconnect_loop())

    async def _reconnect_loop(self):
        delay = 1.0
        while self._running and not self.is_connected:
            if await self._ensure_connected():
                return
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30.0)

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

        transport = self.active_transport
        if transport is None or transport.is_closed:
            return False

        async with self._conn_id_lock:
            if len(self.channels) >= self.max_channels:
                return False
            conn_id = self._next_conn_id
            self._next_conn_id = 1 if self._next_conn_id == 0xFFFFFFFF else self._next_conn_id + 1

        channel = ClientChannel(conn_id, dest_host, dest_port, local_reader, local_writer, transport)
        channel.flow = StreamFlow(transport, conn_id, local_writer,
            lambda: self._close_channel(conn_id, notify_remote=True), self.bandwidth)
        self.channels[conn_id] = channel

        try:
            # Send CONNECT command
            connect_payload = encode_connect_payload(dest_host, dest_port)
            connect_msg = TunnelMessage(Command.CMD_CONNECT, conn_id=conn_id, payload=connect_payload)
            await transport.send_message(connect_msg)
            self.bytes_sent += len(connect_payload)

            # Await confirmation from relay
            try:
                await asyncio.wait_for(channel.connected_event.wait(), timeout=12.0)
            except asyncio.TimeoutError:
                self.logger.warning(f"[Conn #{conn_id}] Timed out waiting for relay connection to {dest_host}:{dest_port}")
                await self._close_channel(conn_id, notify_remote=True, close_local=False)
                return False

            if not channel.is_connected:
                self.logger.debug(f"[Conn #{conn_id}] Relay rejected connection to {dest_host}:{dest_port}: {channel.error_reason}")
                await self._close_channel(conn_id, notify_remote=False, close_local=False)
                return False

            if on_connected:
                res = on_connected()
                if asyncio.iscoroutine(res):
                    await res

            # Forward local reader data into the tunnel
            while self._running and not transport.is_closed and not local_writer.is_closing():
                data = await local_reader.read(65536)
                if not data:
                    break
                data_msg = TunnelMessage(Command.CMD_DATA, conn_id=conn_id, payload=data)
                await transport.send_message(data_msg)
                self.bytes_sent += len(data)

            return True

        except Exception as e:
            self.logger.debug(f"[Conn #{conn_id}] Forwarding error: {e}")
            return False
        finally:
            if channel.is_connected:
                await self._close_channel(conn_id, notify_remote=True, close_local=True)
            else:
                if channel.flow:
                    channel.flow.close()
                self.channels.pop(conn_id, None)

    async def _close_channel(self, conn_id: int, notify_remote: bool = False, close_local: bool = True):
        ch = self.channels.pop(conn_id, None)
        if ch:
            if ch.flow:
                ch.flow.close()
        if ch and close_local:
            try:
                ch.local_writer.close()
                await ch.local_writer.wait_closed()
            except Exception:
                pass

        transport = ch.transport if ch else None
        if notify_remote and transport is not None and not transport.is_closed:
            try:
                close_msg = TunnelMessage(Command.CMD_CLOSE, conn_id=conn_id)
                await transport.send_message(close_msg)
            except Exception:
                pass

    async def stop(self):
        self._running = False
        transport_to_close = self.active_transport
        tasks_to_wait = []
        if self._rx_task and not self._rx_task.done():
            self._rx_task.cancel()
            tasks_to_wait.append(self._rx_task)
        if self._ping_task and not self._ping_task.done():
            self._ping_task.cancel()
            tasks_to_wait.append(self._ping_task)
        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            tasks_to_wait.append(self._reconnect_task)

        for conn_id in list(self.channels.keys()):
            await self._close_channel(conn_id, notify_remote=True)

        if transport_to_close:
            await transport_to_close.close()
            self.active_transport = None

        if tasks_to_wait:
            await asyncio.gather(*tasks_to_wait, return_exceptions=True)
