"""
End-to-end integration tests for PsiTunnel.
"""

import asyncio
import socket
import unittest

from psitunnel.client.fallback_mgr import FallbackManager
from psitunnel.client.local_http import LocalHttpProxyServer
from psitunnel.client.local_socks5 import LocalSocks5Server
from psitunnel.server.relay import PsiTunnelServer


class TestPsiTunnelIntegration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.psk = "test-secret-psk-12345"

        # 1. Start a simple TCP echo target server
        self.echo_received = []

        async def handle_echo(reader, writer):
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                self.echo_received.append(data)
                writer.write(b"ECHO:" + data)
                await writer.drain()
            writer.close()
            await writer.wait_closed()

        self.echo_server = await asyncio.start_server(handle_echo, host="127.0.0.1", port=0)
        self.echo_port = self.echo_server.sockets[0].getsockname()[1]

        # 2. Start PsiTunnel Relay Server on dynamic ports
        self.server = PsiTunnelServer(psk=self.psk)
        # Use ephemeral ports for test
        s_obfs = await asyncio.start_server(self.server._on_obfs_client, host="127.0.0.1", port=0)
        self.obfs_port = s_obfs.sockets[0].getsockname()[1]
        self.server.servers.append(s_obfs)

        s_ws = await asyncio.start_server(self.server._on_ws_client, host="127.0.0.1", port=0)
        self.ws_port = s_ws.sockets[0].getsockname()[1]
        self.server.servers.append(s_ws)

    async def asyncTearDown(self):
        if hasattr(self, "echo_server"):
            self.echo_server.close()
            await self.echo_server.wait_closed()
        if hasattr(self, "server"):
            await self.server.stop()

    async def test_fallback_and_socks5_proxy(self):
        # Candidates: first is a non-existent port (simulate censored / down), second is valid ws_port
        candidates = [
            {"transport": "ws", "host": "127.0.0.1", "port": 54321},  # Dead port
            {"transport": "ws", "host": "127.0.0.1", "port": self.ws_port},  # Working port
        ]

        fallback_mgr = FallbackManager(psk=self.psk, candidate_endpoints=candidates)
        connected = await fallback_mgr.start()
        self.assertTrue(connected, "FallbackManager should successfully connect via fallback candidate")
        self.assertEqual(fallback_mgr.active_candidate["port"], self.ws_port)

        # Start SOCKS5 proxy on ephemeral port
        socks = LocalSocks5Server(fallback_mgr, host="127.0.0.1", port=0)
        socks_srv = await asyncio.start_server(socks._handle_client, host="127.0.0.1", port=0)
        socks_port = socks_srv.sockets[0].getsockname()[1]

        try:
            # Client connects to SOCKS5 proxy
            reader, writer = await asyncio.open_connection("127.0.0.1", socks_port)

            # SOCKS5 handshake: VER=5, NMETHODS=1, METHOD=0
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            self.assertEqual(resp, b"\x05\x00")

            # SOCKS5 CONNECT to 127.0.0.1:echo_port (IPv4)
            ip_bytes = socket.inet_aton("127.0.0.1")
            import struct
            port_bytes = struct.pack(">H", self.echo_port)
            writer.write(b"\x05\x01\x00\x01" + ip_bytes + port_bytes)
            await writer.drain()

            connect_resp = await reader.readexactly(10)
            self.assertEqual(connect_resp[1], 0x00, "SOCKS5 reply should be SUCCESS (0x00)")

            # Send payload through SOCKS5 tunnel
            test_msg = b"Hello through PsiTunnel SOCKS5!"
            writer.write(test_msg)
            await writer.drain()

            echo_reply = await reader.read(1024)
            self.assertEqual(echo_reply, b"ECHO:" + test_msg)

            writer.close()
            await writer.wait_closed()
        finally:
            socks_srv.close()
            await socks_srv.wait_closed()
            await fallback_mgr.stop()

    async def test_http_connect_proxy(self):
        candidates = [
            {"transport": "obfs", "host": "127.0.0.1", "port": self.obfs_port},
        ]

        fallback_mgr = FallbackManager(psk=self.psk, candidate_endpoints=candidates)
        connected = await fallback_mgr.start()
        self.assertTrue(connected)

        # Start HTTP proxy on ephemeral port
        http_proxy = LocalHttpProxyServer(fallback_mgr, host="127.0.0.1", port=0)
        http_srv = await asyncio.start_server(http_proxy._handle_client, host="127.0.0.1", port=0)
        http_port = http_srv.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", http_port)

            # Send HTTP CONNECT
            req = f"CONNECT 127.0.0.1:{self.echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{self.echo_port}\r\n\r\n"
            writer.write(req.encode("ascii"))
            await writer.drain()

            # Read 200 Connection Established
            resp_line = await reader.readline()
            self.assertIn(b"200 Connection Established", resp_line)
            # Read until empty line
            while True:
                line = await reader.readline()
                if line == b"\r\n" or line == b"\n" or not line:
                    break

            # Send payload through HTTP tunnel
            test_msg = b"Hello through PsiTunnel HTTP CONNECT!"
            writer.write(test_msg)
            await writer.drain()

            echo_reply = await reader.read(1024)
            self.assertEqual(echo_reply, b"ECHO:" + test_msg)

            writer.close()
            await writer.wait_closed()
        finally:
            http_srv.close()
            await http_srv.wait_closed()
            await fallback_mgr.stop()


    async def test_tls_transport(self):
        # Ephemeral TLS server
        from psitunnel.transports.tls_tunnel import create_server_ssl_context
        ssl_ctx, cert_to_clean, key_to_clean = create_server_ssl_context()
        s_tls = await asyncio.start_server(self.server._on_tls_client, host="127.0.0.1", port=0, ssl=ssl_ctx)
        tls_port = s_tls.sockets[0].getsockname()[1]
        self.server.servers.append(s_tls)

        candidates = [
            {"transport": "tls", "host": "127.0.0.1", "port": tls_port, "sni": "localhost"},
        ]

        fallback_mgr = FallbackManager(psk=self.psk, candidate_endpoints=candidates)
        connected = await fallback_mgr.start()
        self.assertTrue(connected)

        # Start SOCKS5 proxy on ephemeral port
        socks = LocalSocks5Server(fallback_mgr, host="127.0.0.1", port=0)
        socks_srv = await asyncio.start_server(socks._handle_client, host="127.0.0.1", port=0)
        socks_port = socks_srv.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", socks_port)
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            self.assertEqual(resp, b"\x05\x00")

            # Connect via domain name (ATYP=0x03) to test remote DNS / FQDN support
            dest_host_bytes = b"127.0.0.1"
            import struct
            port_bytes = struct.pack(">H", self.echo_port)
            req = bytes([0x05, 0x01, 0x00, 0x03, len(dest_host_bytes)]) + dest_host_bytes + port_bytes
            writer.write(req)
            await writer.drain()

            connect_resp = await reader.readexactly(10)
            self.assertEqual(connect_resp[1], 0x00)

            test_msg = b"Hello through PsiTunnel TLS + Domain SOCKS5!"
            writer.write(test_msg)
            await writer.drain()

            echo_reply = await reader.read(1024)
            self.assertEqual(echo_reply, b"ECHO:" + test_msg)

            writer.close()
            await writer.wait_closed()
        finally:
            socks_srv.close()
            await socks_srv.wait_closed()
            await fallback_mgr.stop()
            import os
            if cert_to_clean and os.path.exists(cert_to_clean):
                os.remove(cert_to_clean)
            if key_to_clean and os.path.exists(key_to_clean):
                os.remove(key_to_clean)


    async def test_upstream_corporate_proxy(self):
        # 1. Spin up a mock Corporate Proxy / Firewall on localhost
        async def handle_corp_proxy(c_reader, c_writer):
            req_line = await c_reader.readline()
            while True:
                line = await c_reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
            # Status: 200 Connection Established
            c_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await c_writer.drain()

            # Pipe between client and PsiTunnel OBFS relay
            t_reader, t_writer = await asyncio.open_connection("127.0.0.1", self.obfs_port)

            async def pipe(src, dst):
                try:
                    while True:
                        data = await src.read(4096)
                        if not data:
                            break
                        dst.write(data)
                        await dst.drain()
                except Exception:
                    pass
                finally:
                    dst.close()

            t1 = asyncio.create_task(pipe(c_reader, t_writer))
            t2 = asyncio.create_task(pipe(t_reader, c_writer))
            await asyncio.gather(t1, t2, return_exceptions=True)

        corp_proxy_srv = await asyncio.start_server(handle_corp_proxy, host="127.0.0.1", port=0)
        corp_proxy_port = corp_proxy_srv.sockets[0].getsockname()[1]

        candidates = [
            {"transport": "obfs", "host": "127.0.0.1", "port": self.obfs_port},
        ]

        # Client connects to PsiTunnel relay through the corporate proxy
        fallback_mgr = FallbackManager(
            psk=self.psk,
            candidate_endpoints=candidates,
            upstream_proxy=f"http://127.0.0.1:{corp_proxy_port}",
        )
        connected = await fallback_mgr.start()
        self.assertTrue(connected, "Should establish tunnel through upstream corporate proxy")

        # Open SOCKS5 to echo server
        socks = LocalSocks5Server(fallback_mgr, host="127.0.0.1", port=0)
        socks_srv = await asyncio.start_server(socks._handle_client, host="127.0.0.1", port=0)
        socks_port = socks_srv.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", socks_port)
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            self.assertEqual(resp, b"\x05\x00")

            import struct
            port_bytes = struct.pack(">H", self.echo_port)
            dest_host_bytes = b"127.0.0.1"
            req = bytes([0x05, 0x01, 0x00, 0x03, len(dest_host_bytes)]) + dest_host_bytes + port_bytes
            writer.write(req)
            await writer.drain()

            connect_resp = await reader.readexactly(10)
            self.assertEqual(connect_resp[1], 0x00)

            test_msg = b"Traffic routed through Company Firewall to Netflix/WhatsApp!"
            writer.write(test_msg)
            await writer.drain()

            echo_reply = await reader.read(1024)
            self.assertEqual(echo_reply, b"ECHO:" + test_msg)

            writer.close()
            await writer.wait_closed()
        finally:
            socks_srv.close()
            await socks_srv.wait_closed()
            await fallback_mgr.stop()
            corp_proxy_srv.close()
            await corp_proxy_srv.wait_closed()

    async def test_concurrent_multiplexing(self):
        """Tests that multiple simultaneous streams through the same tunnel don't corrupt AEAD nonces."""
        candidates = [
            {"transport": "ws", "host": "127.0.0.1", "port": self.ws_port},
        ]
        fallback_mgr = FallbackManager(psk=self.psk, candidate_endpoints=candidates)
        connected = await fallback_mgr.start()
        self.assertTrue(connected)

        socks = LocalSocks5Server(fallback_mgr, host="127.0.0.1", port=0)
        socks_srv = await asyncio.start_server(socks._handle_client, host="127.0.0.1", port=0)
        socks_port = socks_srv.sockets[0].getsockname()[1]

        async def worker(idx: int):
            reader, writer = await asyncio.open_connection("127.0.0.1", socks_port)
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await reader.readexactly(2)
            self.assertEqual(resp, b"\x05\x00")

            import struct
            port_bytes = struct.pack(">H", self.echo_port)
            writer.write(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + port_bytes)
            await writer.drain()

            connect_resp = await reader.readexactly(10)
            self.assertEqual(connect_resp[1], 0x00)

            msg = f"Concurrent stream payload #{idx} - " * 20
            payload = msg.encode("utf-8")
            writer.write(payload)
            await writer.drain()

            reply = await reader.readexactly(len(b"ECHO:") + len(payload))
            self.assertEqual(reply, b"ECHO:" + payload)

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        try:
            tasks = [worker(i) for i in range(8)]
            await asyncio.gather(*tasks)
        finally:
            socks_srv.close()
            await socks_srv.wait_closed()
            await fallback_mgr.stop()

    async def test_socks5_target_unreachable(self):
        """Tests that SOCKS5 returns proper unreachable error when target connection fails."""
        candidates = [
            {"transport": "obfs", "host": "127.0.0.1", "port": self.obfs_port},
        ]
        fallback_mgr = FallbackManager(psk=self.psk, candidate_endpoints=candidates)
        connected = await fallback_mgr.start()
        self.assertTrue(connected)

        socks = LocalSocks5Server(fallback_mgr, host="127.0.0.1", port=0)
        socks_srv = await asyncio.start_server(socks._handle_client, host="127.0.0.1", port=0)
        socks_port = socks_srv.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", socks_port)
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            await reader.readexactly(2)

            # Connect to unused port 59998
            import struct
            port_bytes = struct.pack(">H", 59998)
            writer.write(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + port_bytes)
            await writer.drain()

            reply = await reader.readexactly(10)
            self.assertNotEqual(reply[1], 0x00, "Should return error status code for unreachable host")
            self.assertEqual(reply[1], 0x04)  # REP_HOST_UNREACHABLE

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        finally:
            socks_srv.close()
            await socks_srv.wait_closed()
            await fallback_mgr.stop()

    async def test_http_connect_target_unreachable(self):
        """Tests that HTTP proxy returns 502 Bad Gateway when target connection fails."""
        candidates = [
            {"transport": "obfs", "host": "127.0.0.1", "port": self.obfs_port},
        ]
        fallback_mgr = FallbackManager(psk=self.psk, candidate_endpoints=candidates)
        connected = await fallback_mgr.start()
        self.assertTrue(connected)

        http_proxy = LocalHttpProxyServer(fallback_mgr, host="127.0.0.1", port=0)
        http_srv = await asyncio.start_server(http_proxy._handle_client, host="127.0.0.1", port=0)
        http_port = http_srv.sockets[0].getsockname()[1]

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", http_port)
            writer.write(b"CONNECT 127.0.0.1:59998 HTTP/1.1\r\nHost: 127.0.0.1:59998\r\n\r\n")
            await writer.drain()

            status_line = await reader.readline()
            self.assertIn(b"502 Bad Gateway", status_line)

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        finally:
            http_srv.close()
            await http_srv.wait_closed()
            await fallback_mgr.stop()


if __name__ == "__main__":
    unittest.main()


