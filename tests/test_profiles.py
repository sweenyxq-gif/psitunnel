import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from psitunnel.client.client_cli import create_parser
from psitunnel.client.config import parse_client_args
from psitunnel.client.fallback_mgr import FallbackManager
from psitunnel.client.doctor import diagnose
from psitunnel.server.relay import PsiTunnelServer
from types import SimpleNamespace


class Profiles(unittest.TestCase):
    def test_profile_override_and_secret_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "secret").write_text("test-key\n", encoding="utf-8")
            (root / "config.json").write_text(json.dumps({
                "defaults": {"socks_port": 1081, "psk_file": "secret"},
                "default_profile": "work",
                "profiles": {"work": {"socks_port": 1082, "relays": [
                    {"host": "first.example", "transport": "ws"},
                    {"host": "second.example", "transport": "obfs"}]}}
            }), encoding="utf-8")
            with patch.dict("os.environ", {}, clear=True):
                args = parse_client_args(create_parser(), ["--config", str(root / "config.json"), "--socks-port", "1083"])
            self.assertEqual(args.socks_port, 1083)
            self.assertEqual(args.psk, "test-key")
            self.assertEqual([c["host"] for c in args.endpoints], ["first.example", "second.example"])

    def test_unknown_profile_is_rejected(self):
        from psitunnel.client.config import load_settings
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text('{"profiles": {}}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_settings(path, "missing")


class FakeConnection:
    name = "obfs"
    def __init__(self):
        self.is_closed = False
        self.closed = asyncio.Event()
    async def recv_message(self):
        await self.closed.wait()
        return None
    async def send_message(self, *args, **kwargs):
        pass
    async def close(self):
        self.is_closed = True
        self.closed.set()


class Health(unittest.IsolatedAsyncioTestCase):
    async def test_doctor_authenticates_and_checks_heartbeat(self):
        relay = PsiTunnelServer("test-key")
        listener = await asyncio.start_server(relay._on_obfs_client, "127.0.0.1", 0)
        port = listener.sockets[0].getsockname()[1]
        args = SimpleNamespace(psk="test-key", upstream_proxy=None,
                               endpoints=[dict(host="127.0.0.1", port=port, transport="obfs")])
        try:
            result = await diagnose(args)
            self.assertTrue(result[0]["ok"])
            args.psk = "wrong-key"
            result = await diagnose(args)
            self.assertFalse(result[0]["ok"])
        finally:
            listener.close()
            await listener.wait_closed()
            await relay.stop()

    async def test_failed_endpoint_cools_down_and_backup_selected(self):
        endpoints = [dict(host="one", port=1, transport="obfs"), dict(host="two", port=2, transport="obfs")]
        manager = FallbackManager("test-key", endpoints)
        connection = FakeConnection()
        manager.connect_endpoint = AsyncMock(side_effect=[OSError(), connection])
        try:
            self.assertTrue(await manager.start())
            self.assertEqual(manager.active_candidate, endpoints[1])
            self.assertEqual(manager.health[manager.endpoint_key(endpoints[0])].failures, 1)
            self.assertGreater(manager.health[manager.endpoint_key(endpoints[0])].retry_at, 0)
        finally:
            await manager.stop()

    async def test_missing_pong_closes_connection(self):
        endpoint = dict(host="one", port=1, transport="obfs")
        manager = FallbackManager("test-key", [endpoint])
        connection = FakeConnection()
        manager.heartbeat_interval = 0.01
        manager.heartbeat_timeout = 0.02
        manager.connect_endpoint = AsyncMock(return_value=connection)
        try:
            await manager.start()
            await asyncio.wait_for(connection.closed.wait(), 1)
            self.assertTrue(connection.is_closed)
        finally:
            await manager.stop()
