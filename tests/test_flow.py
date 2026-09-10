import asyncio
import struct
import unittest
from unittest.mock import AsyncMock

from psitunnel.common.flow import StreamFlow, WINDOW, CHUNK
from psitunnel.common.protocol import Command
from psitunnel.common.protocol import TunnelMessage
from psitunnel.server.relay import RelaySession
from psitunnel.client.fallback_mgr import FallbackManager
import logging


class FlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_relay_rejects_connect_when_pending_limit_reached(self):
        transport = AsyncMock()
        transport.name = "test"
        transport.recv_message.side_effect = [TunnelMessage(Command.CMD_CONNECT, 2), None]
        session = RelaySession(transport, "test", logging.getLogger("test"), max_channels=1)
        pending = asyncio.create_task(asyncio.sleep(100))
        session._pending_connects[1] = pending
        await session.run()
        commands = [call.args[0].cmd for call in transport.send_message.call_args_list]
        self.assertEqual(commands, [Command.CMD_ERROR, Command.CMD_CLOSE])
        self.assertTrue(pending.cancelled())

    async def test_client_limit_rejects_before_sending_connect(self):
        manager = FallbackManager("test", [], max_channels=1)
        transport = AsyncMock()
        transport.is_closed = False
        manager.active_transport = transport
        manager.channels[1] = object()
        self.assertFalse(await manager.open_channel("example.org", 443, AsyncMock(), AsyncMock()))
        transport.send_message.assert_not_called()

    async def test_slow_writer_does_not_block_other_stream(self):
        transport = AsyncMock()
        slow_gate = asyncio.Event()
        slow_writer = AsyncMock()
        slow_writer.write = lambda data: None
        slow_writer.drain.side_effect = slow_gate.wait
        fast_writer = AsyncMock()
        received = []
        fast_writer.write = received.append
        slow = StreamFlow(transport, 1, slow_writer, AsyncMock())
        fast = StreamFlow(transport, 2, fast_writer, AsyncMock())
        slow.start()
        fast.start()
        try:
            slow.receive(b"blocked")
            fast.receive(b"interactive")
            for _ in range(10):
                await asyncio.sleep(0)
            self.assertEqual(received, [b"interactive"])
            messages = [call.args[0] for call in transport.send_message.call_args_list]
            self.assertTrue(any(m.conn_id == 2 and m.cmd == Command.CMD_WINDOW for m in messages))
            self.assertFalse(any(m.conn_id == 1 for m in messages))
        finally:
            slow.close()
            fast.close()
            await asyncio.gather(slow.task, fast.task)

    async def test_credit_blocks_until_receiver_consumes(self):
        transport = AsyncMock()
        flow = StreamFlow(transport, 1, AsyncMock(), AsyncMock())
        for _ in range(WINDOW // CHUNK):
            await flow.send(b"a" * CHUNK)
        pending = asyncio.create_task(flow.send(b"b"))
        await asyncio.sleep(0)
        self.assertFalse(pending.done())
        flow.update(struct.pack(">I", CHUNK))
        await asyncio.wait_for(pending, 1)
        flow.close()

    async def test_receive_budget_and_invalid_credit(self):
        flow = StreamFlow(AsyncMock(), 1, AsyncMock(), AsyncMock())
        for _ in range(WINDOW // CHUNK):
            flow.receive(b"a" * CHUNK)
        with self.assertRaises(ValueError):
            flow.receive(b"b")
        with self.assertRaises(ValueError):
            flow.update(struct.pack(">I", 1))
        flow.close()

    async def test_eof_drains_queued_bytes_before_close(self):
        writer = AsyncMock()
        received = []
        writer.write = received.append
        close = AsyncMock()
        flow = StreamFlow(AsyncMock(), 1, writer, close)
        flow.receive(b"last bytes")
        flow.finish()
        flow.start()
        await flow.task
        self.assertEqual(received, [b"last bytes"])
        close.assert_awaited_once()

    async def test_bandwidth_delays_delivery(self):
        writer = AsyncMock()
        received = []
        writer.write = received.append
        flow = StreamFlow(AsyncMock(), 1, writer, AsyncMock(), bandwidth=1000)
        flow.receive(b"a" * 100)
        flow.finish()
        start = asyncio.get_running_loop().time()
        flow.start()
        await flow.task
        self.assertGreaterEqual(asyncio.get_running_loop().time() - start, 0.09)
