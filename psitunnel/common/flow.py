"""Bounded per-stream delivery and explicit byte credits (protocol V3)."""
import asyncio
import struct

from psitunnel.common.protocol import Command, TunnelMessage

WINDOW = 262144
CHUNK = 32768


class StreamFlow:
    def __init__(self, transport, conn_id, writer, on_close, bandwidth=0):
        self.transport, self.conn_id = transport, conn_id
        self.writer, self.on_close = writer, on_close
        self.bandwidth = bandwidth
        self.credit = WINDOW
        self.available = asyncio.Event()
        self.available.set()
        self.remaining = WINDOW
        self.queue = asyncio.Queue(maxsize=4097)
        self.task = None
        self.closed = False
        self.eof = False

    def start(self):
        self.task = asyncio.create_task(self.deliver())

    async def send(self, data):
        # All senders emit fixed maximum chunks. Credit is charged before send.
        if not data or len(data) > CHUNK:
            raise ValueError("Invalid stream chunk")
        while self.credit < len(data) and not self.closed:
            self.available.clear()
            await self.available.wait()
        if self.closed:
            raise ConnectionError("Stream closed")
        self.credit -= len(data)
        await self.transport.send_message(TunnelMessage(Command.CMD_DATA, self.conn_id, data))

    def update(self, payload):
        if len(payload) != 4:
            raise ValueError("Invalid window update")
        count = struct.unpack(">I", payload)[0]
        if not count or self.credit + count > WINDOW:
            raise ValueError("Invalid stream credit")
        self.credit += count
        self.available.set()

    def receive(self, data):
        if self.eof or not data or len(data) > CHUNK or len(data) > self.remaining:
            raise ValueError("Stream receive window exceeded")
        self.remaining -= len(data)
        if self.queue.qsize() >= 4096:
            raise ValueError("Too many queued stream frames")
        # Limit tiny-frame attacks by frame count as well as bytes.
        self.queue.put_nowait(data)

    def finish(self):
        self.eof = True
        if not self.closed:
            self.queue.put_nowait(None)

    async def deliver(self):
        try:
            while not self.closed:
                data = await self.queue.get()
                if data is None:
                    break
                if self.bandwidth:
                    await asyncio.sleep(len(data) / self.bandwidth)
                self.writer.write(data)
                await self.writer.drain()
                self.remaining += len(data)
                await self.transport.send_message(TunnelMessage(
                    Command.CMD_WINDOW, self.conn_id, struct.pack(">I", len(data))))
        except (Exception, asyncio.CancelledError):
            pass
        finally:
            if not self.closed:
                await self.on_close()

    def close(self):
        self.closed = True
        self.available.set()
        if self.task and self.task is not asyncio.current_task():
            self.task.cancel()
