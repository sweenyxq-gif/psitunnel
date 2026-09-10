import asyncio
import struct
import unittest

from psitunnel.client.local_http import parse_connect_target
from psitunnel.transports.base import MAX_FRAME_SIZE
from psitunnel.transports.ws_tunnel import read_ws_frame


class TestHttpParsing(unittest.TestCase):
    def test_connect_authority(self):
        self.assertEqual(parse_connect_target("example.org:8443"), ("example.org", 8443))
        self.assertEqual(parse_connect_target("example.org"), ("example.org", 443))

    def test_ipv6_connect_authority(self):
        self.assertEqual(parse_connect_target("[2001:db8::1]:443"), ("2001:db8::1", 443))

    def test_rejects_invalid_connect_authority(self):
        with self.assertRaises(ValueError):
            parse_connect_target("example.org:not-a-port")


class TestWebSocketLimits(unittest.IsolatedAsyncioTestCase):
    async def test_rejects_oversized_frame_before_reading_payload(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x82\xff" + struct.pack(">Q", MAX_FRAME_SIZE + 5))
        with self.assertRaises(ValueError):
            await read_ws_frame(reader, is_client=False)

    async def test_server_rejects_unmasked_client_frame(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x82\x01x")
        with self.assertRaises(ValueError):
            await read_ws_frame(reader, is_client=False)


if __name__ == "__main__":
    unittest.main()
