import unittest
from psitunnel.common.protocol import (
    Command,
    TunnelMessage,
    encode_connect_payload,
    decode_connect_payload,
)


class TestProtocol(unittest.TestCase):
    def test_message_encode_decode(self):
        msg = TunnelMessage(Command.CMD_DATA, conn_id=101, payload=b"test payload")
        encoded = msg.encode()

        header = encoded[:TunnelMessage.HEADER_LEN]
        cmd, conn_id, payload_len = TunnelMessage.decode_header(header)

        self.assertEqual(cmd, Command.CMD_DATA)
        self.assertEqual(conn_id, 101)
        self.assertEqual(payload_len, len(b"test payload"))
        self.assertEqual(encoded[TunnelMessage.HEADER_LEN:], b"test payload")

    def test_connect_payload(self):
        host = "example.org"
        port = 443
        encoded = encode_connect_payload(host, port)
        decoded_host, decoded_port = decode_connect_payload(encoded)

        self.assertEqual(decoded_host, host)
        self.assertEqual(decoded_port, port)


if __name__ == "__main__":
    unittest.main()

