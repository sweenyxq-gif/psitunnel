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

    def test_rejects_malformed_connect_payload(self):
        with self.assertRaises(ValueError):
            decode_connect_payload(b"\x01\xbb\x03\x05abc")
        with self.assertRaises(ValueError):
            decode_connect_payload(b"\x00\x00\x03\x01a")
        with self.assertRaises(ValueError):
            encode_connect_payload("", 443)


if __name__ == "__main__":
    unittest.main()
