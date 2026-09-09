import unittest
from psitunnel.common.crypto import (
    TunnelCryptoSession,
    derive_keys,
    generate_handshake_auth,
    verify_handshake_auth,
)


class TestCrypto(unittest.TestCase):
    def test_key_derivation(self):
        psk = "my-secret-psk-12345"
        salt = b"0" * 32
        c2s_1, s2c_1 = derive_keys(psk, salt)
        c2s_2, s2c_2 = derive_keys(psk, salt)
        self.assertEqual(c2s_1, c2s_2)
        self.assertEqual(s2c_1, s2c_2)
        self.assertNotEqual(c2s_1, s2c_1)

    def test_handshake_auth(self):
        psk = "my-secret-psk-12345"
        salt = b"x" * 32
        auth_token = generate_handshake_auth(psk, salt)
        self.assertTrue(verify_handshake_auth(psk, salt, auth_token))

        # Wrong psk should fail
        self.assertFalse(verify_handshake_auth("wrong-psk", salt, auth_token))
        # Wrong salt should fail
        self.assertFalse(verify_handshake_auth(psk, b"y" * 32, auth_token))

    def test_aead_framing_and_padding(self):
        key = b"\x01" * 32
        sender = TunnelCryptoSession(key)
        receiver = TunnelCryptoSession(key)

        original_data = b"Hello, secure anti-censorship world!"
        # Encrypt with 30 bytes padding
        frame = sender.encrypt_frame(original_data, pad_len=30)

        # Ciphertext length should include padding (2 bytes len + 30 bytes pad) + data + 16 bytes tag
        self.assertGreater(len(frame), len(original_data) + 32)

        # Read 4-byte frame length header
        import struct
        frame_len = struct.unpack(">I", frame[:4])[0]
        ciphertext = frame[4:4 + frame_len]

        decrypted = receiver.decrypt_frame(ciphertext)
        self.assertEqual(decrypted, original_data)


if __name__ == "__main__":
    unittest.main()

