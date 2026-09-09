"""
Cryptographic primitives, AEAD framing, and key derivation for PsiTunnel.
"""

import os
import struct
import time
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class TunnelCryptoSession:
    """
    Manages bidirectional AEAD encryption/decryption state with monotonic nonces.
    """

    MAGIC_AUTH = b"PSITUNNEL_V1"

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for ChaCha20-Poly1305")
        self.aead = ChaCha20Poly1305(key)
        self.nonce_seq = 0

    def _next_nonce(self) -> bytes:
        """
        Derives a 12-byte nonce: 4 bytes zero prefix + 8 bytes big-endian counter.
        """
        nonce = struct.pack(">IQ", 0, self.nonce_seq)
        self.nonce_seq += 1
        return nonce

    def encrypt_frame(self, data: bytes, pad_len: int = 0) -> bytes:
        """
        Encrypts data into a padded AEAD frame.
        Internal payload format:
          [2 bytes: pad_len] + [pad_len bytes random padding] + [data]
        Frame format:
          [4 bytes: ciphertext length] + [ciphertext (including 16-byte Poly1305 tag)]
        """
        if pad_len > 255:
            pad_len = 255
        padding = os.urandom(pad_len) if pad_len > 0 else b""
        payload = struct.pack(">H", pad_len) + padding + data

        nonce = self._next_nonce()
        ciphertext = self.aead.encrypt(nonce, payload, None)
        frame_len = len(ciphertext)
        return struct.pack(">I", frame_len) + ciphertext

    def decrypt_frame(self, ciphertext: bytes) -> bytes:
        """
        Decrypts an AEAD ciphertext frame, extracts and removes padding.
        """
        nonce = self._next_nonce()
        plaintext = self.aead.decrypt(nonce, ciphertext, None)
        if len(plaintext) < 2:
            raise ValueError("Decrypted frame is too short")
        pad_len = struct.unpack(">H", plaintext[:2])[0]
        if len(plaintext) < 2 + pad_len:
            raise ValueError("Invalid padding length in decrypted frame")
        return plaintext[2 + pad_len:]


def derive_keys(psk: str | bytes, salt: bytes) -> Tuple[bytes, bytes]:
    """
    Derives (client_to_server_key, server_to_client_key) using HKDF-SHA256 from a pre-shared key.
    """
    if isinstance(psk, str):
        psk = psk.encode("utf-8")

    hkdf_c2s = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"psitunnel-client-to-server",
    )
    c2s_key = hkdf_c2s.derive(psk)

    hkdf_s2c = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"psitunnel-server-to-client",
    )
    s2c_key = hkdf_s2c.derive(psk)

    return c2s_key, s2c_key


def generate_handshake_auth(psk: str | bytes, salt: bytes) -> bytes:
    """
    Generates an authenticated handshake token containing timestamp + magic bytes,
    encrypted with the derived client-to-server key.
    """
    c2s_key, _ = derive_keys(psk, salt)
    aead = ChaCha20Poly1305(c2s_key)
    # 8-byte unix timestamp + magic string + random padding
    ts = int(time.time())
    payload = struct.pack(">Q", ts) + TunnelCryptoSession.MAGIC_AUTH + os.urandom(16)
    nonce = b"\x00" * 12
    return aead.encrypt(nonce, payload, None)


def verify_handshake_auth(psk: str | bytes, salt: bytes, auth_tag_and_ciphertext: bytes, max_skew_sec: int = 120) -> bool:
    """
    Verifies that the handshake token matches the PSK and is within the allowed clock skew window.
    """
    try:
        c2s_key, _ = derive_keys(psk, salt)
        aead = ChaCha20Poly1305(c2s_key)
        nonce = b"\x00" * 12
        plaintext = aead.decrypt(nonce, auth_tag_and_ciphertext, None)
        if len(plaintext) < 8 + len(TunnelCryptoSession.MAGIC_AUTH):
            return False
        ts, magic = struct.unpack(f">Q{len(TunnelCryptoSession.MAGIC_AUTH)}s", plaintext[:8 + len(TunnelCryptoSession.MAGIC_AUTH)])
        if magic != TunnelCryptoSession.MAGIC_AUTH:
            return False
        current_ts = int(time.time())
        if abs(current_ts - ts) > max_skew_sec:
            return False
        return True
    except Exception:
        return False

