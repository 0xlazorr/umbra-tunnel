"""
Unit tests for Umbra Cryptographic Engine.
"""

import os
import unittest
from umbra.crypto import (
    derive_master_key,
    derive_session_key,
    seal_frame,
    open_frame,
    zeroize_buffer,
    sanitize_fingerprint,
)


class TestUmbraCrypto(unittest.TestCase):
    def setUp(self):
        self.psk = "super_secure_umbra_psk_99812739"
        self.master_key = derive_master_key(self.psk)
        self.c_nonce = os.urandom(16)
        self.s_nonce = os.urandom(16)
        self.session_key = derive_session_key(self.master_key, self.c_nonce, self.s_nonce)

    def test_seal_and_open_roundtrip(self):
        payload = b"SECRET_PAYLOAD_TUNNEL_DATA_12345"
        sealed = seal_frame(self.session_key, 3, payload)
        ftype, decrypted, err = open_frame(self.session_key, sealed)

        self.assertIsNone(err)
        self.assertEqual(ftype, 3)
        self.assertEqual(decrypted, payload)

    def test_tamper_detection(self):
        payload = b"AUTHENTICATED_TRANSACTION"
        sealed = bytearray(seal_frame(self.session_key, 3, payload))

        # Tamper with 1 byte in payload
        sealed[-1] ^= 0xFF

        ftype, decrypted, err = open_frame(self.session_key, bytes(sealed))
        self.assertIsNotNone(err)
        self.assertIn("Authentication tag verification failed", err)

    def test_zeroize_buffer(self):
        buf = bytearray(b"SENSITIVE_SECRET_DATA")
        zeroize_buffer(buf)
        self.assertTrue(all(b == 0 for b in buf))


if __name__ == "__main__":
    unittest.main()
