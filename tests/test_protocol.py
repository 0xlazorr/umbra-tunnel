"""
Unit tests for Umbra Protocol Framing and Obfuscator.
"""

import unittest
from umbra.protocol import wrap_obfuscated_envelope, unwrap_obfuscated_envelope


class TestUmbraProtocol(unittest.TestCase):
    def test_obfuscation_wrap_unwrap(self):
        data = b"UMBR\x01\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x04" + b"A" * 16 + b"B" * 32 + b"TEST"
        wrapped = wrap_obfuscated_envelope(data, enable_tls_mimic=True)

        self.assertTrue(wrapped.startswith(b"\x16\x03\x01"))

        buf = bytearray(wrapped)
        unwrapped, consumed = unwrap_obfuscated_envelope(buf)

        self.assertEqual(consumed, len(wrapped))
        self.assertEqual(unwrapped, data)


if __name__ == "__main__":
    unittest.main()
