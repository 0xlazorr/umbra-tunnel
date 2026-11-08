"""
Protocol Specification and DPI Obfuscation Envelope for Umbra Tunnel.
"""

import os
import struct
from typing import Tuple

FRAME_HANDSHAKE_INIT = 1
FRAME_HANDSHAKE_RESP = 2
FRAME_DATA = 3
FRAME_HEARTBEAT = 4
FRAME_DISCONNECT = 5

# Synthetic TLS 1.3 ClientHello prefix (22 03 01 - ContentType Handshake, TLS 1.0 record legacy version)
TLS_RECORD_MAGIC = b"\x16\x03\x01"


def wrap_obfuscated_envelope(data: bytes, enable_tls_mimic: bool = True) -> bytes:
    """
    Wrap an Umbra packet with synthetic TLS record framing to bypass basic DPI heuristics.
    Format:
    [0..3] TLS record magic (3B)
    [3..5] Length (2B big-endian)
    [5..]  Data
    """
    if not enable_tls_mimic:
        return data

    length = len(data)
    if length > 65535:
        return data

    return TLS_RECORD_MAGIC + struct.pack("!H", length) + data


def unwrap_obfuscated_envelope(stream_buffer: bytearray) -> Tuple[bytes, int]:
    """
    Check if incoming stream buffer has a TLS envelope, and unwrap.
    Returns (unwrapped_bytes, consumed_bytes).
    If incomplete, returns (b"", 0).
    """
    if len(stream_buffer) < 5:
        return b"", 0

    if stream_buffer[:3] == TLS_RECORD_MAGIC:
        length = struct.unpack("!H", stream_buffer[3:5])[0]
        total_len = 5 + length
        if len(stream_buffer) < total_len:
            return b"", 0  # Incomplete frame
        payload = bytes(stream_buffer[5:total_len])
        return payload, total_len

    # If raw Umbra protocol without TLS envelope
    if stream_buffer[:4] == b"UMBR":
        if len(stream_buffer) < 17:
            return b"", 0
        payload_len = struct.unpack("!I", stream_buffer[13:17])[0]
        total_len = 65 + payload_len
        if len(stream_buffer) < total_len:
            return b"", 0
        payload = bytes(stream_buffer[:total_len])
        return payload, total_len

    return b"", 0
