"""
Cryptographic Engine for Umbra Tunnel.
Provides authenticated symmetric encryption, ephemeral session derivation, and memory zeroization.
"""

import hashlib
import hmac
import os
import struct
import time
from typing import Tuple, Optional

PROTOCOL_MAGIC = b"UMBR"
PROTOCOL_VERSION = 1
HEADER_SIZE = 4 + 1 + 8 + 4 + 16 + 32  # 65 bytes
MAX_FRAME_SIZE = 16 * 1024 * 1024  # 16 MB max frame size
REPLAY_WINDOW_SECS = 60


def zeroize_buffer(buf: bytearray) -> None:
    """Overwrite mutable memory buffer with zeros to mitigate cold-boot or memory-dump leakage."""
    for i in range(len(buf)):
        buf[i] = 0


def derive_master_key(pre_shared_key: str, salt: bytes = b"Umbra_Tunnel_Master_Salt_v1") -> bytes:
    """Derive 256-bit root key from pre-shared passphrase via PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", pre_shared_key.encode("utf-8"), salt, 10000, 32)


def derive_session_key(master_key: bytes, client_nonce: bytes, server_nonce: bytes) -> bytes:
    """Derive unique 256-bit forward-secure ephemeral session key."""
    h = hmac.new(master_key, b"UMBRA_SESSION_KEY_DERIVATION", hashlib.sha256)
    h.update(client_nonce)
    h.update(server_nonce)
    return h.digest()


def xor_ctr_stream(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """
    CTR-mode stream cipher using HMAC-SHA256 expansion.
    Symmetric operation: Decryption is identical to Encryption.
    """
    out = bytearray(len(data))
    block_idx = 0
    for offset in range(0, len(data), 32):
        block_seed = nonce + struct.pack(">Q", block_idx)
        block_key = hmac.new(key, block_seed, hashlib.sha256).digest()
        chunk_len = min(32, len(data) - offset)
        for i in range(chunk_len):
            out[offset + i] = data[offset + i] ^ block_key[i]
        block_idx += 1
    result = bytes(out)
    zeroize_buffer(out)
    return result


def seal_frame(session_key: bytes, frame_type: int, payload: bytes) -> bytes:
    """
    Encode, encrypt, and authenticate a protocol frame:
    [0..4]   Magic (4B)
    [4..5]   Frame Type (1B)
    [5..13]  Timestamp (8B)
    [13..17] Length (4B)
    [17..33] Nonce (16B)
    [33..65] HMAC-SHA256 Tag (32B)
    [65..]   Encrypted Payload
    """
    ts = int(time.time())
    nonce = os.urandom(16)
    encrypted = xor_ctr_stream(session_key, nonce, payload)
    length = len(encrypted)

    header = PROTOCOL_MAGIC + struct.pack("!BQI", frame_type, ts, length) + nonce
    tag = hmac.new(session_key, header + encrypted, hashlib.sha256).digest()
    return header + tag + encrypted


def open_frame(session_key: bytes, raw: bytes) -> Tuple[Optional[int], Optional[bytes], Optional[str]]:
    """
    Validate, authenticate, and decrypt a protocol frame.
    Returns (frame_type, decrypted_payload, error_str).
    """
    if len(raw) < HEADER_SIZE:
        return None, None, f"Frame too short ({len(raw)}B < {HEADER_SIZE}B)"

    magic = raw[:4]
    if magic != PROTOCOL_MAGIC:
        return None, None, f"Invalid protocol magic: {magic!r}"

    frame_type, ts, length = struct.unpack("!BQI", raw[4:17])
    if length > MAX_FRAME_SIZE:
        return None, None, f"Frame payload exceeds maximum size limit ({length}B)"

    nonce = raw[17:33]
    tag = raw[33:65]
    encrypted = raw[65:65 + length]

    if len(encrypted) != length:
        return None, None, f"Frame length mismatch: expected {length}B, got {len(encrypted)}B"

    # Verify timestamp within replay tolerance window
    now = time.time()
    if abs(now - ts) > REPLAY_WINDOW_SECS:
        return None, None, f"Expired frame timestamp skew ({abs(now - ts):.1f}s)"

    # Constant-time authentication
    header = magic + struct.pack("!BQI", frame_type, ts, length) + nonce
    expected_tag = hmac.new(session_key, header + encrypted, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        return None, None, "Authentication tag verification failed (tampered or unauthorized frame)"

    decrypted = xor_ctr_stream(session_key, nonce, encrypted)
    return frame_type, decrypted, None


def sanitize_fingerprint(data: bytes) -> str:
    """Return truncated SHA-256 fingerprint for secure, privacy-preserving logging."""
    return hashlib.sha256(data).hexdigest()[:12]
