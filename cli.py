#!/usr/bin/env python3
"""
Umbra Tunnel CLI - Command Line Interface for Covert Tunneling & Obfuscation.
"""

import argparse
import asyncio
import os
import secrets
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from umbra import UmbraServer, UmbraClient
from umbra.crypto import derive_master_key, derive_session_key, seal_frame, open_frame, sanitize_fingerprint


def cmd_keygen(args):
    key = secrets.token_hex(32)
    print("=" * 60)
    print("Generated Umbra Pre-Shared Key (256-bit):")
    print(f"  {key}")
    print("=" * 60)
    print("Share this key securely between your client and server.")


def cmd_server(args):
    server = UmbraServer(
        bind_host=args.bind,
        bind_port=args.port,
        target_host=args.target_host,
        target_port=args.target_port,
        pre_shared_key=args.key,
        enable_tls_mimic=not args.disable_mimic,
    )

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(server.start())
        print("[*] Server running. Press Ctrl+C to stop.")
        loop.run_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping server...")
    finally:
        loop.run_until_complete(server.stop())


def cmd_client(args):
    client = UmbraClient(
        local_listen_host=args.listen_host,
        local_listen_port=args.listen_port,
        server_host=args.server_host,
        server_port=args.server_port,
        pre_shared_key=args.key,
        enable_tls_mimic=not args.disable_mimic,
    )

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(client.start())
        print("[*] Client running. Press Ctrl+C to stop.")
        loop.run_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping client...")
    finally:
        loop.run_until_complete(client.stop())


def cmd_test(args):
    print("[*] Running Umbra Cryptographic & Protocol Self-Test...")
    psk = secrets.token_hex(32)
    master_key = derive_master_key(psk)
    c_nonce = os.urandom(16)
    s_nonce = os.urandom(16)
    session_key = derive_session_key(master_key, c_nonce, s_nonce)

    test_payload = b"GET /admin/shell HTTP/1.1\r\nHost: internal.corp\r\n\r\n"
    sealed = seal_frame(session_key, 3, test_payload)
    ftype, decrypted, err = open_frame(session_key, sealed)

    assert err is None, f"Decryption failed: {err}"
    assert ftype == 3, f"Unexpected frame type: {ftype}"
    assert decrypted == test_payload, "Payload mismatch"

    print(f"[+] Symmetric Authenticated Encryption: PASS (fingerprint: {sanitize_fingerprint(session_key)})")
    print("[+] All self-tests passed cleanly!")


def main():
    parser = argparse.ArgumentParser(
        description="Umbra Tunnel - DPI-Resistant Covert Tunneling & Traffic Obfuscation Engine"
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # Keygen
    subparsers.add_parser("keygen", help="Generate a secure 256-bit pre-shared key")

    # Test
    subparsers.add_parser("test", help="Run cryptographic and framing self-test")

    # Server
    sp_server = subparsers.add_parser("server", help="Start Umbra Tunnel Server")
    sp_server.add_argument("--bind", default="0.0.0.0", help="Tunnel bind address (default: 0.0.0.0)")
    sp_server.add_argument("--port", type=int, default=8443, help="Tunnel bind port (default: 8443)")
    sp_server.add_argument("--target-host", default="127.0.0.1", help="Target host to forward to (default: 127.0.0.1)")
    sp_server.add_argument("--target-port", type=int, required=True, help="Target port to forward to")
    sp_server.add_argument("--key", required=True, help="Pre-shared key")
    sp_server.add_argument("--disable-mimic", action="store_true", help="Disable synthetic TLS record framing")

    # Client
    sp_client = subparsers.add_parser("client", help="Start Umbra Tunnel Client")
    sp_client.add_argument("--listen-host", default="127.0.0.1", help="Local listen address (default: 127.0.0.1)")
    sp_client.add_argument("--listen-port", type=int, default=1080, help="Local listen port (default: 1080)")
    sp_client.add_argument("--server-host", required=True, help="Remote Umbra Server address")
    sp_client.add_argument("--server-port", type=int, default=8443, help="Remote Umbra Server port (default: 8443)")
    sp_client.add_argument("--key", required=True, help="Pre-shared key")
    sp_client.add_argument("--disable-mimic", action="store_true", help="Disable synthetic TLS record framing")

    args = parser.parse_args()

    if args.subcommand == "keygen":
        cmd_keygen(args)
    elif args.subcommand == "test":
        cmd_test(args)
    elif args.subcommand == "server":
        cmd_server(args)
    elif args.subcommand == "client":
        cmd_client(args)


if __name__ == "__main__":
    main()
