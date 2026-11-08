"""
Asyncio Tunnel Engine for Umbra Tunnel.
Handles full-duplex proxying, ephemeral session negotiation, and strict FSM lifecycle enforcement.
"""

import asyncio
import logging
import os
import uuid
from typing import Optional

from .fsm import TunnelSessionFSM, SessionState
from .crypto import (
    derive_master_key,
    derive_session_key,
    seal_frame,
    open_frame,
    sanitize_fingerprint,
    zeroize_buffer,
    HEADER_SIZE,
)
from .protocol import (
    FRAME_HANDSHAKE_INIT,
    FRAME_HANDSHAKE_RESP,
    FRAME_DATA,
    FRAME_DISCONNECT,
    wrap_obfuscated_envelope,
    unwrap_obfuscated_envelope,
)

logger = logging.getLogger("umbra.tunnel")


class UmbraServer:
    """Server that terminates encrypted tunnels and forwards plaintext to local target service."""

    def __init__(
        self,
        bind_host: str,
        bind_port: int,
        target_host: str,
        target_port: int,
        pre_shared_key: str,
        enable_tls_mimic: bool = True,
    ):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.target_host = target_host
        self.target_port = target_port
        self.master_key = derive_master_key(pre_shared_key)
        self.enable_tls_mimic = enable_tls_mimic
        self._server: Optional[asyncio.Server] = None
        self.active_sessions = set()

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_client, self.bind_host, self.bind_port
        )
        print(f"[+] Umbra Server active on {self.bind_host}:{self.bind_port}")
        print(f"[+] Forwarding decrypted traffic to {self.target_host}:{self.target_port}")

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            print("[*] Umbra Server stopped.")

    async def _handle_client(
        self, tunnel_reader: asyncio.StreamReader, tunnel_writer: asyncio.StreamWriter
    ):
        session_id = str(uuid.uuid4())[:8]
        fsm = TunnelSessionFSM(session_id)
        fsm.transition_to(SessionState.HANDSHAKING, "Inbound tunnel connection")

        session_key_buf = bytearray(32)
        target_writer = None

        try:
            # 1. Handshake Phase
            # Read Handshake Init from client
            raw_init = await tunnel_reader.read(4096)
            if not raw_init:
                return

            buf = bytearray(raw_init)
            unwrapped, consumed = unwrap_obfuscated_envelope(buf)
            if not unwrapped:
                return

            frame_type, client_nonce, err = open_frame(self.master_key, unwrapped)
            if err or frame_type != FRAME_HANDSHAKE_INIT or len(client_nonce) != 16:
                logger.warning(f"[{session_id}] Handshake init rejected: {err}")
                return

            # Generate server nonce and derive ephemeral session key
            server_nonce = os.urandom(16)
            session_key = derive_session_key(self.master_key, client_nonce, server_nonce)
            session_key_buf[:] = session_key

            # Reply with Handshake Response (using session key)
            resp_frame = seal_frame(session_key, FRAME_HANDSHAKE_RESP, server_nonce)
            tunnel_writer.write(wrap_obfuscated_envelope(resp_frame, self.enable_tls_mimic))
            await tunnel_writer.drain()

            fsm.transition_to(SessionState.ESTABLISHED, "Handshake completed")
            print(f"[+] Tunnel session [{session_id}] established (fingerprint: {sanitize_fingerprint(session_key)})")

            # 2. Connect to local target service
            try:
                target_reader, target_writer = await asyncio.open_connection(
                    self.target_host, self.target_port
                )
            except Exception as e:
                logger.error(f"[{session_id}] Failed to connect to target {self.target_host}:{self.target_port}: {e}")
                return

            # 3. Bi-Directional Full-Duplex Forwarding
            async def tunnel_to_target():
                stream_buf = bytearray()
                while fsm.current_state == SessionState.ESTABLISHED:
                    chunk = await tunnel_reader.read(16384)
                    if not chunk:
                        break
                    stream_buf.extend(chunk)

                    while True:
                        payload, n_consumed = unwrap_obfuscated_envelope(stream_buf)
                        if n_consumed == 0:
                            break
                        stream_buf = stream_buf[n_consumed:]

                        ftype, data, ferr = open_frame(session_key, payload)
                        if ferr:
                            logger.warning(f"[{session_id}] Corrupt frame: {ferr}")
                            break
                        if ftype == FRAME_DATA and data:
                            target_writer.write(data)
                            await target_writer.drain()
                        elif ftype == FRAME_DISCONNECT:
                            return

            async def target_to_tunnel():
                while fsm.current_state == SessionState.ESTABLISHED:
                    data = await target_reader.read(16384)
                    if not data:
                        break
                    frame = seal_frame(session_key, FRAME_DATA, data)
                    tunnel_writer.write(wrap_obfuscated_envelope(frame, self.enable_tls_mimic))
                    await tunnel_writer.drain()

            await asyncio.gather(tunnel_to_target(), target_to_tunnel())

        except Exception as e:
            logger.debug(f"[{session_id}] Session error: {e}")
        finally:
            try:
                fsm.transition_to(SessionState.TERMINATED, "Closing session")
            except Exception:
                pass

            if target_writer:
                try:
                    target_writer.close()
                    await target_writer.wait_closed()
                except Exception:
                    pass

            try:
                tunnel_writer.close()
                await tunnel_writer.wait_closed()
            except Exception:
                pass

            # Zeroize sensitive ephemeral session key
            zeroize_buffer(session_key_buf)
            print(f"[*] Tunnel session [{session_id}] terminated and memory zeroized.")


class UmbraClient:
    """Client that accepts local application connections and tunnels them to UmbraServer."""

    def __init__(
        self,
        local_listen_host: str,
        local_listen_port: int,
        server_host: str,
        server_port: int,
        pre_shared_key: str,
        enable_tls_mimic: bool = True,
    ):
        self.local_host = local_listen_host
        self.local_port = local_listen_port
        self.server_host = server_host
        self.server_port = server_port
        self.master_key = derive_master_key(pre_shared_key)
        self.enable_tls_mimic = enable_tls_mimic
        self._server: Optional[asyncio.Server] = None

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_local_app, self.local_host, self.local_port
        )
        print(f"[+] Umbra Client listening locally on {self.local_host}:{self.local_port}")
        print(f"[+] Tunneling encrypted traffic to Umbra Server at {self.server_host}:{self.server_port}")

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            print("[*] Umbra Client stopped.")

    async def _handle_local_app(
        self, app_reader: asyncio.StreamReader, app_writer: asyncio.StreamWriter
    ):
        session_id = str(uuid.uuid4())[:8]
        fsm = TunnelSessionFSM(session_id)
        fsm.transition_to(SessionState.HANDSHAKING, "Local app connected")

        session_key_buf = bytearray(32)
        tunnel_writer = None

        try:
            # 1. Connect to remote UmbraServer
            try:
                tunnel_reader, tunnel_writer = await asyncio.open_connection(
                    self.server_host, self.server_port
                )
            except Exception as e:
                logger.error(f"[{session_id}] Failed to connect to Umbra Server {self.server_host}:{self.server_port}: {e}")
                return

            # 2. Handshake Phase
            client_nonce = os.urandom(16)
            init_frame = seal_frame(self.master_key, FRAME_HANDSHAKE_INIT, client_nonce)
            tunnel_writer.write(wrap_obfuscated_envelope(init_frame, self.enable_tls_mimic))
            await tunnel_writer.drain()

            raw_resp = await tunnel_reader.read(4096)
            if not raw_resp:
                return

            buf = bytearray(raw_resp)
            unwrapped, _ = unwrap_obfuscated_envelope(buf)
            if not unwrapped:
                return

            # The server will have generated server_nonce
            # We first extract server_nonce by trying derivation or inspecting payload
            # In our protocol: session_key is derived from master_key + client_nonce + server_nonce
            # Let's derive session key by testing server nonce candidate:
            server_nonce_candidate = unwrapped[17:33]
            derived_key = derive_session_key(self.master_key, client_nonce, server_nonce_candidate)
            ftype, server_nonce_verified, err = open_frame(derived_key, unwrapped)

            if err or ftype != FRAME_HANDSHAKE_RESP or server_nonce_verified != server_nonce_candidate:
                logger.warning(f"[{session_id}] Server handshake rejected: {err}")
                return

            session_key = derived_key
            session_key_buf[:] = session_key

            fsm.transition_to(SessionState.ESTABLISHED, "Tunnel handshake verified")
            print(f"[+] Tunnel session [{session_id}] established (fingerprint: {sanitize_fingerprint(session_key)})")

            # 3. Bi-Directional Proxying
            async def app_to_tunnel():
                while fsm.current_state == SessionState.ESTABLISHED:
                    data = await app_reader.read(16384)
                    if not data:
                        break
                    frame = seal_frame(session_key, FRAME_DATA, data)
                    tunnel_writer.write(wrap_obfuscated_envelope(frame, self.enable_tls_mimic))
                    await tunnel_writer.drain()

            async def tunnel_to_app():
                stream_buf = bytearray()
                while fsm.current_state == SessionState.ESTABLISHED:
                    chunk = await tunnel_reader.read(16384)
                    if not chunk:
                        break
                    stream_buf.extend(chunk)

                    while True:
                        payload, n_consumed = unwrap_obfuscated_envelope(stream_buf)
                        if n_consumed == 0:
                            break
                        stream_buf = stream_buf[n_consumed:]

                        ftype, data, ferr = open_frame(session_key, payload)
                        if ferr:
                            break
                        if ftype == FRAME_DATA and data:
                            app_writer.write(data)
                            await app_writer.drain()
                        elif ftype == FRAME_DISCONNECT:
                            return

            await asyncio.gather(app_to_tunnel(), tunnel_to_app())

        except Exception as e:
            logger.debug(f"[{session_id}] Client session error: {e}")
        finally:
            try:
                fsm.transition_to(SessionState.TERMINATED, "Terminating client session")
            except Exception:
                pass

            if tunnel_writer:
                try:
                    tunnel_writer.close()
                    await tunnel_writer.wait_closed()
                except Exception:
                    pass

            try:
                app_writer.close()
                await app_writer.wait_closed()
            except Exception:
                pass

            zeroize_buffer(session_key_buf)
            print(f"[*] Client session [{session_id}] terminated and memory zeroized.")
