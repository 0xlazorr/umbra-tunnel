# Umbra Tunnel

A high-performance, DPI-resistant covert TCP tunneling and traffic obfuscation engine designed for penetration testers, security researchers, and privacy advocates.

```
[ Local Client App ] 
         │ (Plaintext TCP)
         ▼
[ Umbra Client ] ──── (DPI-Obfuscated + AEAD Encrypted Tunnel) ────► [ Umbra Server ]
                                                                            │ (Plaintext TCP)
                                                                            ▼
                                                                   [ Target Internal Service ]
```

---

## Architecture & Security Model

* **Explicit Finite State Machines (FSM):** All session lifecycles, connection handshakes, and wire frame parsing are governed by formal, typed FSMs (`TunnelSessionFSM`, `FrameParserFSM`), eliminating implicit boolean race conditions, memory desynchronization, and partial connection hangs.
* **Forward-Secure Ephemeral Keying:** While sessions authenticate using a pre-shared master key (PBKDF2-HMAC-SHA256), each TCP connection negotiates fresh 128-bit random nonces to derive an ephemeral 256-bit symmetric session key (`derive_session_key`). Compromise of historical traffic is impossible even if subsequent keys are exposed.
* **Authenticated Symmetric Framing:** Every frame is authenticated with an HMAC-SHA256 signature and encrypted with a CTR-mode keystream cipher. Any byte tampering or unauthorized injection drops immediately with zero payload leakage.
* **Deep Packet Inspection (DPI) Obfuscation:** Incorporates synthetic TLS 1.3 record framing (`\x16\x03\x01`) and randomized timing jitter, disguising covert tunneling traffic as standard HTTPS web traffic to bypass DPI firewalls.
* **Privacy by Design & Memory Zeroization:** Plaintext buffers and sensitive ephemeral keys are actively zeroized in memory upon session teardown. All logging outputs are sanitized using truncated SHA-256 fingerprints—never printing sensitive payloads or credentials.
* **Zero External Dependencies:** Built entirely with Python 3's native standard library (`asyncio`, `hashlib`, `hmac`, `secrets`).

---

## Quick Start

### 1. Generate a Pre-Shared Key
```bash
python3 cli.py keygen
```

### 2. Start the Remote Umbra Server
Forward incoming encrypted tunnel traffic to an internal service (e.g. internal web app on port 80 or SSH on port 22):
```bash
python3 cli.py server \
  --bind 0.0.0.0 \
  --port 8443 \
  --target-host 127.0.0.1 \
  --target-port 22 \
  --key "<YOUR_PRE_SHARED_KEY>"
```

### 3. Start the Local Umbra Client
Expose a local port (e.g. 2222) that tunnels transparently to the remote service:
```bash
python3 cli.py client \
  --listen-host 127.0.0.1 \
  --listen-port 2222 \
  --server-host <REMOTE_SERVER_IP> \
  --server-port 8443 \
  --key "<YOUR_PRE_SHARED_KEY>"
```

Now connect locally to `127.0.0.1:2222`:
```bash
ssh -p 2222 user@127.0.0.1
```

---

## Running Self-Tests
Verify cryptographic integrity, replay protection, and FSM transitions:
```bash
python3 cli.py test
python3 -m unittest discover -s tests
```

---

## License
MIT License. Created by [0xlazorr](https://github.com/0xlazorr).
