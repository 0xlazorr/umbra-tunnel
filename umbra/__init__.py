"""
Umbra Tunnel - High-Performance DPI-Resistant Covert Tunneling & Traffic Obfuscation Engine.
"""

__version__ = "1.0.0"

from .fsm import TunnelSessionFSM, FrameParserFSM, SessionState
from .crypto import derive_master_key, derive_session_key, seal_frame, open_frame
from .tunnel import UmbraServer, UmbraClient
