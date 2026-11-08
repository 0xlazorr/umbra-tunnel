"""
Explicit Finite State Machine (FSM) Engine for Umbra Tunnel.
Guarantees deterministic lifecycle transitions, preventing race conditions and desync.
"""

from enum import Enum
from typing import Set, Dict, Optional


class StateTransitionError(Exception):
    """Raised when an illegal FSM state transition is attempted."""
    pass


class SessionState(Enum):
    INITIALIZING = "INITIALIZING"
    HANDSHAKING = "HANDSHAKING"
    ESTABLISHED = "ESTABLISHED"
    REKEYING = "REKEYING"
    DRAINING = "DRAINING"
    TERMINATED = "TERMINATED"


class FrameParserState(Enum):
    AWAITING_HEADER = "AWAITING_HEADER"
    VALIDATING_TAG = "VALIDATING_TAG"
    DECRYPTING_BODY = "DECRYPTING_BODY"
    DISPATCHING = "DISPATCHING"
    ERROR = "ERROR"


class ObfuscationState(Enum):
    CLEARTEXT_PADDING = "CLEARTEXT_PADDING"
    OBFUSCATED_STREAM = "OBFUSCATED_STREAM"
    JITTER_WINDOW = "JITTER_WINDOW"
    TERMINATING = "TERMINATING"


class TunnelSessionFSM:
    """Explicit FSM governing end-to-end tunnel session lifecycles."""

    _VALID_TRANSITIONS: Dict[SessionState, Set[SessionState]] = {
        SessionState.INITIALIZING: {
            SessionState.HANDSHAKING,
            SessionState.TERMINATED,
        },
        SessionState.HANDSHAKING: {
            SessionState.ESTABLISHED,
            SessionState.TERMINATED,
        },
        SessionState.ESTABLISHED: {
            SessionState.REKEYING,
            SessionState.DRAINING,
            SessionState.TERMINATED,
        },
        SessionState.REKEYING: {
            SessionState.ESTABLISHED,
            SessionState.DRAINING,
            SessionState.TERMINATED,
        },
        SessionState.DRAINING: {
            SessionState.TERMINATED,
        },
        SessionState.TERMINATED: set(),
    }

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._state = SessionState.INITIALIZING
        self._previous_state: Optional[SessionState] = None

    @property
    def current_state(self) -> SessionState:
        return self._state

    @property
    def previous_state(self) -> Optional[SessionState]:
        return self._previous_state

    def transition_to(self, target_state: SessionState, reason: str = "") -> None:
        if target_state == self._state:
            return
        allowed = self._VALID_TRANSITIONS.get(self._state, set())
        if target_state not in allowed:
            raise StateTransitionError(
                f"Session [{self.session_id}] illegal transition from {self._state.value} to {target_state.value} ({reason})"
            )
        self._previous_state = self._state
        self._state = target_state


class FrameParserFSM:
    """Explicit FSM governing per-frame wire parsing and authentication."""

    _VALID_TRANSITIONS: Dict[FrameParserState, Set[FrameParserState]] = {
        FrameParserState.AWAITING_HEADER: {
            FrameParserState.VALIDATING_TAG,
            FrameParserState.ERROR,
        },
        FrameParserState.VALIDATING_TAG: {
            FrameParserState.DECRYPTING_BODY,
            FrameParserState.ERROR,
        },
        FrameParserState.DECRYPTING_BODY: {
            FrameParserState.DISPATCHING,
            FrameParserState.ERROR,
        },
        FrameParserState.DISPATCHING: {
            FrameParserState.AWAITING_HEADER,
            FrameParserState.ERROR,
        },
        FrameParserState.ERROR: {
            FrameParserState.AWAITING_HEADER,
        },
    }

    def __init__(self):
        self._state = FrameParserState.AWAITING_HEADER

    @property
    def current_state(self) -> FrameParserState:
        return self._state

    def transition_to(self, target_state: FrameParserState) -> None:
        if target_state == self._state:
            return
        allowed = self._VALID_TRANSITIONS.get(self._state, set())
        if target_state not in allowed:
            raise StateTransitionError(
                f"FrameParser illegal transition from {self._state.value} to {target_state.value}"
            )
        self._state = target_state

    def reset(self) -> None:
        self._state = FrameParserState.AWAITING_HEADER
