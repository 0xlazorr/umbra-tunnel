"""
Unit tests for Umbra FSM state machines.
"""

import unittest
from umbra.fsm import (
    TunnelSessionFSM,
    SessionState,
    FrameParserFSM,
    FrameParserState,
    StateTransitionError,
)


class TestTunnelSessionFSM(unittest.TestCase):
    def test_initial_state(self):
        fsm = TunnelSessionFSM("test-sess")
        self.assertEqual(fsm.current_state, SessionState.INITIALIZING)

    def test_valid_lifecycle(self):
        fsm = TunnelSessionFSM("test-sess")
        fsm.transition_to(SessionState.HANDSHAKING)
        self.assertEqual(fsm.current_state, SessionState.HANDSHAKING)

        fsm.transition_to(SessionState.ESTABLISHED)
        self.assertEqual(fsm.current_state, SessionState.ESTABLISHED)

        fsm.transition_to(SessionState.DRAINING)
        self.assertEqual(fsm.current_state, SessionState.DRAINING)

        fsm.transition_to(SessionState.TERMINATED)
        self.assertEqual(fsm.current_state, SessionState.TERMINATED)

    def test_invalid_transition(self):
        fsm = TunnelSessionFSM("test-sess")
        with self.assertRaises(StateTransitionError):
            fsm.transition_to(SessionState.DRAINING)


class TestFrameParserFSM(unittest.TestCase):
    def test_frame_parser_lifecycle(self):
        fsm = FrameParserFSM()
        self.assertEqual(fsm.current_state, FrameParserState.AWAITING_HEADER)

        fsm.transition_to(FrameParserState.VALIDATING_TAG)
        self.assertEqual(fsm.current_state, FrameParserState.VALIDATING_TAG)

        fsm.transition_to(FrameParserState.DECRYPTING_BODY)
        self.assertEqual(fsm.current_state, FrameParserState.DECRYPTING_BODY)

        fsm.transition_to(FrameParserState.DISPATCHING)
        self.assertEqual(fsm.current_state, FrameParserState.DISPATCHING)

        fsm.transition_to(FrameParserState.AWAITING_HEADER)
        self.assertEqual(fsm.current_state, FrameParserState.AWAITING_HEADER)


if __name__ == "__main__":
    unittest.main()
