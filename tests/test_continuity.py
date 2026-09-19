"""Tests for formal continuity loop, gap detection, and state resynchronization."""

import json
import unittest

from terminal_bridge import (
    BridgeState,
    EventStore,
    MCPToolRegistry,
    build_context_snapshot,
)


class TestContinuityLoop(unittest.TestCase):
    """Verifies the formal continuity contract: Snapshot -> cursor N -> delta events -> gap detection -> resync."""

    def setUp(self) -> None:
        self.state = BridgeState(
            allow_control=False,
            token=None,
            shell="powershell",
        )
        self.registry = MCPToolRegistry(self.state)

    def test_nominal_snapshot_and_delta_consumption(self) -> None:
        # 1. Establish initial baseline
        for i in range(5):
            self.state.events.add("terminal_output", f"init_{i}")

        snapshot = build_context_snapshot(self.state)
        cursor = snapshot["latest_event_id"]
        self.assertEqual(cursor, 5)

        # 2. Add new delta events
        for i in range(5, 8):
            self.state.events.add("terminal_output", f"delta_{i}")

        # 3. Pull delta since cursor
        delta_events = self.state.events.get_since(event_id=cursor)
        gap_detected, _ = self.state.events.check_gap(cursor)
        self.assertFalse(gap_detected)
        self.assertEqual(len(delta_events), 3)
        self.assertEqual(self.state.events.sequence, 8)
        self.assertEqual(delta_events[0]["data"], "delta_5")

    def test_buffer_overwrite_gap_detection(self) -> None:
        store = EventStore(maximum=10)
        # Add 25 events to force ring buffer eviction
        for i in range(1, 26):
            store.add("terminal_output", f"event_{i}")

        # Client requests since event #3 (which has been overwritten)
        gap_detected, oldest_id = store.check_gap(client_cursor=3)
        self.assertTrue(gap_detected)
        self.assertEqual(oldest_id, 16)
        self.assertEqual(store.sequence, 25)

    def test_mcp_gap_recovery_flow(self) -> None:
        # 1. Start with limited buffer
        self.state.events = EventStore(maximum=10)
        self.registry = MCPToolRegistry(self.state)

        # 2. Call MCP get_context_snapshot to establish baseline
        snap_res = self.registry.call_tool("get_context_snapshot", {})
        self.assertFalse(snap_res["isError"])
        snap_data = json.loads(snap_res["content"][0]["text"])
        initial_cursor = snap_data["latest_event_id"]

        # 3. Add enough events to blow past buffer capacity (15 events)
        for i in range(1, 16):
            self.state.events.add("terminal_output", f"entry_{i}")

        # 4. Request delta using stale initial_cursor (0)
        events_res = self.registry.call_tool("get_events", {"since": 1})
        self.assertFalse(events_res["isError"])
        events_data = json.loads(events_res["content"][0]["text"])

        # 5. Verify gap detected and resync recommended
        self.assertTrue(events_data["gap_detected"])
        self.assertEqual(events_data["recommended_action"], "get_context_snapshot")
        self.assertEqual(events_data["oldest_available"], 6)

        # 6. Perform recovery resync via snapshot
        resync_res = self.registry.call_tool("get_context_snapshot", {})
        self.assertFalse(resync_res["isError"])
        resync_data = json.loads(resync_res["content"][0]["text"])
        new_cursor = resync_data["latest_event_id"]
        self.assertEqual(new_cursor, 15)

        # 7. Resume delta stream cleanly from new_cursor
        self.state.events.add("terminal_output", "entry_16")
        resume_res = self.registry.call_tool("get_events", {"since": new_cursor})
        self.assertFalse(resume_res["isError"])
        resume_data = json.loads(resume_res["content"][0]["text"])
        self.assertFalse(resume_data["gap_detected"])
        self.assertEqual(len(resume_data["events"]), 1)
        self.assertEqual(resume_data["events"][0]["data"], "entry_16")


if __name__ == "__main__":
    unittest.main()
