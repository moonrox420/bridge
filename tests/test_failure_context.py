"""Tests for structured failure context, traceback parsing, and policy-gated source previews."""

import json
import unittest
from pathlib import Path

from terminal_bridge import (
    BridgeState,
    MCPToolRegistry,
    _extract_traceback_locations,
    _resolve_snippet_for_location,
    build_context_snapshot,
)


class TestFailureContextExtraction(unittest.TestCase):
    """Verifies traceback parsing and file snippet extraction."""

    def test_extract_traceback_locations(self) -> None:
        sample_tb = (
            "Traceback (most recent call last):\n"
            '  File "C:\\Users\\droxa\\bridge\\terminal_bridge.py", line 42, in <module>\n'
            "    raise RuntimeError('boom')\n"
            "tests/test_sse.py:15: AssertionError\n"
        )
        locations = _extract_traceback_locations(sample_tb)
        self.assertGreaterEqual(len(locations), 2)
        paths = [p for p, _ in locations]
        self.assertTrue(any("terminal_bridge.py" in p for p in paths))
        self.assertTrue(any("test_sse.py" in p for p in paths))

    def test_policy_gated_snippet_blocking(self) -> None:
        # Sensitive files like .env or keys must be blocked
        res_env = _resolve_snippet_for_location(".env", "1", include_snippets=True)
        self.assertTrue(res_env.get("policy_blocked"))
        self.assertNotIn("snippet", res_env)

        res_key = _resolve_snippet_for_location("id_rsa", "10", include_snippets=True)
        self.assertTrue(res_key.get("policy_blocked"))

    def test_valid_file_snippet_reading(self) -> None:
        # terminal_bridge.py is allowed and exists
        target = str(Path(__file__).resolve().parent.parent / "terminal_bridge.py")
        res = _resolve_snippet_for_location(target, "10", include_snippets=True)
        self.assertFalse(res.get("policy_blocked", False))
        self.assertIn("snippet", res)
        self.assertIsInstance(res["snippet"], list)
        self.assertGreater(len(res["snippet"]), 0)


class TestFailureContextTracker(unittest.TestCase):
    """Verifies FailureContextTracker lifecycle and MCP tool integration."""

    def setUp(self) -> None:
        self.state = BridgeState(allow_control=False, token=None, shell="powershell")
        self.registry = MCPToolRegistry(self.state)

    def test_mcp_get_last_error_empty_state(self) -> None:
        res = self.registry.call_tool("get_last_error", {})
        self.assertFalse(res["isError"])
        data = json.loads(res["content"][0]["text"])
        self.assertEqual(data.get("status"), "no_errors_recorded")

    def test_mcp_get_last_error_after_failure(self) -> None:
        tb_sample = (
            "Traceback (most recent call last):\n"
            '  File "terminal_bridge.py", line 25, in test_fn\n'
            "ValueError: simulated test failure\n"
        )
        # Emitting shell_error triggers automatic recording via on_event_callback
        self.state.events.add("shell_error", tb_sample, "shell")

        res = self.registry.call_tool("get_last_error", {"include_snippets": True})
        self.assertFalse(res["isError"])
        data = json.loads(res["content"][0]["text"])

        self.assertEqual(data["event_type"], "shell_error")
        self.assertIn("related_files", data)
        self.assertGreater(len(data["related_files"]), 0)

        # Snapshot reflects the error
        snap = build_context_snapshot(self.state)
        self.assertIsNotNone(snap.get("last_error"))
        self.assertEqual(snap["last_error"]["event_type"], "shell_error")


if __name__ == "__main__":
    unittest.main()
