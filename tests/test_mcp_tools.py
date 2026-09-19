"""
Tests for MCPToolRegistry and tool execution primitives.
"""

import json
import unittest

from terminal_bridge import BridgeState, MCPToolRegistry


class TestMcpTools(unittest.TestCase):
    def test_catalog_visibility_read_only(self):
        state = BridgeState(allow_control=False, token=None, shell="powershell")
        registry = MCPToolRegistry(state)
        tools = registry.get_tools()
        names = [t["name"] for t in tools]
        self.assertEqual(len(names), 5)
        self.assertIn("get_context_snapshot", names)
        self.assertIn("get_events", names)
        self.assertIn("get_last_error", names)
        self.assertIn("read_file", names)
        self.assertIn("list_directory", names)
        self.assertNotIn("execute_command", names)

    def test_catalog_visibility_control_enabled(self):
        state = BridgeState(allow_control=True, token="tok", shell="powershell")
        registry = MCPToolRegistry(state)
        tools = registry.get_tools()
        names = [t["name"] for t in tools]
        self.assertEqual(len(names), 6)
        self.assertIn("execute_command", names)
        self.assertIn("get_last_error", names)

    def test_call_get_context_snapshot(self):
        state = BridgeState(allow_control=False, token=None, shell="powershell")
        registry = MCPToolRegistry(state)
        res = registry.call_tool(
            "get_context_snapshot", {"events_limit": 5, "tree_limit": 5}
        )
        self.assertFalse(res["isError"])
        data = json.loads(res["content"][0]["text"])
        self.assertIn("bridge", data)
        self.assertIn("workspace", data)
        self.assertIn("shell", data)
        self.assertIn("recent_events", data)

    def test_call_get_events(self):
        state = BridgeState(allow_control=False, token=None, shell="powershell")
        state.events.add("test_event_1", "payload 1", "test")
        state.events.add("test_event_2", "payload 2", "test")
        registry = MCPToolRegistry(state)
        res = registry.call_tool("get_events", {"since": 0, "limit": 10})
        self.assertFalse(res["isError"])
        data = json.loads(res["content"][0]["text"])
        self.assertGreaterEqual(data["count"], 2)
        self.assertEqual(data["latest_id"], state.events.sequence)

    def test_call_read_file_bounded(self):
        state = BridgeState(allow_control=False, token=None, shell="powershell")
        registry = MCPToolRegistry(state)
        res = registry.call_tool(
            "read_file", {"path": "terminal_bridge.py", "max_bytes": 150}
        )
        self.assertFalse(res["isError"])
        data = json.loads(res["content"][0]["text"])
        self.assertTrue(data["truncated"])
        self.assertLessEqual(len(data["content"]), 150)

    def test_call_list_directory_bounded(self):
        state = BridgeState(allow_control=False, token=None, shell="powershell")
        registry = MCPToolRegistry(state)
        res = registry.call_tool("list_directory", {"max_entries": 10})
        self.assertFalse(res["isError"])
        data = json.loads(res["content"][0]["text"])
        self.assertIn("entries", data)
        self.assertLessEqual(data["count"], 10)

    def test_call_execute_command_in_control_mode(self):
        state = BridgeState(allow_control=True, token="tok", shell="cmd")
        registry = MCPToolRegistry(state)
        try:
            res = registry.call_tool(
                "execute_command", {"command": "echo TOOL_UNIT_TEST_PASS"}
            )
            self.assertFalse(res["isError"])
            data = json.loads(res["content"][0]["text"])
            self.assertEqual(data["status"], "executed")
            self.assertEqual(data["command"], "echo TOOL_UNIT_TEST_PASS")
        finally:
            state.shell.stop()

    def test_unknown_tool_returns_error(self):
        state = BridgeState(allow_control=False, token=None, shell="powershell")
        registry = MCPToolRegistry(state)
        res = registry.call_tool("bogus_tool", {})
        self.assertTrue(res["isError"])
        self.assertIn("Unknown tool", res["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
