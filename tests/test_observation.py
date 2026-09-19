"""Tests for working directory awareness, cwd tracking, and command duration telemetry."""

import json
import unittest
from pathlib import Path

from terminal_bridge import (
    BridgeState,
    MCPToolRegistry,
    _detect_cwd_from_prompt,
    build_context_snapshot,
)


class TestWorkingDirObservation(unittest.TestCase):
    """Verifies that shell prompts update cwd and trigger cwd_changed events."""

    def test_detect_cwd_from_powershell_prompt(self) -> None:
        target_dir = str(Path.cwd())
        prompt = f"PS {target_dir}>"
        detected = _detect_cwd_from_prompt(prompt)
        self.assertIsNotNone(detected)
        self.assertEqual(detected, Path(target_dir))

    def test_detect_cwd_from_cmd_prompt(self) -> None:
        target_dir = str(Path.cwd())
        prompt = f"{target_dir}>"
        detected = _detect_cwd_from_prompt(prompt)
        self.assertIsNotNone(detected)
        self.assertEqual(detected, Path(target_dir))

    def test_detect_cwd_ignores_non_prompts(self) -> None:
        self.assertIsNone(_detect_cwd_from_prompt("echo hello world"))
        self.assertIsNone(_detect_cwd_from_prompt("Traceback (most recent call last):"))
        self.assertIsNone(_detect_cwd_from_prompt("PS NonExistentDirectory123456789>"))

    def test_cwd_changed_event_emission(self) -> None:
        state = BridgeState(allow_control=False, token=None, shell="powershell")
        initial_cwd = state.shell.cwd

        # Simulate directory change prompt
        parent_dir = initial_cwd.parent
        state.shell._handle_line_read(f"PS {parent_dir}>")

        self.assertEqual(state.shell.cwd, parent_dir)
        events = state.events.get_since(0, limit=10)
        cwd_events = [e for e in events if e["type"] == "cwd_changed"]
        self.assertEqual(len(cwd_events), 1)
        self.assertEqual(cwd_events[0]["data"]["old_cwd"], str(initial_cwd))
        self.assertEqual(cwd_events[0]["data"]["new_cwd"], str(parent_dir))

    def test_snapshot_cwd_synchronization(self) -> None:
        state = BridgeState(allow_control=False, token=None, shell="powershell")
        parent_dir = state.shell.cwd.parent
        state.shell.cwd = parent_dir

        snapshot = build_context_snapshot(state)
        self.assertEqual(snapshot["shell"]["cwd"], str(parent_dir))
        self.assertEqual(snapshot["workspace"]["root"], str(parent_dir))


class TestCommandDurationTelemetry(unittest.TestCase):
    """Verifies timing telemetry on shell command execution."""

    def test_execute_command_duration(self) -> None:
        state = BridgeState(allow_control=True, token="tok", shell="powershell")
        registry = MCPToolRegistry(state)
        res = registry.call_tool("execute_command", {"command": "echo 'timing_test'"})

        self.assertFalse(res["isError"])
        data = json.loads(res["content"][0]["text"])
        self.assertIn("duration_ms", data)
        self.assertIsInstance(data["duration_ms"], float)
        self.assertGreaterEqual(data["duration_ms"], 0.0)

        events = state.events.get_since(0, limit=20)
        completion_events = [
            e for e in events if e["type"] == "terminal_command_completed"
        ]
        self.assertEqual(len(completion_events), 1)
        self.assertIn("duration_ms", completion_events[0]["data"])


if __name__ == "__main__":
    unittest.main()
