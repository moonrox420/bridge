"""Tests for context budgets, byte limits, and event classification in Terminal Bridge."""

import json
import unittest

from terminal_bridge import (
    BridgeState,
    EventCategory,
    EventStore,
    build_context_snapshot,
    classify_event,
)


class TestEventClassification(unittest.TestCase):
    """Verifies semantic classification of bridge events."""

    def test_stdout_classification(self) -> None:
        category = classify_event("terminal_output", "Build completed successfully.")
        self.assertEqual(category, EventCategory.STDOUT)

    def test_stderr_classification_by_type(self) -> None:
        category = classify_event("shell_error", "Access is denied.")
        self.assertEqual(category, EventCategory.STDERR)

    def test_stderr_classification_by_content(self) -> None:
        category = classify_event(
            "terminal_output", "Traceback (most recent call last):\n  File 'a.py'..."
        )
        self.assertEqual(category, EventCategory.STDERR)

    def test_command_classification(self) -> None:
        category = classify_event("terminal_input", "git status")
        self.assertEqual(category, EventCategory.COMMAND)

    def test_lifecycle_classification(self) -> None:
        category = classify_event("shell_started", {"pid": 1234})
        self.assertEqual(category, EventCategory.LIFECYCLE)

    def test_prompt_classification(self) -> None:
        category = classify_event("terminal_output", "PS C:\\Users\\droxa\\bridge>")
        self.assertEqual(category, EventCategory.PROMPT)

    def test_telemetry_classification(self) -> None:
        category = classify_event("background_tick", {"tick": 42})
        self.assertEqual(category, EventCategory.TELEMETRY)


class TestEventStoreBudgets(unittest.TestCase):
    """Verifies byte budget enforcement and category filtering in EventStore."""

    def setUp(self) -> None:
        self.store = EventStore(maximum=100)
        for i in range(20):
            if i % 2 == 0:
                self.store.add("terminal_output", f"stdout message {i} " + ("a" * 80))
            else:
                self.store.add("shell_error", f"stderr message {i} " + ("b" * 80))

    def test_category_filtering(self) -> None:
        stdout_events = self.store.get_since(0, limit=50, categories=["stdout"])
        self.assertEqual(len(stdout_events), 10)
        for evt in stdout_events:
            self.assertEqual(evt["category"], EventCategory.STDOUT)

        stderr_events = self.store.get_since(0, limit=50, categories=["stderr"])
        self.assertEqual(len(stderr_events), 10)
        for evt in stderr_events:
            self.assertEqual(evt["category"], EventCategory.STDERR)

    def test_byte_budget_truncation(self) -> None:
        budgeted = self.store.get_since(0, limit=50, max_bytes=600)
        self.assertGreater(len(budgeted), 0)
        self.assertLess(len(budgeted), 20)
        total_bytes = len(json.dumps(budgeted, ensure_ascii=False).encode("utf-8"))
        self.assertLessEqual(total_bytes, 600)


class TestSnapshotBudgets(unittest.TestCase):
    """Verifies byte budgeting for context snapshots."""

    def test_snapshot_budget_metadata(self) -> None:
        state = BridgeState(allow_control=False, token=None, shell="powershell")
        for i in range(20):
            state.events.add("terminal_output", f"log line {i}: " + ("x" * 50))

        limits = {"events": 10, "procs": 5, "tree": 10, "max_bytes": 2048}
        snapshot = build_context_snapshot(state, limits=limits)

        self.assertIn("budget", snapshot)
        self.assertEqual(snapshot["budget"]["allocated_bytes"], 2048)
        self.assertIsInstance(snapshot["budget"]["truncated"], bool)
        self.assertEqual(snapshot["latest_event_id"], state.events.sequence)


if __name__ == "__main__":
    unittest.main()
