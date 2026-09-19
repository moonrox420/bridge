"""
Tests for high-concurrency tool execution and EventStore monotonic sequencing invariant.
"""

import concurrent.futures
import json
import threading
import time
import unittest

from terminal_bridge import BridgeState, MCPServer, MCPToolRegistry


def _build_mcp_request(idx: int) -> dict:
    mod = idx % 4
    if mod == 0:
        return {
            "jsonrpc": "2.0",
            "id": idx,
            "method": "tools/call",
            "params": {"name": "get_context_snapshot", "arguments": {}},
        }
    if mod == 1:
        return {
            "jsonrpc": "2.0",
            "id": idx,
            "method": "tools/call",
            "params": {
                "name": "get_events",
                "arguments": {"since": 0, "limit": 20},
            },
        }
    if mod == 2:
        return {
            "jsonrpc": "2.0",
            "id": idx,
            "method": "tools/call",
            "params": {
                "name": "list_directory",
                "arguments": {"max_entries": 10},
            },
        }
    return {
        "jsonrpc": "2.0",
        "id": idx,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "terminal_bridge.py", "max_bytes": 100},
        },
    }


class TestConcurrencyAndSequencing(unittest.TestCase):
    def _assert_monotonic_sequence(self, events: list[dict]) -> None:
        self.assertGreater(len(events), 1)
        for i in range(len(events) - 1):
            self.assertEqual(
                events[i + 1]["id"],
                events[i]["id"] + 1,
                f"Sequence discontinuity: {events[i]['id']} -> {events[i + 1]['id']}",
            )

    def test_concurrent_tool_calls_and_monotonic_sequencing(self):
        state = BridgeState(allow_control=True, token="tok", shell="cmd")
        registry = MCPToolRegistry(state)
        server = MCPServer(registry)

        stop_emitter = threading.Event()

        def background_emitter():
            c = 0
            while not stop_emitter.is_set():
                c += 1
                state.events.add("background_tick", f"val_{c}", "emitter")
                time.sleep(0.01)

        emitter_thread = threading.Thread(target=background_emitter, daemon=True)
        emitter_thread.start()

        def worker_task(idx):
            req = _build_mcp_request(idx)
            resp = server.handle_message(json.dumps(req))
            if not resp or resp.get("error") or resp["result"].get("isError"):
                return f"Failed on call {idx}: {resp}"
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
            futures = [executor.submit(worker_task, i) for i in range(60)]
            errors = [
                err
                for err in (
                    f.result() for f in concurrent.futures.as_completed(futures)
                )
                if err
            ]

        stop_emitter.set()
        emitter_thread.join(timeout=2.0)

        self.assertEqual(len(errors), 0, f"Encountered concurrency errors: {errors}")

        with state.events.lock:
            events = list(state.events.events)
            self._assert_monotonic_sequence(events)


if __name__ == "__main__":
    unittest.main()
