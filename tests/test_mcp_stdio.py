"""
Tests for Stdio transport: terminal_bridge.py --stdio.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

BRIDGE_ROOT = Path(__file__).resolve().parent.parent


def _send_stdio_rpc(proc: subprocess.Popen, req: dict) -> dict:
    assert proc.stdin is not None
    assert proc.stdout is not None
    proc.stdin.write(json.dumps(req) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    return json.loads(line)


def _cleanup_stdio_process(proc: subprocess.Popen) -> str:
    proc.terminate()
    try:
        _, stderr_output = proc.communicate(timeout=2.0)
        return stderr_output
    except subprocess.TimeoutExpired:
        proc.kill()
        _, stderr_output = proc.communicate(timeout=1.0)
        return stderr_output


class TestMcpStdio(unittest.TestCase):
    def test_stdio_transport_clean_stdout_and_stderr_diagnostics(self):
        script_path = str(BRIDGE_ROOT / "terminal_bridge.py")
        proc = subprocess.Popen(
            [
                sys.executable,
                script_path,
                "--stdio",
                "--allow-control",
                "--shell",
                "cmd",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )

        try:
            resp1 = _send_stdio_rpc(
                proc, {"jsonrpc": "2.0", "id": 101, "method": "server/discover"}
            )
            self.assertEqual(resp1["id"], 101)
            self.assertEqual(resp1["result"]["protocolVersion"], "2026-07-28")

            resp2 = _send_stdio_rpc(
                proc, {"jsonrpc": "2.0", "id": 102, "method": "tools/list"}
            )
            self.assertEqual(resp2["id"], 102)
            self.assertEqual(len(resp2["result"]["tools"]), 6)

            call_req = {
                "jsonrpc": "2.0",
                "id": 103,
                "method": "tools/call",
                "params": {
                    "name": "execute_command",
                    "arguments": {"command": "echo STDIO_UNIT_PASS"},
                },
            }
            resp3 = _send_stdio_rpc(proc, call_req)
            self.assertEqual(resp3["id"], 103)
            self.assertFalse(resp3["result"]["isError"])
        finally:
            stderr_output = _cleanup_stdio_process(proc)
            self.assertIn("Starting MCP stdio transport", stderr_output)


if __name__ == "__main__":
    unittest.main()
