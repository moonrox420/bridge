"""
Tests for Independent Client Wire Interoperability:
Validates that an arbitrary protocol client adheres cleanly to both stdio and Streamable HTTP transports.
"""

import json
import subprocess
import sys
import time
import unittest
import urllib.request
from pathlib import Path

BRIDGE_ROOT = Path(__file__).resolve().parent.parent
TEST_PORT = 8783
TEST_TOKEN = "interop_test_token_789"


class TestInteroperability(unittest.TestCase):
    def test_independent_client_over_stdio(self):
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
            # 1. Discover
            req = {"jsonrpc": "2.0", "id": 1, "method": "server/discover"}
            assert proc.stdin and proc.stdout
            proc.stdin.write(json.dumps(req) + "\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
            data = json.loads(line)
            self.assertEqual(data["result"]["protocolVersion"], "2026-07-28")

            # 2. Tools
            req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
            proc.stdin.write(json.dumps(req) + "\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
            data = json.loads(line)
            self.assertEqual(len(data["result"]["tools"]), 6)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1.0)

    def test_independent_client_over_http(self):
        script_path = str(BRIDGE_ROOT / "terminal_bridge.py")
        proc = subprocess.Popen(
            [
                sys.executable,
                script_path,
                "--port",
                str(TEST_PORT),
                "--allow-control",
                "--token",
                TEST_TOKEN,
                "--shell",
                "cmd",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(1.0)

        base_url = f"http://127.0.0.1:{TEST_PORT}/api/mcp"
        try:
            # Discover
            req_body = json.dumps(
                {"jsonrpc": "2.0", "id": 10, "method": "server/discover"}
            ).encode("utf-8")
            req = urllib.request.Request(
                base_url,
                data=req_body,
                headers={
                    "Content-Type": "application/json",
                    "MCP-Protocol-Version": "2026-07-28",
                    "Mcp-Method": "server/discover",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(data["result"]["protocolVersion"], "2026-07-28")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1.0)


if __name__ == "__main__":
    unittest.main()
