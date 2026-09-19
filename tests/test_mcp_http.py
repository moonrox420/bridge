"""
Tests for Streamable HTTP endpoint: POST /api/mcp and GET /api/mcp.
"""

import json
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from terminal_bridge import BridgeHandler

BRIDGE_ROOT = Path(__file__).resolve().parent.parent
TEST_PORT = 8781
TEST_TOKEN = "http_test_token_secret_123"


class TestMcpHttp(unittest.TestCase):
    def test_handler_protocol_interface(self):
        self.assertTrue(callable(BridgeHandler.do_GET))
        self.assertTrue(callable(BridgeHandler.do_POST))
        self.assertTrue(callable(BridgeHandler.log_message))
        self.assertTrue(BridgeHandler.server_version.startswith("TerminalBridge/"))

    @classmethod
    def setUpClass(cls):
        script_path = str(BRIDGE_ROOT / "terminal_bridge.py")
        cls.proc = subprocess.Popen(
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
        cls.base_url = f"http://127.0.0.1:{TEST_PORT}"
        time.sleep(1.0)

    @classmethod
    def tearDownClass(cls):
        if cls.proc:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
                cls.proc.wait(timeout=1.0)

    def test_get_mcp_discovery(self):
        req = urllib.request.Request(f"{self.base_url}/api/mcp", method="GET")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["protocolVersion"], "2026-07-28")
            self.assertEqual(data["serverInfo"]["name"], "Terminal Bridge")
            self.assertIn("transports", data)

    def test_post_mcp_discover(self):
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "server/discover"}
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/mcp",
            data=body,
            headers={
                "Content-Type": "application/json",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "server/discover",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get("MCP-Protocol-Version"), "2026-07-28")
            self.assertEqual(resp.headers.get("Mcp-Method"), "server/discover")
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["result"]["protocolVersion"], "2026-07-28")

    def test_post_mcp_tools_list(self):
        body = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).encode(
            "utf-8"
        )
        req = urllib.request.Request(
            f"{self.base_url}/api/mcp",
            data=body,
            headers={
                "Content-Type": "application/json",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/list",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(len(data["result"]["tools"]), 6)

    def test_post_mcp_header_mismatch_rejection(self):
        body = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}).encode(
            "utf-8"
        )
        req = urllib.request.Request(
            f"{self.base_url}/api/mcp",
            data=body,
            headers={
                "Content-Type": "application/json",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "server/discover",  # Mismatch
            },
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3.0)
        self.assertEqual(ctx.exception.code, 400)

    def test_post_mcp_auth_boundary(self):
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "execute_command",
                    "arguments": {"command": "echo HTTP_UNIT_TEST"},
                },
            }
        ).encode("utf-8")

        # Without token -> returns isError: true with auth failure
        req_no_auth = urllib.request.Request(
            f"{self.base_url}/api/mcp",
            data=body,
            headers={
                "Content-Type": "application/json",
                "MCP-Protocol-Version": "2026-07-28",
            },
            method="POST",
        )
        with urllib.request.urlopen(req_no_auth, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(data["result"]["isError"])
            self.assertIn("Authorization failed", data["result"]["content"][0]["text"])

        # With valid token -> executes successfully
        req_auth = urllib.request.Request(
            f"{self.base_url}/api/mcp",
            data=body,
            headers={
                "Content-Type": "application/json",
                "MCP-Protocol-Version": "2026-07-28",
                "Authorization": f"Bearer {TEST_TOKEN}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req_auth, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertFalse(data["result"]["isError"])


if __name__ == "__main__":
    unittest.main()
