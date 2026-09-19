"""
Tests for the v2.0 Security Model:
1. READ CAPABILITY: bounded input, filesystem policy, sensitive-path rejection.
2. CONTROL CAPABILITY: --allow-control, CONTROL_TOKEN, authenticated caller, OS user permissions.
"""

import unittest
from pathlib import Path
from unittest.mock import Mock

import terminal_bridge
from terminal_bridge import (
    BridgeState,
    FilesystemPolicy,
    MCPToolRegistry,
    valid_control_token,
)


class TestSecurityModel(unittest.TestCase):
    def test_filesystem_policy_sensitive_rejections(self):
        blocked_names = [
            ".env",
            ".env.local",
            ".env.production",
            ".env.backup",
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
            "id_dsa",
            ".gitconfig",
            ".bash_history",
            "server.key",
            "cert.pem",
            "cert.pfx",
        ]
        for name in blocked_names:
            err = FilesystemPolicy.check_file_read(Path(name))
            self.assertIsNotNone(err, f"Expected {name} to be blocked by policy")
            self.assertIn("Access denied", err)

    def test_filesystem_policy_allows_normal_files(self):
        allowed_names = [
            "terminal_bridge.py",
            "README.md",
            "package.json",
            "index.html",
            "styles.css",
        ]
        for name in allowed_names:
            err = FilesystemPolicy.check_file_read(Path(name))
            self.assertIsNone(err, f"Expected {name} to be allowed by policy")

    def test_tool_call_read_file_policy_enforcement(self):
        state = BridgeState(allow_control=False, token=None, shell="powershell")
        registry = MCPToolRegistry(state)
        res = registry.call_tool("read_file", {"path": ".env"})
        self.assertTrue(res["isError"])
        self.assertIn("Access denied", res["content"][0]["text"])

    def test_control_capability_enforcement_when_disabled(self):
        state = BridgeState(allow_control=False, token=None, shell="powershell")
        registry = MCPToolRegistry(state)
        res = registry.call_tool("execute_command", {"command": "dir"})
        self.assertTrue(res["isError"])
        self.assertIn("Permission denied", res["content"][0]["text"])

    def test_control_capability_enforcement_unauthorized(self):
        state = BridgeState(allow_control=True, token="valid_token", shell="powershell")
        registry = MCPToolRegistry(state)
        # auth_ok=False simulates unauthenticated HTTP call
        res = registry.call_tool("execute_command", {"command": "dir"}, auth_ok=False)
        self.assertTrue(res["isError"])
        self.assertIn("Authorization failed", res["content"][0]["text"])

    def test_valid_control_token_with_and_without_quotes(self):
        old_state = terminal_bridge.STATE
        try:
            terminal_bridge.STATE = BridgeState(
                allow_control=True, token="my_secret_token", shell="powershell"
            )
            # Unquoted Bearer
            h1 = Mock()
            h1.headers = {"Authorization": "Bearer my_secret_token"}
            self.assertTrue(valid_control_token(h1))

            # Quoted Bearer (e.g. copied from .env)
            h2 = Mock()
            h2.headers = {"Authorization": 'Bearer "my_secret_token"'}
            self.assertTrue(valid_control_token(h2))

            # Invalid Bearer
            h3 = Mock()
            h3.headers = {"Authorization": "Bearer wrong_token"}
            self.assertFalse(valid_control_token(h3))
        finally:
            terminal_bridge.STATE = old_state


if __name__ == "__main__":
    unittest.main()
