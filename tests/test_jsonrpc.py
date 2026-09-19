"""
Tests for MCPProtocol: JSON-RPC 2.0 parser, validator, and error construction.
"""

import json
import unittest

from terminal_bridge import MCPProtocol


class TestJsonRpcProtocol(unittest.TestCase):
    def test_parse_error_on_malformed_json(self):
        raw = "not valid json{{{"
        req, err = MCPProtocol.parse_request(raw)
        self.assertIsNone(req)
        self.assertIsNotNone(err)
        self.assertEqual(err["error"]["code"], MCPProtocol.PARSE_ERROR)
        self.assertIn("Parse error", err["error"]["message"])

    def test_invalid_request_on_non_object(self):
        for payload in ["[]", '"string"', "123", "true", "null"]:
            req, err = MCPProtocol.parse_request(payload)
            self.assertIsNone(req)
            self.assertIsNotNone(err)
            self.assertEqual(err["error"]["code"], MCPProtocol.INVALID_REQUEST)

    def test_invalid_request_on_missing_or_bad_jsonrpc(self):
        for bad_payload in [
            {"id": 1, "method": "ping"},
            {"jsonrpc": "1.0", "id": 1, "method": "ping"},
            {"jsonrpc": 2.0, "id": 1, "method": "ping"},
        ]:
            req, err = MCPProtocol.parse_request(json.dumps(bad_payload))
            self.assertIsNone(req)
            self.assertIsNotNone(err)
            self.assertEqual(err["error"]["code"], MCPProtocol.INVALID_REQUEST)

    def test_invalid_request_on_missing_or_non_string_method(self):
        for bad_payload in [
            {"jsonrpc": "2.0", "id": 1},
            {"jsonrpc": "2.0", "id": 1, "method": 123},
            {"jsonrpc": "2.0", "id": 1, "method": None},
        ]:
            req, err = MCPProtocol.parse_request(json.dumps(bad_payload))
            self.assertIsNone(req)
            self.assertIsNotNone(err)
            self.assertEqual(err["error"]["code"], MCPProtocol.INVALID_REQUEST)

    def test_valid_request_parsed_cleanly(self):
        valid = {
            "jsonrpc": "2.0",
            "id": "test-id-1",
            "method": "tools/list",
            "params": {},
        }
        req, err = MCPProtocol.parse_request(json.dumps(valid))
        self.assertIsNone(err)
        self.assertIsNotNone(req)
        self.assertEqual(req["method"], "tools/list")
        self.assertEqual(req["id"], "test-id-1")

    def test_success_and_error_response_construction(self):
        succ = MCPProtocol.success_response("id-123", {"tools": []})
        self.assertEqual(succ["jsonrpc"], "2.0")
        self.assertEqual(succ["id"], "id-123")
        self.assertEqual(succ["result"], {"tools": []})

        err = MCPProtocol.error_response(
            "id-123", MCPProtocol.METHOD_NOT_FOUND, "Method not found", {"extra": 1}
        )
        self.assertEqual(err["jsonrpc"], "2.0")
        self.assertEqual(err["id"], "id-123")
        self.assertEqual(err["error"]["code"], MCPProtocol.METHOD_NOT_FOUND)
        self.assertEqual(err["error"]["data"], {"extra": 1})


if __name__ == "__main__":
    unittest.main()
