"""
Tests for Server-Sent Events (SSE) streaming on GET /api/events/stream.
"""

import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

BRIDGE_ROOT = Path(__file__).resolve().parent.parent
TEST_PORT = 8782
TEST_TOKEN = "sse_test_token_secret_456"


class TestSseStream(unittest.TestCase):
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

    def test_sse_connect_and_receive_events(self):
        import urllib.request

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", TEST_PORT))
        s.settimeout(5.0)

        try:
            req = (
                f"GET /api/events/stream?since=0 HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{TEST_PORT}\r\n"
                f"Accept: text/event-stream\r\n"
                f"\r\n"
            )
            s.sendall(req.encode("utf-8"))

            # Trigger shell start to generate live shell_started event into the SSE stream
            start_req = urllib.request.Request(
                f"http://127.0.0.1:{TEST_PORT}/api/shell/start",
                data=b"{}",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {TEST_TOKEN}",
                },
                method="POST",
            )
            with urllib.request.urlopen(start_req, timeout=3.0) as resp:
                self.assertEqual(resp.status, 200)

            buf = ""
            start_time = time.time()
            while "event:" not in buf and time.time() - start_time < 3.0:
                chunk = s.recv(4096).decode("utf-8", errors="replace")
                if not chunk:
                    break
                buf += chunk

            self.assertIn("200 OK", buf)
            self.assertIn("text/event-stream", buf)
            self.assertIn("event: shell_started", buf)
        finally:
            s.close()


if __name__ == "__main__":
    unittest.main()
