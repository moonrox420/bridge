"""
PERMANENT REGRESSION GATE RUNNER FOR TERMINAL BRIDGE
===================================================

Runs all unit and integration test suites:
- test_jsonrpc
- test_mcp_tools
- test_mcp_http
- test_mcp_stdio
- test_sse
- test_security
- test_concurrency
- test_interoperability
"""

import sys
import unittest
from pathlib import Path

# Ensure bridge root is in sys.path
BRIDGE_ROOT = Path(__file__).resolve().parent.parent
if str(BRIDGE_ROOT) not in sys.path:
    sys.path.insert(0, str(BRIDGE_ROOT))


def main():
    print("=" * 70)
    print("TERMINAL BRIDGE PERMANENT REGRESSION GATE")
    print("=" * 70)

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(BRIDGE_ROOT / "tests"), pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("=" * 70)
    if result.wasSuccessful():
        print(
            f"REGRESSION GATE PASSED: {result.testsRun} tests completed with 0 failures."
        )
        print("=" * 70)
        return 0
    else:
        print(
            f"REGRESSION GATE FAILED: {len(result.failures)} failures, {len(result.errors)} errors."
        )
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())
