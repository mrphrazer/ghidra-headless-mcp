"""Single-command launcher for the simple Ghidra Headless MCP server.

Usage:
    python ghidra_headless_mcp.py
"""

from ghidra_headless_mcp.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
