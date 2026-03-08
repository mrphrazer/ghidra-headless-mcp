from __future__ import annotations

from typing import Any

from ghidra_headless_mcp.fuzz_support import (
    TOOL_SPECS_BY_NAME,
    ToolContext,
    build_args,
    create_tool_context,
    pre_actions,
    tool_arguments,
    tool_spec,
)

__all__ = [
    "TOOL_SPECS_BY_NAME",
    "ToolContext",
    "build_args",
    "call_tool",
    "call_tool_content",
    "create_tool_context",
    "pre_actions",
    "tool_arguments",
    "tool_spec",
]


def call_tool(
    server,
    name: str,
    arguments: dict[str, Any] | None = None,
    request_id: int = 1,
) -> dict[str, Any]:
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    )
    assert response is not None
    assert "error" not in response
    return response["result"]


def call_tool_content(
    server,
    name: str,
    arguments: dict[str, Any] | None = None,
    request_id: int = 1,
) -> dict[str, Any]:
    return call_tool(server, name, arguments, request_id)["structuredContent"]
