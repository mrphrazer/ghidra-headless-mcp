from __future__ import annotations

import json
from typing import Any

from ghidra_headless_mcp import __version__
from ghidra_headless_mcp.server import ALL_TOOL_SPECS, SimpleMcpServer

EXPECTED_TOOL_NAMES = {spec["name"] for spec in ALL_TOOL_SPECS}


def _tool_name(*candidates: str) -> str:
    for candidate in candidates:
        if candidate in EXPECTED_TOOL_NAMES:
            return candidate
    raise AssertionError(f"none of the tool names exist: {candidates!r}")


def _tool_prefix(*candidates: str) -> str:
    for candidate in candidates:
        if any(name.startswith(candidate) for name in EXPECTED_TOOL_NAMES):
            return candidate
    raise AssertionError(f"none of the tool prefixes exist: {candidates!r}")


def _call_tool(
    server: SimpleMcpServer,
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


def _tool_spec(name: str) -> dict[str, Any]:
    for spec in ALL_TOOL_SPECS:
        if spec["name"] == name:
            return spec
    raise AssertionError(f"tool spec not found: {name}")


def test_initialize_and_tools_list(fake_server: SimpleMcpServer) -> None:
    init_response = fake_server.handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    )
    assert init_response is not None
    assert init_response["result"]["serverInfo"]["name"] == "ghidra_headless_mcp"
    assert init_response["result"]["serverInfo"]["version"] == __version__
    assert init_response["result"]["protocolVersion"] == "2025-03-26"

    listed = fake_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {"offset": 0, "limit": 500},
        }
    )
    assert listed is not None
    names = {tool["name"] for tool in listed["result"]["tools"]}
    assert EXPECTED_TOOL_NAMES.issubset(names)


def test_initialize_negotiates_supported_and_fallback_protocol_versions(
    fake_server: SimpleMcpServer,
) -> None:
    supported = fake_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 20,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
    )
    assert supported is not None
    assert supported["result"]["protocolVersion"] == "2024-11-05"

    fallback = fake_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 21,
            "method": "initialize",
            "params": {"protocolVersion": "2099-01-01"},
        }
    )
    assert fallback is not None
    assert fallback["result"]["protocolVersion"] == "2025-03-26"


def test_initialize_rejects_non_string_protocol_version(fake_server: SimpleMcpServer) -> None:
    invalid = fake_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 22,
            "method": "initialize",
            "params": {"protocolVersion": 20250326},
        }
    )
    assert invalid is not None
    assert invalid["error"]["code"] == -32602
    assert "protocolVersion" in invalid["error"]["message"]


def test_tools_list_supports_filtering_and_pagination(fake_server: SimpleMcpServer) -> None:
    first_page = fake_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {"offset": 0, "limit": 10},
        }
    )
    assert first_page is not None
    assert len(first_page["result"]["tools"]) == 10
    assert first_page["result"]["has_more"] is True
    assert first_page["result"]["next_offset"] == 10

    prefix = _tool_prefix("program.", "binary.")
    filtered = fake_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/list",
            "params": {"prefix": prefix, "offset": 0, "limit": 100},
        }
    )
    assert filtered is not None
    tools = filtered["result"]["tools"]
    assert tools
    assert all(tool["name"].startswith(prefix) for tool in tools)


def test_tool_result_text_and_mode_transition(
    fake_server: SimpleMcpServer, sample_binary_path: str
) -> None:
    opened = _call_tool(
        fake_server,
        _tool_name("program.open", "session.open"),
        {
            "path": sample_binary_path,
            "update_analysis": False,
            "read_only": True,
        },
        request_id=10,
    )
    assert opened["content"][0]["text"].startswith("ok")
    session_id = opened["structuredContent"]["session_id"]

    evaluated = _call_tool(
        fake_server,
        "ghidra.eval",
        {"session_id": session_id, "code": "print('stdout')\n_ = 7"},
        request_id=11,
    )
    assert evaluated["structuredContent"]["result"] == 7
    assert evaluated["structuredContent"]["mode_transitioned"] is True
    assert evaluated["structuredContent"]["transitioned_session_ids"] == [session_id]
    assert evaluated["structuredContent"]["stdout"] == "stdout\n"

    mode = _call_tool(
        fake_server,
        _tool_name("program.mode.get", "program.mode", "session.mode"),
        {"session_id": session_id},
        request_id=12,
    )
    assert mode["structuredContent"]["read_only"] is False


def test_server_wraps_tool_failures_and_non_json_payload(fake_server: SimpleMcpServer) -> None:
    def _boom(_: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("boom")

    def _non_json(_: dict[str, Any]) -> dict[str, Any]:
        return {"value": object()}

    fake_server._tool_handlers["__boom__"] = _boom
    fake_server._tool_handlers["__non_json__"] = _non_json

    boom = fake_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 90,
            "method": "tools/call",
            "params": {"name": "__boom__", "arguments": {}},
        }
    )
    assert boom is not None
    assert "error" not in boom
    assert boom["result"]["isError"] is True
    assert (
        boom["result"]["structuredContent"]["error"]
        == "unexpected tool failure: RuntimeError: boom"
    )

    non_json = fake_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 91,
            "method": "tools/call",
            "params": {"name": "__non_json__", "arguments": {}},
        }
    )
    assert non_json is not None
    assert non_json["result"]["isError"] is True
    assert (
        non_json["result"]["structuredContent"]["error"]
        == "tool returned a non-JSON-serializable payload"
    )

    ping = _call_tool(fake_server, "health.ping", request_id=92)
    assert ping["structuredContent"]["status"] == "ok"


def test_stdio_json_line_round_trip(fake_server: SimpleMcpServer) -> None:
    line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/call",
            "params": {"name": "mcp.response_format", "arguments": {}},
        }
    )
    response = fake_server.handle_json_line(line)
    assert response is not None
    payload = json.loads(response)
    assert payload["result"]["structuredContent"]["structuredContent"]


def test_search_and_comment_tool_schemas_expose_string_queries() -> None:
    comment_list = _tool_spec("comment.list")
    assert comment_list["properties"]["query"]["type"] == "string"
    assert comment_list["properties"]["case_sensitive"]["type"] == "boolean"

    search_text = _tool_spec("search.text")
    assert search_text["properties"]["encoding"]["type"] == "string"
    assert "oneOf" in search_text["properties"]["start"]
    assert "oneOf" in search_text["properties"]["end"]
