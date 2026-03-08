from __future__ import annotations

import pytest
from ghidra_headless_mcp.server import ALL_TOOL_SPECS
from tests.tool_harness import call_tool, create_tool_context, pre_actions, tool_arguments


@pytest.mark.parametrize("tool_spec", ALL_TOOL_SPECS, ids=[spec["name"] for spec in ALL_TOOL_SPECS])
def test_every_tool_is_invocable_via_server(tool_spec: dict[str, object]) -> None:
    ctx = create_tool_context()
    pre_actions(ctx.backend, tool_spec["name"], ctx.session_id)
    arguments = tool_arguments(tool_spec, ctx.session_id, ctx.task_id)
    result = call_tool(ctx.server, tool_spec["name"], arguments)
    assert result["isError"] is False, (tool_spec["name"], result["structuredContent"])
    assert isinstance(result["structuredContent"], dict)
    assert result["content"]
    assert isinstance(result["content"][0]["text"], str)
