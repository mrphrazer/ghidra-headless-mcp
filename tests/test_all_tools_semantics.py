from __future__ import annotations

import pytest
from ghidra_headless_mcp.fuzz_support import resolve_sample_binary_path
from ghidra_headless_mcp.server import ALL_TOOL_SPECS
from tests.tool_harness import (
    TOOL_SPECS_BY_NAME,
    build_args,
    call_tool_content,
    create_tool_context,
)

EXPECTED_TOOL_NAMES = {spec["name"] for spec in ALL_TOOL_SPECS}

META_TOOLS = {
    "health.ping",
    "mcp.response_format",
    "ghidra.call",
    "ghidra.eval",
    "ghidra.info",
    "ghidra.script",
}
ECHO_TOOLS = {
    "analysis.analyzers.list",
    "analysis.analyzers.set",
    "analysis.clear_cache",
    "function.report",
    "memory.block.create",
    "memory.block.remove",
    "pcode.block",
    "pcode.varnode_uses",
    "program.report",
    "type.apply_at",
    "type.parse_c",
}
ANALYSIS_TASK_TOOLS = {
    "analysis.options.get",
    "analysis.options.list",
    "analysis.options.set",
    "analysis.status",
    "analysis.update",
    "analysis.update_and_wait",
    "task.analysis_update",
    "task.cancel",
    "task.result",
    "task.status",
}
PROGRAM_PROJECT_TOOLS = {
    "program.close",
    "program.export_binary",
    "program.image_base.set",
    "program.list_open",
    "program.mode.get",
    "program.mode.set",
    "program.open",
    "program.open_bytes",
    "program.save",
    "program.save_as",
    "program.summary",
    "project.export",
    "project.file.info",
    "project.files.list",
    "project.folders.list",
    "project.program.open",
    "project.program.open_existing",
    "project.search.programs",
}
TRANSACTION_TOOLS = {
    "transaction.begin",
    "transaction.commit",
    "transaction.redo",
    "transaction.revert",
    "transaction.status",
    "transaction.undo",
}
LISTING_TOOLS = {
    "listing.clear",
    "listing.code_unit.after",
    "listing.code_unit.at",
    "listing.code_unit.before",
    "listing.code_unit.containing",
    "listing.code_units.list",
    "listing.data.at",
    "listing.data.clear",
    "listing.data.create",
    "listing.data.list",
    "listing.disassemble.function",
    "listing.disassemble.range",
    "listing.disassemble.seed",
}
MEMORY_PATCH_CONTEXT_TOOLS = {
    "context.get",
    "context.ranges",
    "context.set",
    "memory.blocks.list",
    "memory.read",
    "memory.write",
    "patch.assemble",
    "patch.branch_invert",
    "patch.nop",
}
ANNOTATION_TOOLS = {
    "bookmark.add",
    "bookmark.clear",
    "bookmark.list",
    "bookmark.remove",
    "comment.get",
    "comment.get_all",
    "comment.list",
    "comment.set",
    "metadata.query",
    "metadata.store",
    "relocation.add",
    "relocation.list",
    "source.file.add",
    "source.file.list",
    "source.file.remove",
    "source.map.add",
    "source.map.list",
    "source.map.remove",
    "tag.add",
    "tag.list",
    "tag.remove",
    "tag.stats",
}
SYMBOL_EXTERNAL_TOOLS = {
    "class.create",
    "external.entrypoint.add",
    "external.entrypoint.list",
    "external.entrypoint.remove",
    "external.exports.list",
    "external.function.create",
    "external.imports.list",
    "external.library.create",
    "external.library.list",
    "external.library.set_path",
    "external.location.create",
    "external.location.get",
    "namespace.create",
    "symbol.by_name",
    "symbol.create",
    "symbol.delete",
    "symbol.list",
    "symbol.namespace.move",
    "symbol.primary.set",
    "symbol.rename",
}
REFERENCE_EQUATE_TOOLS = {
    "equate.clear_range",
    "equate.create",
    "equate.delete",
    "equate.list",
    "reference.association.remove",
    "reference.association.set",
    "reference.clear_from",
    "reference.clear_to",
    "reference.create.external",
    "reference.create.memory",
    "reference.create.register",
    "reference.create.stack",
    "reference.delete",
    "reference.from",
    "reference.primary.set",
    "reference.to",
}
FUNCTION_VAR_TOOLS = {
    "function.at",
    "function.batch.run",
    "function.body.set",
    "function.by_name",
    "function.callees",
    "function.callers",
    "function.calling_convention.set",
    "function.calling_conventions.list",
    "function.create",
    "function.delete",
    "function.flags.set",
    "function.list",
    "function.rename",
    "function.return_type.set",
    "function.signature.get",
    "function.signature.set",
    "function.thunk.set",
    "function.variables",
    "parameter.add",
    "parameter.move",
    "parameter.remove",
    "parameter.replace",
    "stackframe.variable.clear",
    "stackframe.variable.create",
    "stackframe.variables",
    "variable.comment.set",
    "variable.local.create",
    "variable.local.remove",
    "variable.rename",
    "variable.retype",
}
TYPE_LAYOUT_DECOMP_TOOLS = {
    "decomp.ast",
    "decomp.function",
    "decomp.global.rename",
    "decomp.global.retype",
    "decomp.high_function.summary",
    "decomp.override.get",
    "decomp.override.set",
    "decomp.tokens",
    "decomp.trace_type.backward",
    "decomp.trace_type.forward",
    "decomp.writeback.locals",
    "decomp.writeback.params",
    "layout.enum.create",
    "layout.enum.member.add",
    "layout.enum.member.remove",
    "layout.inspect.components",
    "layout.struct.bitfield.add",
    "layout.struct.create",
    "layout.struct.field.add",
    "layout.struct.field.clear",
    "layout.struct.field.comment.set",
    "layout.struct.field.rename",
    "layout.struct.field.replace",
    "layout.struct.fill_from_decompiler",
    "layout.struct.get",
    "layout.struct.resize",
    "layout.union.create",
    "layout.union.member.add",
    "layout.union.member.remove",
    "type.archives.list",
    "type.category.create",
    "type.category.list",
    "type.define_c",
    "type.delete",
    "type.get",
    "type.get_by_id",
    "type.list",
    "type.rename",
    "type.source_archives.list",
}
SEARCH_GRAPH_PCODE_TOOLS = {
    "graph.basic_blocks",
    "graph.call_paths",
    "graph.cfg.edges",
    "pcode.function",
    "pcode.op.at",
    "search.bytes",
    "search.constants",
    "search.defined_strings",
    "search.instructions",
    "search.pcode",
    "search.resolve",
    "search.text",
}


def _call(ctx, tool_name: str, **overrides: object) -> dict[str, object]:
    return call_tool_content(ctx.server, tool_name, build_args(ctx, tool_name, **overrides))


def _call_args(ctx, tool_name: str, arguments: dict[str, object]) -> dict[str, object]:
    return call_tool_content(ctx.server, tool_name, arguments)


def _assert_count_items(payload: dict[str, object]) -> None:
    items = payload["items"]
    assert isinstance(items, list)
    assert payload["count"] == len(items)
    if "total" in payload:
        assert payload["total"] >= payload["count"]
    if "limit" in payload:
        assert payload["count"] <= payload["limit"]


def _item_matching(items: list[dict[str, object]], **expected: object) -> dict[str, object] | None:
    for item in items:
        if all(item.get(key) == value for key, value in expected.items()):
            return item
    return None


@pytest.mark.parametrize("name", sorted(ECHO_TOOLS))
def test_echo_tools_round_trip_backend_method_and_arguments(name: str) -> None:
    ctx = create_tool_context()
    arguments = build_args(ctx, name)
    if name == "analysis.analyzers.list":
        arguments.update({"query": "Decompiler", "offset": 1, "limit": 2})
    if name == "memory.block.create":
        arguments.update({"name": "scratch", "address": "0x3000", "length": 16})
    if name == "memory.block.remove":
        arguments.update({"name": ".text"})
    if name == "pcode.block":
        arguments.update({"address": "0x1040"})
    if name == "pcode.varnode_uses":
        arguments.update({"function_start": "0x1040"})
    if name == "type.apply_at":
        arguments.update({"address": "0x2000", "data_type": "/int"})
    if name == "type.parse_c":
        arguments.update({"declaration": "typedef unsigned demo_u32;"})
    payload = _call_args(ctx, name, arguments)
    assert payload["status"] == "ok"
    assert payload["backend_method"] == TOOL_SPECS_BY_NAME[name]["backend_method"]
    assert payload["args"] == []
    for key, value in arguments.items():
        assert payload["kwargs"][key] == value


def test_health_mcp_and_ghidra_tools_have_stable_semantics() -> None:
    ctx = create_tool_context()

    ping = _call(ctx, "health.ping")
    assert ping == {"status": "ok", "message": "pong"}

    response_format = _call(ctx, "mcp.response_format")
    assert "machine-readable" in response_format["structuredContent"]
    assert "summary" in response_format["content"]
    assert "tool failed" in response_format["isError"]

    info = _call(ctx, "ghidra.info")
    assert info["status"] == "ok"
    assert info["install_dir"] == "/fake/ghidra"
    assert info["ghidra_version"] == "fake-1.0"
    assert info["pyghidra_version"] == "fake-1.0"
    assert info["jvm_started"] is True

    called = _call(
        ctx,
        "ghidra.call",
        target="fake.target",
        args=[1, "two"],
        kwargs={"flag": True},
    )
    assert called["target"] == "fake.target"
    assert called["callable"] is True
    assert called["result"] == {"args": [1, "two"], "kwargs": {"flag": True}}
    assert called["mode_transitioned"] is False

    evaluated = _call(ctx, "ghidra.eval", code="print('semantic eval')\n_ = 7")
    assert evaluated["result"] == 7
    assert evaluated["mode_transitioned"] is False

    scripted = _call(
        ctx,
        "ghidra.script",
        path="/tmp/demo.py",
        script_args=["--mode", "semantic"],
    )
    assert scripted["path"] == "/tmp/demo.py"
    assert scripted["session_id"] == ctx.session_id
    assert "semantic" in scripted["stdout"]


def test_analysis_and_task_tools_cover_option_and_task_lifecycle() -> None:
    ctx = create_tool_context(seed=False)

    listed = _call(ctx, "analysis.options.list", query="Decompiler")
    _assert_count_items(listed)
    assert listed["items"][0]["name"] == "Decompiler Parameter ID"

    got = _call(ctx, "analysis.options.get", name="Decompiler Parameter ID")
    assert got["name"] == "Decompiler Parameter ID"
    assert got["current"] is True

    updated_option = _call(
        ctx,
        "analysis.options.set",
        name="Decompiler Parameter ID",
        value=False,
    )
    assert updated_option["current"] is False
    assert updated_option["value"] == "False"

    got_after = _call(ctx, "analysis.options.get", name="Decompiler Parameter ID")
    assert got_after["current"] is False

    status_before = _call(ctx, "analysis.status")
    assert status_before["status"] == "completed"
    assert status_before["has_log"] is False

    task_from_analysis = _call(ctx, "analysis.update")
    assert task_from_analysis["status"] == "completed"
    assert task_from_analysis["kind"] == "analysis.update_and_wait"
    task_id = task_from_analysis["task_id"]

    task_status = _call_args(ctx, "task.status", {"task_id": task_id})
    assert task_status["task_id"] == task_id
    assert task_status["status"] == "completed"

    task_result = _call_args(ctx, "task.result", {"task_id": task_id})
    assert task_result["task_id"] == task_id
    assert task_result["result"]["status"] == "completed"

    cancelled = _call_args(ctx, "task.cancel", {"task_id": task_id})
    assert cancelled["task_id"] == task_id
    assert cancelled["cancelled"] is True
    assert cancelled["status"] == "cancelled"

    cancelled_status = _call_args(ctx, "task.status", {"task_id": task_id})
    assert cancelled_status["cancel_requested"] is True
    assert cancelled_status["status"] == "cancelled"

    analysis_task = _call(ctx, "task.analysis_update")
    assert analysis_task["session_id"] == ctx.session_id
    assert analysis_task["status"] == "completed"

    waited = _call(ctx, "analysis.update_and_wait")
    assert waited["status"] == "completed"
    assert waited["log"] == "fake analysis complete"


def test_program_and_project_tools_manage_sessions_modes_and_project_views() -> None:
    ctx = create_tool_context(seed=False)
    sample_name = "ls"
    sample_program_path = "/ls"

    summary = _call(ctx, "program.summary")
    assert summary["session_id"] == ctx.session_id
    assert summary["program_name"] == sample_name
    assert summary["program_path"] == sample_program_path

    initial = _call_args(ctx, "program.list_open", {})
    assert initial["count"] == 1
    assert initial["sessions"][0]["session_id"] == ctx.session_id

    opened = _call_args(
        ctx,
        "program.open",
        {
            "path": resolve_sample_binary_path(),
            "read_only": True,
            "update_analysis": False,
        },
    )
    opened_bytes = _call_args(
        ctx,
        "program.open_bytes",
        {
            "data_base64": "AA==",
            "filename": "bytes.bin",
            "read_only": False,
            "update_analysis": False,
        },
    )
    project_opened = _call(ctx, "project.program.open", path=sample_program_path)
    existing_project = _call_args(
        ctx,
        "project.program.open_existing",
        {"project_location": "/tmp/project", "project_name": "demo_project"},
    )

    opened_summary = _call_args(ctx, "program.summary", {"session_id": opened["session_id"]})
    assert opened_summary["read_only"] is True
    assert opened_summary["program_name"] == sample_name

    open_sessions = _call_args(ctx, "program.list_open", {})
    session_ids = {session["session_id"] for session in open_sessions["sessions"]}
    assert {
        ctx.session_id,
        opened["session_id"],
        opened_bytes["session_id"],
        project_opened["session_id"],
        existing_project["session_id"],
    }.issubset(session_ids)

    mode = _call(ctx, "program.mode.get")
    assert mode["read_only"] is False
    toggled = _call(ctx, "program.mode.set", read_only=True)
    assert toggled["read_only"] is True
    assert _call(ctx, "program.mode.get")["read_only"] is True
    restored = _call(ctx, "program.mode.set", read_only=False)
    assert restored["read_only"] is False

    rebased = _call(ctx, "program.image_base.set", image_base="0x2000")
    assert rebased["image_base"] == "0x2000"

    saved = _call(ctx, "program.save")
    assert saved["saved"] is True

    saved_as = _call(ctx, "program.save_as", program_name="saved.bin")
    assert saved_as["saved_as"] is True
    assert saved_as["program_name"] == "saved.bin"
    assert saved_as["program_path"] == "/saved.bin"

    project_files = _call(ctx, "project.files.list")
    _assert_count_items(project_files)
    assert _item_matching(project_files["items"], path="/saved.bin", name="saved.bin") is not None

    info = _call(ctx, "project.file.info", path="/saved.bin")
    assert info["file"]["path"] == "/saved.bin"
    assert info["file"]["content_type"] == "Program"

    folders = _call(ctx, "project.folders.list")
    _assert_count_items(folders)
    assert _item_matching(folders["items"], path="/analysis") is not None

    search_hit = _call(ctx, "project.search.programs", query="saved")
    _assert_count_items(search_hit)
    assert search_hit["items"][0]["name"] == "saved.bin"
    search_miss = _call(ctx, "project.search.programs", query="missing")
    assert search_miss["count"] == 0

    exported_project = _call(ctx, "project.export", destination="/tmp/export.gpr")
    assert exported_project["exported"] is True
    assert exported_project["path"] == "/tmp/export.gpr"

    exported_binary = _call(ctx, "program.export_binary", path="/tmp/out.bin")
    assert exported_binary["exported"] is True
    assert exported_binary["path"] == "/tmp/out.bin"

    closed = _call_args(ctx, "program.close", {"session_id": opened["session_id"]})
    assert closed["closed"] is True
    remaining = _call_args(ctx, "program.list_open", {})
    remaining_ids = {session["session_id"] for session in remaining["sessions"]}
    assert opened["session_id"] not in remaining_ids


def test_transaction_tools_manage_undo_redo_state() -> None:
    ctx = create_tool_context(seed=False)

    status_initial = _call(ctx, "transaction.status")
    assert status_initial["can_undo"] is False
    assert status_initial["can_redo"] is False

    begun = _call(ctx, "transaction.begin", description="semantic tx")
    assert begun["active_transaction"]["description"] == "semantic tx"
    assert begun["active_transaction"]["id"] == 1

    status = _call(ctx, "transaction.status")
    assert status["active_transaction"]["description"] == "semantic tx"

    committed = _call(ctx, "transaction.commit")
    assert committed["active_transaction"] is None
    assert committed["can_undo"] is True

    undone = _call(ctx, "transaction.undo")
    assert undone["can_undo"] is False
    assert undone["can_redo"] is True

    redone = _call(ctx, "transaction.redo")
    assert redone["can_undo"] is True
    assert redone["can_redo"] is False

    _call(ctx, "transaction.begin", description="revert tx")
    reverted = _call(ctx, "transaction.revert")
    assert reverted["active_transaction"] is None
    assert reverted["can_redo"] is False


def test_listing_tools_expose_instruction_and_data_relationships() -> None:
    ctx = create_tool_context()

    units = _call(ctx, "listing.code_units.list", kind="instruction")
    _assert_count_items(units)
    assert all(item["kind"] == "instruction" for item in units["items"])

    at = _call(ctx, "listing.code_unit.at", address="0x1000")
    before = _call(ctx, "listing.code_unit.before", address="0x1001")
    after = _call(ctx, "listing.code_unit.after", address="0x1000")
    containing = _call(ctx, "listing.code_unit.containing", address="0x2002")
    assert at["code_unit"]["mnemonic"] == "PUSH"
    assert before["code_unit"]["address"] == "0x1000"
    assert after["code_unit"]["address"] == "0x1001"
    assert containing["code_unit"]["address"] == "0x2000"
    assert containing["code_unit"]["kind"] == "data"

    typed = _call(ctx, "listing.data.at", address="0x2000")
    assert typed["defined"] is True
    assert typed["data"]["value"] == '"Hello"'

    typed_list = _call(ctx, "listing.data.list")
    _assert_count_items(typed_list)
    assert typed_list["items"][0]["address"] == "0x2000"

    created = _call(ctx, "listing.data.create", address="0x1300", data_type="/int", length=4)
    assert created["data"]["address"] == "0x1300"
    assert created["data"]["data_type"] == "/int"

    cleared = _call(ctx, "listing.data.clear", address="0x1300", length=4)
    assert cleared["cleared"] is True
    assert cleared["address"] == "0x1300"

    disassembled_range = _call(ctx, "listing.disassemble.range", start="0x1000", length=4)
    assert disassembled_range["count"] == 3
    assert disassembled_range["items"][0]["mnemonic"] == "PUSH"

    disassembled_function = _call(ctx, "listing.disassemble.function", address="0x1040")
    assert disassembled_function["count"] == 3
    assert disassembled_function["count"] == 3

    seeded = _call(ctx, "listing.disassemble.seed", address="0x1100")
    assert seeded["seed"] == "0x1100"
    assert seeded["count"] == 3
    assert _call(ctx, "listing.code_unit.at", address="0x1100")["code_unit"]["mnemonic"] == "PUSH"

    removed = _call(ctx, "listing.clear", start="0x1000", length=1)
    assert removed["cleared"] == 1
    assert _call(ctx, "listing.code_unit.at", address="0x1000")["code_unit"] is None


def test_memory_patch_and_context_tools_round_trip_changes() -> None:
    ctx = create_tool_context()

    blocks = _call(ctx, "memory.blocks.list")
    _assert_count_items(blocks)
    assert blocks["items"][0]["name"] == ".text"

    before = _call(ctx, "memory.read", address="0x1000", length=4)
    assert before["data_hex"] == "00010203"

    written = _call(ctx, "memory.write", address="0x1000", data_hex="dead")
    assert written["written"] == 2
    after = _call(ctx, "memory.read", address="0x1000", length=4)
    assert after["data_hex"].startswith("dead")

    assembled = _call(ctx, "patch.assemble", address="0x1000", assembly="nop")
    assert assembled["written"] == 1
    assert _call(ctx, "memory.read", address="0x1000", length=1)["data_hex"] == "90"

    nopped = _call(ctx, "patch.nop", address="0x1001", length=1)
    assert nopped["patched"] is True
    assert _call(ctx, "memory.read", address="0x1000", length=2)["data_hex"] == "9090"

    inverted = _call(ctx, "patch.branch_invert", address="0x1002")
    assert inverted["patched"] is True
    assert _call(ctx, "memory.read", address="0x1000", length=4)["data_hex"] == "90900303"

    context_set = _call(
        ctx,
        "context.set",
        register="TMode",
        start="0x1010",
        length=2,
        value=7,
    )
    assert context_set["range"]["value"] == 7
    point = _call(ctx, "context.get", register="TMode", address="0x1010")
    assert _item_matching(point["ranges"], value=7, start="0x1010", end="0x1011") is not None
    ranges = _call(ctx, "context.ranges", register="TMode")
    assert _item_matching(ranges["ranges"], value=7, start="0x1010", end="0x1011") is not None


def test_annotation_tools_persist_comments_bookmarks_tags_metadata_sources_and_relocations() -> (
    None
):
    ctx = create_tool_context()

    comment = _call(
        ctx,
        "comment.set",
        address="0x1040",
        scope="listing",
        comment_type="eol",
        comment="triage note",
    )
    assert comment["comment"] == "triage note"
    fetched = _call(ctx, "comment.get", address="0x1040", scope="listing", comment_type="eol")
    assert fetched["comment"] == "triage note"
    all_comments = _call(ctx, "comment.get_all", address="0x1040")
    assert _item_matching(all_comments["items"], comment_type="eol") is not None
    listed_comments = _call(ctx, "comment.list", query="demo")
    _assert_count_items(listed_comments)
    assert all("demo" in item["comment"] for item in listed_comments["items"])

    bookmarks = _call(ctx, "bookmark.list")
    _assert_count_items(bookmarks)
    assert _item_matching(bookmarks["items"], address="0x1040", category="RE") is not None
    added_bookmark = _call(
        ctx,
        "bookmark.add",
        address="0x1050",
        bookmark_type="Info",
        category="QA",
        comment="follow-up",
    )
    assert added_bookmark["bookmark"]["category"] == "QA"
    after_add = _call(ctx, "bookmark.list")
    assert _item_matching(after_add["items"], address="0x1050", category="QA") is not None
    removed_bookmark = _call(ctx, "bookmark.remove", address="0x1050")
    assert removed_bookmark["removed"] == 1
    assert _item_matching(_call(ctx, "bookmark.list")["items"], address="0x1050") is None
    cleared = _call(ctx, "bookmark.clear", start="0x1040", length=4)
    assert cleared["cleared"] >= 1
    remaining_bookmarks = _call(ctx, "bookmark.list")
    assert remaining_bookmarks["count"] == 0

    tags = _call(ctx, "tag.list")
    _assert_count_items(tags)
    assert "entrypoint" in tags["items"][0]["tags"]
    added_tag = _call(ctx, "tag.add", function_start="0x1200", name="helper")
    assert "helper" in added_tag["tags"]
    stats = _call(ctx, "tag.stats")
    _assert_count_items(stats)
    assert _item_matching(stats["items"], name="helper") is not None
    removed_tag = _call(ctx, "tag.remove", function_start="0x1200", name="helper")
    assert removed_tag["removed"] is True
    assert _item_matching(_call(ctx, "tag.stats")["items"], name="helper") is None

    empty_meta = _call(ctx, "metadata.query", key="triage.owner")
    assert empty_meta["key"] == "triage.owner"
    assert empty_meta["value"] is None
    stored = _call(ctx, "metadata.store", key="triage.owner", value={"name": "mcp"})
    assert stored["value"] == {"name": "mcp"}
    queried = _call(ctx, "metadata.query", key="triage.owner")
    assert queried["value"] == {"name": "mcp"}
    _call(ctx, "metadata.store", key="triage.owner", value={"name": "updated"})
    overwritten = _call(ctx, "metadata.query", key="triage.owner")
    assert overwritten["value"] == {"name": "updated"}

    source_files = _call(ctx, "source.file.list")
    _assert_count_items(source_files)
    added_file = _call(ctx, "source.file.add", path="/tmp/demo2.c")
    assert added_file["source_file"]["path"] == "/tmp/demo2.c"
    assert _item_matching(_call(ctx, "source.file.list")["items"], path="/tmp/demo2.c") is not None
    removed_file = _call(ctx, "source.file.remove", path="/tmp/demo2.c")
    assert removed_file["removed"] == 1
    assert _item_matching(_call(ctx, "source.file.list")["items"], path="/tmp/demo2.c") is None

    source_maps = _call(ctx, "source.map.list")
    _assert_count_items(source_maps)
    assert _item_matching(source_maps["items"], file_path="/tmp/demo.c", line=12) is not None
    added_map = _call(
        ctx,
        "source.map.add",
        path="/tmp/demo2.c",
        line_number=13,
        base_address="0x1050",
        length=4,
    )
    assert added_map["source_map"]["file_path"] == "/tmp/demo2.c"
    ctx.backend.source_map_add(
        ctx.session_id,
        path="/tmp/keep.c",
        line_number=9,
        base_address="0x1060",
        length=4,
    )
    removed_map = _call(
        ctx,
        "source.map.remove",
        path="/tmp/demo.c",
        line_number=12,
        base_address="0x1040",
    )
    assert removed_map["removed"] == 1
    remaining_maps = _call(ctx, "source.map.list")
    assert _item_matching(remaining_maps["items"], file_path="/tmp/demo.c", line=12) is None
    assert _item_matching(remaining_maps["items"], file_path="/tmp/keep.c", line=9) is not None

    empty_relocations = _call(ctx, "relocation.list")
    assert empty_relocations["count"] == 0
    relocation = _call(
        ctx,
        "relocation.add",
        address="0x1040",
        type="R_X86_64_JUMP_SLOT",
        values=[4],
    )
    assert relocation["relocation"]["type"] == "R_X86_64_JUMP_SLOT"
    relocations = _call(ctx, "relocation.list")
    _assert_count_items(relocations)
    assert any(
        item["address"] == "0x1040" and item.get("values") == [4] for item in relocations["items"]
    )


def test_symbol_namespace_class_and_external_tools_manage_symbol_surfaces() -> None:
    ctx = create_tool_context()

    symbol_list = _call(ctx, "symbol.list")
    _assert_count_items(symbol_list)
    assert _item_matching(symbol_list["items"], name="main_label", address="0x1040") is not None

    created_namespace = _call(ctx, "namespace.create", name="SemanticNs")
    assert created_namespace["namespace"]["name"] == "SemanticNs"
    created_class = _call(ctx, "class.create", name="SemanticClass", parent="SemanticNs")
    assert created_class["class"]["parent"] == "SemanticNs"

    created_symbol = _call(ctx, "symbol.create", address="0x1050", name="semantic_label")
    assert created_symbol["symbol"]["address"] == "0x1050"
    looked_up = _call(ctx, "symbol.by_name", name="semantic")
    _assert_count_items(looked_up)
    assert _item_matching(looked_up["items"], name="semantic_label", address="0x1050") is not None

    moved = _call(
        ctx,
        "symbol.namespace.move",
        address="0x1040",
        name="main_label",
        namespace="MovedNs",
    )
    assert moved["symbol"]["namespace"] == "MovedNs"

    renamed = _call(
        ctx,
        "symbol.rename",
        address="0x1040",
        old_name="main_label",
        new_name="renamed_label",
    )
    assert renamed["symbol"]["name"] == "renamed_label"
    renamed_lookup = _call(ctx, "symbol.by_name", name="renamed_label")
    assert _item_matching(renamed_lookup["items"], name="renamed_label") is not None
    assert (
        _item_matching(_call(ctx, "symbol.by_name", name="main_label")["items"], name="main_label")
        is None
    )

    _call(ctx, "symbol.create", address="0x1040", name="secondary_label")
    primary = _call(ctx, "symbol.primary.set", address="0x1040", name="secondary_label")
    assert primary["symbol"]["name"] == "secondary_label"
    same_address = [
        item
        for item in _call(ctx, "symbol.list")["items"]
        if item["address"] == "0x1040"
        and item["name"] in {"main", "renamed_label", "secondary_label"}
    ]
    assert len([item for item in same_address if item["primary"]]) == 1

    deleted = _call(ctx, "symbol.delete", address="0x1050", name="semantic_label")
    assert deleted["deleted"] is True
    assert (
        _item_matching(
            _call(ctx, "symbol.by_name", name="semantic_label")["items"], name="semantic_label"
        )
        is None
    )

    libraries = _call(ctx, "external.library.list")
    _assert_count_items(libraries)
    created_library = _call(ctx, "external.library.create", name="libextra.so")
    assert created_library["library"]["name"] == "libextra.so"
    assert (
        _item_matching(_call(ctx, "external.library.list")["items"], name="libextra.so") is not None
    )

    library_path = _call(
        ctx,
        "external.library.set_path",
        name="libdemo.so",
        path="/tmp/updated-libdemo.so",
    )
    assert library_path["library"]["path"] == "/tmp/updated-libdemo.so"

    created_location = _call(
        ctx,
        "external.location.create",
        library_name="libdemo.so",
        label="puts2",
        external_address="0x4010",
    )
    assert created_location["location"]["symbol_type"] == "Label"
    created_function = _call(
        ctx,
        "external.function.create",
        library_name="libdemo.so",
        name="puts3",
        external_address="0x4020",
    )
    assert created_function["location"]["symbol_type"] == "Function"
    looked_up_location = _call(ctx, "external.location.get", name="puts3")
    assert looked_up_location["location"]["label"] == "puts3"
    assert looked_up_location["location"]["symbol_type"] == "Function"

    entrypoints = _call(ctx, "external.entrypoint.list")
    _assert_count_items(entrypoints)
    added_entry = _call(ctx, "external.entrypoint.add", address="0x4010")
    assert added_entry["entrypoint"] == "0x4010"
    assert (
        _item_matching(_call(ctx, "external.entrypoint.list")["items"], address="0x4010")
        is not None
    )
    removed_entry = _call(ctx, "external.entrypoint.remove", address="0x4010")
    assert removed_entry["removed"] is True
    assert _item_matching(_call(ctx, "external.entrypoint.list")["items"], address="0x4010") is None

    imports = _call(ctx, "external.imports.list")
    exports = _call(ctx, "external.exports.list")
    _assert_count_items(imports)
    _assert_count_items(exports)
    assert imports["items"][0]["external"] is True
    assert exports["items"][0]["symbol"]["name"] == "entry"


def test_reference_and_equate_tools_manage_cross_references() -> None:
    ctx = create_tool_context()

    base_from = _call(ctx, "reference.from", address="0x1048")
    base_to = _call(ctx, "reference.to", address="0x1010")
    _assert_count_items(base_from)
    _assert_count_items(base_to)

    created_memory = _call(
        ctx,
        "reference.create.memory",
        from_address="0x1050",
        to_address="0x1040",
        reference_type="DATA",
    )
    assert created_memory["reference"]["kind"] == "memory"
    assert _call(ctx, "reference.from", address="0x1050")["count"] == 1
    assert _call(ctx, "reference.to", address="0x1040")["count"] >= 1

    created_stack = _call(
        ctx,
        "reference.create.stack",
        from_address="0x1054",
        stack_offset=16,
    )
    assert created_stack["reference"]["to"] == "stack:16"
    session_record = ctx.backend._sessions[ctx.session_id]
    assert any(
        item["from"] == "0x1054" and item["to"] == "stack:16" for item in session_record.references
    )

    created_register = _call(
        ctx,
        "reference.create.register",
        from_address="0x1058",
        register="TMode",
    )
    assert created_register["reference"]["to"] == "register:TMode"
    assert any(
        item["from"] == "0x1058" and item["to"] == "register:TMode"
        for item in session_record.references
    )

    created_external = _call(
        ctx,
        "reference.create.external",
        from_address="0x105c",
        library_name="libdemo.so",
        label="puts",
    )
    assert created_external["reference"]["external"] is True
    assert created_external["reference"]["to"] == "external:libdemo.so::puts"
    assert any(
        item["from"] == "0x105c" and item["to"] == "external:libdemo.so::puts"
        for item in session_record.references
    )

    assert _call(ctx, "reference.from", address="0x1048")["count"] == base_from["count"]
    assert _call(ctx, "reference.to", address="0x1010")["count"] == base_to["count"]

    associated = _call(
        ctx,
        "reference.association.set",
        from_address="0x1048",
        to_address="0x1010",
        symbol_address="0x1010",
    )
    assert associated["updated"] >= 1
    assert any(
        item["from"] == "0x1048" and item["to"] == "0x1010" and item["association"] == "0x1010"
        for item in session_record.references
    )

    removed_association = _call(
        ctx,
        "reference.association.remove",
        from_address="0x1048",
        to_address="0x1010",
    )
    assert removed_association["updated"] >= 1
    assert all(
        item["association"] is None
        for item in session_record.references
        if item["from"] == "0x1048" and item["to"] == "0x1010"
    )

    _call(
        ctx,
        "reference.create.memory",
        from_address="0x1060",
        to_address="0x1010",
        primary=False,
    )
    primary_set = _call(
        ctx,
        "reference.primary.set",
        from_address="0x1060",
        to_address="0x1010",
    )
    assert primary_set["updated"] is True
    assert (
        len(
            [
                item
                for item in session_record.references
                if item["from"] == "0x1060" and item["primary"]
            ]
        )
        == 1
    )

    deleted_ref = _call(
        ctx,
        "reference.delete",
        from_address="0x1050",
        to_address="0x1040",
    )
    assert deleted_ref["deleted"] == 1
    assert _call(ctx, "reference.from", address="0x1050")["count"] == 0

    cleared_from = _call(ctx, "reference.clear_from", from_address="0x1054")
    assert cleared_from["cleared"] == 1
    assert _call(ctx, "reference.from", address="0x1054")["count"] == 0

    cleared_to = _call(ctx, "reference.clear_to", to_address="0x1010")
    assert cleared_to["cleared"] >= 1
    assert _call(ctx, "reference.to", address="0x1010")["count"] == 0

    equates_before = _call(ctx, "equate.list", address="0x1044")
    _assert_count_items(equates_before)
    created_equate = _call(ctx, "equate.create", address="0x1050", name="MEANING", value=42)
    assert created_equate["equate"]["name"] == "MEANING"
    assert (
        _item_matching(
            _call(ctx, "equate.list", address="0x1050")["items"], name="MEANING", value=42
        )
        is not None
    )
    deleted_equate = _call(ctx, "equate.delete", name="ANSWER")
    assert deleted_equate["deleted"] == 1
    assert (
        _item_matching(_call(ctx, "equate.list", address="0x1044")["items"], name="ANSWER") is None
    )
    cleared_equates = _call(ctx, "equate.clear_range", start="0x1050", length=4)
    assert cleared_equates["cleared"] == 1
    assert _call(ctx, "equate.list", address="0x1050")["count"] == 0


def test_function_parameter_variable_and_stackframe_tools_keep_views_in_sync() -> None:
    ctx = create_tool_context()

    function_list = _call(ctx, "function.list")
    _assert_count_items(function_list)
    assert _item_matching(function_list["items"], name="helper_stub") is not None

    at = _call(ctx, "function.at", address="0x1040")
    assert at["function"]["name"] == "main"
    by_name = _call(ctx, "function.by_name", name="main")
    _assert_count_items(by_name)
    assert by_name["items"][0]["entry_point"] == "0x1040"

    callers = _call(ctx, "function.callers", function_start="0x1010")
    callees = _call(ctx, "function.callees", function_start="0x1040")
    _assert_count_items(callers)
    _assert_count_items(callees)
    assert callers["items"][0]["name"] == "main"
    assert callees["items"][0]["name"] == "add_numbers"

    conventions = _call(ctx, "function.calling_conventions.list")
    _assert_count_items(conventions)
    assert "__stdcall" in conventions["items"]

    signature_before = _call(ctx, "function.signature.get", function_start="0x1200")
    assert signature_before["signature"] == "void helper_stub(int x)"
    signature_set = _call(
        ctx,
        "function.signature.set",
        function_start="0x1200",
        signature="long helper_stub(void)",
    )
    assert signature_set["signature_source"] == "USER_DEFINED"
    assert (
        _call(ctx, "function.signature.get", function_start="0x1200")["signature"]
        == signature_set["signature"]
    )

    renamed = _call(ctx, "function.rename", function_start="0x1200", name="helper_renamed")
    assert renamed["function"]["name"] == "helper_renamed"
    assert (
        _item_matching(
            _call(ctx, "function.by_name", name="helper_renamed")["items"], name="helper_renamed"
        )
        is not None
    )

    body = _call(ctx, "function.body.set", function_start="0x1200", body_end="0x1210")
    assert body["function"]["body_end"] == "0x1210"

    calling_convention = _call(
        ctx,
        "function.calling_convention.set",
        function_start="0x1200",
        calling_convention="__stdcall",
    )
    assert calling_convention["function"]["calling_convention"] == "__stdcall"

    flags = _call(
        ctx,
        "function.flags.set",
        function_start="0x1200",
        noreturn=True,
        inline=True,
        varargs=True,
    )
    assert flags["flags"]["noreturn"] is True
    assert flags["flags"]["inline"] is True
    assert flags["flags"]["varargs"] is True

    thunked = _call(
        ctx,
        "function.thunk.set",
        function_start="0x1200",
        thunk_target="0x1010",
    )
    assert thunked["function"]["thunk"] is True
    assert _call(ctx, "function.at", address="0x1200")["function"]["thunk"] is True

    returned = _call(
        ctx,
        "function.return_type.set",
        function_start="0x1200",
        data_type="/long",
    )
    assert returned["function"]["signature"].startswith("long ")
    assert _call(ctx, "function.signature.get", function_start="0x1200")["return_type"] == "/long"

    created = _call(ctx, "function.create", address="0x1300", name="helper_two")
    assert created["function"]["entry_point"] == "0x1300"
    assert _item_matching(_call(ctx, "function.list")["items"], name="helper_two") is not None
    deleted = _call(ctx, "function.delete", function_start="0x1300")
    assert deleted["deleted"] is True
    assert _item_matching(_call(ctx, "function.list")["items"], name="helper_two") is None

    variables_before = _call(ctx, "function.variables", function_start="0x1200")
    assert variables_before["parameters"][0]["name"] == "x"
    assert variables_before["locals"][0]["name"] == "tmp"

    added_param = _call(ctx, "parameter.add", function_start="0x1200", name="y", data_type="/int")
    assert [item["name"] for item in added_param["parameters"]] == ["x", "y"]
    moved_param = _call(ctx, "parameter.move", function_start="0x1200", ordinal=1, new_ordinal=0)
    assert [item["name"] for item in moved_param["parameters"]] == ["y", "x"]
    replaced_param = _call(
        ctx,
        "parameter.replace",
        function_start="0x1200",
        name="x",
        data_type="/long",
        comment="widened",
    )
    assert (
        _item_matching(replaced_param["parameters"], name="x", data_type="/long", comment="widened")
        is not None
    )
    removed_param = _call(ctx, "parameter.remove", function_start="0x1200", name="y")
    assert _item_matching(removed_param["parameters"], name="y") is None

    added_local = _call(
        ctx, "variable.local.create", function_start="0x1200", name="tmp2", data_type="/int"
    )
    assert _item_matching(added_local["locals"], name="tmp2", data_type="/int") is not None
    commented = _call(
        ctx,
        "variable.comment.set",
        function_start="0x1200",
        name="tmp",
        comment="scratch",
    )
    assert _item_matching(commented["locals"], name="tmp", comment="scratch") is not None
    renamed_var = _call(
        ctx,
        "variable.rename",
        function_start="0x1200",
        name="x",
        new_name="x2",
    )
    assert _item_matching(renamed_var["parameters"], name="x2") is not None
    retyped_var = _call(
        ctx,
        "variable.retype",
        function_start="0x1200",
        name="x2",
        data_type="/ulong",
    )
    assert _item_matching(retyped_var["parameters"], name="x2", data_type="/ulong") is not None
    removed_local = _call(ctx, "variable.local.remove", function_start="0x1200", name="tmp2")
    assert _item_matching(removed_local["locals"], name="tmp2") is None

    stackframe = _call(ctx, "stackframe.variables", function_start="0x1200")
    assert (
        _item_matching(stackframe["stackframe"], name="saved_rbp", storage="stack[8]") is not None
    )
    created_stack = _call(
        ctx,
        "stackframe.variable.create",
        function_start="0x1200",
        name="saved_r12",
        stack_offset=16,
        data_type="/int",
    )
    assert (
        _item_matching(created_stack["stackframe"], name="saved_r12", storage="stack[16]")
        is not None
    )
    cleared_stack = _call(
        ctx,
        "stackframe.variable.clear",
        function_start="0x1200",
        stack_offset=16,
    )
    assert _item_matching(cleared_stack["stackframe"], name="saved_r12") is None

    batch = _call(ctx, "function.batch.run")
    _assert_count_items(batch)
    assert all(item["status"] == "ok" for item in batch["items"])


def test_type_layout_and_decompiler_tools_reflect_catalog_and_high_level_state() -> None:
    ctx = create_tool_context()

    listed_types = _call(ctx, "type.list")
    _assert_count_items(listed_types)
    assert _item_matching(listed_types["items"], name="int", path="/int") is not None

    got_type = _call(ctx, "type.get", name="int")
    got_by_id = _call(ctx, "type.get_by_id", type_id=got_type["type"]["id"])
    assert got_by_id["type"] == got_type["type"]

    categories_before = _call(ctx, "type.category.list")
    _assert_count_items(categories_before)
    created_category = _call(ctx, "type.category.create", path="/mcp2")
    assert created_category["category"]["path"] == "/mcp2"
    categories_after = _call(ctx, "type.category.list")
    assert _item_matching(categories_after["items"], path="/mcp2") is not None

    defined = _call(
        ctx,
        "type.define_c",
        declaration="typedef int semantic_int;",
    )
    assert "semantic_int" in defined["type"]["description"]

    renamed = _call(ctx, "type.rename", name="int", new_name="int2")
    assert renamed["type"]["name"] == "int2"
    assert _call(ctx, "type.get", name="int2")["type"]["name"] == "int2"
    deleted = _call(ctx, "type.delete", name="int2")
    assert deleted["deleted"] is True

    archives = _call(ctx, "type.archives.list")
    source_archives = _call(ctx, "type.source_archives.list")
    _assert_count_items(archives)
    _assert_count_items(source_archives)

    created_struct = _call(ctx, "layout.struct.create", name="fresh_struct")
    assert created_struct["struct"]["name"] == "fresh_struct"
    struct_before = _call(ctx, "layout.struct.get", struct_path="/mcp/demo_struct")
    assert struct_before["struct"]["members"][0]["name"] == "field0"
    resized = _call(ctx, "layout.struct.resize", struct_path="/mcp/demo_struct", length=16)
    assert resized["struct"]["length"] == 16
    added_field = _call(
        ctx,
        "layout.struct.field.add",
        struct_path="/mcp/demo_struct",
        field_name="field1",
        data_type="/int",
    )
    assert _item_matching(added_field["struct"]["members"], name="field1") is not None
    renamed_field = _call(
        ctx,
        "layout.struct.field.rename",
        struct_path="/mcp/demo_struct",
        old_name="field0",
        new_name="header",
    )
    assert _item_matching(renamed_field["struct"]["members"], name="header") is not None
    commented_field = _call(
        ctx,
        "layout.struct.field.comment.set",
        struct_path="/mcp/demo_struct",
        field_name="header",
        comment="semantic",
    )
    assert (
        _item_matching(commented_field["struct"]["members"], name="header", comment="semantic")
        is not None
    )
    replaced_field = _call(
        ctx,
        "layout.struct.field.replace",
        struct_path="/mcp/demo_struct",
        offset=0,
        data_type="/char",
        field_name="header",
    )
    assert (
        _item_matching(replaced_field["struct"]["members"], name="header", data_type="/char")
        is not None
    )
    bitfield = _call(
        ctx,
        "layout.struct.bitfield.add",
        struct_path="/mcp/demo_struct",
        byte_offset=4,
        byte_width=4,
        bit_offset=0,
        bit_size=1,
        data_type="/int",
        field_name="flags",
    )
    assert _item_matching(bitfield["struct"]["members"], name="flags", bit_size=1) is not None
    inspected = _call(ctx, "layout.inspect.components", path="/mcp/demo_struct")
    _assert_count_items(inspected)
    cleared_field = _call(
        ctx, "layout.struct.field.clear", struct_path="/mcp/demo_struct", offset=0
    )
    assert all(item["offset"] != 0 for item in cleared_field["struct"]["members"])

    filled = _call(
        ctx, "layout.struct.fill_from_decompiler", function_start="0x1040", name="filled_struct"
    )
    assert len(filled["struct"]["members"]) >= 1

    created_union = _call(ctx, "layout.union.create", name="fresh_union")
    assert created_union["union"]["name"] == "fresh_union"
    added_member = _call(
        ctx,
        "layout.union.member.add",
        union_path="/mcp/demo_union",
        field_name="member1",
        data_type="/int",
    )
    assert _item_matching(added_member["union"]["members"], name="member1") is not None
    removed_member = _call(
        ctx,
        "layout.union.member.remove",
        union_path="/mcp/demo_union",
        field_name="member1",
    )
    assert _item_matching(removed_member["union"]["members"], name="member1") is None

    created_enum = _call(ctx, "layout.enum.create", name="fresh_enum")
    assert created_enum["enum"]["name"] == "fresh_enum"
    added_enum = _call(
        ctx,
        "layout.enum.member.add",
        enum_path="/mcp/demo_enum",
        name="ITEM2",
        value=2,
    )
    assert _item_matching(added_enum["enum"]["members"], name="ITEM2", value=2) is not None
    removed_enum = _call(
        ctx,
        "layout.enum.member.remove",
        enum_path="/mcp/demo_enum",
        name="ITEM2",
    )
    assert _item_matching(removed_enum["enum"]["members"], name="ITEM2") is None

    decompiled = _call(ctx, "decomp.function", function_start="0x1040")
    assert decompiled["decompile_completed"] is True

    tokens = _call(ctx, "decomp.tokens", function_start="0x1040")
    ast = _call(ctx, "decomp.ast", function_start="0x1040")
    assert tokens["count"] == len(tokens["items"])
    assert tokens["items"][0]["text"] == "main"
    assert ast["ast"]["name"] == "main"

    high = _call(ctx, "decomp.high_function.summary", function_start="0x1200")
    assert (
        _item_matching(high["high_symbols"], name="x", kind="parameter", data_type="/int")
        is not None
    )
    assert (
        _item_matching(high["high_symbols"], name="tmp", kind="local", data_type="/int") is not None
    )

    params = _call(
        ctx,
        "decomp.writeback.params",
        function_start="0x1200",
        parameters=[{"name": "arg0", "data_type": "/long"}],
    )
    assert _item_matching(params["parameters"], name="arg0", data_type="/long") is not None
    variables_after_params = _call(ctx, "function.variables", function_start="0x1200")
    assert (
        _item_matching(variables_after_params["parameters"], name="arg0", data_type="/long")
        is not None
    )

    locals_payload = _call(
        ctx,
        "decomp.writeback.locals",
        function_start="0x1200",
        locals=[{"name": "local_0", "data_type": "/int", "storage": "stack[-0x4]"}],
    )
    assert _item_matching(locals_payload["locals"], name="local_0", data_type="/int") is not None
    variables_after_locals = _call(ctx, "function.variables", function_start="0x1200")
    assert (
        _item_matching(variables_after_locals["locals"], name="local_0", data_type="/int")
        is not None
    )

    override_before = _call(ctx, "decomp.override.get", function_start="0x1040", callsite="0x1048")
    assert override_before["override"] is None
    override_after = _call(
        ctx,
        "decomp.override.set",
        function_start="0x1040",
        callsite="0x1048",
        signature="int helper(int x)",
    )
    assert override_after["override"]["signature"] == "int helper(int x)"
    assert (
        _call(ctx, "decomp.override.get", function_start="0x1040", callsite="0x1048")["override"][
            "signature"
        ]
        == "int helper(int x)"
    )

    forward = _call(ctx, "decomp.trace_type.forward", function_start="0x1200", name="arg0")
    backward = _call(ctx, "decomp.trace_type.backward", function_start="0x1200", name="arg0")
    assert forward["items"][0]["symbol"] == "arg0"
    assert backward["items"][0]["direction"] == "backward"

    renamed_global = _call(
        ctx,
        "decomp.global.rename",
        function_start="0x1040",
        name="main",
        new_name="main_renamed",
    )
    assert renamed_global["symbol"]["name"] == "main_renamed"
    retyped_global = _call(
        ctx,
        "decomp.global.retype",
        function_start="0x1040",
        name="main_renamed",
        data_type="/pointer",
    )
    assert retyped_global["data_type"] == "/pointer"


def test_search_graph_and_pcode_tools_return_consistent_relationship_views() -> None:
    ctx = create_tool_context()

    strings = _call(ctx, "search.defined_strings")
    _assert_count_items(strings)
    assert _item_matching(strings["items"], value="Hello") is not None

    text = _call(ctx, "search.text", text="Hello")
    _assert_count_items(text)
    assert "Hello" in text["items"][0]["value"]

    pattern = _call(ctx, "search.bytes", pattern_hex="00010203")
    _assert_count_items(pattern)
    assert pattern["items"][0]["address"] == "0x1000"

    constants = _call(ctx, "search.constants", value=1)
    _assert_count_items(constants)
    assert constants["items"][0]["value"] == 1

    instructions = _call(ctx, "search.instructions", query="ret")
    _assert_count_items(instructions)
    assert all(item["mnemonic"] == "RET" for item in instructions["items"])

    pcode_hits = _call(ctx, "search.pcode", function_start="0x1040", query="copy")
    _assert_count_items(pcode_hits)
    assert "COPY" in pcode_hits["items"][0]["ops"][0]["text"]

    resolved = _call(ctx, "search.resolve", query="main")
    assert resolved["address"] == "0x1040"

    blocks = _call(ctx, "graph.basic_blocks", function_start="0x1040")
    edges = _call(ctx, "graph.cfg.edges", function_start="0x1040")
    paths = _call(
        ctx,
        "graph.call_paths",
        source_function="main",
        target_function="add_numbers",
    )
    _assert_count_items(blocks)
    _assert_count_items(edges)
    _assert_count_items(paths)
    assert blocks["items"][0]["start"] <= blocks["items"][0]["end"]
    assert paths["items"][0]["path"][0] == "main"
    assert paths["items"][0]["path"][-1] == "add_numbers"

    pcode_function = _call(ctx, "pcode.function", function_start="0x1040")
    pcode_op = _call(ctx, "pcode.op.at", address="0x1040")
    _assert_count_items(pcode_function)
    assert pcode_function["function"]["name"] == "main"
    assert pcode_function["items"][0]["ops"][0]["mnemonic"] == "COPY"
    assert pcode_op["ops"][0]["mnemonic"] == "CALL"


def test_semantic_suite_covers_every_tool_name() -> None:
    covered = (
        META_TOOLS
        | ECHO_TOOLS
        | ANALYSIS_TASK_TOOLS
        | PROGRAM_PROJECT_TOOLS
        | TRANSACTION_TOOLS
        | LISTING_TOOLS
        | MEMORY_PATCH_CONTEXT_TOOLS
        | ANNOTATION_TOOLS
        | SYMBOL_EXTERNAL_TOOLS
        | REFERENCE_EQUATE_TOOLS
        | FUNCTION_VAR_TOOLS
        | TYPE_LAYOUT_DECOMP_TOOLS
        | SEARCH_GRAPH_PCODE_TOOLS
    )
    assert covered == EXPECTED_TOOL_NAMES
