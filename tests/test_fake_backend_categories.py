from __future__ import annotations

from ghidra_headless_mcp.fake_ghidra import FakeGhidraBackend


def _open_writable(fake_backend: FakeGhidraBackend) -> str:
    opened = fake_backend.program_open(
        "/tmp/fake-sample.bin",
        read_only=False,
        update_analysis=False,
    )
    return opened["session_id"]


def test_fake_backend_project_listing_and_transaction_categories(
    fake_backend: FakeGhidraBackend,
) -> None:
    session_id = _open_writable(fake_backend)

    summary = fake_backend.program_summary(session_id)
    assert summary["program_name"] == "fake-sample.bin"

    files = fake_backend.project_files_list(session_id)
    assert files["count"] >= 1
    info = fake_backend.project_file_info(session_id, path=f"/{summary['program_name']}")
    assert info["file"]["content_type"] == "Program"

    started = fake_backend.transaction_begin(session_id, description="listing update")
    assert started["active_transaction"]["description"] == "listing update"

    units = fake_backend.listing_code_units_list(session_id, limit=20)
    assert units["count"] >= 3
    containing = fake_backend.listing_code_unit_containing(session_id, address="0x2002")
    assert containing["code_unit"]["kind"] == "data"

    fake_backend.context_set(
        session_id,
        register="TMode",
        start="0x1000",
        length=0x10,
        value=1,
    )
    ranges = fake_backend.context_ranges(session_id)
    assert any(item["value"] == 1 for item in ranges["ranges"])

    seeded = fake_backend.listing_disassemble_seed(session_id, address="0x1100", limit=3)
    assert seeded["count"] == 3
    patched = fake_backend.patch_nop(session_id, address="0x1004", length=2)
    assert patched["patched"] is True

    committed = fake_backend.transaction_commit(session_id)
    assert committed["active_transaction"] is None
    assert committed["can_undo"] is True


def test_fake_backend_symbol_reference_and_annotation_categories(
    fake_backend: FakeGhidraBackend,
) -> None:
    session_id = _open_writable(fake_backend)

    fake_backend.namespace_create(session_id, name="ns_demo")
    fake_backend.class_create(session_id, name="ClassDemo", parent="ns_demo")
    created = fake_backend.symbol_create(session_id, address="0x1040", name="main_label")
    assert created["symbol"]["name"] == "main_label"

    moved = fake_backend.symbol_namespace_move(
        session_id,
        address="0x1040",
        name="main_label",
        namespace="ClassDemo",
    )
    assert moved["symbol"]["namespace"] == "ClassDemo"
    fake_backend.external_library_create(session_id, name="libdemo.so")
    fake_backend.external_library_set_path(
        session_id,
        name="libdemo.so",
        path="/tmp/libdemo.so",
    )
    ext_function = fake_backend.external_function_create(
        session_id,
        library_name="libdemo.so",
        name="puts",
        external_address="0x4000",
    )
    assert ext_function["location"]["symbol_type"] == "Function"
    entrypoints = fake_backend.external_entrypoint_add(session_id, address="0x4000")
    assert entrypoints["added"] is True

    created_ref = fake_backend.reference_create_memory(
        session_id,
        from_address="0x104c",
        to_address="0x1040",
        reference_type="DATA",
    )
    assert created_ref["reference"]["kind"] == "memory"
    refs_to = fake_backend.reference_to(session_id, address="0x1040")
    assert refs_to["count"] >= 1

    equate = fake_backend.equate_create(
        session_id,
        address="0x1044",
        name="ANSWER",
        value=42,
    )
    assert equate["equate"]["value"] == 42
    assert fake_backend.equate_list(session_id, address="0x1044")["count"] == 1

    fake_backend.comment_set(
        session_id,
        address="0x1040",
        comment_type="eol",
        comment="interesting call site",
    )
    all_comments = fake_backend.comment_get_all(session_id, address="0x1040")
    assert all_comments["items"][0]["comment"] == "interesting call site"
    comment_hits = fake_backend.comment_list(session_id, query="interesting")
    assert comment_hits["count"] == 1

    bookmark = fake_backend.bookmark_add(
        session_id,
        address="0x1040",
        bookmark_type="Info",
        category="RE",
        comment="needs review",
    )
    assert bookmark["bookmark"]["category"] == "RE"
    assert fake_backend.bookmark_remove(session_id, address="0x1040")["removed"] == 1

    fake_backend.tag_add(session_id, function_start="0x1040", name="entrypoint")
    tag_stats = fake_backend.tag_stats(session_id)
    assert tag_stats["items"][0]["name"] == "entrypoint"
    assert fake_backend.tag_remove(session_id, function_start="0x1040", name="entrypoint")[
        "removed"
    ]

    fake_backend.metadata_store(session_id, key="triage.owner", value={"name": "mcp"})
    assert fake_backend.metadata_query(session_id, key="triage.owner")["value"]["name"] == "mcp"

    fake_backend.source_file_add(session_id, path="/tmp/demo.c")
    assert fake_backend.source_file_list(session_id)["count"] == 1
    fake_backend.source_map_add(
        session_id,
        path="/tmp/demo.c",
        line_number=12,
        base_address="0x1040",
        length=4,
    )
    assert fake_backend.source_map_list(session_id)["count"] == 1
    fake_backend.relocation_add(
        session_id,
        address="0x1040",
        type="R_X86_64_JUMP_SLOT",
        values=[4],
    )
    assert fake_backend.relocation_list(session_id)["count"] == 1


def test_fake_backend_function_type_layout_decomp_and_graph_categories(
    fake_backend: FakeGhidraBackend,
) -> None:
    session_id = _open_writable(fake_backend)

    functions = fake_backend.function_list(session_id)
    assert functions["count"] >= 3

    created = fake_backend.function_create(session_id, address="0x1200", name="helper_stub")
    assert created["function"]["name"] == "helper_stub"
    fake_backend.function_body_set(session_id, function_start="0x1200", body_end="0x1210")
    fake_backend.function_calling_convention_set(
        session_id,
        function_start="0x1200",
        calling_convention="__stdcall",
    )
    fake_backend.function_flags_set(
        session_id,
        function_start="0x1200",
        noreturn=True,
        inline=True,
    )
    fake_backend.function_thunk_set(
        session_id,
        function_start="0x1200",
        thunk_target="0x1010",
    )
    fake_backend.function_return_type_set(session_id, function_start="0x1200", data_type="/int")

    fake_backend.parameter_add(
        session_id,
        function_start="0x1200",
        name="x",
        data_type="/int",
        ordinal=0,
    )
    fake_backend.parameter_replace(
        session_id,
        function_start="0x1200",
        name="x",
        data_type="/long",
        comment="widened",
    )
    fake_backend.variable_local_create(
        session_id,
        function_start="0x1200",
        name="tmp",
        data_type="/int",
        storage="stack[-0x10]",
    )
    fake_backend.variable_comment_set(
        session_id,
        function_start="0x1200",
        name="tmp",
        comment="scratch slot",
    )
    fake_backend.stackframe_variable_create(
        session_id,
        function_start="0x1200",
        name="saved_rbp",
        data_type="/pointer",
        stack_offset=8,
    )
    variables = fake_backend.function_variables(session_id, function_start="0x1200")
    assert variables["parameters"][0]["data_type"] == "/long"
    assert variables["locals"][0]["comment"] == "scratch slot"

    fake_backend.type_category_create(session_id, path="/mcp")
    created_type = fake_backend.type_define_c(
        session_id,
        declaration="typedef int demo_int;",
        name="demo_int",
        category="/mcp",
    )
    assert created_type["type"]["category"] == "/mcp"
    assert (
        fake_backend.type_get_by_id(session_id, type_id=created_type["type"]["id"])["type"]["name"]
        == "demo_int"
    )
    assert fake_backend.type_archives_list(session_id)["count"] >= 1
    assert fake_backend.type_source_archives_list(session_id)["count"] >= 1

    struct = fake_backend.layout_struct_create(
        session_id, name="demo_struct", path="/mcp/demo_struct"
    )
    assert struct["struct"]["kind"] == "struct"
    fake_backend.layout_struct_field_add(
        session_id,
        path="/mcp/demo_struct",
        name="field_0",
        data_type="/int",
        offset=0,
        length=4,
    )
    fake_backend.layout_struct_field_comment_set(
        session_id,
        path="/mcp/demo_struct",
        name="field_0",
        comment="seed field",
    )
    fake_backend.layout_struct_bitfield_add(
        session_id,
        path="/mcp/demo_struct",
        name="flags",
        data_type="/uint",
        offset=4,
        bit_offset=0,
        bit_size=1,
    )
    inspected = fake_backend.layout_inspect_components(session_id, path="/mcp/demo_struct")
    assert inspected["count"] >= 2

    fake_backend.layout_union_create(session_id, name="demo_union", path="/mcp/demo_union")
    fake_backend.layout_union_member_add(
        session_id,
        path="/mcp/demo_union",
        name="as_int",
        data_type="/int",
    )
    fake_backend.layout_enum_create(session_id, name="demo_enum", path="/mcp/demo_enum")
    fake_backend.layout_enum_member_add(
        session_id,
        path="/mcp/demo_enum",
        name="ENUM_A",
        value=1,
    )

    high = fake_backend.decomp_high_function_summary(session_id, function_start="0x1010")
    assert high["function"]["name"] == "add_numbers"
    fake_backend.decomp_writeback_params(
        session_id,
        function_start="0x1200",
        parameters=[{"name": "arg0", "data_type": "/int"}],
    )
    fake_backend.decomp_writeback_locals(
        session_id,
        function_start="0x1200",
        locals=[{"name": "local_0", "data_type": "/int", "storage": "stack[-0x4]"}],
    )
    fake_backend.decomp_override_set(
        session_id,
        function_start="0x1040",
        callsite="0x1048",
        signature="int helper(int x)",
    )
    assert (
        fake_backend.decomp_override_get(
            session_id,
            function_start="0x1040",
            callsite="0x1048",
        )["override"]["signature"]
        == "int helper(int x)"
    )
    assert (
        fake_backend.decomp_trace_type_forward(session_id, function_start="0x1010", name="a")[
            "count"
        ]
        == 1
    )

    fake_backend.decomp_global_rename(
        session_id,
        function_start="0x1040",
        name="main",
        new_name="main_global",
    )
    fake_backend.decomp_global_retype(
        session_id,
        function_start="0x1040",
        name="main_global",
        data_type="/pointer",
    )

    fake_backend.comment_set(
        session_id,
        address="0x1048",
        comment="call helper",
    )
    blocks = fake_backend.graph_basic_blocks(session_id, function_start="0x1040")
    assert blocks["count"] == 2
    edges = fake_backend.graph_cfg_edges(session_id, function_start="0x1040")
    assert edges["items"][0]["type"] == "fallthrough"
    paths = fake_backend.graph_callgraph_paths(
        session_id,
        source_function="main",
        target_function="add_numbers",
    )
    assert paths["items"][0]["path"] == ["main", "add_numbers"]
    assert fake_backend.search_comments(session_id, query="helper")["count"] == 1
    assert fake_backend.search_xrefs_range(session_id, start="0x1040", end="0x1050")["count"] >= 1
