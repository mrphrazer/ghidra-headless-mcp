from __future__ import annotations

import base64
from pathlib import Path

import pytest
from ghidra_headless_mcp.backend import GhidraBackend

pytestmark = pytest.mark.live


def _backend_method(backend: GhidraBackend, *candidates: str):
    for candidate in candidates:
        method = getattr(backend, candidate, None)
        if callable(method):
            return method
    raise AssertionError(f"none of the backend methods exist: {candidates!r}")


def _open(
    real_backend: GhidraBackend,
    sample_binary_path: str,
    *,
    read_only: bool,
    update_analysis: bool = False,
    project_location: str | None = None,
    project_name: str | None = None,
) -> str:
    summary = _backend_method(real_backend, "program_open", "session_open")(
        sample_binary_path,
        update_analysis=update_analysis,
        read_only=read_only,
        project_location=project_location,
        project_name=project_name,
    )
    return summary["session_id"]


def _find_function_start(functions: dict[str, object], name: str) -> str:
    for item in functions["items"]:  # type: ignore[index]
        assert isinstance(item, dict)
        if item.get("name") == name:
            start = item.get("entry_point")
            assert isinstance(start, str)
            return start
    raise AssertionError(f"function not found: {name}")


def test_real_backend_session_open_list_close_and_alternate_open_modes(
    real_backend: GhidraBackend,
    sample_binary_path: str,
    tmp_path: Path,
) -> None:
    session_ids: list[str] = []
    try:
        session_id = _open(real_backend, sample_binary_path, read_only=True)
        session_ids.append(session_id)

        summary = _backend_method(real_backend, "program_summary", "binary_summary")(session_id)
        assert summary["filename"] == sample_binary_path
        assert summary["language_id"]
        assert summary["read_only"] is True

        listed = _backend_method(real_backend, "program_list", "session_list")()
        assert listed["count"] >= 1

        mode = _backend_method(real_backend, "program_mode_get", "program_mode", "session_mode")(
            session_id
        )
        assert mode["read_only"] is True
        assert mode["deterministic"] is True

        analyzed = real_backend.analysis_update_and_wait(session_id)
        assert analyzed["status"] == "completed"

        with open(sample_binary_path, "rb") as handle:
            data_base64 = base64.b64encode(handle.read()).decode("ascii")
        bytes_summary = _backend_method(real_backend, "program_open_bytes", "session_open_bytes")(
            data_base64,
            filename="hello-bytes",
            update_analysis=False,
            read_only=True,
        )
        bytes_session_id = bytes_summary["session_id"]
        session_ids.append(bytes_session_id)
        assert bytes_summary["program_name"] == "hello-bytes"

        project_location = str(tmp_path / "ghidra-project")
        project_name = "hello_project"
        source_session_id = _open(
            real_backend,
            sample_binary_path,
            read_only=True,
            project_location=project_location,
            project_name=project_name,
        )
        session_ids.append(source_session_id)
        existing = _backend_method(real_backend, "program_open_existing", "session_open_existing")(
            project_location,
            project_name,
            program_name=_backend_method(real_backend, "program_summary", "binary_summary")(
                source_session_id
            )["program_name"],
            read_only=True,
            update_analysis=False,
        )
        existing_session_id = existing["session_id"]
        session_ids.append(existing_session_id)
        assert existing["project_name"] == project_name
    finally:
        for session_id in reversed(session_ids):
            try:
                _backend_method(real_backend, "program_close", "session_close")(session_id)
            except Exception:
                pass


def test_real_backend_navigation_disassembly_decompilation_and_xrefs(
    real_backend: GhidraBackend,
    sample_binary_path: str,
) -> None:
    session_id = _open(real_backend, sample_binary_path, read_only=False)
    try:
        real_backend.analysis_update_and_wait(session_id)

        functions = _backend_method(real_backend, "function_list", "binary_functions")(
            session_id, offset=0, limit=200
        )
        assert functions["total"] >= 2
        main_start = _find_function_start(functions, "main")
        add_start = _find_function_start(functions, "helper")

        function_at = _backend_method(real_backend, "function_get_at", "binary_get_function_at")(
            session_id, main_start
        )
        assert function_at["function"]["name"] == "main"

        symbols = _backend_method(real_backend, "symbol_list", "binary_symbols")(
            session_id, offset=0, limit=50
        )
        assert symbols["total"] >= 1

        string_method = _backend_method(real_backend, "search_text", "binary_strings")
        if string_method.__name__ == "search_text":
            strings = string_method(session_id, text="Hello")
        else:
            strings = string_method(session_id, offset=0, limit=50, query="Hello")
        assert strings["count"] >= 1

        blocks = _backend_method(real_backend, "memory_blocks_list", "binary_memory_blocks")(
            session_id
        )
        assert blocks["count"] >= 1

        disasm = _backend_method(real_backend, "listing_disassemble_function", "disasm_function")(
            session_id, main_start
        )
        assert disasm["count"] >= 1
        assert disasm["items"][0]["text"]

        linear = _backend_method(real_backend, "listing_disassemble_range", "disasm_range")(
            session_id, main_start, length=16, limit=16
        )
        assert linear["count"] >= 1

        decomp = real_backend.decomp_function(session_id, main_start)
        assert decomp["decompile_completed"] is True
        assert "main" in decomp.get("c", "")

        pcode = real_backend.pcode_function(session_id, main_start, limit=10)
        assert pcode["count"] >= 1

        op_at = real_backend.pcode_op_at(session_id, main_start)
        assert op_at["ops"]

        refs_to = _backend_method(real_backend, "reference_to", "xref_to")(
            session_id, address=add_start
        )
        assert refs_to["count"] >= 1

        refs_from = _backend_method(real_backend, "reference_from", "xref_from")(
            session_id, address=refs_to["items"][0]["from"]
        )
        assert refs_from["count"] >= 1

        callers = real_backend.function_callers(session_id, add_start)
        assert callers["count"] >= 1

        callees = real_backend.function_callees(session_id, main_start)
        assert callees["count"] >= 1

        signature = real_backend.function_signature_get(session_id, add_start)
        assert "helper" in signature["signature"]

        variables = real_backend.function_variables(session_id, add_start)
        assert isinstance(variables["parameters"], list)
        assert isinstance(variables["locals"], list)
    finally:
        _backend_method(real_backend, "program_close", "session_close")(session_id)


def test_real_backend_mutation_types_comments_memory_and_undo(
    real_backend: GhidraBackend,
    sample_binary_path: str,
) -> None:
    session_id = _open(real_backend, sample_binary_path, read_only=False)
    try:
        real_backend.analysis_update_and_wait(session_id)
        functions = _backend_method(real_backend, "function_list", "binary_functions")(
            session_id, offset=0, limit=200
        )
        main_start = _find_function_start(functions, "main")

        renamed = real_backend.function_rename(session_id, main_start, "main_mcp")
        assert renamed["function"]["name"] == "main_mcp"
        renamed_back = real_backend.function_rename(session_id, main_start, "main")
        assert renamed_back["function"]["name"] == "main"

        set_comment = _backend_method(real_backend, "comment_set", "annotation_comment_set")(
            session_id,
            scope="function",
            function_start=main_start,
            comment="mcp comment",
        )
        assert set_comment["comment"] == "mcp comment"
        get_comment = _backend_method(real_backend, "comment_get", "annotation_comment_get")(
            session_id,
            scope="function",
            function_start=main_start,
        )
        assert get_comment["comment"] == "mcp comment"

        symbol = _backend_method(real_backend, "symbol_create", "annotation_symbol_create")(
            session_id, address=main_start, name="main_label"
        )
        assert symbol["symbol"]["name"] == "main_label"
        renamed_symbol = _backend_method(real_backend, "symbol_rename", "annotation_symbol_rename")(
            session_id,
            address=main_start,
            old_name="main_label",
            new_name="main_label_2",
        )
        assert renamed_symbol["symbol"]["name"] == "main_label_2"
        deleted = _backend_method(real_backend, "symbol_delete", "annotation_symbol_delete")(
            session_id,
            address=main_start,
            name="main_label_2",
        )
        assert deleted["deleted"] is True

        writable_block = next(
            item
            for item in _backend_method(real_backend, "memory_blocks_list", "binary_memory_blocks")(
                session_id
            )["items"]
            if item["write"]
        )
        write_address = writable_block["start"]
        read = real_backend.memory_read(session_id, write_address, length=4)
        written = real_backend.memory_write(session_id, write_address, data_hex=read["data_hex"])
        assert written["written"] == 4

        defined = real_backend.type_define_c(session_id, declaration="int", name="mcp_int")
        assert defined["type"]["name"] == "mcp_int"
        fetched = real_backend.type_get(session_id, name="mcp_int")
        assert fetched["type"]["name"] == "mcp_int"
        renamed_type = real_backend.type_rename(session_id, name="mcp_int", new_name="mcp_int2")
        assert renamed_type["type"]["name"] == "mcp_int2"
        deleted_type = real_backend.type_delete(session_id, name="mcp_int2")
        assert deleted_type["deleted"] is True

        tx = _backend_method(real_backend, "transaction_begin", "undo_begin")(
            session_id, description="comment update"
        )
        assert tx["active_transaction"] is not None
        _backend_method(real_backend, "comment_set", "annotation_comment_set")(
            session_id,
            scope="function",
            function_start=main_start,
            comment="comment inside tx",
        )
        committed = _backend_method(real_backend, "transaction_commit", "undo_commit")(session_id)
        assert committed["active_transaction"] is None
        assert isinstance(committed["can_undo"], bool)
        if committed["can_undo"]:
            undone = _backend_method(real_backend, "transaction_undo", "undo_undo")(session_id)
            assert isinstance(undone["can_redo"], bool)
            if undone["can_redo"]:
                redone = _backend_method(real_backend, "transaction_redo", "undo_redo")(session_id)
                assert isinstance(redone["can_undo"], bool)

        saved = _backend_method(real_backend, "program_save", "session_save")(session_id)
        assert saved["saved"] is True
        assert real_backend._get_record(session_id).program.getCurrentTransactionInfo() is None
    finally:
        _backend_method(real_backend, "program_close", "session_close")(session_id)
