"""Minimal MCP (JSON-RPC) server with Ghidra-backed tools."""

from __future__ import annotations

import inspect
import json
import socketserver
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, BinaryIO

from ._version import __version__
from .backend import GhidraBackend, GhidraBackendError

_ADDRESS_SCHEMA: dict[str, Any] = {
    "oneOf": [{"type": "integer"}, {"type": "string"}],
}

_SERVER_TOOL_SPECS: tuple[dict[str, Any], ...] = (
    {
        "name": "health.ping",
        "description": "Health check.",
        "properties": {},
        "required": [],
        "backend_method": None,
    },
    {
        "name": "mcp.response_format",
        "description": "Explain MCP tool result fields (`structuredContent` full payload, `content[0].text` summary).",
        "properties": {},
        "required": [],
        "backend_method": None,
    },
)

_BACKEND_TOOL_NAME_MAP: dict[str, str] = {
    "ghidra_info": "ghidra.info",
    "call_api": "ghidra.call",
    "eval_code": "ghidra.eval",
    "run_script": "ghidra.script",
    "session_open": "program.open",
    "session_open_bytes": "program.open_bytes",
    "session_open_existing": "project.program.open_existing",
    "session_close": "program.close",
    "session_list": "program.list_open",
    "session_mode": "program.mode.get",
    "session_set_mode": "program.mode.set",
    "analysis_status": "analysis.status",
    "analysis_update": "analysis.update",
    "analysis_update_and_wait": "analysis.update_and_wait",
    "analysis_options_list": "analysis.options.list",
    "analysis_options_get": "analysis.options.get",
    "analysis_options_set": "analysis.options.set",
    "binary_summary": "program.summary",
    "binary_functions": "function.list",
    "binary_get_function_at": "function.at",
    "binary_symbols": "symbol.list",
    "binary_strings": "search.defined_strings",
    "binary_imports": "external.imports.list",
    "binary_exports": "external.exports.list",
    "binary_memory_blocks": "memory.blocks.list",
    "binary_data": "listing.data.list",
    "disasm_function": "listing.disassemble.function",
    "disasm_range": "listing.disassemble.range",
    "decomp_function": "decomp.function",
    "pcode_function": "pcode.function",
    "pcode_op_at": "pcode.op.at",
    "xref_to": "reference.to",
    "xref_from": "reference.from",
    "function_callers": "function.callers",
    "function_callees": "function.callees",
    "function_signature_get": "function.signature.get",
    "function_signature_set": "function.signature.set",
    "function_variables": "function.variables",
    "function_rename": "function.rename",
    "annotation_comment_get": "comment.get",
    "annotation_comment_set": "comment.set",
    "annotation_symbol_rename": "symbol.rename",
    "annotation_symbol_create": "symbol.create",
    "annotation_symbol_delete": "symbol.delete",
    "memory_read": "memory.read",
    "memory_write": "memory.write",
    "data_typed_at": "listing.data.at",
    "data_create": "listing.data.create",
    "data_clear": "listing.data.clear",
    "type_list": "type.list",
    "type_get": "type.get",
    "type_define_c": "type.define_c",
    "type_rename": "type.rename",
    "type_delete": "type.delete",
    "function_by_name": "function.by_name",
    "symbol_by_name": "symbol.by_name",
    "address_resolve": "search.resolve",
    "search_text": "search.text",
    "search_bytes": "search.bytes",
    "search_constants": "search.constants",
    "search_instructions": "search.instructions",
    "search_pcode": "search.pcode",
    "function_basic_blocks": "graph.basic_blocks",
    "cfg_edges": "graph.cfg.edges",
    "callgraph_paths": "graph.call_paths",
    "function_variable_rename": "variable.rename",
    "function_variable_retype": "variable.retype",
    "function_return_type_set": "function.return_type.set",
    "function_create": "function.create",
    "function_delete": "function.delete",
    "type_parse_c": "type.parse_c",
    "type_apply_at": "type.apply_at",
    "struct_create": "layout.struct.create",
    "struct_field_add": "layout.struct.field.add",
    "struct_field_rename": "layout.struct.field.rename",
    "enum_create": "layout.enum.create",
    "enum_member_add": "layout.enum.member.add",
    "patch_assemble": "patch.assemble",
    "patch_nop": "patch.nop",
    "patch_branch_invert": "patch.branch_invert",
    "session_save": "program.save",
    "session_save_as": "program.save_as",
    "session_export_project": "project.export",
    "session_export_binary": "program.export_binary",
    "bookmark_add": "bookmark.add",
    "bookmark_list": "bookmark.list",
    "tag_add": "tag.add",
    "tag_list": "tag.list",
    "metadata_store": "metadata.store",
    "metadata_query": "metadata.query",
    "analysis_analyzers_list": "analysis.analyzers.list",
    "analysis_analyzers_set": "analysis.analyzers.set",
    "analysis_clear_cache": "analysis.clear_cache",
    "memory_block_create": "memory.block.create",
    "memory_block_remove": "memory.block.remove",
    "external_library_list": "external.library.list",
    "external_location_get": "external.location.get",
    "decomp_tokens": "decomp.tokens",
    "decomp_ast": "decomp.ast",
    "pcode_block": "pcode.block",
    "pcode_varnode_uses": "pcode.varnode_uses",
    "report_program_summary": "program.report",
    "report_function_summary": "function.report",
    "batch_run_on_functions": "function.batch.run",
    "binary_rebase": "program.image_base.set",
    "undo_begin": "transaction.begin",
    "undo_commit": "transaction.commit",
    "undo_revert": "transaction.revert",
    "undo_undo": "transaction.undo",
    "undo_redo": "transaction.redo",
    "undo_status": "transaction.status",
    "task_analysis_update": "task.analysis_update",
    "task_status": "task.status",
    "task_result": "task.result",
    "task_cancel": "task.cancel",
    "project_folders_list": "project.folders.list",
    "project_files_list": "project.files.list",
    "project_file_info": "project.file.info",
    "project_program_open": "project.program.open",
    "project_search_programs": "project.search.programs",
    "listing_code_units_list": "listing.code_units.list",
    "listing_code_unit_at": "listing.code_unit.at",
    "listing_code_unit_before": "listing.code_unit.before",
    "listing_code_unit_after": "listing.code_unit.after",
    "listing_code_unit_containing": "listing.code_unit.containing",
    "listing_clear": "listing.clear",
    "listing_disassemble_seed": "listing.disassemble.seed",
    "context_get": "context.get",
    "context_set": "context.set",
    "context_ranges": "context.ranges",
    "symbol_primary_set": "symbol.primary.set",
    "namespace_create": "namespace.create",
    "class_create": "class.create",
    "symbol_namespace_move": "symbol.namespace.move",
    "external_library_create": "external.library.create",
    "external_library_set_path": "external.library.set_path",
    "external_location_create": "external.location.create",
    "external_function_create": "external.function.create",
    "external_entrypoint_add": "external.entrypoint.add",
    "external_entrypoint_remove": "external.entrypoint.remove",
    "external_entrypoint_list": "external.entrypoint.list",
    "reference_create_memory": "reference.create.memory",
    "reference_create_stack": "reference.create.stack",
    "reference_create_register": "reference.create.register",
    "reference_create_external": "reference.create.external",
    "reference_delete": "reference.delete",
    "reference_clear_from": "reference.clear_from",
    "reference_clear_to": "reference.clear_to",
    "reference_primary_set": "reference.primary.set",
    "reference_association_set": "reference.association.set",
    "reference_association_remove": "reference.association.remove",
    "equate_create": "equate.create",
    "equate_list": "equate.list",
    "equate_delete": "equate.delete",
    "equate_clear_range": "equate.clear_range",
    "comment_get_all": "comment.get_all",
    "comment_list": "comment.list",
    "bookmark_remove": "bookmark.remove",
    "bookmark_clear": "bookmark.clear",
    "tag_remove": "tag.remove",
    "tag_stats": "tag.stats",
    "source_file_list": "source.file.list",
    "source_file_add": "source.file.add",
    "source_file_remove": "source.file.remove",
    "source_map_list": "source.map.list",
    "source_map_add": "source.map.add",
    "source_map_remove": "source.map.remove",
    "relocation_list": "relocation.list",
    "relocation_add": "relocation.add",
    "function_body_set": "function.body.set",
    "function_calling_conventions_list": "function.calling_conventions.list",
    "function_calling_convention_set": "function.calling_convention.set",
    "function_flags_set": "function.flags.set",
    "function_thunk_set": "function.thunk.set",
    "parameter_add": "parameter.add",
    "parameter_remove": "parameter.remove",
    "parameter_move": "parameter.move",
    "parameter_replace": "parameter.replace",
    "variable_local_create": "variable.local.create",
    "variable_local_remove": "variable.local.remove",
    "variable_comment_set": "variable.comment.set",
    "stackframe_variable_create": "stackframe.variable.create",
    "stackframe_variable_clear": "stackframe.variable.clear",
    "stackframe_variables": "stackframe.variables",
    "type_category_list": "type.category.list",
    "type_category_create": "type.category.create",
    "type_archives_list": "type.archives.list",
    "type_source_archives_list": "type.source_archives.list",
    "type_get_by_id": "type.get_by_id",
    "layout_struct_get": "layout.struct.get",
    "layout_struct_resize": "layout.struct.resize",
    "layout_struct_field_replace": "layout.struct.field.replace",
    "layout_struct_field_clear": "layout.struct.field.clear",
    "layout_struct_field_comment_set": "layout.struct.field.comment.set",
    "layout_struct_bitfield_add": "layout.struct.bitfield.add",
    "layout_union_create": "layout.union.create",
    "layout_union_member_add": "layout.union.member.add",
    "layout_union_member_remove": "layout.union.member.remove",
    "layout_enum_member_remove": "layout.enum.member.remove",
    "layout_inspect_components": "layout.inspect.components",
    "layout_struct_fill_from_decompiler": "layout.struct.fill_from_decompiler",
    "decomp_high_function_summary": "decomp.high_function.summary",
    "decomp_writeback_params": "decomp.writeback.params",
    "decomp_writeback_locals": "decomp.writeback.locals",
    "decomp_override_get": "decomp.override.get",
    "decomp_override_set": "decomp.override.set",
    "decomp_trace_type_forward": "decomp.trace_type.forward",
    "decomp_trace_type_backward": "decomp.trace_type.backward",
    "decomp_global_rename": "decomp.global.rename",
    "decomp_global_retype": "decomp.global.retype",
}

_DESCRIPTION_OVERRIDES: dict[str, str] = {
    "ghidra.info": "Return Ghidra and PyGhidra runtime information.",
    "ghidra.call": "Generic API bridge for direct Ghidra and Java access.",
    "ghidra.eval": "Evaluate Python code inside the Ghidra runtime context.",
    "ghidra.script": "Run a Ghidra script against an open program session.",
    "program.open": "Open a binary file for analysis and return a session ID.",
    "program.open_bytes": "Open a binary from base64-encoded bytes and return a session ID.",
    "program.close": "Close an open program session and release resources.",
    "program.list_open": "List all currently open program sessions.",
    "program.summary": "Return a summary of the program in a session (architecture, memory, entry point).",
    "program.save": "Save the current program state to the project.",
    "program.mode.get": "Get the current read/write mode of a session.",
    "program.mode.set": "Set a session to read-only or read-write mode.",
    "function.list": "List functions in the program with optional filtering and pagination.",
    "function.at": "Get function information at a specific address.",
    "function.by_name": "Look up a function by its name.",
    "function.create": "Create a new function at a given address.",
    "function.delete": "Delete a function at a given address.",
    "function.rename": "Rename a function.",
    "function.callers": "List functions that call a given function.",
    "function.callees": "List functions called by a given function.",
    "function.signature.get": "Get the full signature of a function.",
    "function.signature.set": "Set the signature of a function from a C declaration.",
    "function.variables": "List local variables and parameters of a function.",
    "decomp.function": "Decompile a function and return C source code.",
    "memory.read": "Read raw bytes from program memory.",
    "memory.write": "Write raw bytes to program memory.",
    "memory.blocks.list": "List all memory blocks in the program.",
    "search.text": "Search for a text string in the program.",
    "search.bytes": "Search for a byte pattern in program memory.",
    "search.defined_strings": "List defined strings in the program.",
    "search.resolve": "Resolve a symbol name or expression to an address.",
    "search.constants": "Search for scalar constants in instructions and data.",
    "search.instructions": "Search for instructions matching a pattern.",
    "search.pcode": "Search for p-code operations matching criteria.",
    "comment.get": "Get the comment at a specific address.",
    "comment.set": "Set or clear a comment at an address.",
    "comment.list": "List comments matching optional filters.",
    "comment.get_all": "Get all comment types at an address.",
    "symbol.list": "List symbols with optional filtering and pagination.",
    "symbol.rename": "Rename an existing symbol.",
    "symbol.create": "Create a new symbol (label) at an address.",
    "symbol.delete": "Delete a symbol at an address.",
    "symbol.by_name": "Look up a symbol by its name.",
    "type.list": "List data types with optional filtering and pagination.",
    "type.get": "Get details of a data type by name or path.",
    "type.define_c": "Define a new data type from a C declaration.",
    "type.parse_c": "Parse a C type declaration without committing it (unless composite).",
    "type.rename": "Rename an existing data type.",
    "type.delete": "Delete a data type by name or path.",
    "type.apply_at": "Apply a data type at an address.",
    "transaction.begin": "Begin an explicit undo transaction.",
    "transaction.commit": "Commit the active transaction.",
    "transaction.revert": "Revert (roll back) the active transaction.",
    "transaction.undo": "Undo the last committed change.",
    "transaction.redo": "Redo the last undone change.",
    "transaction.status": "Get the current transaction status.",
    "listing.disassemble.function": "Disassemble an entire function.",
    "listing.disassemble.range": "Disassemble a range of addresses.",
    "listing.disassemble.seed": "Disassemble starting from a seed address.",
    "reference.to": "List cross-references to an address.",
    "reference.from": "List cross-references from an address.",
    "external.imports.list": "List imported symbols.",
    "external.exports.list": "List exported symbols.",
    "analysis.status": "Get the current analysis status.",
    "analysis.update": "Start auto-analysis (non-blocking).",
    "analysis.update_and_wait": "Run auto-analysis and wait for completion.",
    "analysis.options.list": "List available analysis options.",
    "analysis.options.get": "Get the value of an analysis option.",
    "analysis.options.set": "Set an analysis option value.",
    "task.status": "Get the status of an asynchronous task.",
    "task.result": "Get the result of a completed task.",
    "task.cancel": "Cancel a running or queued task.",
}

_ADDRESS_PARAM_NAMES = {
    "address",
    "start",
    "end",
    "function_start",
    "callsite",
    "from_address",
    "to_address",
    "external_address",
    "base_address",
    "image_base",
    "source_function",
    "target_function",
    "symbol_address",
    "storage_address",
    "thunk_target",
}


def _tool_name_map() -> dict[str, str]:
    return dict(_BACKEND_TOOL_NAME_MAP)


def _tool_description(tool_name: str) -> str:
    if tool_name in _DESCRIPTION_OVERRIDES:
        return _DESCRIPTION_OVERRIDES[tool_name]
    return tool_name.replace(".", " ").replace("_", " ") + "."


def _tool_property_schema(param_name: str, param: inspect.Parameter) -> dict[str, Any]:
    if param_name in _ADDRESS_PARAM_NAMES:
        return dict(_ADDRESS_SCHEMA)
    annotation = "" if param.annotation is inspect._empty else str(param.annotation)
    default = param.default
    if param_name in {"args", "script_args", "values"}:
        return {"type": "array"}
    if param_name == "kwargs":
        return {"type": "object"}
    if isinstance(default, bool) or "bool" in annotation:
        return {"type": "boolean"}
    if isinstance(default, int) and not isinstance(default, bool):
        return {"type": "integer"}
    if isinstance(default, float):
        return {"type": "number"}
    if isinstance(default, str):
        return {"type": "string"}
    if isinstance(default, (list, tuple)):
        return {"type": "array"}
    if isinstance(default, dict):
        return {"type": "object"}
    if "list" in annotation or "tuple" in annotation:
        return {"type": "array"}
    if "dict" in annotation:
        return {"type": "object"}
    if "int" in annotation and "str" not in annotation:
        return {"type": "integer"}
    if "str" in annotation and "int" not in annotation:
        return {"type": "string"}
    if "int" in annotation and "str" in annotation:
        return dict(_ADDRESS_SCHEMA)
    return {}


def _backend_tool_spec(backend_method: str) -> dict[str, Any]:
    method = getattr(GhidraBackend, backend_method)
    signature = inspect.signature(method)
    properties: dict[str, Any] = {}
    required: list[str] = []
    for name, param in signature.parameters.items():
        if name == "self":
            continue
        properties[name] = _tool_property_schema(name, param)
        if param.default is inspect._empty:
            required.append(name)
    tool_name = _tool_name_map()[backend_method]
    return {
        "name": tool_name,
        "description": _tool_description(tool_name),
        "backend_method": backend_method,
        "properties": properties,
        "required": required,
    }


def _build_backend_tool_specs() -> tuple[dict[str, Any], ...]:
    mapping = _tool_name_map()
    backend_methods = {
        name
        for name, member in inspect.getmembers(GhidraBackend, inspect.isfunction)
        if not name.startswith("_") and name not in {"ping", "shutdown"}
    }
    missing = sorted(backend_methods - set(mapping))
    if missing:
        raise RuntimeError("missing tool name mappings for backend methods: " + ", ".join(missing))
    return tuple(
        _backend_tool_spec(backend_method)
        for backend_method in sorted(mapping, key=lambda item: mapping[item])
    )


BACKEND_TOOL_SPECS: tuple[dict[str, Any], ...] = _build_backend_tool_specs()

ALL_TOOL_SPECS: tuple[dict[str, Any], ...] = _SERVER_TOOL_SPECS + BACKEND_TOOL_SPECS

_SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = (
    "2025-03-26",
    "2024-11-05",
)
_DEFAULT_PROTOCOL_VERSION = _SUPPORTED_PROTOCOL_VERSIONS[0]


@dataclass
class JsonRpcError(Exception):
    """Represents a JSON-RPC error payload."""

    code: int
    message: str
    data: Any = None


class _ThreadingTcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class SimpleMcpServer:
    """Simple MCP-compatible server exposing Ghidra tools."""

    def __init__(self, backend: Any):
        self._backend = backend
        self._tool_handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "health.ping": self._tool_ping,
            "mcp.response_format": self._tool_mcp_response_format,
        }
        for spec in BACKEND_TOOL_SPECS:
            self._tool_handlers[spec["name"]] = self._make_backend_handler(spec["backend_method"])

    def serve_stdio(
        self,
        input_stream: BinaryIO | None = None,
        output_stream: BinaryIO | None = None,
    ) -> None:
        """Run JSON-RPC over stdio, mirroring line or Content-Length framing."""

        in_stream = input_stream or sys.stdin.buffer
        out_stream = output_stream or sys.stdout.buffer

        while True:
            try:
                line, framing = self._read_stdio_request(in_stream)
            except JsonRpcError as exc:
                response = json.dumps(self._error_response(None, exc), sort_keys=True)
                self._write_stdio_response(out_stream, response)
                continue
            if line is None:
                return

            response = self.handle_json_line(line)
            if response is None:
                continue

            self._write_stdio_response(out_stream, response, framing=framing)

    def serve_tcp(self, host: str, port: int) -> None:
        """Run line-delimited JSON-RPC over TCP."""

        parent = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                while True:
                    raw_line = self.rfile.readline()
                    if not raw_line:
                        return
                    line = raw_line.decode("utf-8").strip()
                    if not line:
                        continue

                    response = parent.handle_json_line(line)
                    if response is None:
                        continue

                    self.wfile.write(response.encode("utf-8"))
                    self.wfile.write(b"\n")
                    self.wfile.flush()

        with _ThreadingTcpServer((host, port), Handler) as server:
            server.serve_forever()

    def handle_json_line(self, line: str) -> str | None:
        """Handle one JSON-RPC line and return a serialized response line."""

        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            error = JsonRpcError(code=-32700, message="Parse error", data=str(exc))
            return json.dumps(self._error_response(None, error), sort_keys=True)

        response = self.handle_request(request)
        if response is None:
            return None
        try:
            return json.dumps(response, sort_keys=True)
        except TypeError as exc:
            request_id = request.get("id") if isinstance(request, dict) else None
            fallback = self._error_response(
                request_id,
                JsonRpcError(
                    code=-32603,
                    message="Internal error",
                    data=f"failed to serialize response: {exc}",
                ),
            )
            return json.dumps(fallback, sort_keys=True)

    @staticmethod
    def _read_stdio_request(stream: BinaryIO) -> tuple[str | None, str]:
        """Read one stdio request, preferring MCP framing and tolerating JSON lines."""

        while True:
            raw_line = stream.readline()
            if not raw_line:
                return None, "line"
            if raw_line in (b"\r\n", b"\n"):
                continue

            stripped = raw_line.strip()
            if stripped.startswith((b"{", b"[")):
                try:
                    return stripped.decode("utf-8"), "line"
                except UnicodeDecodeError as exc:
                    raise JsonRpcError(
                        code=-32700,
                        message="Parse error",
                        data=f"invalid UTF-8 request line: {exc}",
                    ) from exc

            header_lines = [raw_line]
            break

        while True:
            raw_line = stream.readline()
            if not raw_line:
                raise JsonRpcError(
                    code=-32700,
                    message="Parse error",
                    data="unexpected EOF while reading stdio headers",
                )
            if raw_line in (b"\r\n", b"\n"):
                break
            header_lines.append(raw_line)

        content_length: int | None = None
        for raw_header in header_lines:
            try:
                header = raw_header.decode("ascii").strip()
            except UnicodeDecodeError as exc:
                raise JsonRpcError(
                    code=-32700,
                    message="Parse error",
                    data=f"invalid stdio header encoding: {exc}",
                ) from exc
            name, sep, value = header.partition(":")
            if not sep:
                raise JsonRpcError(
                    code=-32700,
                    message="Parse error",
                    data=f"invalid stdio header: {header}",
                )
            if name.lower() != "content-length":
                continue
            try:
                content_length = int(value.strip())
            except ValueError as exc:
                raise JsonRpcError(
                    code=-32700,
                    message="Parse error",
                    data=f"invalid Content-Length header: {header}",
                ) from exc

        if content_length is None:
            raise JsonRpcError(
                code=-32700,
                message="Parse error",
                data="missing Content-Length header",
            )

        body = stream.read(content_length)
        if len(body) != content_length:
            raise JsonRpcError(
                code=-32700,
                message="Parse error",
                data="unexpected EOF while reading stdio body",
            )
        try:
            return body.decode("utf-8"), "content-length"
        except UnicodeDecodeError as exc:
            raise JsonRpcError(
                code=-32700,
                message="Parse error",
                data=f"invalid UTF-8 request body: {exc}",
            ) from exc

    @staticmethod
    def _write_stdio_response(
        stream: BinaryIO,
        response: str,
        *,
        framing: str = "line",
    ) -> None:
        body = response.encode("utf-8")
        if framing == "content-length":
            header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
            stream.write(header)
        stream.write(body)
        if framing != "content-length":
            stream.write(b"\n")
        stream.flush()

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Handle one JSON-RPC request object."""

        if not isinstance(request, dict):
            return self._error_response(None, JsonRpcError(-32600, "Invalid Request"))

        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        try:
            if not isinstance(method, str):
                raise JsonRpcError(-32600, "Invalid Request")
            if not isinstance(params, dict):
                raise JsonRpcError(-32602, "Invalid params")

            if method == "notifications/initialized":
                return None

            result = self._dispatch(method, params)
            return self._success_response(request_id, result)
        except JsonRpcError as exc:
            return self._error_response(request_id, exc)
        except Exception as exc:
            return self._error_response(
                request_id,
                JsonRpcError(
                    code=-32603,
                    message="Internal error",
                    data=f"{type(exc).__name__}: {exc}",
                ),
            )

    def _dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            return {
                "protocolVersion": self._negotiate_protocol_version(params),
                "serverInfo": {
                    "name": "ghidra_headless_mcp",
                    "version": __version__,
                },
                "capabilities": {
                    "tools": {},
                },
            }

        if method == "ping":
            return {"status": "ok"}

        if method == "tools/list":
            return self._dispatch_tools_list(params)

        if method == "tools/call":
            return self._dispatch_tool_call(params)

        if method == "shutdown":
            self._backend.shutdown()
            return {"ok": True}

        raise JsonRpcError(code=-32601, message=f"Method not found: {method}")

    @staticmethod
    def _negotiate_protocol_version(params: dict[str, Any]) -> str:
        requested = params.get("protocolVersion")
        if requested is None:
            return _DEFAULT_PROTOCOL_VERSION
        if not isinstance(requested, str):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: initialize 'protocolVersion' must be a string",
            )
        if requested in _SUPPORTED_PROTOCOL_VERSIONS:
            return requested
        return _DEFAULT_PROTOCOL_VERSION

    def _dispatch_tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        paginate = "offset" in params or "limit" in params
        offset = params.get("offset", 0)
        limit = params.get("limit", 50 if paginate else None)
        prefix = params.get("prefix")
        query = params.get("query")

        if not isinstance(offset, int):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'offset' must be an integer",
            )
        if limit is not None and not isinstance(limit, int):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'limit' must be an integer",
            )
        if offset < 0:
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'offset' must be >= 0",
            )
        if limit is not None and limit <= 0:
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'limit' must be > 0",
            )
        if prefix is not None and not isinstance(prefix, str):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'prefix' must be a string",
            )
        if query is not None and not isinstance(query, str):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'query' must be a string",
            )

        tools = self._tool_definitions()
        if prefix is not None:
            tools = [tool for tool in tools if tool["name"].startswith(prefix)]
        if query is not None:
            lowered = query.lower()
            tools = [
                tool
                for tool in tools
                if lowered in tool["name"].lower() or lowered in tool["description"].lower()
            ]

        total = len(tools)
        if limit is None:
            items = tools[offset:]
            effective_limit = len(items)
        else:
            items = tools[offset : offset + limit]
            effective_limit = limit

        has_more = offset + len(items) < total
        response = {
            "tools": items,
            "offset": offset,
            "limit": effective_limit,
            "total": total,
            "has_more": has_more,
        }
        if has_more:
            response["next_offset"] = offset + len(items)
            response["notice"] = (
                "tool list is truncated; request the next page via tools/list with "
                f"offset={response['next_offset']}"
            )
        return response

    def _dispatch_tool_call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments", {})

        if not isinstance(name, str):
            raise JsonRpcError(code=-32602, message="Invalid params: tools/call requires 'name'")
        if not isinstance(arguments, dict):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/call 'arguments' must be an object",
            )

        handler = self._tool_handlers.get(name)
        if handler is None:
            raise JsonRpcError(code=-32601, message=f"Tool not found: {name}")

        try:
            payload = handler(arguments)
            return self._tool_result(payload)
        except GhidraBackendError as exc:
            return self._tool_result({"error": str(exc)}, is_error=True)
        except Exception as exc:  # pragma: no cover - safety net
            return self._tool_result(
                {"error": f"unexpected tool failure: {type(exc).__name__}: {exc}"},
                is_error=True,
            )

    def _make_backend_handler(self, method_name: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
        backend_method = getattr(self._backend, method_name)
        signature = inspect.signature(backend_method)

        def handler(arguments: dict[str, Any]) -> dict[str, Any]:
            try:
                bound = signature.bind(**arguments)
            except TypeError as exc:
                raise GhidraBackendError(str(exc)) from exc
            return backend_method(*bound.args, **bound.kwargs)

        return handler

    def _tool_ping(self, _arguments: dict[str, Any]) -> dict[str, Any]:
        return self._backend.ping()

    def _tool_mcp_response_format(self, _arguments: dict[str, Any]) -> dict[str, Any]:
        return {
            "structuredContent": "canonical machine-readable payload for agents",
            "content": "compact text summary for humans and UIs",
            "isError": "true when the tool failed at the tool layer",
            "tool_error_policy": "backend and tool failures are returned as tool errors, not JSON-RPC protocol errors",
        }

    @staticmethod
    def _tool_result(payload: dict[str, Any], *, is_error: bool = False) -> dict[str, Any]:
        try:
            _ = json.dumps(payload, sort_keys=True)
            structured_payload = payload
        except TypeError as exc:
            structured_payload = {
                "error": "tool returned a non-JSON-serializable payload",
                "detail": str(exc),
            }
            is_error = True

        text = SimpleMcpServer._tool_summary_text(structured_payload, is_error=is_error)
        return {
            "content": [{"type": "text", "text": text}],
            "structuredContent": structured_payload,
            "isError": is_error,
        }

    @staticmethod
    def _tool_summary_text(payload: dict[str, Any], *, is_error: bool) -> str:
        if is_error:
            error = payload.get("error")
            if isinstance(error, str) and error:
                return f"error: {error}"
            return "error"

        keys = (
            "session_id",
            "task_id",
            "status",
            "count",
            "total",
            "offset",
            "limit",
            "read_only",
            "closed",
            "deleted",
            "defined",
        )
        parts = ["ok"]
        for key in keys:
            value = payload.get(key)
            if value is not None:
                parts.append(f"{key}={value}")
        return " ".join(parts)

    def _tool_definitions(self) -> list[dict[str, Any]]:
        return [
            self._tool(
                spec["name"],
                spec["description"],
                spec.get("properties"),
                spec.get("required"),
            )
            for spec in ALL_TOOL_SPECS
        ]

    @staticmethod
    def _tool(
        name: str,
        description: str,
        properties: dict[str, Any] | None = None,
        required: list[str] | tuple[str, ...] | None = None,
        schema_extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        input_schema: dict[str, Any] = {
            "type": "object",
            "properties": properties or {},
        }
        if required:
            input_schema["required"] = list(required)
        if schema_extra:
            input_schema.update(schema_extra)
        return {
            "name": name,
            "description": description,
            "inputSchema": input_schema,
        }

    @staticmethod
    def _success_response(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error_response(request_id: Any, error: JsonRpcError) -> dict[str, Any]:
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": error.code,
                "message": error.message,
            },
        }
        if error.data is not None:
            payload["error"]["data"] = error.data
        return payload
