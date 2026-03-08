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
        "description": "Confirm that the server is reachable and responding.",
        "properties": {},
        "required": [],
        "backend_method": None,
    },
    {
        "name": "mcp.response_format",
        "description": "Explain how MCP tool responses split full structured data and human-readable summary text.",
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
    "analysis.analyzers.list": "List boolean analyzers available for the current program and show whether each one is enabled.",
    "analysis.analyzers.set": "Enable or disable a specific boolean analyzer for the current program.",
    "analysis.clear_cache": "Clear cached decompiler state for the current session so later requests rebuild it cleanly.",
    "analysis.options.get": "Return the current value of a specific analysis option.",
    "analysis.options.list": "List available analysis options together with their current values.",
    "analysis.options.set": "Update the value of an analysis option for the current session.",
    "analysis.status": "Return the current auto-analysis status for the session.",
    "analysis.update": "Start auto-analysis in the background and return immediately.",
    "analysis.update_and_wait": "Run auto-analysis and wait until it completes.",
    "health.ping": "Confirm that the server is reachable and responding.",
    "mcp.response_format": "Explain how MCP tool responses split full structured data and human-readable summary text.",
    "task.analysis_update": "Start auto-analysis as a tracked background task and return a task ID.",
    "task.cancel": "Request cancellation for a running or queued asynchronous task.",
    "task.result": "Return the terminal result or error payload for a completed task.",
    "task.status": "Return status, timing, and cancellation details for an asynchronous task.",
    "program.close": "Close an open program session and release its associated resources.",
    "program.export_binary": "Export the program to disk as either the original-file format or raw bytes.",
    "program.image_base.set": "Change the program image base and optionally commit the rebasing operation.",
    "program.list_open": "List all program sessions currently held open by the server.",
    "program.mode.get": "Return whether a session is currently read-only or read-write.",
    "program.mode.set": "Switch a session between read-only and read-write mode.",
    "program.open": "Open a binary file for analysis and return a new session.",
    "program.open_bytes": "Open a binary from base64-encoded bytes and return a new session.",
    "program.report": "Return a compact program report with counts plus sample functions, strings, imports, and memory blocks.",
    "program.save": "Save the current program state back into the project.",
    "program.save_as": "Save the current program under a new project path or name.",
    "program.summary": "Return core program metadata such as architecture, memory layout, and entry point.",
    "project.export": "Export the current Ghidra project artifacts to a destination directory.",
    "project.file.info": "Return metadata and state flags for a specific project file.",
    "project.files.list": "List project files with folder, content-type, query, and pagination filters.",
    "project.folders.list": "List project folders, optionally walking the tree recursively.",
    "project.program.open": "Open a program already stored in the current project and return a new session.",
    "project.program.open_existing": "Open a program from a named existing Ghidra project and return a new session.",
    "project.search.programs": "Search program files in the project by name or path.",
    "transaction.begin": "Begin an explicit undo transaction for grouped changes.",
    "transaction.commit": "Commit the active transaction so its changes become undoable.",
    "transaction.redo": "Reapply the most recently undone change.",
    "transaction.revert": "Roll back the active transaction without committing it.",
    "transaction.status": "Return undo, redo, and active-transaction status for the session.",
    "transaction.undo": "Undo the most recently committed change.",
    "context.get": "Return processor context register values at a specific address.",
    "context.ranges": "List address ranges where a processor context register value applies.",
    "context.set": "Set processor context register values across an address range.",
    "listing.clear": "Clear listing content over a range, including optional symbols, comments, references, functions, or context.",
    "listing.code_unit.after": "Return the nearest code unit that follows a given address.",
    "listing.code_unit.at": "Return the code unit that starts exactly at a given address.",
    "listing.code_unit.before": "Return the nearest code unit that precedes a given address.",
    "listing.code_unit.containing": "Return the code unit that contains a given address.",
    "listing.code_units.list": "List code units in a range with pagination and direction controls.",
    "listing.data.at": "Return the defined data item at a specific address.",
    "listing.data.clear": "Clear one or more data definitions starting at an address.",
    "listing.data.create": "Create a data definition of a chosen type at an address.",
    "listing.data.list": "List defined data items in the program with range and pagination controls.",
    "listing.disassemble.function": "Disassemble all instructions that belong to a function body.",
    "listing.disassemble.range": "Disassemble instructions across a selected address range.",
    "listing.disassemble.seed": "Start disassembly from a seed address and follow discovered flows.",
    "memory.block.create": "Create a memory block with permissions, initialization, and an optional comment.",
    "memory.block.remove": "Remove an existing memory block from the program.",
    "memory.blocks.list": "List memory blocks together with addresses, permissions, and sizes.",
    "memory.read": "Read raw bytes directly from program memory.",
    "memory.write": "Write raw bytes directly into program memory.",
    "patch.assemble": "Assemble instruction text at an address and write the resulting bytes.",
    "patch.branch_invert": "Invert a conditional branch instruction in place.",
    "patch.nop": "Replace instructions in a range with NOP bytes.",
    "class.create": "Create a class namespace for recovered methods or fields.",
    "equate.clear_range": "Remove equate references across an address range and delete empty equates.",
    "equate.create": "Create an equate and attach it to an operand at an address.",
    "equate.delete": "Delete an equate entirely, or remove one of its references before deletion.",
    "equate.list": "List equates together with values and attached references.",
    "external.entrypoint.add": "Add an address to the program's external entry point set.",
    "external.entrypoint.list": "List addresses currently marked as external entry points.",
    "external.entrypoint.remove": "Remove an address from the external entry point set.",
    "external.exports.list": "List symbols exported by the program.",
    "external.function.create": "Create an external function symbol under an external location.",
    "external.imports.list": "List symbols imported by the program.",
    "external.library.create": "Create a new external library record.",
    "external.library.list": "List external libraries known to the program.",
    "external.library.set_path": "Set or update the filesystem path associated with an external library.",
    "external.location.create": "Create an external location for a symbol within a library.",
    "external.location.get": "Return details for a specific external location.",
    "namespace.create": "Create a namespace under an optional parent namespace.",
    "reference.association.remove": "Remove the symbol association attached to a specific reference.",
    "reference.association.set": "Associate a specific reference with a symbol.",
    "reference.clear_from": "Remove references originating from one address or an address range.",
    "reference.clear_to": "Remove all references that target a specific address.",
    "reference.create.external": "Create a reference from an address to an external location.",
    "reference.create.memory": "Create a memory reference between two program addresses.",
    "reference.create.register": "Create a reference from an address to a register.",
    "reference.create.stack": "Create a reference from an address to a stack location.",
    "reference.delete": "Delete a specific reference selected by source, destination, and operand.",
    "reference.from": "List cross-references that originate from an address.",
    "reference.primary.set": "Mark a specific reference as the primary one for its operand.",
    "reference.to": "List cross-references that target an address.",
    "symbol.by_name": "Look up a symbol by name and return its details.",
    "symbol.create": "Create a new symbol or label at an address.",
    "symbol.delete": "Delete a symbol at an address, optionally by name.",
    "symbol.list": "List symbols with filtering and pagination support.",
    "symbol.namespace.move": "Move a symbol into a different namespace.",
    "symbol.primary.set": "Mark a selected symbol as the primary symbol at its address.",
    "symbol.rename": "Rename an existing symbol.",
    "bookmark.add": "Add a bookmark at an address with a type, category, and comment.",
    "bookmark.clear": "Remove bookmarks in an address range, optionally filtered by bookmark type.",
    "bookmark.list": "List bookmarks, optionally scoped to an address or bookmark type.",
    "bookmark.remove": "Remove bookmarks at an address, optionally filtered by type or category.",
    "comment.get": "Return one comment type from a specific address.",
    "comment.get_all": "Return all available comment types at an address, with optional function comments.",
    "comment.list": "List comments matching range, type, text, and pagination filters.",
    "comment.set": "Set or clear a comment of a selected type at an address.",
    "metadata.query": "Read metadata entries stored by this server, optionally filtered by key or prefix.",
    "metadata.store": "Store a JSON-serializable metadata value under a program-scoped key.",
    "relocation.add": "Add a relocation entry at an address with type, status, values, and symbol metadata.",
    "relocation.list": "List relocation entries, optionally limited to an address range.",
    "source.file.add": "Register a source file record with the program's source file manager.",
    "source.file.list": "List all source files currently registered with the program.",
    "source.file.remove": "Remove a source file record by path.",
    "source.map.add": "Add a source mapping entry from a source line to an address range.",
    "source.map.list": "List source mapping entries by address, source file, or line filters.",
    "source.map.remove": "Remove a specific source mapping entry by file, line, and base address.",
    "tag.add": "Create or reuse a function tag and attach it to a function.",
    "tag.list": "List tags for one function or across the whole program.",
    "tag.remove": "Remove a function tag from a function.",
    "tag.stats": "Summarize function tags and the number of functions using each one.",
    "function.at": "Return the function that starts at, or contains, a specific address.",
    "function.batch.run": "Run one supported action across a filtered batch of functions.",
    "function.body.set": "Replace the body range of an existing function.",
    "function.by_name": "Look up a function by name and return its details.",
    "function.callees": "List the functions called by a specific function.",
    "function.callers": "List the functions that call a specific function.",
    "function.calling_convention.set": "Set the calling convention used by a function.",
    "function.calling_conventions.list": "List calling conventions available in the current program.",
    "function.create": "Create a new function at a given address.",
    "function.delete": "Delete a function at a given address.",
    "function.flags.set": "Update function flags such as varargs, inline, noreturn, or custom storage.",
    "function.list": "List functions in the program with filtering and pagination support.",
    "function.rename": "Rename an existing function.",
    "function.report": "Return a richer function report with signature, variables, call graph edges, xrefs, and decompilation output.",
    "function.return_type.set": "Set the return type of a function.",
    "function.signature.get": "Return the full signature of a function.",
    "function.signature.set": "Apply a full C-style signature declaration to a function.",
    "function.thunk.set": "Mark a function as a thunk to another function.",
    "function.variables": "List parameters and local variables for a function.",
    "layout.enum.create": "Create an enum data type in a chosen category.",
    "layout.enum.member.add": "Add a named value to an enum data type.",
    "layout.enum.member.remove": "Remove a named member from an enum data type.",
    "layout.inspect.components": "Inspect the component layout of a composite data type.",
    "layout.struct.bitfield.add": "Insert a bitfield into a structure at a byte and bit offset.",
    "layout.struct.create": "Create a structure data type in a chosen category.",
    "layout.struct.field.add": "Add a field to a structure at a specific offset or append position.",
    "layout.struct.field.clear": "Clear a field from a structure by offset, ordinal, or field name.",
    "layout.struct.field.comment.set": "Set or clear the comment on a structure field.",
    "layout.struct.field.rename": "Rename a structure field.",
    "layout.struct.field.replace": "Replace an existing structure field with a new type, size, name, or comment.",
    "layout.struct.fill_from_decompiler": "Build or extend a structure from decompiler-observed usage of a variable.",
    "layout.struct.get": "Return a structure definition together with its components.",
    "layout.struct.resize": "Resize a structure to a specific total length.",
    "layout.union.create": "Create a union data type in a chosen category.",
    "layout.union.member.add": "Add a member to a union data type.",
    "layout.union.member.remove": "Remove a member from a union data type.",
    "parameter.add": "Add a new parameter to a function with a chosen type and storage.",
    "parameter.move": "Reorder a parameter to a new ordinal within the signature.",
    "parameter.remove": "Remove a parameter from a function by ordinal or name.",
    "parameter.replace": "Replace an existing parameter definition by ordinal or name.",
    "stackframe.variable.clear": "Clear a stack-frame variable at a specific stack offset.",
    "stackframe.variable.create": "Create a stack-frame variable at a specific stack offset.",
    "stackframe.variables": "List stack-frame variables for a function.",
    "type.apply_at": "Apply a data type at an address in the listing.",
    "type.archives.list": "List the current program archive plus attached source archives.",
    "type.category.create": "Create a new data type category path.",
    "type.category.list": "List data type categories under a path, optionally recursively.",
    "type.define_c": "Define a new data type from a C declaration.",
    "type.delete": "Delete a data type by name or full path.",
    "type.get": "Return details for a data type by name or full path.",
    "type.get_by_id": "Look up a data type by internal ID, universal ID, or source archive ID.",
    "type.list": "List data types with filtering and pagination support.",
    "type.parse_c": "Parse a C declaration and return the resulting type without necessarily committing it.",
    "type.rename": "Rename an existing data type.",
    "type.source_archives.list": "List source archives referenced by the current data type manager.",
    "variable.comment.set": "Set or clear the comment attached to a local variable or parameter.",
    "variable.local.create": "Create a local variable with explicit type, storage, and optional comment.",
    "variable.local.remove": "Remove a local variable from a function.",
    "variable.rename": "Rename a local variable or parameter.",
    "variable.retype": "Change the data type of a local variable or parameter.",
    "decomp.ast": "Decompile a function and return the Clang markup tree for the result.",
    "decomp.function": "Decompile a function and return recovered C source code.",
    "decomp.global.rename": "Rename a global symbol selected through decompiler high-symbol information.",
    "decomp.global.retype": "Retype a global symbol selected through decompiler high-symbol information.",
    "decomp.high_function.summary": "Summarize the high-function view, including local symbols, globals, blocks, and jump tables.",
    "decomp.override.get": "Return the decompiler call override, if any, for a specific callsite.",
    "decomp.override.set": "Set or replace the decompiler call override signature for a specific callsite.",
    "decomp.tokens": "Decompile a function and return tokenized Clang markup for the output.",
    "decomp.trace_type.backward": "Trace type propagation backward from a selected decompiler symbol.",
    "decomp.trace_type.forward": "Trace type propagation forward from a selected decompiler symbol.",
    "decomp.writeback.locals": "Commit decompiler-recovered local names back into the program database.",
    "decomp.writeback.params": "Commit decompiler-recovered parameter information back into the program database.",
    "ghidra.call": "Invoke Ghidra or Java APIs directly through a generic bridge.",
    "ghidra.eval": "Evaluate Python code inside the live Ghidra runtime context.",
    "ghidra.info": "Return runtime information about Ghidra, PyGhidra, and the server environment.",
    "ghidra.script": "Run a Ghidra script against an open program session.",
    "graph.basic_blocks": "List the basic blocks that make up a function.",
    "graph.call_paths": "Find call graph paths between two functions up to a chosen depth.",
    "graph.cfg.edges": "List control-flow edges between the basic blocks of a function.",
    "pcode.block": "Return per-instruction p-code for the basic block containing an address.",
    "pcode.function": "Return per-instruction p-code for a function.",
    "pcode.op.at": "Return the p-code ops generated by the instruction at an address.",
    "pcode.varnode_uses": "Find p-code reads and writes that match a selected varnode.",
    "search.bytes": "Search program memory for an exact byte pattern.",
    "search.constants": "Search instructions for scalar constant operands that match a value.",
    "search.defined_strings": "List defined strings discovered in the program.",
    "search.instructions": "Search instructions by mnemonic or rendered instruction text.",
    "search.pcode": "Search p-code operations by mnemonic or rendered op text.",
    "search.resolve": "Resolve a symbol name or expression into an address.",
    "search.text": "Search for text across defined strings and raw memory matches.",
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
