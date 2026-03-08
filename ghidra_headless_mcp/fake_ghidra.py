"""Fake Ghidra backend for tests and local smoke runs."""

from __future__ import annotations

import base64
import binascii
import copy
import io
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from .backend import MAX_MEMORY_READ_BYTES, GhidraBackendError


@dataclass
class _FakeSession:
    session_id: str
    filename: str
    program_name: str
    project_location: str = "/tmp/fake-ghidra-project"
    project_name: str = "fake_project"
    read_only: bool = True
    function_names: dict[int, str] = field(
        default_factory=lambda: {
            0x1000: "entry",
            0x1010: "add_numbers",
            0x1040: "main",
        }
    )
    comments: dict[tuple[str, str], str | None] = field(default_factory=dict)
    symbols: dict[int, list[dict[str, Any]]] = field(
        default_factory=lambda: {
            0x1000: [
                {
                    "id": 1,
                    "name": "entry",
                    "short_name": "entry",
                    "address": "0x1000",
                    "symbol_type": "Function",
                    "source_type": "USER_DEFINED",
                    "namespace": "Global",
                    "primary": True,
                    "external": False,
                }
            ],
            0x1010: [
                {
                    "id": 2,
                    "name": "add_numbers",
                    "short_name": "add_numbers",
                    "address": "0x1010",
                    "symbol_type": "Function",
                    "source_type": "USER_DEFINED",
                    "namespace": "Global",
                    "primary": True,
                    "external": False,
                }
            ],
            0x1040: [
                {
                    "id": 3,
                    "name": "main",
                    "short_name": "main",
                    "address": "0x1040",
                    "symbol_type": "Function",
                    "source_type": "USER_DEFINED",
                    "namespace": "Global",
                    "primary": True,
                    "external": False,
                }
            ],
        }
    )
    memory: bytearray = field(default_factory=lambda: bytearray(range(256)) * 8)
    active_transaction: dict[str, Any] | None = None
    can_undo: bool = False
    can_redo: bool = False
    analysis_status: str = "idle"
    analysis_option_values: dict[str, Any] = field(
        default_factory=lambda: {
            "Decompiler Parameter ID": True,
            "Create Address Tables": True,
            "ELF Scalar Operand References": True,
        }
    )
    types: dict[str, dict[str, Any]] = field(
        default_factory=lambda: {
            "/int": {
                "name": "int",
                "display_name": "int",
                "path": "/int",
                "category": "/",
                "length": 4,
                "description": "fake built-in int",
                "java_type": "ghidra.program.model.data.IntegerDataType",
            }
        }
    )


@dataclass
class _FakeTask:
    task_id: str
    kind: str
    session_id: str | None
    status: str = "completed"
    result: dict[str, Any] | None = None
    error: str | None = None
    cancel_requested: bool = False


class FakeGhidraBackend:
    """Small fake backend with enough behavior for server tests."""

    def __init__(self, *, deterministic: bool = True):
        self._deterministic = deterministic
        self._sessions: dict[str, _FakeSession] = {}
        self._tasks: dict[str, _FakeTask] = {}

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)

        canonical_alias = self._canonical_aliases().get(name)
        if canonical_alias is not None:
            return getattr(self, canonical_alias)

        if self._is_canonical_method(name):
            return lambda *args, **kwargs: self._dispatch_canonical(name, *args, **kwargs)

        def _fallback(*args: Any, **kwargs: Any) -> dict[str, Any]:
            return {
                "backend_method": name,
                "args": list(args),
                "kwargs": kwargs,
                "status": "ok",
            }

        return _fallback

    def ping(self) -> dict[str, str]:
        return {"status": "ok", "message": "pong"}

    def ghidra_info(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "install_dir": "/fake/ghidra",
            "ghidra_version": "fake-1.0",
            "pyghidra_version": "fake-1.0",
            "deterministic": self._deterministic,
            "jvm_started": True,
        }

    def session_open(
        self,
        path: str,
        *,
        update_analysis: bool = True,
        read_only: bool = True,
        project_location: str | None = None,
        project_name: str | None = None,
        program_name: str | None = None,
        language: str | None = None,
        compiler: str | None = None,
        loader: str | None = None,
    ) -> dict[str, Any]:
        _ = (
            update_analysis,
            project_location,
            project_name,
            program_name,
            language,
            compiler,
            loader,
        )
        session_id = uuid4().hex
        record = _FakeSession(
            session_id=session_id,
            filename=path,
            program_name=program_name or path.rsplit("/", 1)[-1],
            read_only=read_only,
        )
        if project_location is not None:
            record.project_location = project_location
        if project_name is not None:
            record.project_name = project_name
        self._sessions[session_id] = record
        self._ensure_extended_state(record)
        if update_analysis:
            record.analysis_status = "completed"
        return self.binary_summary(session_id)

    def session_open_bytes(
        self,
        data_base64: str,
        *,
        filename: str = "session.bin",
        update_analysis: bool = True,
        read_only: bool = True,
        project_location: str | None = None,
        project_name: str | None = None,
        program_name: str | None = None,
        language: str | None = None,
        compiler: str | None = None,
        loader: str | None = None,
    ) -> dict[str, Any]:
        try:
            data = base64.b64decode(data_base64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise GhidraBackendError(f"invalid base64 data: {exc}") from exc
        opened = self.session_open(
            filename,
            update_analysis=update_analysis,
            read_only=read_only,
            project_location=project_location,
            project_name=project_name,
            program_name=program_name,
            language=language,
            compiler=compiler,
            loader=loader,
        )
        self._get_session(opened["session_id"]).memory[: len(data)] = data[
            : len(self._get_session(opened["session_id"]).memory)
        ]
        return opened

    def session_open_existing(
        self,
        project_location: str,
        project_name: str,
        *,
        program_path: str | None = None,
        folder_path: str = "/",
        program_name: str | None = None,
        read_only: bool = True,
        update_analysis: bool = False,
    ) -> dict[str, Any]:
        _ = folder_path
        return self.session_open(
            program_path or program_name or f"{project_location}/{project_name}",
            update_analysis=update_analysis,
            read_only=read_only,
            project_location=project_location,
            project_name=project_name,
            program_name=program_name,
        )

    def session_close(self, session_id: str) -> dict[str, Any]:
        self._get_session(session_id)
        del self._sessions[session_id]
        return {"closed": True, "session_id": session_id}

    def session_list(self) -> dict[str, Any]:
        items = [self.binary_summary(session_id) for session_id in sorted(self._sessions)]
        return {"sessions": items, "count": len(items)}

    def session_mode(self, session_id: str) -> dict[str, Any]:
        record = self._get_session(session_id)
        return {
            "session_id": session_id,
            "read_only": record.read_only,
            "deterministic": self._deterministic,
            "deterministic_scope": "process",
            "active_transaction": record.active_transaction,
        }

    def session_set_mode(
        self,
        session_id: str,
        *,
        read_only: bool | None = None,
        deterministic: bool | None = None,
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        if read_only is not None:
            record.read_only = read_only
        if deterministic is not None and deterministic != self._deterministic:
            raise GhidraBackendError(
                "deterministic mode is process-level in Ghidra and cannot be changed after startup"
            )
        return self.session_mode(session_id)

    def analysis_status(self, session_id: str) -> dict[str, Any]:
        record = self._get_session(session_id)
        return {
            "session_id": session_id,
            "status": record.analysis_status,
            "last_analysis_started_at": None,
            "last_analysis_completed_at": None,
            "last_analysis_task_id": None,
            "last_analysis_error": None,
            "has_log": False,
        }

    def analysis_update(self, session_id: str) -> dict[str, Any]:
        return self.task_analysis_update(session_id)

    def analysis_update_and_wait(self, session_id: str) -> dict[str, Any]:
        record = self._get_session(session_id)
        record.analysis_status = "completed"
        return {"session_id": session_id, "status": "completed", "log": "fake analysis complete"}

    def analysis_options_list(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        query: str | None = None,
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        names = sorted(record.analysis_option_values)
        if query:
            names = [name for name in names if query.lower() in name.lower()]
        items = [
            self._analysis_option_record(record, name) for name in names[offset : offset + limit]
        ]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(names),
            "count": len(items),
            "items": items,
        }

    def analysis_options_get(self, session_id: str, name: str) -> dict[str, Any]:
        record = self._get_session(session_id)
        if name not in record.analysis_option_values:
            raise GhidraBackendError(f"unknown analysis option: {name}")
        return {"session_id": session_id, **self._analysis_option_record(record, name)}

    def analysis_options_set(self, session_id: str, name: str, value: Any) -> dict[str, Any]:
        record = self._get_session(session_id)
        if name not in record.analysis_option_values:
            raise GhidraBackendError(f"unknown analysis option: {name}")
        self._require_writable(record)
        record.analysis_option_values[name] = value
        record.can_undo = True
        record.can_redo = False
        return self.analysis_options_get(session_id, name)

    def binary_summary(self, session_id: str) -> dict[str, Any]:
        record = self._get_session(session_id)
        return {
            "session_id": session_id,
            "filename": record.filename,
            "program_name": record.program_name,
            "program_path": f"/{record.program_name}",
            "project_location": record.project_location,
            "project_name": record.project_name,
            "language_id": "x86:LE:64:default",
            "compiler_spec_id": "gcc",
            "format": "ELF",
            "entry_point": "0x1000",
            "image_base": "0x1000",
            "min_address": "0x1000",
            "max_address": "0x1fff",
            "read_only": record.read_only,
        }

    def binary_functions(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        query: str | None = None,
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        items = self._function_items(record)
        if query:
            items = [item for item in items if query.lower() in item["name"].lower()]
        page = items[offset : offset + limit]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(items),
            "count": len(page),
            "items": page,
        }

    def binary_get_function_at(self, session_id: str, address: int | str) -> dict[str, Any]:
        record = self._get_session(session_id)
        function = self._get_function(record, address)
        return {"session_id": session_id, "function": self._function_state_record(function)}

    def binary_symbols(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        include_dynamic: bool = False,
        query: str | None = None,
    ) -> dict[str, Any]:
        _ = include_dynamic
        record = self._get_session(session_id)
        items = [symbol for group in record.symbols.values() for symbol in group]
        if query:
            items = [item for item in items if query.lower() in item["name"].lower()]
        page = items[offset : offset + limit]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(items),
            "count": len(page),
            "items": page,
        }

    def binary_strings(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        query: str | None = None,
    ) -> dict[str, Any]:
        items = [
            {"address": "0x2000", "length": 6, "value": "Hello", "data_type": "/string"},
            {"address": "0x2008", "length": 10, "value": "add_numbers", "data_type": "/string"},
        ]
        if query:
            items = [item for item in items if query.lower() in item["value"].lower()]
        page = items[offset : offset + limit]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(items),
            "count": len(page),
            "items": page,
        }

    def binary_imports(
        self, session_id: str, *, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        items = [
            {
                "id": 99,
                "name": "printf",
                "short_name": "printf",
                "address": "0x3000",
                "symbol_type": "Function",
                "source_type": "IMPORTED",
                "namespace": "External",
                "primary": True,
                "external": True,
            }
        ]
        page = items[offset : offset + limit]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(items),
            "count": len(page),
            "items": page,
        }

    def binary_exports(
        self, session_id: str, *, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        items = [
            {"address": "0x1000", "symbol": self._symbol_at(self._get_session(session_id), 0x1000)}
        ]
        page = items[offset : offset + limit]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(items),
            "count": len(page),
            "items": page,
        }

    def binary_memory_blocks(self, session_id: str) -> dict[str, Any]:
        return {
            "session_id": session_id,
            "count": 1,
            "items": [
                {
                    "name": ".text",
                    "start": "0x1000",
                    "end": "0x1fff",
                    "length": 0x1000,
                    "read": True,
                    "write": True,
                    "execute": True,
                    "comment": "fake block",
                }
            ],
        }

    def binary_data(self, session_id: str, *, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        items = [
            {
                "address": "0x2000",
                "length": 6,
                "data_type": "/char",
                "base_data_type": "/char",
                "value": '"Hello"',
                "label": "s_Hello",
                "path_name": "Hello",
            }
        ]
        page = items[offset : offset + limit]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(items),
            "count": len(page),
            "items": page,
        }

    def disasm_function(
        self, session_id: str, address: int | str, *, limit: int = 500
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        addr = self._normalize_function_start(record, self._address_to_int(address))
        items = self._disasm_items(addr)[:limit]
        return {
            "session_id": session_id,
            "function": self._function_record(addr, record.function_names[addr]),
            "count": len(items),
            "items": items,
        }

    def disasm_range(
        self, session_id: str, start: int | str, *, length: int, limit: int = 200
    ) -> dict[str, Any]:
        addr = self._address_to_int(start)
        items = self._disasm_items(addr)[: min(length, limit)]
        return {
            "session_id": session_id,
            "start": hex(addr),
            "length": length,
            "limit": limit,
            "count": len(items),
            "items": items,
        }

    def decomp_function(
        self, session_id: str, function_start: int | str, *, timeout_secs: int = 30
    ) -> dict[str, Any]:
        return self._decomp(session_id, self._address_to_int(function_start), timeout_secs)

    def pcode_function(
        self, session_id: str, function_start: int | str, *, limit: int = 200
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        start = self._normalize_function_start(record, self._address_to_int(function_start))
        items = [
            {
                "address": hex(start),
                "instruction": "MOV EAX, 1",
                "ops": [
                    {
                        "opcode": 1,
                        "mnemonic": "COPY",
                        "sequence": "(ram,0x1000,0)",
                        "inputs": [
                            {
                                "address": "const:1",
                                "size": 4,
                                "space": "const",
                                "constant": True,
                                "register": False,
                                "unique": False,
                            }
                        ],
                        "output": {
                            "address": "register:RAX",
                            "size": 8,
                            "space": "register",
                            "constant": False,
                            "register": True,
                            "unique": False,
                        },
                        "text": "COPY const:1 -> RAX",
                    }
                ],
            }
        ]
        page = items[:limit]
        return {
            "session_id": session_id,
            "function": self._function_record(start, record.function_names[start]),
            "limit": limit,
            "count": len(page),
            "items": page,
        }

    def pcode_op_at(self, session_id: str, address: int | str) -> dict[str, Any]:
        addr = self._address_to_int(address)
        return {
            "session_id": session_id,
            "address": hex(addr),
            "instruction": "CALL add_numbers",
            "ops": [
                {
                    "opcode": 7,
                    "mnemonic": "CALL",
                    "sequence": "(ram,0x1048,0)",
                    "inputs": [],
                    "output": None,
                    "text": "CALL add_numbers",
                }
            ],
        }

    def xref_to(
        self,
        session_id: str,
        address: int | str | None = None,
        *,
        start: int | str | None = None,
        end: int | str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        return self._dispatch_reference_category(
            "reference_to",
            session_id,
            address=address,
            start=start,
            end=end,
            limit=limit,
        )

    def xref_from(
        self,
        session_id: str,
        address: int | str | None = None,
        *,
        start: int | str | None = None,
        end: int | str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        return self._dispatch_reference_category(
            "reference_from",
            session_id,
            address=address,
            start=start,
            end=end,
            limit=limit,
        )

    def function_callers(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        addr = self._address_to_int(function_start)
        items = [self._function_record(0x1040, "main")] if addr == 0x1010 else []
        return {
            "session_id": session_id,
            "function_start": hex(addr),
            "count": len(items),
            "items": items,
        }

    def function_callees(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        addr = self._address_to_int(function_start)
        items = [self._function_record(0x1010, "add_numbers")] if addr == 0x1040 else []
        return {
            "session_id": session_id,
            "function_start": hex(addr),
            "count": len(items),
            "items": items,
        }

    def function_signature_get(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        record = self._get_session(session_id)
        function = self._get_function(record, function_start)
        return {
            "session_id": session_id,
            "function": self._function_state_record(function),
            "signature": self._function_state_record(function)["signature"],
            "calling_convention": function["calling_convention"],
            "signature_source": function["signature_source"],
            "return_type": function["return_type"],
            "parameters": copy.deepcopy(function["parameters"]),
        }

    def function_signature_set(
        self, session_id: str, function_start: int | str, signature: str
    ) -> dict[str, Any]:
        _ = signature
        record = self._get_session(session_id)
        self._require_writable(record)
        record.can_undo = True
        record.can_redo = False
        return self.function_signature_get(session_id, function_start)

    def function_variables(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        record = self._get_session(session_id)
        function = self._get_function(record, function_start)
        return {
            "session_id": session_id,
            "function": self._function_state_record(function),
            "parameters": copy.deepcopy(function["parameters"]),
            "locals": copy.deepcopy(function["locals"]),
        }

    def function_rename(
        self, session_id: str, function_start: int | str, name: str
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        self._require_writable(record)
        function = self._get_function(record, function_start)
        start = int(function["entry_point"])
        record.function_names[start] = name
        function["name"] = name
        record.symbols[start][0]["name"] = name
        record.symbols[start][0]["short_name"] = name
        record.can_undo = True
        record.can_redo = False
        return {"session_id": session_id, "function": self._function_state_record(function)}

    def annotation_comment_get(
        self,
        session_id: str,
        *,
        address: int | str | None = None,
        comment_type: str = "eol",
        function_start: int | str | None = None,
        scope: str = "listing",
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        if scope == "function":
            if function_start is None:
                raise GhidraBackendError("function_start is required for function comments")
            addr = self._normalize_function_start(record, self._address_to_int(function_start))
            key = (scope, hex(addr))
            return {
                "session_id": session_id,
                "scope": scope,
                "function_start": hex(addr),
                "comment_type": comment_type,
                "comment": record.comments.get(key),
            }
        if address is None:
            raise GhidraBackendError("address is required for listing comments")
        key = (scope, hex(self._address_to_int(address)))
        return {
            "session_id": session_id,
            "scope": scope,
            "address": key[1],
            "comment_type": comment_type,
            "comment": record.comments.get(key),
        }

    def annotation_comment_set(
        self,
        session_id: str,
        *,
        comment: str | None,
        address: int | str | None = None,
        comment_type: str = "eol",
        function_start: int | str | None = None,
        scope: str = "listing",
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        self._require_writable(record)
        if scope == "function":
            if function_start is None:
                raise GhidraBackendError("function_start is required for function comments")
            addr = self._normalize_function_start(record, self._address_to_int(function_start))
            record.comments[(scope, hex(addr))] = comment
            record.can_undo = True
            record.can_redo = False
            return self.annotation_comment_get(
                session_id, function_start=hex(addr), comment_type=comment_type, scope=scope
            )
        if address is None:
            raise GhidraBackendError("address is required for listing comments")
        key = (scope, hex(self._address_to_int(address)))
        record.comments[key] = comment
        record.can_undo = True
        record.can_redo = False
        return self.annotation_comment_get(
            session_id, address=key[1], comment_type=comment_type, scope=scope
        )

    def annotation_symbol_rename(
        self, session_id: str, *, address: int | str, new_name: str, old_name: str | None = None
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        self._require_writable(record)
        symbol = self._resolve_symbol(record, self._address_to_int(address), old_name)
        symbol["name"] = new_name
        symbol["short_name"] = new_name
        record.can_undo = True
        record.can_redo = False
        return {"session_id": session_id, "symbol": symbol}

    def annotation_symbol_create(
        self, session_id: str, *, address: int | str, name: str, make_primary: bool = True
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        self._require_writable(record)
        addr = self._address_to_int(address)
        created = {
            "id": max(
                (item["id"] for group in record.symbols.values() for item in group), default=100
            )
            + 1,
            "name": name,
            "short_name": name,
            "address": hex(addr),
            "symbol_type": "Label",
            "source_type": "USER_DEFINED",
            "namespace": "Global",
            "primary": make_primary,
            "external": False,
        }
        record.symbols.setdefault(addr, []).append(created)
        record.can_undo = True
        record.can_redo = False
        return {"session_id": session_id, "symbol": created}

    def annotation_symbol_delete(
        self, session_id: str, *, address: int | str, name: str | None = None
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        self._require_writable(record)
        addr = self._address_to_int(address)
        symbol = self._resolve_symbol(record, addr, name)
        record.symbols[addr].remove(symbol)
        record.can_undo = True
        record.can_redo = False
        return {
            "session_id": session_id,
            "deleted": True,
            "address": hex(addr),
            "name": symbol["name"],
        }

    def memory_read(self, session_id: str, address: int | str, *, length: int) -> dict[str, Any]:
        record = self._get_session(session_id)
        addr = self._address_to_int(address) - 0x1000
        raw = bytes(record.memory[addr : addr + length])
        return {
            "session_id": session_id,
            "address": hex(addr + 0x1000),
            "length": length,
            "data_base64": base64.b64encode(raw).decode("ascii"),
            "data_hex": raw.hex(),
        }

    def memory_write(
        self,
        session_id: str,
        address: int | str,
        *,
        data_base64: str | None = None,
        data_hex: str | None = None,
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        self._require_writable(record)
        payload = self._decode_payload(data_base64=data_base64, data_hex=data_hex)
        if len(payload) > MAX_MEMORY_READ_BYTES:
            raise GhidraBackendError(
                f"write payload too large ({len(payload)} bytes); max is {MAX_MEMORY_READ_BYTES}"
            )
        addr = self._address_to_int(address) - 0x1000
        record.memory[addr : addr + len(payload)] = payload
        record.can_undo = True
        record.can_redo = False
        return {
            "session_id": session_id,
            "address": hex(addr + 0x1000),
            "requested": len(payload),
            "written": len(payload),
        }

    def data_typed_at(self, session_id: str, address: int | str) -> dict[str, Any]:
        addr = self._address_to_int(address)
        defined = addr in {0x2000, 0x2008}
        return {
            "session_id": session_id,
            "address": hex(addr),
            "defined": defined,
            "data": {
                "address": hex(addr),
                "length": 6,
                "data_type": "/char",
                "base_data_type": "/char",
                "value": '"Hello"',
                "label": "s_Hello",
                "path_name": "Hello",
            }
            if defined
            else None,
        }

    def data_create(
        self,
        session_id: str,
        address: int | str,
        *,
        data_type: str,
        length: int | None = None,
        clear_existing: bool = True,
    ) -> dict[str, Any]:
        _ = clear_existing
        record = self._get_session(session_id)
        self._require_writable(record)
        addr = self._address_to_int(address)
        record.can_undo = True
        record.can_redo = False
        return {
            "session_id": session_id,
            "data": {
                "address": hex(addr),
                "length": length or 1,
                "data_type": data_type,
                "base_data_type": data_type,
                "value": None,
                "label": None,
                "path_name": data_type,
            },
        }

    def data_clear(self, session_id: str, address: int | str, *, length: int = 1) -> dict[str, Any]:
        record = self._get_session(session_id)
        self._require_writable(record)
        record.can_undo = True
        record.can_redo = False
        return {
            "session_id": session_id,
            "address": hex(self._address_to_int(address)),
            "length": length,
            "cleared": True,
        }

    def type_list(
        self, session_id: str, *, offset: int = 0, limit: int = 100, query: str | None = None
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        items = list(record.types.values())
        items.sort(key=lambda item: item["path"])
        if query:
            items = [item for item in items if query.lower() in item["path"].lower()]
        page = items[offset : offset + limit]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(items),
            "count": len(page),
            "items": page,
        }

    def type_get(
        self, session_id: str, *, path: str | None = None, name: str | None = None
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        if path:
            if path not in record.types:
                raise GhidraBackendError(f"type not found: {path}")
            return {"session_id": session_id, "type": record.types[path]}
        if name:
            for item in record.types.values():
                if item["name"] == name:
                    return {"session_id": session_id, "type": item}
            raise GhidraBackendError(f"type not found: {name}")
        raise GhidraBackendError("path or name is required")

    def type_define_c(
        self, session_id: str, *, declaration: str, name: str | None = None, category: str = "/"
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        self._require_writable(record)
        type_name = name or declaration.strip().rstrip(";")
        path = f"{category.rstrip('/')}/{type_name}" if category != "/" else f"/{type_name}"
        item = {
            "id": record.next_type_id,
            "name": type_name,
            "display_name": type_name,
            "path": path,
            "category": category,
            "length": 4,
            "description": declaration,
            "java_type": "fake.Type",
        }
        record.types[path] = item
        record.next_type_id += 1
        record.type_categories.add(category)
        record.can_undo = True
        record.can_redo = False
        return {"session_id": session_id, "type": item}

    def type_rename(
        self, session_id: str, *, path: str | None = None, name: str | None = None, new_name: str
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        self._require_writable(record)
        current = self.type_get(session_id, path=path, name=name)["type"]
        old_path = current["path"]
        new_path = (
            f"{current['category'].rstrip('/')}/{new_name}"
            if current["category"] != "/"
            else f"/{new_name}"
        )
        current = dict(current)
        current["name"] = new_name
        current["display_name"] = new_name
        current["path"] = new_path
        del record.types[old_path]
        record.types[new_path] = current
        record.can_undo = True
        record.can_redo = False
        return {"session_id": session_id, "type": current}

    def type_delete(
        self, session_id: str, *, path: str | None = None, name: str | None = None
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        self._require_writable(record)
        current = self.type_get(session_id, path=path, name=name)["type"]
        del record.types[current["path"]]
        record.can_undo = True
        record.can_redo = False
        return {"session_id": session_id, "deleted": True, "type": current}

    def undo_begin(
        self, session_id: str, *, description: str = "MCP Transaction"
    ) -> dict[str, Any]:
        record = self._get_session(session_id)
        self._require_writable(record)
        if record.active_transaction is not None:
            raise GhidraBackendError("session already has an active transaction")
        record.active_transaction = {"id": 1, "description": description}
        return self.undo_status(session_id)

    def undo_commit(self, session_id: str) -> dict[str, Any]:
        record = self._get_session(session_id)
        if record.active_transaction is None:
            raise GhidraBackendError("session has no active transaction")
        record.active_transaction = None
        record.can_undo = True
        record.can_redo = False
        return self.undo_status(session_id)

    def undo_revert(self, session_id: str) -> dict[str, Any]:
        record = self._get_session(session_id)
        if record.active_transaction is None:
            raise GhidraBackendError("session has no active transaction")
        record.active_transaction = None
        record.can_redo = False
        return self.undo_status(session_id)

    def undo_undo(self, session_id: str) -> dict[str, Any]:
        record = self._get_session(session_id)
        if not record.can_undo:
            raise GhidraBackendError("program cannot undo")
        record.can_undo = False
        record.can_redo = True
        return self.undo_status(session_id)

    def undo_redo(self, session_id: str) -> dict[str, Any]:
        record = self._get_session(session_id)
        if not record.can_redo:
            raise GhidraBackendError("program cannot redo")
        record.can_redo = False
        record.can_undo = True
        return self.undo_status(session_id)

    def undo_status(self, session_id: str) -> dict[str, Any]:
        record = self._get_session(session_id)
        return {
            "session_id": session_id,
            "can_undo": record.can_undo,
            "can_redo": record.can_redo,
            "active_transaction": record.active_transaction,
        }

    def task_analysis_update(self, session_id: str) -> dict[str, Any]:
        self._get_session(session_id).analysis_status = "running"
        task_id = uuid4().hex
        task = _FakeTask(
            task_id=task_id,
            kind="analysis.update_and_wait",
            session_id=session_id,
            result={
                "session_id": session_id,
                "status": "completed",
                "log": "fake analysis complete",
            },
        )
        self._tasks[task_id] = task
        self._get_session(session_id).analysis_status = "completed"
        return {
            "task_id": task_id,
            "kind": task.kind,
            "session_id": session_id,
            "status": task.status,
        }

    def task_status(self, task_id: str) -> dict[str, Any]:
        task = self._get_task(task_id)
        return {
            "task_id": task_id,
            "kind": task.kind,
            "session_id": task.session_id,
            "status": task.status,
            "cancel_requested": task.cancel_requested,
            "cancel_supported": False,
            "result_ready": task.status in {"completed", "failed", "cancelled"},
            "error": task.error,
            "created_at": None,
        }

    def task_result(self, task_id: str) -> dict[str, Any]:
        task = self._get_task(task_id)
        if task.status not in {"completed", "failed", "cancelled"}:
            raise GhidraBackendError(
                f"task {task_id} is not in a terminal state (status={task.status})"
            )
        payload = {
            "task_id": task_id,
            "kind": task.kind,
            "session_id": task.session_id,
            "status": task.status,
        }
        if task.error is not None:
            payload["error"] = task.error
        if task.result is not None:
            payload["result"] = task.result
        return payload

    def task_cancel(self, task_id: str) -> dict[str, Any]:
        task = self._get_task(task_id)
        task.cancel_requested = True
        task.status = "cancelled"
        return {
            "task_id": task_id,
            "cancel_requested": True,
            "cancelled": True,
            "status": task.status,
        }

    def call_api(
        self,
        target: str,
        *,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        transitioned = self._transition(session_id)
        return {
            "target": target,
            "callable": True,
            "result": {"args": args or [], "kwargs": kwargs or {}},
            "mode_transitioned": bool(transitioned),
            "transitioned_session_ids": transitioned,
        }

    def eval_code(self, code: str, *, session_id: str | None = None) -> dict[str, Any]:
        transitioned = self._transition(session_id)
        context: dict[str, Any] = {
            "sessions": list(self._sessions),
            "session_id": session_id,
            "backend": self,
        }
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            try:
                compiled = compile(code, "<fake-ghidra-headless-mcp>", "eval")
            except SyntaxError:
                compiled = compile(code, "<fake-ghidra-headless-mcp>", "exec")
                exec(compiled, context, context)
                result = context.get("_")
            else:
                result = eval(compiled, context, context)
        payload: dict[str, Any] = {
            "result": result,
            "mode_transitioned": bool(transitioned),
            "transitioned_session_ids": transitioned,
        }
        if stdout_buffer.getvalue():
            payload["stdout"] = stdout_buffer.getvalue()
        if stderr_buffer.getvalue():
            payload["stderr"] = stderr_buffer.getvalue()
        return payload

    def run_script(
        self, path: str, *, session_id: str | None = None, script_args: list[str] | None = None
    ) -> dict[str, Any]:
        if session_id is None:
            raise GhidraBackendError("session_id is required")
        transitioned = self._transition(session_id)
        return {
            "path": path,
            "session_id": session_id,
            "stdout": f"fake script args={script_args or []}\n",
            "mode_transitioned": bool(transitioned),
            "transitioned_session_ids": transitioned,
        }

    def _canonical_aliases(self) -> dict[str, str]:
        return {
            "program_open": "session_open",
            "program_open_bytes": "session_open_bytes",
            "program_open_existing": "session_open_existing",
            "program_close": "session_close",
            "program_list": "session_list",
            "program_mode_get": "session_mode",
            "program_mode_set": "session_set_mode",
            "session_save": "program_save",
            "session_save_as": "program_save_as",
            "session_export_project": "program_export_project",
            "session_export_binary": "program_export_binary",
            "program_summary": "binary_summary",
            "binary_rebase": "program_rebase",
            "listing_disassemble_function": "disasm_function",
            "listing_disassemble_range": "disasm_range",
            "struct_create": "layout_struct_create",
            "struct_field_add": "layout_struct_field_add",
            "struct_field_rename": "layout_struct_field_rename",
            "enum_create": "layout_enum_create",
            "enum_member_add": "layout_enum_member_add",
            "function_by_name": "function_find",
            "function_basic_blocks": "graph_basic_blocks",
            "symbol_by_name": "symbol_find",
            "cfg_edges": "graph_cfg_edges",
            "callgraph_paths": "graph_callgraph_paths",
            "external_library_list": "external_libraries_list",
        }

    def _is_canonical_method(self, name: str) -> bool:
        return name.startswith(
            (
                "program_",
                "project_",
                "transaction_",
                "listing_",
                "patch_",
                "context_",
                "memory_blocks_",
                "symbol_",
                "namespace_",
                "class_",
                "external_",
                "reference_",
                "equate_",
                "comment_",
                "bookmark_",
                "tag_",
                "metadata_",
                "source_",
                "relocation_",
                "function_",
                "parameter_",
                "variable_",
                "stackframe_",
                "type_category_",
                "type_archives_",
                "type_source_archives_",
                "type_get_by_id",
                "layout_",
                "decomp_",
                "graph_",
                "search_",
                "address_resolve",
                "batch_run_on_functions",
            )
        )

    def _dispatch_canonical(self, name: str, /, *args: Any, **kwargs: Any) -> dict[str, Any]:
        if name.startswith(("program_", "project_", "transaction_")):
            return self._dispatch_program_category(name, *args, **kwargs)
        if name.startswith(("listing_", "patch_", "context_", "memory_blocks_")):
            return self._dispatch_listing_category(name, *args, **kwargs)
        if name.startswith(("symbol_", "namespace_", "class_", "external_")):
            return self._dispatch_symbol_category(name, *args, **kwargs)
        if name.startswith(("reference_", "equate_")):
            return self._dispatch_reference_category(name, *args, **kwargs)
        if name.startswith(
            (
                "comment_",
                "bookmark_",
                "tag_",
                "metadata_",
                "source_",
                "relocation_",
            )
        ):
            return self._dispatch_annotation_category(name, *args, **kwargs)
        if name.startswith(("function_", "parameter_", "variable_", "stackframe_")):
            return self._dispatch_function_category(name, *args, **kwargs)
        if name.startswith(("type_category_", "type_archives_", "type_source_archives_")):
            return self._dispatch_type_category(name, *args, **kwargs)
        if name.startswith(("type_favorites_", "type_get_by_id")):
            return self._dispatch_type_category(name, *args, **kwargs)
        if name.startswith("layout_"):
            return self._dispatch_layout_category(name, *args, **kwargs)
        if name.startswith("decomp_"):
            return self._dispatch_decomp_category(name, *args, **kwargs)
        if name.startswith(("graph_", "search_", "address_resolve", "batch_run_on_functions")):
            return self._dispatch_graph_category(name, *args, **kwargs)
        raise AttributeError(name)

    def shutdown(self) -> None:
        self._sessions.clear()
        self._tasks.clear()

    def _get_session(self, session_id: str) -> _FakeSession:
        try:
            record = self._sessions[session_id]
        except KeyError as exc:
            raise GhidraBackendError(f"unknown session_id: {session_id}") from exc
        self._ensure_extended_state(record)
        return record

    def _get_task(self, task_id: str) -> _FakeTask:
        try:
            return self._tasks[task_id]
        except KeyError as exc:
            raise GhidraBackendError(f"unknown task_id: {task_id}") from exc

    def _analysis_option_record(self, record: _FakeSession, name: str) -> dict[str, Any]:
        value = record.analysis_option_values[name]
        return {
            "name": name,
            "value": str(value),
            "default": True,
            "current": value,
            "java_type": type(value).__name__,
        }

    def _address_to_int(self, value: int | str) -> int:
        if isinstance(value, int):
            return value
        return int(str(value), 0)

    def _function_name(self, record: _FakeSession, addr: int) -> str:
        return record.function_names.get(
            self._normalize_function_start(record, addr), record.function_names[0x1040]
        )

    def _normalize_function_start(self, record: _FakeSession, addr: int) -> int:
        if addr in record.function_names:
            return addr
        if 0x1010 <= addr < 0x1030:
            return 0x1010
        if 0x1040 <= addr < 0x1080:
            return 0x1040
        return 0x1000

    def _function_record(self, start: int, name: str) -> dict[str, Any]:
        end = start + (0x1F if name == "main" else 0x0F)
        signature = f"int {name}(int a, int b)" if name == "add_numbers" else f"int {name}(void)"
        return {
            "name": name,
            "entry_point": hex(start),
            "body_start": hex(start),
            "body_end": hex(end),
            "signature": signature,
            "calling_convention": "default",
            "external": False,
            "thunk": False,
        }

    def _symbol_at(self, record: _FakeSession, addr: int) -> dict[str, Any] | None:
        group = record.symbols.get(addr)
        return None if not group else group[0]

    def _resolve_symbol(
        self, record: _FakeSession, addr: int, old_name: str | None
    ) -> dict[str, Any]:
        for symbol in record.symbols.get(addr, []):
            if old_name is None or symbol["name"] == old_name or symbol["short_name"] == old_name:
                return symbol
        raise GhidraBackendError(f"no symbol found at {hex(addr)}")

    def _disasm_items(self, start: int) -> list[dict[str, Any]]:
        return [
            {"address": hex(start), "mnemonic": "PUSH", "text": "PUSH RBP", "bytes": "55"},
            {
                "address": hex(start + 1),
                "mnemonic": "MOV",
                "text": "MOV RBP, RSP",
                "bytes": "4889e5",
            },
            {"address": hex(start + 4), "mnemonic": "RET", "text": "RET", "bytes": "c3"},
        ]

    def _decomp(self, session_id: str, start: int, timeout_secs: int) -> dict[str, Any]:
        _ = timeout_secs
        record = self._get_session(session_id)
        start = self._normalize_function_start(record, start)
        name = record.function_names[start]
        body = "return a + b;" if name == "add_numbers" else "return 0;"
        return {
            "session_id": session_id,
            "function": self._function_record(start, name),
            "decompile_completed": True,
            "timed_out": False,
            "cancelled": False,
            "error_message": None,
            "c": f"int {name}(void) {{ {body} }}",
            "signature": f"int {name}(void)",
        }

    def _transition(self, session_id: str | None) -> list[str]:
        if session_id is None:
            return []
        record = self._get_session(session_id)
        if record.read_only:
            record.read_only = False
            return [session_id]
        return []

    def _require_writable(self, record: _FakeSession) -> None:
        if record.read_only:
            raise GhidraBackendError(f"session {record.session_id} is read-only")

    def _decode_payload(self, *, data_base64: str | None, data_hex: str | None) -> bytes:
        if bool(data_base64) == bool(data_hex):
            raise GhidraBackendError("exactly one of data_base64 or data_hex is required")
        if data_base64:
            try:
                return base64.b64decode(data_base64, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise GhidraBackendError(f"invalid base64 payload: {exc}") from exc
        try:
            return bytes.fromhex(data_hex or "")
        except ValueError as exc:
            raise GhidraBackendError(f"invalid hex payload: {exc}") from exc

    def _ensure_extended_state(self, record: _FakeSession) -> None:
        if getattr(record, "_extended_ready", False):
            return

        functions: dict[int, dict[str, Any]] = {
            0x1000: {
                "name": "entry",
                "entry_point": 0x1000,
                "body_start": 0x1000,
                "body_end": 0x100F,
                "return_type": "/int",
                "calling_convention": "default",
                "signature_source": "USER_DEFINED",
                "flags": {
                    "varargs": False,
                    "inline": False,
                    "noreturn": False,
                    "custom_storage": False,
                },
                "thunk_target": None,
                "parameters": [],
                "locals": [],
                "stackframe": [],
            },
            0x1010: {
                "name": "add_numbers",
                "entry_point": 0x1010,
                "body_start": 0x1010,
                "body_end": 0x102F,
                "return_type": "/int",
                "calling_convention": "default",
                "signature_source": "USER_DEFINED",
                "flags": {
                    "varargs": False,
                    "inline": False,
                    "noreturn": False,
                    "custom_storage": False,
                },
                "thunk_target": None,
                "parameters": [
                    self._parameter_entry("a", "/int", 0),
                    self._parameter_entry("b", "/int", 1),
                ],
                "locals": [self._local_entry("local_4", "/int", "stack[-0x4]")],
                "stackframe": [],
            },
            0x1040: {
                "name": "main",
                "entry_point": 0x1040,
                "body_start": 0x1040,
                "body_end": 0x107F,
                "return_type": "/int",
                "calling_convention": "default",
                "signature_source": "USER_DEFINED",
                "flags": {
                    "varargs": False,
                    "inline": False,
                    "noreturn": False,
                    "custom_storage": False,
                },
                "thunk_target": None,
                "parameters": [],
                "locals": [self._local_entry("result", "/int", "stack[-0x8]")],
                "stackframe": [],
            },
        }
        record.function_state = functions
        record.function_names = {start: item["name"] for start, item in functions.items()}
        record.memory_blocks = [
            {
                "name": ".text",
                "start": "0x1000",
                "end": "0x1fff",
                "length": 0x1000,
                "read": True,
                "write": True,
                "execute": True,
                "comment": "fake text block",
            },
            {
                "name": ".data",
                "start": "0x2000",
                "end": "0x20ff",
                "length": 0x100,
                "read": True,
                "write": True,
                "execute": False,
                "comment": "fake data block",
            },
        ]
        record.typed_data = {
            0x2000: {
                "address": "0x2000",
                "length": 6,
                "data_type": "/char",
                "base_data_type": "/char",
                "value": '"Hello"',
                "label": "s_Hello",
                "path_name": "Hello",
            },
            0x2008: {
                "address": "0x2008",
                "length": 12,
                "data_type": "/string",
                "base_data_type": "/string",
                "value": '"add_numbers"',
                "label": "s_add_numbers",
                "path_name": "add_numbers",
            },
        }
        record.code_units = self._build_code_units(record)
        record.context_ranges = [
            {"register": "TMode", "start": "0x1000", "end": "0x1fff", "value": 0}
        ]
        record.namespaces = {
            "Global": {"name": "Global", "parent": None, "kind": "namespace"},
            "External": {"name": "External", "parent": None, "kind": "namespace"},
        }
        record.symbol_history = {
            symbol["id"]: [
                {"action": "create", "name": symbol["name"], "namespace": symbol["namespace"]}
            ]
            for group in record.symbols.values()
            for symbol in group
        }
        record.external_libraries = {
            "libc.so.6": {
                "name": "libc.so.6",
                "path": "/lib/x86_64-linux-gnu/libc.so.6",
            }
        }
        record.external_locations = {
            "printf": {
                "label": "printf",
                "library_name": "libc.so.6",
                "address": "0x3000",
                "symbol_type": "Function",
            }
        }
        record.external_entrypoints = {"0x3000"}
        record.references = [
            {
                "id": 1,
                "from": "0x1048",
                "to": "0x1010",
                "reference_type": "CALL",
                "operand_index": 0,
                "primary": True,
                "external": False,
                "association": None,
                "kind": "memory",
            }
        ]
        record.reference_next_id = 2
        record.equates = []
        record.comment_store = {}
        record.bookmarks = []
        record.tags = {}
        record.metadata_store = {}
        record.source_files = []
        record.source_maps = []
        record.relocations = []
        record.type_categories = {"/"}
        next_type_id = 1
        for item in record.types.values():
            item.setdefault("id", next_type_id)
            next_type_id += 1
        record.next_type_id = next_type_id
        record.type_archives = [
            {"name": "program", "kind": "program", "path": record.project_location},
            {"name": "builtin", "kind": "builtin", "path": "/fake/ghidra/data-types"},
        ]
        record.type_source_archives = [
            {"name": "program", "source_archive_id": "program-1", "path": record.project_location}
        ]
        record.favorite_types = {"/int"}
        record.layouts = {}
        record.decomp_overrides = {}
        record.global_types = {}
        record.undo_label = None
        record.redo_label = None
        record.project_folders = [
            {"path": "/", "name": "/", "parent_path": None},
            {"path": "/analysis", "name": "analysis", "parent_path": "/"},
        ]
        record.project_files = {
            f"/{record.program_name}": {
                "path": f"/{record.program_name}",
                "name": record.program_name,
                "folder_path": "/",
                "content_type": "Program",
                "versioned": False,
                "read_only": record.read_only,
            }
        }
        record._extended_ready = True

    def _build_code_units(self, record: _FakeSession) -> dict[int, dict[str, Any]]:
        items: dict[int, dict[str, Any]] = {}
        for function in record.function_state.values():
            for insn in self._disasm_items(int(function["entry_point"])):
                addr = int(insn["address"], 16)
                items[addr] = {
                    "address": insn["address"],
                    "kind": "instruction",
                    "length": max(1, len(insn["bytes"]) // 2),
                    "mnemonic": insn["mnemonic"],
                    "text": insn["text"],
                    "bytes": insn["bytes"],
                }
        for addr, data in record.typed_data.items():
            items[addr] = {"address": hex(addr), "kind": "data", **data}
        return items

    def _parameter_entry(
        self,
        name: str,
        data_type: str,
        ordinal: int,
        *,
        storage: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        return {
            "name": name,
            "data_type": data_type,
            "storage": storage,
            "comment": comment,
            "first_use_offset": None,
            "ordinal": ordinal,
            "auto_parameter": False,
        }

    def _local_entry(
        self,
        name: str,
        data_type: str,
        storage: str,
        *,
        comment: str | None = None,
    ) -> dict[str, Any]:
        return {
            "name": name,
            "data_type": data_type,
            "storage": storage,
            "comment": comment,
            "first_use_offset": 0,
        }

    def _note_mutation(self, record: _FakeSession, label: str) -> None:
        record.can_undo = True
        record.can_redo = False
        record.undo_label = label
        record.redo_label = None

    def _page(
        self, items: list[dict[str, Any]], offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        page = items[offset : offset + limit]
        return {
            "offset": offset,
            "limit": limit,
            "total": len(items),
            "count": len(page),
            "items": page,
        }

    def _function_items(self, record: _FakeSession) -> list[dict[str, Any]]:
        items = [self._function_state_record(item) for item in record.function_state.values()]
        items.sort(key=lambda item: int(item["entry_point"], 16))
        return items

    def _function_state_record(self, function: dict[str, Any]) -> dict[str, Any]:
        name = str(function["name"])
        params = function.get("parameters", [])
        if not params:
            signature = f"{function['return_type'].split('/')[-1]} {name}(void)"
        else:
            rendered_params = ", ".join(
                f"{param['data_type'].split('/')[-1]} {param['name']}" for param in params
            )
            signature = f"{function['return_type'].split('/')[-1]} {name}({rendered_params})"
        return {
            "name": name,
            "entry_point": hex(int(function["entry_point"])),
            "body_start": hex(int(function["body_start"])),
            "body_end": hex(int(function["body_end"])),
            "signature": signature,
            "calling_convention": function["calling_convention"],
            "external": False,
            "thunk": bool(function.get("thunk_target")),
        }

    def _get_function(self, record: _FakeSession, function_start: int | str) -> dict[str, Any]:
        start = self._normalize_function_start(record, self._address_to_int(function_start))
        try:
            return record.function_state[start]
        except KeyError as exc:
            raise GhidraBackendError(f"unknown function start: {hex(start)}") from exc

    def _find_var(self, function: dict[str, Any], name: str) -> tuple[str, dict[str, Any], int]:
        for bucket_name in ("parameters", "locals", "stackframe"):
            bucket = function.get(bucket_name, [])
            for index, item in enumerate(bucket):
                if item["name"] == name:
                    return bucket_name, item, index
        raise GhidraBackendError(f"unknown variable: {name}")

    def _next_symbol_id(self, record: _FakeSession) -> int:
        return (
            max((item["id"] for group in record.symbols.values() for item in group), default=0) + 1
        )

    def _comment_key(self, scope: str, location: str, comment_type: str) -> tuple[str, str, str]:
        return (scope, location, comment_type.lower())

    def _range_bounds(
        self,
        start: int | str | None = None,
        end: int | str | None = None,
        length: int | None = None,
    ) -> tuple[int | None, int | None]:
        if start is None:
            return None, None if end is None else self._address_to_int(end)
        start_int = self._address_to_int(start)
        if end is not None:
            return start_int, self._address_to_int(end)
        if length is not None:
            return start_int, start_int + max(0, int(length)) - 1
        return start_int, start_int

    def _reference_target_matches(self, value: str, target: int | str) -> bool:
        if isinstance(target, int):
            return value == hex(target)
        text = str(target)
        if text.startswith("0x"):
            return value == text.lower()
        return value == text

    def _coerce_type_id(self, value: int | str) -> int:
        return int(value)

    def _arg_value(
        self, args: tuple[Any, ...], kwargs: dict[str, Any], key: str, index: int
    ) -> Any:
        if key in kwargs:
            return kwargs[key]
        return args[index]

    def _session_id(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
        return str(self._arg_value(args, kwargs, "session_id", 0))

    def _dispatch_program_category(self, name: str, /, *args: Any, **kwargs: Any) -> dict[str, Any]:
        session_id = self._session_id(args, kwargs)
        record = self._get_session(session_id)

        if name == "program_save":
            self._note_mutation(record, f"save:{record.program_name}")
            return {
                **self.binary_summary(session_id),
                "saved": True,
            }

        if name == "program_save_as":
            self._require_writable(record)
            folder_path = str(kwargs.get("folder_path", "/"))
            program_name = str(kwargs.get("program_name") or record.program_name)
            record.program_name = program_name
            new_path = (
                f"{folder_path.rstrip('/')}/{program_name}"
                if folder_path != "/"
                else f"/{program_name}"
            )
            record.project_files[new_path] = {
                "path": new_path,
                "name": program_name,
                "folder_path": folder_path,
                "content_type": "Program",
                "versioned": False,
                "read_only": record.read_only,
            }
            self._note_mutation(record, f"save_as:{program_name}")
            return {
                **self.binary_summary(session_id),
                "saved_as": True,
                "program_path": new_path,
            }

        if name == "program_export_project":
            return {
                "session_id": session_id,
                "path": kwargs.get("destination")
                or kwargs.get("path")
                or f"{record.project_location}/{record.project_name}.gpr",
                "exported": True,
            }

        if name == "program_export_binary":
            return {
                "session_id": session_id,
                "path": kwargs.get("path")
                or f"{record.project_location}/{record.program_name}.bin",
                "exported": True,
            }

        if name == "program_rebase":
            self._require_writable(record)
            image_base = self._address_to_int(kwargs["image_base"])
            self._note_mutation(record, f"rebase:{hex(image_base)}")
            return {**self.binary_summary(session_id), "image_base": hex(image_base)}

        if name == "project_files_list":
            folder_path = str(kwargs.get("folder_path", "/"))
            items = [
                copy.deepcopy(item)
                for item in sorted(record.project_files.values(), key=lambda item: item["path"])
                if folder_path == "/" or item["folder_path"] == folder_path
            ]
            return {
                "session_id": session_id,
                **self._page(items, kwargs.get("offset", 0), kwargs.get("limit", 100)),
            }

        if name == "project_folders_list":
            items = sorted(record.project_folders, key=lambda item: item["path"])
            return {
                "session_id": session_id,
                **self._page(
                    copy.deepcopy(items), kwargs.get("offset", 0), kwargs.get("limit", 100)
                ),
            }

        if name == "project_file_info":
            path = str(kwargs.get("path") or f"/{record.program_name}")
            try:
                item = record.project_files[path]
            except KeyError as exc:
                raise GhidraBackendError(f"unknown project file: {path}") from exc
            return {"session_id": session_id, "file": copy.deepcopy(item)}

        if name == "project_program_open":
            file_path = str(kwargs.get("path") or f"/{record.program_name}")
            file_info = record.project_files.get(file_path)
            if file_info is None:
                raise GhidraBackendError(f"unknown project file: {file_path}")
            return self.session_open_existing(
                record.project_location,
                record.project_name,
                folder_path=file_info["folder_path"],
                program_name=file_info["name"],
                read_only=bool(kwargs.get("read_only", True)),
                update_analysis=bool(kwargs.get("update_analysis", False)),
            )

        if name == "project_search_programs":
            items = [
                copy.deepcopy(item)
                for item in sorted(record.project_files.values(), key=lambda item: item["path"])
                if str(item.get("content_type")) == str(kwargs.get("content_type", "Program"))
            ]
            query = kwargs.get("query")
            if query is not None:
                needle = str(query).lower()
                items = [
                    item
                    for item in items
                    if needle in str(item.get("path", "")).lower()
                    or needle in str(item.get("name", "")).lower()
                ]
            return {
                "session_id": session_id,
                **self._page(items, kwargs.get("offset", 0), kwargs.get("limit", 100)),
            }

        if name == "transaction_begin":
            self._require_writable(record)
            if record.active_transaction is not None:
                raise GhidraBackendError("session already has an active transaction")
            description = str(kwargs.get("description", "MCP Transaction"))
            record.active_transaction = {
                "id": 1,
                "description": description,
            }
            return self._transaction_status_record(record)

        if name == "transaction_commit":
            if record.active_transaction is None:
                raise GhidraBackendError("session has no active transaction")
            description = record.active_transaction["description"]
            record.active_transaction = None
            self._note_mutation(record, description)
            return self._transaction_status_record(record)

        if name == "transaction_revert":
            if record.active_transaction is None:
                raise GhidraBackendError("session has no active transaction")
            record.active_transaction = None
            record.redo_label = None
            return self._transaction_status_record(record)

        if name == "transaction_undo":
            if not record.can_undo:
                raise GhidraBackendError("program cannot undo")
            record.can_undo = False
            record.can_redo = True
            record.redo_label = record.undo_label
            return self._transaction_status_record(record)

        if name == "transaction_redo":
            if not record.can_redo:
                raise GhidraBackendError("program cannot redo")
            record.can_redo = False
            record.can_undo = True
            record.undo_label = record.redo_label
            record.redo_label = None
            return self._transaction_status_record(record)

        if name == "transaction_status":
            return self._transaction_status_record(record)

        raise AttributeError(name)

    def _transaction_status_record(self, record: _FakeSession) -> dict[str, Any]:
        return {
            "session_id": record.session_id,
            "can_undo": record.can_undo,
            "can_redo": record.can_redo,
            "undo_label": record.undo_label,
            "redo_label": record.redo_label,
            "active_transaction": copy.deepcopy(record.active_transaction),
        }

    def _dispatch_listing_category(self, name: str, /, *args: Any, **kwargs: Any) -> dict[str, Any]:
        session_id = self._session_id(args, kwargs)
        record = self._get_session(session_id)

        if name == "listing_code_units_list":
            start, end = self._range_bounds(
                kwargs.get("start"), kwargs.get("end"), kwargs.get("length")
            )
            kind = kwargs.get("kind")
            items = [
                copy.deepcopy(item)
                for addr, item in sorted(record.code_units.items())
                if (start is None or addr >= start)
                and (end is None or addr <= end)
                and (kind is None or item["kind"] == kind)
            ]
            return {
                "session_id": session_id,
                **self._page(items, kwargs.get("offset", 0), kwargs.get("limit", 100)),
            }

        if name == "listing_code_unit_at":
            addr = self._address_to_int(self._arg_value(args, kwargs, "address", 1))
            unit = record.code_units.get(addr)
            return {
                "session_id": session_id,
                "address": hex(addr),
                "code_unit": copy.deepcopy(unit),
            }

        if name == "listing_code_unit_before":
            addr = self._address_to_int(self._arg_value(args, kwargs, "address", 1))
            candidates = [item for item_addr, item in record.code_units.items() if item_addr < addr]
            unit = (
                max(candidates, key=lambda item: int(item["address"], 16)) if candidates else None
            )
            return {
                "session_id": session_id,
                "address": hex(addr),
                "code_unit": copy.deepcopy(unit),
            }

        if name == "listing_code_unit_after":
            addr = self._address_to_int(self._arg_value(args, kwargs, "address", 1))
            candidates = [item for item_addr, item in record.code_units.items() if item_addr > addr]
            unit = (
                min(candidates, key=lambda item: int(item["address"], 16)) if candidates else None
            )
            return {
                "session_id": session_id,
                "address": hex(addr),
                "code_unit": copy.deepcopy(unit),
            }

        if name == "listing_code_unit_containing":
            addr = self._address_to_int(self._arg_value(args, kwargs, "address", 1))
            unit = None
            for item_addr, item in sorted(record.code_units.items()):
                length = int(item.get("length", 1))
                if item_addr <= addr < item_addr + max(length, 1):
                    unit = item
                    break
            return {
                "session_id": session_id,
                "address": hex(addr),
                "code_unit": copy.deepcopy(unit),
            }

        if name == "listing_clear":
            self._require_writable(record)
            start, end = self._range_bounds(
                kwargs.get("start"), kwargs.get("end"), kwargs.get("length")
            )
            clear_instructions = bool(kwargs.get("clear_instructions", True))
            clear_data = bool(kwargs.get("clear_data", True))
            removed = 0
            for addr in sorted(list(record.code_units)):
                item = record.code_units[addr]
                if start is not None and addr < start:
                    continue
                if end is not None and addr > end:
                    continue
                if item["kind"] == "instruction" and not clear_instructions:
                    continue
                if item["kind"] == "data" and not clear_data:
                    continue
                removed += 1
                del record.code_units[addr]
            self._note_mutation(record, f"listing_clear:{removed}")
            return {
                "session_id": session_id,
                "start": None if start is None else hex(start),
                "end": None if end is None else hex(end),
                "cleared": removed,
            }

        if name == "listing_disassemble_seed":
            addr = self._address_to_int(self._arg_value(args, kwargs, "address", 1))
            items = self._disasm_items(addr)[: int(kwargs.get("limit", 16))]
            for item in items:
                insn_addr = int(item["address"], 16)
                record.code_units[insn_addr] = {
                    "address": item["address"],
                    "kind": "instruction",
                    "length": max(1, len(item["bytes"]) // 2),
                    "mnemonic": item["mnemonic"],
                    "text": item["text"],
                    "bytes": item["bytes"],
                }
            return {
                "session_id": session_id,
                "seed": hex(addr),
                "follow_flow": bool(kwargs.get("follow_flow", True)),
                "count": len(items),
                "items": items,
            }

        if name == "memory_blocks_list":
            return {
                "session_id": session_id,
                "count": len(record.memory_blocks),
                "items": copy.deepcopy(record.memory_blocks),
            }

        if name == "context_get":
            register = kwargs.get("register")
            address = kwargs.get("address")
            items = record.context_ranges
            if register is not None:
                items = [item for item in items if item["register"] == register]
            if address is not None:
                addr = self._address_to_int(address)
                items = [
                    item
                    for item in items
                    if self._address_to_int(item["start"])
                    <= addr
                    <= self._address_to_int(item["end"])
                ]
            return {"session_id": session_id, "ranges": copy.deepcopy(items)}

        if name == "context_set":
            self._require_writable(record)
            start, end = self._range_bounds(
                kwargs.get("start"), kwargs.get("end"), kwargs.get("length")
            )
            if start is None or end is None:
                raise GhidraBackendError("start and end/length are required")
            entry = {
                "register": str(kwargs["register"]),
                "start": hex(start),
                "end": hex(end),
                "value": kwargs["value"],
            }
            record.context_ranges = [
                item
                for item in record.context_ranges
                if not (
                    item["register"] == entry["register"]
                    and item["start"] == entry["start"]
                    and item["end"] == entry["end"]
                )
            ]
            record.context_ranges.append(entry)
            self._note_mutation(record, f"context:{entry['register']}")
            return {"session_id": session_id, "range": copy.deepcopy(entry)}

        if name == "context_ranges":
            return {"session_id": session_id, "ranges": copy.deepcopy(record.context_ranges)}

        if name == "patch_assemble":
            self._require_writable(record)
            addr = self._address_to_int(self._arg_value(args, kwargs, "address", 1))
            assembly = str(kwargs.get("assembly", ""))
            written = max(1, len(assembly.split(";")))
            record.memory[addr - 0x1000 : addr - 0x1000 + written] = b"\x90" * written
            self._note_mutation(record, f"patch_assemble:{hex(addr)}")
            return {
                "session_id": session_id,
                "address": hex(addr),
                "assembly": assembly,
                "written": written,
            }

        if name == "patch_nop":
            self._require_writable(record)
            addr = self._address_to_int(self._arg_value(args, kwargs, "address", 1))
            length = int(kwargs.get("length", 1))
            record.memory[addr - 0x1000 : addr - 0x1000 + length] = b"\x90" * length
            self._note_mutation(record, f"patch_nop:{hex(addr)}")
            return {
                "session_id": session_id,
                "address": hex(addr),
                "length": length,
                "patched": True,
            }

        if name == "patch_branch_invert":
            self._require_writable(record)
            addr = self._address_to_int(self._arg_value(args, kwargs, "address", 1))
            index = addr - 0x1000
            record.memory[index] ^= 0x01
            self._note_mutation(record, f"patch_branch:{hex(addr)}")
            return {"session_id": session_id, "address": hex(addr), "patched": True}

        raise AttributeError(name)

    def _dispatch_symbol_category(self, name: str, /, *args: Any, **kwargs: Any) -> dict[str, Any]:
        session_id = self._session_id(args, kwargs)
        record = self._get_session(session_id)

        if name == "symbol_list":
            items = [copy.deepcopy(symbol) for group in record.symbols.values() for symbol in group]
            query = kwargs.get("query")
            namespace = kwargs.get("namespace")
            if query is not None:
                items = [item for item in items if str(query).lower() in item["name"].lower()]
            if namespace is not None:
                items = [item for item in items if item["namespace"] == namespace]
            items.sort(key=lambda item: (int(item["address"], 16), item["name"]))
            return {
                "session_id": session_id,
                **self._page(items, kwargs.get("offset", 0), kwargs.get("limit", 100)),
            }

        if name == "symbol_find":
            query = str(kwargs.get("name") or kwargs.get("query") or "")
            return self._dispatch_symbol_category(
                "symbol_list",
                session_id,
                query=query,
                offset=0,
                limit=kwargs.get("limit", 100),
            )

        if name == "symbol_create":
            address = kwargs["address"] if "address" in kwargs else args[1]
            created = self.annotation_symbol_create(
                session_id,
                address=address,
                name=str(kwargs["name"]),
                make_primary=bool(kwargs.get("make_primary", True)),
            )["symbol"]
            record.symbol_history.setdefault(created["id"], []).append(
                {"action": "create", "name": created["name"], "namespace": created["namespace"]}
            )
            self._note_mutation(record, f"symbol_create:{created['name']}")
            return {"session_id": session_id, "symbol": copy.deepcopy(created)}

        if name == "symbol_rename":
            address = kwargs["address"] if "address" in kwargs else args[1]
            renamed = self.annotation_symbol_rename(
                session_id,
                address=address,
                old_name=kwargs.get("old_name") or kwargs.get("name"),
                new_name=str(kwargs["new_name"]),
            )["symbol"]
            record.symbol_history.setdefault(renamed["id"], []).append(
                {"action": "rename", "name": renamed["name"], "namespace": renamed["namespace"]}
            )
            self._note_mutation(record, f"symbol_rename:{renamed['name']}")
            return {"session_id": session_id, "symbol": copy.deepcopy(renamed)}

        if name == "symbol_delete":
            address = kwargs["address"] if "address" in kwargs else args[1]
            deleted = self.annotation_symbol_delete(
                session_id, address=address, name=kwargs.get("name")
            )
            self._note_mutation(record, f"symbol_delete:{deleted['name']}")
            return deleted

        if name == "symbol_primary_set":
            addr = self._address_to_int(kwargs["address"] if "address" in kwargs else args[1])
            target = self._resolve_symbol(record, addr, kwargs.get("name"))
            for symbol in record.symbols.get(addr, []):
                symbol["primary"] = symbol["id"] == target["id"]
            record.symbol_history.setdefault(target["id"], []).append(
                {"action": "set_primary", "name": target["name"], "namespace": target["namespace"]}
            )
            self._note_mutation(record, f"symbol_primary:{target['name']}")
            return {"session_id": session_id, "symbol": copy.deepcopy(target)}

        if name in {"namespace_create", "class_create"}:
            namespace_name = str(kwargs["name"])
            parent = str(kwargs.get("parent", "Global"))
            kind = "class" if name == "class_create" else "namespace"
            record.namespaces[namespace_name] = {
                "name": namespace_name,
                "parent": parent,
                "kind": kind,
            }
            self._note_mutation(record, f"{kind}:{namespace_name}")
            return {
                "session_id": session_id,
                kind: copy.deepcopy(record.namespaces[namespace_name]),
            }

        if name == "symbol_namespace_move":
            addr = self._address_to_int(kwargs["address"] if "address" in kwargs else args[1])
            target = self._resolve_symbol(record, addr, kwargs.get("name"))
            namespace_name = str(kwargs["namespace"])
            if namespace_name not in record.namespaces:
                raise GhidraBackendError(f"unknown namespace: {namespace_name}")
            target["namespace"] = namespace_name
            record.symbol_history.setdefault(target["id"], []).append(
                {"action": "move_namespace", "name": target["name"], "namespace": namespace_name}
            )
            self._note_mutation(record, f"symbol_move:{target['name']}")
            return {"session_id": session_id, "symbol": copy.deepcopy(target)}

        if name == "external_libraries_list":
            items = sorted(record.external_libraries.values(), key=lambda item: item["name"])
            return {"session_id": session_id, "count": len(items), "items": copy.deepcopy(items)}

        if name == "external_library_create":
            library_name = str(kwargs["name"])
            record.external_libraries[library_name] = {
                "name": library_name,
                "path": kwargs.get("path"),
            }
            self._note_mutation(record, f"external_library:{library_name}")
            return {
                "session_id": session_id,
                "library": copy.deepcopy(record.external_libraries[library_name]),
            }

        if name == "external_library_set_path":
            library_name = str(kwargs["name"])
            if library_name not in record.external_libraries:
                raise GhidraBackendError(f"unknown external library: {library_name}")
            record.external_libraries[library_name]["path"] = kwargs.get("path")
            self._note_mutation(record, f"external_library_path:{library_name}")
            return {
                "session_id": session_id,
                "library": copy.deepcopy(record.external_libraries[library_name]),
            }

        if name in {
            "external_location_get",
            "external_location_create",
            "external_function_create",
        }:
            label = str(kwargs.get("label") or kwargs.get("name") or "")
            if name == "external_location_get":
                location = record.external_locations.get(label)
                if location is None:
                    raise GhidraBackendError(f"unknown external location: {label}")
                return {"session_id": session_id, "location": copy.deepcopy(location)}
            library_name = str(kwargs["library_name"])
            location = {
                "label": label,
                "library_name": library_name,
                "address": kwargs.get("external_address") or kwargs.get("address"),
                "symbol_type": "Function" if name == "external_function_create" else "Label",
            }
            record.external_locations[label] = location
            self._note_mutation(record, f"external_location:{label}")
            return {"session_id": session_id, "location": copy.deepcopy(location)}

        if name == "external_entrypoint_add":
            address = hex(self._address_to_int(kwargs["address"]))
            record.external_entrypoints.add(address)
            self._note_mutation(record, f"external_entry:{address}")
            return {"session_id": session_id, "entrypoint": address, "added": True}

        if name == "external_entrypoint_remove":
            address = hex(self._address_to_int(kwargs["address"]))
            removed = address in record.external_entrypoints
            record.external_entrypoints.discard(address)
            self._note_mutation(record, f"external_entry_remove:{address}")
            return {"session_id": session_id, "entrypoint": address, "removed": removed}

        if name == "external_entrypoint_list":
            items = [{"address": entrypoint} for entrypoint in sorted(record.external_entrypoints)]
            return {"session_id": session_id, "count": len(items), "items": items}

        raise AttributeError(name)

    def _dispatch_reference_category(
        self, name: str, /, *args: Any, **kwargs: Any
    ) -> dict[str, Any]:
        session_id = self._session_id(args, kwargs)
        record = self._get_session(session_id)

        if name == "reference_to":
            target = kwargs.get("address")
            start, end = self._range_bounds(
                kwargs.get("start"), kwargs.get("end"), kwargs.get("length")
            )
            items = [
                copy.deepcopy(item)
                for item in record.references
                if (target is not None and self._reference_target_matches(item["to"], target))
                or (
                    target is None
                    and start is not None
                    and end is not None
                    and item["to"].startswith("0x")
                    and start <= self._address_to_int(item["to"]) <= end
                )
            ]
            return {
                "session_id": session_id,
                "address": None if target is None else str(target),
                "count": len(items[: kwargs.get("limit", 100)]),
                "items": items[: kwargs.get("limit", 100)],
            }

        if name == "reference_from":
            source = kwargs.get("address")
            start, end = self._range_bounds(
                kwargs.get("start"), kwargs.get("end"), kwargs.get("length")
            )
            items = [
                copy.deepcopy(item)
                for item in record.references
                if (source is not None and item["from"] == hex(self._address_to_int(source)))
                or (
                    source is None
                    and start is not None
                    and end is not None
                    and start <= self._address_to_int(item["from"]) <= end
                )
            ]
            return {
                "session_id": session_id,
                "address": None if source is None else hex(self._address_to_int(source)),
                "count": len(items[: kwargs.get("limit", 100)]),
                "items": items[: kwargs.get("limit", 100)],
            }

        if name.startswith("reference_create_"):
            self._require_writable(record)
            source = hex(self._address_to_int(kwargs["from_address"]))
            ref = {
                "id": record.reference_next_id,
                "from": source,
                "to": "",
                "reference_type": str(kwargs.get("reference_type", "DATA")),
                "operand_index": int(kwargs.get("operand_index", 0)),
                "primary": bool(kwargs.get("primary", True)),
                "external": False,
                "association": None,
                "kind": name.removeprefix("reference_create_"),
            }
            if name == "reference_create_memory":
                ref["to"] = hex(self._address_to_int(kwargs["to_address"]))
            elif name == "reference_create_stack":
                ref["to"] = f"stack:{kwargs['stack_offset']}"
            elif name == "reference_create_register":
                ref["to"] = f"register:{kwargs['register']}"
            elif name == "reference_create_external":
                label = str(kwargs.get("label") or kwargs.get("name") or "")
                ref["to"] = f"external:{kwargs['library_name']}::{label}"
                ref["external"] = True
            else:
                raise AttributeError(name)
            record.reference_next_id += 1
            record.references.append(ref)
            self._note_mutation(record, f"reference_create:{ref['kind']}")
            return {"session_id": session_id, "reference": copy.deepcopy(ref)}

        if name == "reference_delete":
            self._require_writable(record)
            source = hex(self._address_to_int(kwargs["from_address"]))
            target = kwargs.get("to_address")
            before = len(record.references)
            record.references = [
                item
                for item in record.references
                if not (
                    item["from"] == source
                    and (
                        target is None
                        or item["to"] == hex(self._address_to_int(target))
                        or item["to"] == str(target)
                    )
                )
            ]
            removed = before - len(record.references)
            self._note_mutation(record, f"reference_delete:{removed}")
            return {"session_id": session_id, "deleted": removed}

        if name in {"reference_clear_from", "reference_clear_to"}:
            self._require_writable(record)
            target_key = "from" if name == "reference_clear_from" else "to"
            target_value = kwargs["from_address"] if target_key == "from" else kwargs["to_address"]
            normalized = (
                hex(self._address_to_int(target_value))
                if target_key == "from" or str(target_value).startswith("0x")
                else str(target_value)
            )
            before = len(record.references)
            record.references = [
                item for item in record.references if item[target_key] != normalized
            ]
            removed = before - len(record.references)
            self._note_mutation(record, f"{name}:{removed}")
            return {"session_id": session_id, "cleared": removed}

        if name == "reference_primary_set":
            self._require_writable(record)
            source = hex(self._address_to_int(kwargs["from_address"]))
            target = kwargs.get("to_address")
            for item in record.references:
                if item["from"] == source:
                    item["primary"] = target is not None and (
                        item["to"] == hex(self._address_to_int(target)) or item["to"] == str(target)
                    )
            self._note_mutation(record, f"reference_primary:{source}")
            return {"session_id": session_id, "updated": True}

        if name in {"reference_association_set", "reference_association_remove"}:
            self._require_writable(record)
            source = hex(self._address_to_int(kwargs["from_address"]))
            target = kwargs.get("to_address")
            association = (
                kwargs.get("symbol_name") or kwargs.get("symbol_address")
                if name.endswith("_set")
                else None
            )
            updated = 0
            for item in record.references:
                if item["from"] == source and (
                    target is None
                    or item["to"] == hex(self._address_to_int(target))
                    or item["to"] == str(target)
                ):
                    item["association"] = association
                    updated += 1
            self._note_mutation(record, f"{name}:{updated}")
            return {"session_id": session_id, "updated": updated}

        if name == "equate_create":
            self._require_writable(record)
            equate = {
                "address": hex(self._address_to_int(kwargs["address"])),
                "name": str(kwargs["name"]),
                "value": int(kwargs["value"]),
                "operand_index": int(kwargs.get("operand_index", 0)),
            }
            record.equates.append(equate)
            self._note_mutation(record, f"equate:{equate['name']}")
            return {"session_id": session_id, "equate": copy.deepcopy(equate)}

        if name == "equate_list":
            address = kwargs.get("address")
            items = [
                copy.deepcopy(item)
                for item in record.equates
                if address is None or item["address"] == hex(self._address_to_int(address))
            ]
            return {"session_id": session_id, "count": len(items), "items": items}

        if name == "equate_delete":
            self._require_writable(record)
            equate_name = str(kwargs["name"])
            address = kwargs.get("address")
            normalized_address = None if address is None else hex(self._address_to_int(address))
            before = len(record.equates)
            record.equates = [
                item
                for item in record.equates
                if not (
                    item["name"] == equate_name
                    and (normalized_address is None or item["address"] == normalized_address)
                )
            ]
            removed = before - len(record.equates)
            self._note_mutation(record, f"equate_delete:{equate_name}")
            return {"session_id": session_id, "deleted": removed}

        if name == "equate_clear_range":
            self._require_writable(record)
            start, end = self._range_bounds(
                kwargs.get("start"), kwargs.get("end"), kwargs.get("length")
            )
            before = len(record.equates)
            record.equates = [
                item
                for item in record.equates
                if start is None
                or end is None
                or not (start <= self._address_to_int(item["address"]) <= end)
            ]
            removed = before - len(record.equates)
            self._note_mutation(record, f"equate_clear:{removed}")
            return {"session_id": session_id, "cleared": removed}

        raise AttributeError(name)

    def _dispatch_annotation_category(
        self, name: str, /, *args: Any, **kwargs: Any
    ) -> dict[str, Any]:
        session_id = self._session_id(args, kwargs)
        record = self._get_session(session_id)

        if name in {"comment_get", "comment_set"}:
            scope = str(kwargs.get("scope", "listing"))
            comment_type = str(kwargs.get("comment_type", "eol")).lower()
            location = (
                hex(
                    self._normalize_function_start(
                        record, self._address_to_int(kwargs["function_start"])
                    )
                )
                if scope == "function"
                else hex(self._address_to_int(kwargs["address"]))
            )
            key = self._comment_key(scope, location, comment_type)
            if name == "comment_set":
                self._require_writable(record)
                record.comment_store[key] = kwargs.get("comment")
                self._note_mutation(record, f"comment:{location}")
            comment = record.comment_store.get(key)
            return {
                "session_id": session_id,
                "scope": scope,
                "comment_type": comment_type,
                "comment": comment,
                "function_start": location if scope == "function" else None,
                "address": location if scope != "function" else None,
            }

        if name == "comment_get_all":
            scope = str(kwargs.get("scope", "listing"))
            location = (
                hex(
                    self._normalize_function_start(
                        record, self._address_to_int(kwargs["function_start"])
                    )
                )
                if scope == "function"
                else hex(self._address_to_int(kwargs["address"]))
            )
            items = [
                {"comment_type": key[2], "comment": value}
                for key, value in sorted(record.comment_store.items())
                if key[0] == scope and key[1] == location
            ]
            return {"session_id": session_id, "scope": scope, "location": location, "items": items}

        if name == "comment_list":
            scope = kwargs.get("scope")
            query = kwargs.get("query")
            start, end = self._range_bounds(
                kwargs.get("start"), kwargs.get("end"), kwargs.get("length")
            )
            items = []
            for (entry_scope, location, comment_type), comment in sorted(
                record.comment_store.items()
            ):
                addr = self._address_to_int(location)
                if scope is not None and entry_scope != scope:
                    continue
                if start is not None and addr < start:
                    continue
                if end is not None and addr > end:
                    continue
                if query is not None and query.lower() not in str(comment or "").lower():
                    continue
                items.append(
                    {
                        "scope": entry_scope,
                        "location": location,
                        "comment_type": comment_type,
                        "comment": comment,
                    }
                )
            return {
                "session_id": session_id,
                **self._page(items, kwargs.get("offset", 0), kwargs.get("limit", 100)),
            }

        if name == "bookmark_add":
            self._require_writable(record)
            bookmark = {
                "address": hex(self._address_to_int(kwargs["address"])),
                "type": str(kwargs.get("bookmark_type", "Info")),
                "category": str(kwargs.get("category", "MCP")),
                "comment": kwargs.get("comment"),
            }
            record.bookmarks.append(bookmark)
            self._note_mutation(record, f"bookmark:{bookmark['address']}")
            return {"session_id": session_id, "bookmark": copy.deepcopy(bookmark)}

        if name == "bookmark_list":
            items = copy.deepcopy(record.bookmarks)
            return {"session_id": session_id, "count": len(items), "items": items}

        if name == "bookmark_remove":
            self._require_writable(record)
            address = hex(self._address_to_int(kwargs["address"]))
            before = len(record.bookmarks)
            record.bookmarks = [item for item in record.bookmarks if item["address"] != address]
            removed = before - len(record.bookmarks)
            self._note_mutation(record, f"bookmark_remove:{address}")
            return {"session_id": session_id, "removed": removed}

        if name == "bookmark_clear":
            self._require_writable(record)
            before = len(record.bookmarks)
            record.bookmarks = []
            self._note_mutation(record, "bookmark_clear")
            return {"session_id": session_id, "cleared": before}

        if name == "tag_add":
            self._require_writable(record)
            function = self._get_function(record, kwargs["function_start"])
            tags = record.tags.setdefault(int(function["entry_point"]), set())
            tags.add(str(kwargs["name"]))
            self._note_mutation(record, f"tag:{kwargs['name']}")
            return {
                "session_id": session_id,
                "function_start": hex(int(function["entry_point"])),
                "tags": sorted(tags),
            }

        if name == "tag_list":
            function_start = kwargs.get("function_start")
            if function_start is not None:
                function = self._get_function(record, function_start)
                tags = sorted(record.tags.get(int(function["entry_point"]), set()))
                return {
                    "session_id": session_id,
                    "function_start": hex(int(function["entry_point"])),
                    "count": len(tags),
                    "items": tags,
                }
            items = [
                {"function_start": hex(start), "tags": sorted(tags)}
                for start, tags in sorted(record.tags.items())
            ]
            return {"session_id": session_id, "count": len(items), "items": items}

        if name == "tag_remove":
            self._require_writable(record)
            function = self._get_function(record, kwargs["function_start"])
            tags = record.tags.setdefault(int(function["entry_point"]), set())
            removed = str(kwargs["name"]) in tags
            tags.discard(str(kwargs["name"]))
            self._note_mutation(record, f"tag_remove:{kwargs['name']}")
            return {"session_id": session_id, "removed": removed, "tags": sorted(tags)}

        if name == "tag_stats":
            counts: dict[str, int] = {}
            for tags in record.tags.values():
                for tag in tags:
                    counts[tag] = counts.get(tag, 0) + 1
            items = [{"name": name, "count": count} for name, count in sorted(counts.items())]
            return {"session_id": session_id, "count": len(items), "items": items}

        if name == "metadata_store":
            self._require_writable(record)
            key = str(kwargs["key"])
            record.metadata_store[key] = kwargs.get("value")
            self._note_mutation(record, f"metadata:{key}")
            return {"session_id": session_id, "key": key, "value": record.metadata_store[key]}

        if name == "metadata_query":
            key = kwargs.get("key")
            if key is not None:
                return {
                    "session_id": session_id,
                    "key": key,
                    "value": record.metadata_store.get(str(key)),
                }
            items = [
                {"key": item_key, "value": value}
                for item_key, value in sorted(record.metadata_store.items())
            ]
            return {"session_id": session_id, "count": len(items), "items": items}

        if name.startswith("source_file_"):
            return self._dispatch_source_category(name, record, kwargs)

        if name.startswith("source_map_"):
            return self._dispatch_source_map_category(name, record, kwargs)

        if name == "relocation_add":
            self._require_writable(record)
            values = kwargs.get("values")
            if values is None and "value" in kwargs:
                values = [kwargs["value"]]
            relocation = {
                "address": hex(self._address_to_int(kwargs["address"])),
                "status": kwargs.get("status", "APPLIED"),
                "type": kwargs.get("type"),
                "values": list(values or []),
                "byte_length": int(kwargs.get("byte_length", 0)),
                "symbol_name": kwargs.get("symbol_name"),
            }
            record.relocations.append(relocation)
            self._note_mutation(record, f"relocation:{relocation['address']}")
            return {"session_id": session_id, "relocation": copy.deepcopy(relocation)}

        if name == "relocation_list":
            return {
                "session_id": session_id,
                "count": len(record.relocations),
                "items": copy.deepcopy(record.relocations),
            }

        raise AttributeError(name)

    def _dispatch_source_category(
        self, name: str, /, record: _FakeSession, kwargs: dict[str, Any]
    ) -> dict[str, Any]:
        if name == "source_file_list":
            return {
                "session_id": record.session_id,
                "count": len(record.source_files),
                "items": copy.deepcopy(record.source_files),
            }
        if name == "source_file_add":
            self._require_writable(record)
            item = {"path": str(kwargs["path"]), "id": len(record.source_files) + 1}
            record.source_files.append(item)
            self._note_mutation(record, f"source_file:{item['path']}")
            return {"session_id": record.session_id, "source_file": copy.deepcopy(item)}
        if name == "source_file_remove":
            self._require_writable(record)
            path = str(kwargs["path"])
            before = len(record.source_files)
            record.source_files = [item for item in record.source_files if item["path"] != path]
            self._note_mutation(record, f"source_file_remove:{path}")
            return {"session_id": record.session_id, "removed": before - len(record.source_files)}
        raise AttributeError(name)

    def _dispatch_source_map_category(
        self, name: str, /, record: _FakeSession, kwargs: dict[str, Any]
    ) -> dict[str, Any]:
        if name == "source_map_list":
            return {
                "session_id": record.session_id,
                "count": len(record.source_maps),
                "items": copy.deepcopy(record.source_maps),
            }
        if name == "source_map_add":
            self._require_writable(record)
            item = {
                "address": hex(self._address_to_int(kwargs["base_address"])),
                "file_path": str(kwargs["path"]),
                "line": int(kwargs["line_number"]),
                "length": int(kwargs["length"]),
            }
            record.source_maps.append(item)
            self._note_mutation(record, f"source_map:{item['address']}")
            return {"session_id": record.session_id, "source_map": copy.deepcopy(item)}
        if name == "source_map_remove":
            self._require_writable(record)
            address = hex(self._address_to_int(kwargs["base_address"]))
            path = str(kwargs["path"])
            line_number = int(kwargs["line_number"])
            before = len(record.source_maps)
            record.source_maps = [
                item
                for item in record.source_maps
                if not (
                    item["address"] == address
                    and item["file_path"] == path
                    and int(item["line"]) == line_number
                )
            ]
            self._note_mutation(record, f"source_map_remove:{address}")
            return {"session_id": record.session_id, "removed": before - len(record.source_maps)}
        raise AttributeError(name)

    def _dispatch_function_category(
        self, name: str, /, *args: Any, **kwargs: Any
    ) -> dict[str, Any]:
        session_id = self._session_id(args, kwargs)
        record = self._get_session(session_id)

        if name == "function_list":
            items = self._function_items(record)
            query = kwargs.get("query")
            if query is not None:
                items = [item for item in items if str(query).lower() in item["name"].lower()]
            return {
                "session_id": session_id,
                **self._page(items, kwargs.get("offset", 0), kwargs.get("limit", 100)),
            }

        if name == "function_get_at":
            address = kwargs["address"] if "address" in kwargs else args[1]
            function = self._get_function(record, address)
            return {"session_id": session_id, "function": self._function_state_record(function)}

        if name == "function_find":
            query = str(kwargs.get("name") or kwargs.get("query") or "")
            items = [
                item
                for item in self._function_items(record)
                if query.lower() in item["name"].lower()
            ]
            return {"session_id": session_id, "count": len(items), "items": items}

        if name == "function_create":
            self._require_writable(record)
            entry_point = self._address_to_int(kwargs["address"])
            function_name = str(kwargs.get("name") or f"sub_{entry_point:x}")
            function = {
                "name": function_name,
                "entry_point": entry_point,
                "body_start": entry_point,
                "body_end": self._address_to_int(kwargs.get("end", entry_point + 0x0F)),
                "return_type": str(kwargs.get("return_type", "/void")),
                "calling_convention": str(kwargs.get("calling_convention", "default")),
                "signature_source": "USER_DEFINED",
                "flags": {
                    "varargs": False,
                    "inline": False,
                    "noreturn": False,
                    "custom_storage": False,
                },
                "thunk_target": None,
                "parameters": [],
                "locals": [],
                "stackframe": [],
            }
            record.function_state[entry_point] = function
            record.function_names[entry_point] = function_name
            record.symbols.setdefault(entry_point, []).append(
                {
                    "id": self._next_symbol_id(record),
                    "name": function_name,
                    "short_name": function_name,
                    "address": hex(entry_point),
                    "symbol_type": "Function",
                    "source_type": "USER_DEFINED",
                    "namespace": "Global",
                    "primary": True,
                    "external": False,
                }
            )
            self._note_mutation(record, f"function_create:{function_name}")
            return {"session_id": session_id, "function": self._function_state_record(function)}

        if name == "function_delete":
            self._require_writable(record)
            function = self._get_function(record, kwargs["function_start"])
            start = int(function["entry_point"])
            deleted = self._function_state_record(function)
            del record.function_state[start]
            record.function_names.pop(start, None)
            record.symbols.pop(start, None)
            self._note_mutation(record, f"function_delete:{deleted['name']}")
            return {"session_id": session_id, "deleted": True, "function": deleted}

        if name == "function_body_set":
            self._require_writable(record)
            function = self._get_function(record, kwargs["function_start"])
            start_value = kwargs.get("start", kwargs.get("body_start", function["body_start"]))
            end_value = kwargs.get("end", kwargs.get("body_end"))
            if end_value is None and "length" in kwargs:
                start_addr = self._address_to_int(start_value)
                end_value = start_addr + max(0, int(kwargs["length"]) - 1)
            function["body_start"] = self._address_to_int(start_value)
            if end_value is not None:
                function["body_end"] = self._address_to_int(end_value)
            self._note_mutation(record, f"function_body:{function['name']}")
            return {"session_id": session_id, "function": self._function_state_record(function)}

        if name == "function_calling_conventions_list":
            return {
                "session_id": session_id,
                "count": 3,
                "items": ["default", "__stdcall", "__fastcall"],
            }

        if name == "function_calling_convention_set":
            self._require_writable(record)
            function = self._get_function(record, kwargs["function_start"])
            function["calling_convention"] = str(kwargs.get("name") or kwargs["calling_convention"])
            self._note_mutation(record, f"calling_convention:{function['name']}")
            return {"session_id": session_id, "function": self._function_state_record(function)}

        if name == "function_flags_set":
            self._require_writable(record)
            function = self._get_function(record, kwargs["function_start"])
            for flag in ("varargs", "inline", "noreturn", "custom_storage"):
                if flag in kwargs:
                    function["flags"][flag] = bool(kwargs[flag])
            self._note_mutation(record, f"function_flags:{function['name']}")
            return {"session_id": session_id, "flags": copy.deepcopy(function["flags"])}

        if name == "function_thunk_set":
            self._require_writable(record)
            function = self._get_function(record, kwargs["function_start"])
            thunk_target = kwargs.get("thunk_target") or kwargs.get("target")
            function["thunk_target"] = hex(self._address_to_int(thunk_target))
            self._note_mutation(record, f"function_thunk:{function['name']}")
            return {"session_id": session_id, "function": self._function_state_record(function)}

        if name == "function_return_type_set":
            self._require_writable(record)
            function = self._get_function(record, kwargs["function_start"])
            function["return_type"] = str(kwargs.get("data_type") or kwargs["return_type"])
            self._note_mutation(record, f"return_type:{function['name']}")
            return {"session_id": session_id, "function": self._function_state_record(function)}

        if name in {"parameter_add", "parameter_remove", "parameter_move", "parameter_replace"}:
            self._require_writable(record)
            function = self._get_function(record, kwargs["function_start"])
            parameters = function["parameters"]
            if name == "parameter_add":
                ordinal = int(kwargs.get("ordinal", len(parameters)))
                entry = self._parameter_entry(
                    str(kwargs["name"]),
                    str(kwargs.get("data_type", "/int")),
                    ordinal,
                    storage=kwargs.get("storage"),
                    comment=kwargs.get("comment"),
                )
                parameters.insert(min(ordinal, len(parameters)), entry)
            elif name == "parameter_remove":
                parameters[:] = [item for item in parameters if item["name"] != kwargs["name"]]
            elif name == "parameter_move":
                from_index = int(kwargs.get("from_ordinal", kwargs.get("ordinal", 0)))
                to_index = int(kwargs.get("to_ordinal", kwargs.get("new_ordinal", 0)))
                entry = parameters.pop(from_index)
                parameters.insert(to_index, entry)
            else:
                for item in parameters:
                    if item["name"] == kwargs["name"]:
                        item["data_type"] = str(kwargs.get("data_type", item["data_type"]))
                        item["comment"] = kwargs.get("comment", item.get("comment"))
                        break
            for ordinal, item in enumerate(parameters):
                item["ordinal"] = ordinal
            self._note_mutation(record, f"{name}:{function['name']}")
            return {"session_id": session_id, "parameters": copy.deepcopy(parameters)}

        if name in {
            "variable_local_create",
            "variable_local_remove",
            "variable_comment_set",
            "function_variable_rename",
            "function_variable_retype",
            "variable_rename",
            "variable_retype",
        }:
            self._require_writable(record)
            function = self._get_function(record, kwargs["function_start"])
            if name == "variable_local_create":
                entry = self._local_entry(
                    str(kwargs["name"]),
                    str(kwargs.get("data_type", "/int")),
                    str(kwargs.get("storage", "stack[-0x10]")),
                    comment=kwargs.get("comment"),
                )
                function["locals"].append(entry)
            elif name == "variable_local_remove":
                function["locals"] = [
                    item for item in function["locals"] if item["name"] != kwargs["name"]
                ]
            else:
                _, item, _ = self._find_var(function, str(kwargs["name"]))
                if name in {"variable_comment_set"}:
                    item["comment"] = kwargs.get("comment")
                elif name in {"function_variable_rename", "variable_rename"}:
                    item["name"] = str(kwargs["new_name"])
                elif name in {"function_variable_retype", "variable_retype"}:
                    item["data_type"] = str(kwargs["data_type"])
            self._note_mutation(record, f"{name}:{function['name']}")
            return {
                "session_id": session_id,
                "parameters": copy.deepcopy(function["parameters"]),
                "locals": copy.deepcopy(function["locals"]),
            }

        if name in {"stackframe_variable_create", "stackframe_variable_clear"}:
            self._require_writable(record)
            function = self._get_function(record, kwargs["function_start"])
            if name == "stackframe_variable_create":
                function["stackframe"].append(
                    self._local_entry(
                        str(kwargs["name"]),
                        str(kwargs.get("data_type", "/int")),
                        f"stack[{kwargs.get('stack_offset', kwargs.get('offset', 0))}]",
                        comment=kwargs.get("comment"),
                    )
                )
            else:
                stack_offset = kwargs.get("stack_offset")
                if stack_offset is None:
                    function["stackframe"] = []
                else:
                    marker = f"stack[{stack_offset}]"
                    function["stackframe"] = [
                        item for item in function["stackframe"] if item["storage"] != marker
                    ]
            self._note_mutation(record, f"{name}:{function['name']}")
            return {"session_id": session_id, "stackframe": copy.deepcopy(function["stackframe"])}

        if name == "stackframe_variables":
            function = self._get_function(record, kwargs["function_start"])
            return {
                "session_id": session_id,
                "function": self._function_state_record(function),
                "stackframe": copy.deepcopy(function["stackframe"]),
            }

        if name == "function_variables":
            function = self._get_function(
                record, self._arg_value(args, kwargs, "function_start", 1)
            )
            return {
                "session_id": session_id,
                "function": self._function_state_record(function),
                "parameters": copy.deepcopy(function["parameters"]),
                "locals": copy.deepcopy(function["locals"]),
            }

        raise AttributeError(name)

    def _dispatch_type_category(self, name: str, /, *args: Any, **kwargs: Any) -> dict[str, Any]:
        session_id = self._session_id(args, kwargs)
        record = self._get_session(session_id)

        if name == "type_category_list":
            items = [{"path": category} for category in sorted(record.type_categories)]
            return {"session_id": session_id, "count": len(items), "items": items}

        if name == "type_category_create":
            self._require_writable(record)
            path = str(kwargs["path"])
            record.type_categories.add(path)
            self._note_mutation(record, f"type_category:{path}")
            return {"session_id": session_id, "category": {"path": path}}

        if name == "type_archives_list":
            return {
                "session_id": session_id,
                "count": len(record.type_archives),
                "items": copy.deepcopy(record.type_archives),
            }

        if name == "type_source_archives_list":
            return {
                "session_id": session_id,
                "count": len(record.type_source_archives),
                "items": copy.deepcopy(record.type_source_archives),
            }

        if name == "type_get_by_id":
            type_id_value = kwargs.get("data_type_id", kwargs.get("type_id"))
            if type_id_value is None and kwargs.get("universal_id") is not None:
                type_id_value = kwargs["universal_id"]
            type_id = self._coerce_type_id(type_id_value)
            for item in record.types.values():
                if int(item["id"]) == type_id:
                    return {"session_id": session_id, "type": copy.deepcopy(item)}
            raise GhidraBackendError(f"type not found: {type_id}")

        raise AttributeError(name)

    def _dispatch_layout_category(self, name: str, /, *args: Any, **kwargs: Any) -> dict[str, Any]:
        session_id = self._session_id(args, kwargs)
        record = self._get_session(session_id)

        if name in {"layout_struct_create", "layout_union_create", "layout_enum_create"}:
            self._require_writable(record)
            category = str(kwargs.get("category", "/")).rstrip("/")
            default_path = f"{category}/{kwargs['name']}" if category else f"/{kwargs['name']}"
            path = str(kwargs.get("path") or default_path)
            kind = (
                "struct"
                if name == "layout_struct_create"
                else "union"
                if name == "layout_union_create"
                else "enum"
            )
            layout = {
                "kind": kind,
                "name": str(kwargs["name"]),
                "path": path,
                "length": int(kwargs.get("length", 0)),
                "members": [],
            }
            record.layouts[path] = layout
            record.types[path] = {
                "id": record.next_type_id,
                "name": layout["name"],
                "display_name": layout["name"],
                "path": path,
                "category": path.rsplit("/", 1)[0] or "/",
                "length": layout["length"],
                "description": f"fake {kind}",
                "java_type": f"fake.{kind}",
            }
            record.next_type_id += 1
            self._note_mutation(record, f"{kind}:{layout['name']}")
            return {"session_id": session_id, kind: copy.deepcopy(layout)}

        if name == "layout_struct_get":
            layout_path = str(
                kwargs.get("struct_path") or kwargs.get("path") or f"/{kwargs['struct_name']}"
            )
            layout = self._get_layout(record, layout_path, expected="struct")
            return {"session_id": session_id, "struct": copy.deepcopy(layout)}

        if name == "layout_struct_resize":
            self._require_writable(record)
            layout_path = str(
                kwargs.get("struct_path") or kwargs.get("path") or f"/{kwargs['struct_name']}"
            )
            layout = self._get_layout(record, layout_path, expected="struct")
            layout["length"] = int(kwargs["length"])
            record.types[layout["path"]]["length"] = layout["length"]
            self._note_mutation(record, f"struct_resize:{layout['name']}")
            return {"session_id": session_id, "struct": copy.deepcopy(layout)}

        if name in {
            "layout_struct_field_add",
            "layout_struct_field_rename",
            "layout_struct_field_replace",
            "layout_struct_field_clear",
            "layout_struct_field_comment_set",
            "layout_struct_bitfield_add",
        }:
            self._require_writable(record)
            layout_path = str(
                kwargs.get("struct_path") or kwargs.get("path") or f"/{kwargs['struct_name']}"
            )
            layout = self._get_layout(record, layout_path, expected="struct")
            members = layout["members"]
            if name == "layout_struct_field_add":
                members.append(
                    {
                        "name": str(kwargs.get("field_name") or kwargs.get("name") or "field"),
                        "offset": int(kwargs.get("offset", len(members) * 4)),
                        "data_type": str(kwargs.get("data_type", "/int")),
                        "length": int(kwargs.get("length", 4)),
                        "comment": kwargs.get("comment"),
                    }
                )
            elif name == "layout_struct_field_rename":
                for item in members:
                    old_name = (
                        kwargs.get("old_name") or kwargs.get("field_name") or kwargs.get("name")
                    )
                    if item["name"] == old_name:
                        item["name"] = str(kwargs["new_name"])
                        break
            elif name == "layout_struct_field_replace":
                target_name = kwargs.get("field_name")
                target_offset = kwargs.get("offset")
                for item in members:
                    if (target_name is not None and item["name"] == target_name) or (
                        target_offset is not None
                        and int(item.get("offset", -1)) == int(target_offset)
                    ):
                        item["data_type"] = str(kwargs.get("data_type", item["data_type"]))
                        item["length"] = int(kwargs.get("length", item["length"]))
                        item["comment"] = kwargs.get("comment", item.get("comment"))
                        if target_name is not None:
                            item["name"] = str(target_name)
                        break
            elif name == "layout_struct_field_clear":
                target_name = kwargs.get("field_name")
                target_offset = kwargs.get("offset")
                layout["members"] = [
                    item
                    for item in members
                    if not (
                        (target_name is not None and item["name"] == target_name)
                        or (
                            target_offset is not None
                            and int(item.get("offset", -1)) == int(target_offset)
                        )
                    )
                ]
            elif name == "layout_struct_field_comment_set":
                for item in members:
                    target_name = kwargs.get("field_name")
                    target_offset = kwargs.get("offset")
                    if (target_name is not None and item["name"] == target_name) or (
                        target_offset is not None
                        and int(item.get("offset", -1)) == int(target_offset)
                    ):
                        item["comment"] = kwargs.get("comment")
                        break
            else:
                members.append(
                    {
                        "name": str(kwargs.get("field_name") or kwargs.get("name") or "bitfield"),
                        "offset": int(
                            kwargs.get("byte_offset", kwargs.get("offset", len(members) * 4))
                        ),
                        "data_type": str(kwargs.get("data_type", "/int")),
                        "bit_offset": int(kwargs.get("bit_offset", 0)),
                        "bit_size": int(kwargs.get("bit_size", 1)),
                        "length": int(kwargs.get("byte_width", kwargs.get("length", 4))),
                        "comment": kwargs.get("comment"),
                    }
                )
            self._note_mutation(record, f"struct_field:{layout['name']}")
            return {"session_id": session_id, "struct": copy.deepcopy(layout)}

        if name in {"layout_union_member_add", "layout_union_member_remove"}:
            self._require_writable(record)
            layout_path = str(
                kwargs.get("union_path") or kwargs.get("path") or f"/{kwargs['union_name']}"
            )
            layout = self._get_layout(record, layout_path, expected="union")
            if name == "layout_union_member_add":
                layout["members"].append(
                    {
                        "name": str(kwargs.get("field_name") or kwargs.get("name") or "member"),
                        "data_type": str(kwargs.get("data_type", "/int")),
                        "length": int(kwargs.get("length", 4)),
                    }
                )
            else:
                target_name = kwargs.get("field_name") or kwargs.get("name")
                target_ordinal = kwargs.get("ordinal")
                layout["members"] = [
                    item
                    for index, item in enumerate(layout["members"])
                    if not (
                        (target_name is not None and item["name"] == target_name)
                        or (target_ordinal is not None and index == int(target_ordinal))
                    )
                ]
            self._note_mutation(record, f"union_member:{layout['name']}")
            return {"session_id": session_id, "union": copy.deepcopy(layout)}

        if name in {"layout_enum_member_add", "layout_enum_member_remove"}:
            self._require_writable(record)
            layout_path = str(
                kwargs.get("enum_path") or kwargs.get("path") or f"/{kwargs['enum_name']}"
            )
            layout = self._get_layout(record, layout_path, expected="enum")
            if name == "layout_enum_member_add":
                layout["members"].append(
                    {
                        "name": str(kwargs["name"]),
                        "value": int(kwargs["value"]),
                        "comment": kwargs.get("comment"),
                    }
                )
            else:
                layout["members"] = [
                    item for item in layout["members"] if item["name"] != kwargs["name"]
                ]
            self._note_mutation(record, f"enum_member:{layout['name']}")
            return {"session_id": session_id, "enum": copy.deepcopy(layout)}

        if name == "layout_inspect_components":
            layout = self._get_layout(record, kwargs["path"])
            return {
                "session_id": session_id,
                "path": layout["path"],
                "kind": layout["kind"],
                "count": len(layout["members"]),
                "items": copy.deepcopy(layout["members"]),
            }

        if name == "layout_struct_fill_from_decompiler":
            self._require_writable(record)
            layout_path = str(kwargs.get("path") or f"/{kwargs['name']}")
            if layout_path not in record.layouts:
                record.layouts[layout_path] = {
                    "kind": "struct",
                    "name": str(kwargs["name"]),
                    "path": layout_path,
                    "length": 0,
                    "members": [],
                }
            layout = self._get_layout(record, layout_path, expected="struct")
            if not layout["members"]:
                layout["members"].append(
                    {
                        "name": "field_0",
                        "offset": 0,
                        "data_type": "/int",
                        "length": 4,
                        "comment": "filled from fake decompiler",
                    }
                )
            self._note_mutation(record, f"struct_fill:{layout['name']}")
            return {"session_id": session_id, "struct": copy.deepcopy(layout)}

        raise AttributeError(name)

    def _get_layout(
        self, record: _FakeSession, path: str, *, expected: str | None = None
    ) -> dict[str, Any]:
        layout = record.layouts.get(str(path))
        if layout is None:
            raise GhidraBackendError(f"unknown layout: {path}")
        if expected is not None and layout["kind"] != expected:
            raise GhidraBackendError(f"layout {path} is not a {expected}")
        return layout

    def _dispatch_decomp_category(self, name: str, /, *args: Any, **kwargs: Any) -> dict[str, Any]:
        session_id = self._session_id(args, kwargs)
        record = self._get_session(session_id)

        if name == "decomp_high_function_summary":
            function = self._get_function(record, kwargs["function_start"])
            high_symbols = [
                {"name": item["name"], "kind": "parameter", "data_type": item["data_type"]}
                for item in function["parameters"]
            ] + [
                {"name": item["name"], "kind": "local", "data_type": item["data_type"]}
                for item in function["locals"]
            ]
            return {
                "session_id": session_id,
                "function": self._function_state_record(function),
                "high_symbols": high_symbols,
            }

        if name in {"decomp_writeback_params", "decomp_writeback_locals"}:
            self._require_writable(record)
            function = self._get_function(record, kwargs["function_start"])
            key = "parameters" if name.endswith("params") else "locals"
            entries = []
            for index, item in enumerate(kwargs.get(key, [])):
                copied = dict(item)
                if key == "parameters":
                    copied.setdefault("ordinal", index)
                    copied.setdefault("auto_parameter", False)
                    copied.setdefault("first_use_offset", None)
                else:
                    copied.setdefault("first_use_offset", 0)
                entries.append(copied)
            function[key] = entries
            self._note_mutation(record, f"decomp_writeback:{key}")
            return {"session_id": session_id, key: copy.deepcopy(entries)}

        if name in {"decomp_override_get", "decomp_override_set"}:
            address = hex(self._address_to_int(kwargs["callsite"]))
            if name.endswith("_set"):
                self._require_writable(record)
                record.decomp_overrides[address] = {
                    "signature": kwargs.get("signature"),
                    "calling_convention": kwargs.get("calling_convention"),
                }
                self._note_mutation(record, f"decomp_override:{address}")
            return {
                "session_id": session_id,
                "address": address,
                "override": copy.deepcopy(record.decomp_overrides.get(address)),
            }

        if name in {"decomp_trace_type_forward", "decomp_trace_type_backward"}:
            direction = "forward" if name.endswith("forward") else "backward"
            function = self._get_function(record, kwargs["function_start"])
            variable_name = str(kwargs["name"])
            _, item, _ = self._find_var(function, variable_name)
            trace = [
                {
                    "step": 0,
                    "direction": direction,
                    "symbol": variable_name,
                    "data_type": item["data_type"],
                }
            ]
            return {"session_id": session_id, "count": len(trace), "items": trace}

        if name in {"decomp_global_rename", "decomp_global_retype"}:
            self._require_writable(record)
            address = self._address_to_int(kwargs["function_start"])
            symbol = self._resolve_symbol(record, address, kwargs.get("name"))
            if name.endswith("rename"):
                symbol["name"] = str(kwargs["new_name"])
                symbol["short_name"] = symbol["name"]
            else:
                record.global_types[hex(address)] = str(kwargs["data_type"])
            self._note_mutation(record, f"{name}:{hex(address)}")
            return {
                "session_id": session_id,
                "symbol": copy.deepcopy(symbol),
                "data_type": record.global_types.get(hex(address)),
            }

        if name in {"decomp_variable_rename", "decomp_variable_retype"}:
            rewritten = (
                "function_variable_rename"
                if name.endswith("rename")
                else "function_variable_retype"
            )
            payload = dict(kwargs)
            if name.endswith("rename"):
                payload["new_name"] = kwargs["new_name"]
            return self._dispatch_function_category(rewritten, session_id, **payload)

        if name == "decomp_variables":
            return self._dispatch_function_category("function_variables", session_id, **kwargs)

        if name in {"decomp_tokens", "decomp_ast"}:
            function = self._get_function(record, kwargs["function_start"])
            if name == "decomp_tokens":
                return {
                    "session_id": session_id,
                    "function": self._function_state_record(function),
                    "count": 3,
                    "items": [
                        {"text": function["name"], "kind": "identifier"},
                        {"text": "(", "kind": "punctuation"},
                        {"text": ")", "kind": "punctuation"},
                    ],
                }
            return {
                "session_id": session_id,
                "function": self._function_state_record(function),
                "ast": {"kind": "function", "name": function["name"]},
            }

        raise AttributeError(name)

    def _dispatch_graph_category(self, name: str, /, *args: Any, **kwargs: Any) -> dict[str, Any]:
        session_id = self._session_id(args, kwargs)
        record = self._get_session(session_id)

        if name == "address_resolve":
            query = kwargs.get("query")
            if query is None:
                raise GhidraBackendError("query is required")
            if str(query).startswith("0x"):
                return {"session_id": session_id, "address": str(query)}
            for group in record.symbols.values():
                for symbol in group:
                    if symbol["name"] == query or symbol["short_name"] == query:
                        return {"session_id": session_id, "address": symbol["address"]}
            raise GhidraBackendError(f"unable to resolve address: {query}")

        if name == "search_text":
            query = str(kwargs.get("text") or kwargs.get("query") or "").lower()
            items = [
                {"address": item["address"], "value": item["value"], "kind": "string"}
                for item in record.typed_data.values()
                if query in str(item.get("value", "")).lower()
            ]
            return {
                "session_id": session_id,
                "count": len(items),
                "items": items[: kwargs.get("limit", 100)],
            }

        if name == "search_bytes":
            payload = self._decode_payload(
                data_base64=kwargs.get("pattern_base64") or kwargs.get("data_base64"),
                data_hex=kwargs.get("pattern_hex") or kwargs.get("data_hex"),
            )
            data = bytes(record.memory)
            items = []
            index = data.find(payload)
            while index >= 0 and len(items) < int(kwargs.get("limit", 100)):
                items.append({"address": hex(0x1000 + index), "data_hex": payload.hex()})
                index = data.find(payload, index + 1)
            return {"session_id": session_id, "count": len(items), "items": items}

        if name == "search_constants":
            value = int(kwargs["value"])
            items = [{"address": "0x1044", "value": value}] if value in {0, 1, 2} else []
            return {"session_id": session_id, "count": len(items), "items": items}

        if name == "search_instructions":
            query = str(kwargs.get("query") or kwargs.get("mnemonic") or "").lower()
            items = [
                copy.deepcopy(item)
                for item in record.code_units.values()
                if item["kind"] == "instruction"
                and query in f"{item.get('mnemonic', '')} {item.get('text', '')}".lower()
            ]
            return {
                "session_id": session_id,
                "count": len(items),
                "items": items[: kwargs.get("limit", 100)],
            }

        if name == "search_pcode":
            query = str(kwargs.get("query") or kwargs.get("text") or "").lower()
            ops = self.pcode_function(session_id, kwargs.get("function_start", "0x1040"))
            items = [
                item
                for item in ops["items"]
                if any(query in op["text"].lower() for op in item.get("ops", []))
            ]
            return {"session_id": session_id, "count": len(items), "items": items}

        if name == "search_comments":
            query = str(kwargs["query"]).lower()
            items = [
                {
                    "scope": scope,
                    "location": location,
                    "comment_type": comment_type,
                    "comment": comment,
                }
                for (scope, location, comment_type), comment in sorted(record.comment_store.items())
                if query in str(comment or "").lower()
            ]
            return {"session_id": session_id, "count": len(items), "items": items}

        if name == "search_xrefs_range":
            start, end = self._range_bounds(
                kwargs.get("start"), kwargs.get("end"), kwargs.get("length")
            )
            items = [
                copy.deepcopy(item)
                for item in record.references
                if start is not None
                and end is not None
                and start <= self._address_to_int(item["from"]) <= end
            ]
            return {"session_id": session_id, "count": len(items), "items": items}

        if name in {"graph_basic_blocks", "function_basic_blocks"}:
            function = self._get_function(record, kwargs["function_start"])
            blocks = [
                {
                    "start": hex(int(function["body_start"])),
                    "end": hex(int(function["body_start"]) + 7),
                    "label": f"block_{int(function['entry_point']):x}_0",
                },
                {
                    "start": hex(int(function["body_start"]) + 8),
                    "end": hex(int(function["body_end"])),
                    "label": f"block_{int(function['entry_point']):x}_1",
                },
            ]
            return {"session_id": session_id, "count": len(blocks), "items": blocks}

        if name in {"graph_cfg_edges", "cfg_edges"}:
            function = self._get_function(record, kwargs["function_start"])
            edges = [
                {
                    "source": hex(int(function["body_start"])),
                    "target": hex(int(function["body_start"]) + 8),
                    "type": "fallthrough",
                }
            ]
            return {"session_id": session_id, "count": len(edges), "items": edges}

        if name in {"graph_callgraph_paths", "callgraph_paths"}:
            start_name = str(
                kwargs.get("start_name")
                or kwargs.get("source")
                or kwargs.get("source_function")
                or "main"
            )
            end_name = str(
                kwargs.get("end_name")
                or kwargs.get("target")
                or kwargs.get("target_function")
                or "add_numbers"
            )
            path = [start_name]
            if start_name != end_name:
                path.append(end_name)
            return {"session_id": session_id, "count": 1, "items": [{"path": path}]}

        if name == "batch_run_on_functions":
            items = [
                {"function": function["name"], "status": "ok"}
                for function in self._function_items(record)
            ]
            return {"session_id": session_id, "count": len(items), "items": items}

        raise AttributeError(name)
