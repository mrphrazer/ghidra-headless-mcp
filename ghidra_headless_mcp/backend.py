"""Backend abstraction over PyGhidra and Ghidra APIs for the MCP server."""

from __future__ import annotations

import base64
import binascii
import io
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

MAX_MEMORY_READ_BYTES = 64 * 1024
DEFAULT_ANALYSIS_TIMEOUT = 60 * 60


class GhidraBackendError(RuntimeError):
    """Raised when a backend operation fails."""


@dataclass
class SessionRecord:
    """Tracks an open Ghidra program session."""

    session_id: str
    project: Any
    program: Any
    flat_api: Any
    program_name: str
    program_path: str
    project_location: str
    project_name: str
    source_path: str | None = None
    read_only: bool = True
    managed_project: bool = False
    managed_project_root: str | None = None
    temp_source_path: str | None = None
    program_consumer: Any = None
    decompiler: Any = None
    active_transaction_id: int | None = None
    active_transaction_description: str | None = None
    last_analysis_status: str = "idle"
    last_analysis_started_at: float | None = None
    last_analysis_completed_at: float | None = None
    last_analysis_log: str | None = None
    last_analysis_error: str | None = None
    last_analysis_task_id: str | None = None


@dataclass
class TaskRecord:
    """Tracks an asynchronous backend task."""

    task_id: str
    kind: str
    future: Future[Any]
    session_id: str | None
    cancel_hook: Callable[[], None] | None = None
    cancel_requested: bool = False
    created_at: float = field(default_factory=time.time)


class GhidraBackend:
    """High-level Ghidra operations exposed to MCP tools."""

    def __init__(
        self,
        pyghidra_module: Any,
        *,
        install_dir: str | os.PathLike[str] | None = None,
        deterministic: bool = True,
    ):
        self._pyghidra = pyghidra_module
        self._install_dir = str(Path(install_dir).resolve()) if install_dir else None
        self._deterministic = deterministic
        self._sessions: dict[str, SessionRecord] = {}
        self._tasks: dict[str, TaskRecord] = {}
        self._lock = threading.Lock()
        self._startup_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ghidra_headless_mcp")
        self._started = False
        self._launcher: Any = None

    def ping(self) -> dict[str, str]:
        return {"status": "ok", "message": "pong"}

    def ghidra_info(self) -> dict[str, Any]:
        self._ensure_started()
        from ghidra.framework import Application

        version = None
        with suppress(Exception):
            version = Application.getApplicationVersion()

        return {
            "status": "ok",
            "install_dir": self._install_dir,
            "ghidra_version": version,
            "pyghidra_version": getattr(self._pyghidra, "__version__", None),
            "deterministic": self._deterministic,
            "jvm_started": bool(self._pyghidra.started()),
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
        self._ensure_started()
        if not path:
            raise GhidraBackendError("path is required")
        binary_path = Path(path)
        if not binary_path.exists():
            raise GhidraBackendError(f"path does not exist: {path}")

        project_root, effective_project_name, managed_project = self._allocate_project(
            binary_path.name,
            project_location=project_location,
            project_name=project_name,
        )
        project = self._open_or_create_project(project_root, effective_project_name)
        effective_program_name = program_name or binary_path.name
        program = self._import_or_open_program(
            project,
            str(binary_path),
            effective_program_name,
            language=language,
            compiler=compiler,
            loader=loader,
        )
        self._finalize_open_program(program, project)

        session_id = self._register_session(
            project=project,
            program=program,
            project_location=project_root,
            project_name=effective_project_name,
            program_name=effective_program_name,
            program_path=f"/{effective_program_name}",
            source_path=str(binary_path),
            read_only=read_only,
            managed_project=managed_project,
            managed_project_root=project_root if managed_project else None,
        )

        if update_analysis:
            self.analysis_update_and_wait(session_id)

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
        self._ensure_started()
        if not data_base64:
            raise GhidraBackendError("data_base64 is required")
        try:
            raw_bytes = base64.b64decode(data_base64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise GhidraBackendError(f"invalid base64 data: {exc}") from exc

        effective_program_name = program_name or filename or "session.bin"
        project_root, effective_project_name, managed_project = self._allocate_project(
            effective_program_name,
            project_location=project_location,
            project_name=project_name,
        )
        project = self._open_or_create_project(project_root, effective_project_name)

        temp_source_path: str | None = None
        consumer = None
        try:
            program, consumer = self._load_program_from_bytes(
                project,
                raw_bytes,
                effective_program_name,
                language=language,
                compiler=compiler,
                loader=loader,
            )
            self._finalize_open_program(program, project)
        except GhidraBackendError:
            if language or compiler or loader:
                raise
            suffix = Path(filename or "session.bin").suffix or ".bin"
            with tempfile.NamedTemporaryFile(
                prefix="ghidra_headless_mcp-",
                suffix=suffix,
                delete=False,
            ) as tmp:
                tmp.write(raw_bytes)
                temp_source_path = tmp.name
            opened = self.session_open(
                temp_source_path,
                update_analysis=update_analysis,
                read_only=read_only,
                project_location=project_location,
                project_name=project_name,
                program_name=effective_program_name,
            )
            fallback_record = self._get_record(opened["session_id"])
            fallback_record.temp_source_path = temp_source_path
            fallback_record.source_path = None
            return opened

        session_id = self._register_session(
            project=project,
            program=program,
            project_location=project_root,
            project_name=effective_project_name,
            program_name=effective_program_name,
            program_path=f"/{effective_program_name}",
            source_path=None,
            read_only=read_only,
            managed_project=managed_project,
            managed_project_root=project_root if managed_project else None,
            temp_source_path=temp_source_path,
            program_consumer=consumer,
        )

        if update_analysis:
            self.analysis_update_and_wait(session_id)

        return self.binary_summary(session_id)

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
        self._ensure_started()
        if not project_location:
            raise GhidraBackendError("project_location is required")
        if not project_name:
            raise GhidraBackendError("project_name is required")

        shared_project = self._find_open_project(project_location, project_name) is not None
        project = self._open_existing_project(project_location, project_name)
        if program_path:
            normalized = program_path if program_path.startswith("/") else f"/{program_path}"
            folder_path, _, tail = normalized.rpartition("/")
            folder_path = folder_path or "/"
            program_name = tail
        if not program_name:
            raise GhidraBackendError("program_name or program_path is required")

        try:
            program = project.openProgram(folder_path, program_name, False)
        except Exception as exc:
            if not shared_project:
                project.close()
            raise GhidraBackendError(f"failed to open program from project: {exc}") from exc
        if program is None:
            if not shared_project:
                project.close()
            raise GhidraBackendError("failed to open program from project: no Program returned")
        self._finalize_open_program(program, project)

        session_id = self._register_session(
            project=project,
            program=program,
            project_location=str(Path(project_location).resolve()),
            project_name=project_name,
            program_name=program_name,
            program_path=f"{folder_path.rstrip('/')}/{program_name}"
            if folder_path != "/"
            else f"/{program_name}",
            source_path=None,
            read_only=read_only,
            managed_project=False,
        )

        if update_analysis:
            self.analysis_update_and_wait(session_id)

        return self.binary_summary(session_id)

    def session_close(self, session_id: str) -> dict[str, Any]:
        record = self._sessions.pop(session_id, None)
        if record is None:
            raise GhidraBackendError(f"unknown session_id: {session_id}")
        project_still_in_use = self._project_in_use(
            record.project_location,
            record.project_name,
            excluding_session_id=session_id,
        )

        with suppress(Exception):
            if record.decompiler is not None:
                record.decompiler.closeProgram()
                record.decompiler.dispose()

        if record.program_consumer is not None:
            with suppress(Exception):
                record.program.release(record.program_consumer)

        with suppress(Exception):
            record.project.close(record.program)
        if not project_still_in_use:
            with suppress(Exception):
                record.project.close()

        if record.temp_source_path:
            with suppress(OSError):
                os.unlink(record.temp_source_path)
        if record.managed_project_root and not project_still_in_use:
            shutil.rmtree(record.managed_project_root, ignore_errors=True)

        return {"closed": True, "session_id": session_id}

    def session_list(self) -> dict[str, Any]:
        return {
            "sessions": [self.binary_summary(session_id) for session_id in sorted(self._sessions)],
            "count": len(self._sessions),
        }

    def session_mode(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        return {
            "session_id": session_id,
            "read_only": record.read_only,
            "deterministic": self._deterministic,
            "deterministic_scope": "process",
            "active_transaction": self._transaction_summary(record),
        }

    def session_set_mode(
        self,
        session_id: str,
        *,
        read_only: bool | None = None,
        deterministic: bool | None = None,
    ) -> dict[str, Any]:
        record = self._get_record(session_id)
        if read_only is not None:
            record.read_only = read_only
        if deterministic is not None and deterministic != self._deterministic:
            raise GhidraBackendError(
                "deterministic mode is process-level in Ghidra and cannot be changed after startup"
            )
        return self.session_mode(session_id)

    def analysis_status(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        return {
            "session_id": session_id,
            "status": record.last_analysis_status,
            "last_analysis_started_at": record.last_analysis_started_at,
            "last_analysis_completed_at": record.last_analysis_completed_at,
            "last_analysis_task_id": record.last_analysis_task_id,
            "last_analysis_error": record.last_analysis_error,
            "has_log": record.last_analysis_log is not None,
        }

    def analysis_update(self, session_id: str) -> dict[str, Any]:
        return self.task_analysis_update(session_id)

    def analysis_update_and_wait(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        monitor = self._pyghidra.task_monitor(DEFAULT_ANALYSIS_TIMEOUT)
        record.last_analysis_status = "running"
        record.last_analysis_started_at = time.time()
        record.last_analysis_completed_at = None
        record.last_analysis_error = None
        try:
            log = self._analyze_program(record.program, monitor)
        except Exception as exc:
            record.last_analysis_status = "failed"
            record.last_analysis_completed_at = time.time()
            record.last_analysis_error = str(exc)
            raise GhidraBackendError(f"analysis failed: {exc}") from exc

        self._finalize_open_program(record.program, record.project)
        record.last_analysis_log = log or ""
        record.last_analysis_status = "completed"
        record.last_analysis_completed_at = time.time()
        return {
            "session_id": session_id,
            "status": record.last_analysis_status,
            "log": record.last_analysis_log,
        }

    def analysis_options_list(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        query: str | None = None,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        options = self._analysis_options(session_id)
        names = sorted(str(name) for name in options.getOptionNames())
        if query:
            needle = query.lower()
            names = [name for name in names if needle in name.lower()]
        items = [
            self._analysis_option_record(options, name) for name in names[offset : offset + limit]
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
        if not name:
            raise GhidraBackendError("name is required")
        options = self._analysis_options(session_id)
        self._require_option(options, name)
        return {"session_id": session_id, **self._analysis_option_record(options, name)}

    def analysis_options_set(self, session_id: str, name: str, value: Any) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        options = self._analysis_options(session_id)
        self._require_option(options, name)

        def mutate() -> None:
            current = self._option_object(options, name)
            if isinstance(value, bool):
                options.setBoolean(name, value)
            elif isinstance(value, int) and not isinstance(value, bool):
                if current is not None and current.__class__.__name__.lower().endswith("long"):
                    options.setLong(name, value)
                else:
                    options.setInt(name, value)
            elif isinstance(value, float):
                options.setDouble(name, value)
            elif isinstance(value, str):
                lowered = value.strip().lower()
                if current is not None and current.__class__.__name__.lower().endswith("boolean"):
                    options.setBoolean(name, lowered in {"1", "true", "yes", "on"})
                elif current is not None and current.__class__.__name__.lower().endswith("integer"):
                    options.setInt(name, int(value, 0))
                elif current is not None and current.__class__.__name__.lower().endswith("long"):
                    options.setLong(name, int(value, 0))
                elif current is not None and current.__class__.__name__.lower().endswith("double"):
                    options.setDouble(name, float(value))
                elif current is not None and current.__class__.__name__.lower().endswith("float"):
                    options.setFloat(name, float(value))
                else:
                    options.setString(name, value)
            else:
                raise GhidraBackendError("unsupported option value type")

        self._with_write(session_id, f"Set analysis option {name}", mutate)
        return self.analysis_options_get(session_id, name)

    def binary_summary(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        program = record.program
        entry = None
        with suppress(Exception):
            entry = record.flat_api.getEntryPoint()
        compiler_spec = None
        with suppress(Exception):
            compiler_spec = program.getCompilerSpec().getCompilerSpecID().toString()
        return {
            "session_id": session_id,
            "filename": record.source_path or record.program_name,
            "program_name": record.program_name,
            "program_path": record.program_path,
            "project_location": record.project_location,
            "project_name": record.project_name,
            "language_id": program.getLanguageID().toString(),
            "compiler_spec_id": compiler_spec,
            "format": program.getExecutableFormat(),
            "entry_point": self._addr_str(entry),
            "image_base": self._addr_str(program.getImageBase()),
            "min_address": self._addr_str(program.getMinAddress()),
            "max_address": self._addr_str(program.getMaxAddress()),
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
        self._validate_offset_limit(offset, limit)
        funcs = list(self._get_program(session_id).getFunctionManager().getFunctions(True))
        if query:
            needle = query.lower()
            funcs = [func for func in funcs if needle in func.getName().lower()]
        items = [self._function_record(func) for func in funcs[offset : offset + limit]]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(funcs),
            "count": len(items),
            "items": items,
        }

    def binary_get_function_at(self, session_id: str, address: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, address)
        return {"session_id": session_id, "function": self._function_record(function)}

    def binary_symbols(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        include_dynamic: bool = False,
        query: str | None = None,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        symbol_table = self._get_program(session_id).getSymbolTable()
        symbols = list(symbol_table.getAllSymbols(include_dynamic))
        if query:
            needle = query.lower()
            symbols = [sym for sym in symbols if needle in sym.getName(True).lower()]
        items = [self._symbol_record(sym) for sym in symbols[offset : offset + limit]]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(symbols),
            "count": len(items),
            "items": items,
        }

    def binary_strings(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        query: str | None = None,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        program = self._get_program(session_id)
        strings = list(self._iter_strings(program))
        if query:
            needle = query.lower()
            strings = [item for item in strings if needle in item["value"].lower()]
        items = strings[offset : offset + limit]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(strings),
            "count": len(items),
            "items": items,
        }

    def binary_imports(
        self, session_id: str, *, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        symbols = list(self._get_program(session_id).getSymbolTable().getExternalSymbols())
        items = [self._symbol_record(sym) for sym in symbols[offset : offset + limit]]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(symbols),
            "count": len(items),
            "items": items,
        }

    def binary_exports(
        self, session_id: str, *, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        symbol_table = self._get_program(session_id).getSymbolTable()
        addrs = list(symbol_table.getExternalEntryPointIterator())
        items = []
        for addr in addrs[offset : offset + limit]:
            symbol = symbol_table.getPrimarySymbol(addr)
            items.append(
                {
                    "address": self._addr_str(addr),
                    "symbol": self._symbol_record(symbol) if symbol is not None else None,
                }
            )
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(addrs),
            "count": len(items),
            "items": items,
        }

    def binary_memory_blocks(self, session_id: str) -> dict[str, Any]:
        blocks = list(self._get_program(session_id).getMemory().getBlocks())
        items = [
            {
                "name": block.getName(),
                "start": self._addr_str(block.getStart()),
                "end": self._addr_str(block.getEnd()),
                "length": int(block.getSize()),
                "read": bool(block.isRead()),
                "write": bool(block.isWrite()),
                "execute": bool(block.isExecute()),
                "comment": block.getComment(),
            }
            for block in blocks
        ]
        return {"session_id": session_id, "count": len(items), "items": items}

    def binary_data(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        listing = self._get_program(session_id).getListing()
        data_items = list(
            listing.getDefinedData(
                self._get_program(session_id).getMemory().getAllInitializedAddressSet(), True
            )
        )
        items = [self._data_record(data) for data in data_items[offset : offset + limit]]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(data_items),
            "count": len(items),
            "items": items,
        }

    def disasm_function(
        self,
        session_id: str,
        address: int | str,
        *,
        limit: int = 500,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, address)
        items = self._disassemble_instructions(
            self._get_program(session_id).getListing().getInstructions(function.getBody(), True),
            limit,
        )
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "count": len(items),
            "items": items,
        }

    def disasm_range(
        self,
        session_id: str,
        start: int | str,
        *,
        length: int,
        limit: int = 200,
    ) -> dict[str, Any]:
        if length <= 0:
            raise GhidraBackendError("length must be > 0")
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        start_addr = self._coerce_address(session_id, start, "start")
        end_addr = start_addr.add(length - 1)
        from ghidra.program.model.address import AddressSet

        address_set = AddressSet(start_addr, end_addr)
        instructions = self._get_program(session_id).getListing().getInstructions(address_set, True)
        items = self._disassemble_instructions(instructions, limit)
        return {
            "session_id": session_id,
            "start": self._addr_str(start_addr),
            "length": length,
            "limit": limit,
            "count": len(items),
            "items": items,
        }

    def decomp_function(
        self,
        session_id: str,
        function_start: int | str,
        *,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        return self._decompile_function(session_id, function, timeout_secs=timeout_secs)

    def pcode_function(
        self,
        session_id: str,
        function_start: int | str,
        *,
        limit: int = 200,
    ) -> dict[str, Any]:
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        function = self._resolve_function(session_id, function_start)
        listing = self._get_program(session_id).getListing()
        instructions = listing.getInstructions(function.getBody(), True)
        items: list[dict[str, Any]] = []
        for instruction in instructions:
            if len(items) >= limit:
                break
            items.append(self._pcode_instruction_record(instruction))
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "limit": limit,
            "count": len(items),
            "items": items,
        }

    def pcode_op_at(self, session_id: str, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        instruction = self._get_program(session_id).getListing().getInstructionAt(addr)
        if instruction is None:
            raise GhidraBackendError(f"no instruction at {self._addr_str(addr)}")
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "instruction": instruction.toString(),
            "ops": [self._pcode_op_record(op) for op in instruction.getPcode()],
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
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        if address is not None:
            if start is not None or end is not None:
                raise GhidraBackendError("address cannot be combined with start/end")
            addr = self._coerce_address(session_id, address, "address")
            refs = list(self._get_program(session_id).getReferenceManager().getReferencesTo(addr))
            items = [self._reference_record(ref) for ref in refs[:limit]]
            return {
                "session_id": session_id,
                "address": self._addr_str(addr),
                "count": len(items),
                "items": items,
            }
        start_addr, end_addr, address_set = self._optional_address_range(
            session_id,
            start=start,
            end=end,
            arg_name="start",
        )
        if address_set is None:
            raise GhidraBackendError("address or start is required")
        manager = self._get_program(session_id).getReferenceManager()
        items: list[dict[str, Any]] = []
        for to_addr in manager.getReferenceDestinationIterator(address_set, True):
            for ref in manager.getReferencesTo(to_addr):
                items.append(self._reference_record(ref))
                if len(items) >= limit:
                    break
            if len(items) >= limit:
                break
        return {
            "session_id": session_id,
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "count": len(items),
            "items": items,
        }

    def xref_from(
        self,
        session_id: str,
        address: int | str | None = None,
        *,
        start: int | str | None = None,
        end: int | str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        if address is not None:
            if start is not None or end is not None:
                raise GhidraBackendError("address cannot be combined with start/end")
            addr = self._coerce_address(session_id, address, "address")
            refs = list(self._get_program(session_id).getReferenceManager().getReferencesFrom(addr))
            items = [self._reference_record(ref) for ref in refs[:limit]]
            return {
                "session_id": session_id,
                "address": self._addr_str(addr),
                "count": len(items),
                "items": items,
            }
        start_addr, end_addr, address_set = self._optional_address_range(
            session_id,
            start=start,
            end=end,
            arg_name="start",
        )
        if address_set is None:
            raise GhidraBackendError("address or start is required")
        manager = self._get_program(session_id).getReferenceManager()
        items: list[dict[str, Any]] = []
        for from_addr in manager.getReferenceSourceIterator(address_set, True):
            for ref in manager.getReferencesFrom(from_addr):
                items.append(self._reference_record(ref))
                if len(items) >= limit:
                    break
            if len(items) >= limit:
                break
        return {
            "session_id": session_id,
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "count": len(items),
            "items": items,
        }

    def function_callers(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        callers = sorted(
            function.getCallingFunctions(self._pyghidra.task_monitor()), key=self._function_sort_key
        )
        items = [self._function_record(func) for func in callers]
        return {
            "session_id": session_id,
            "function_start": self._addr_str(function.getEntryPoint()),
            "count": len(items),
            "items": items,
        }

    def function_callees(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        callees = sorted(
            function.getCalledFunctions(self._pyghidra.task_monitor()), key=self._function_sort_key
        )
        items = [self._function_record(func) for func in callees]
        return {
            "session_id": session_id,
            "function_start": self._addr_str(function.getEntryPoint()),
            "count": len(items),
            "items": items,
        }

    def function_signature_get(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "signature": function.getPrototypeString(False, True),
            "calling_convention": function.getCallingConventionName(),
            "signature_source": str(function.getSignatureSource()),
            "return_type": function.getReturnType().getPathName(),
            "parameters": [self._parameter_record(param) for param in function.getParameters()],
        }

    def function_signature_set(
        self, session_id: str, function_start: int | str, signature: str
    ) -> dict[str, Any]:
        if not signature:
            raise GhidraBackendError("signature is required")
        function = self._resolve_function(session_id, function_start)

        def mutate() -> None:
            from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
            from ghidra.app.util.cparser.C import CParserUtils
            from ghidra.program.model.symbol import SourceType

            definition = CParserUtils.parseSignature(
                None, self._get_program(session_id), signature, False
            )
            if definition is None:
                raise GhidraBackendError("failed to parse function signature")
            cmd = ApplyFunctionSignatureCmd(
                function.getEntryPoint(), definition, SourceType.USER_DEFINED
            )
            if not cmd.applyTo(self._get_program(session_id)):
                raise GhidraBackendError(
                    getattr(cmd, "getStatusMsg", lambda: None)()
                    or "failed to apply function signature"
                )

        self._with_write(session_id, f"Set function signature {function.getName()}", mutate)
        return self.function_signature_get(session_id, function.getEntryPoint())

    def function_variables(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "parameters": [self._parameter_record(param) for param in function.getParameters()],
            "locals": [self._variable_record(var) for var in function.getLocalVariables()],
        }

    def function_rename(
        self, session_id: str, function_start: int | str, name: str
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        function = self._resolve_function(session_id, function_start)

        def mutate() -> None:
            from ghidra.program.model.symbol import SourceType

            function.setName(name, SourceType.USER_DEFINED)

        self._with_write(session_id, f"Rename function {function.getName()}", mutate)
        return {"session_id": session_id, "function": self._function_record(function)}

    def annotation_comment_get(
        self,
        session_id: str,
        *,
        address: int | str | None = None,
        comment_type: str = "eol",
        function_start: int | str | None = None,
        scope: str = "listing",
    ) -> dict[str, Any]:
        if scope == "function":
            function = self._resolve_function(session_id, function_start or address)
            if comment_type == "repeatable":
                comment = function.getRepeatableComment()
            else:
                comment = function.getComment()
            return {
                "session_id": session_id,
                "scope": scope,
                "function_start": self._addr_str(function.getEntryPoint()),
                "comment_type": comment_type,
                "comment": comment,
            }
        if address is None:
            raise GhidraBackendError("address is required for listing comments")
        addr = self._coerce_address(session_id, address, "address")
        listing = self._get_program(session_id).getListing()
        comment = listing.getComment(self._comment_type(comment_type), addr)
        return {
            "session_id": session_id,
            "scope": scope,
            "address": self._addr_str(addr),
            "comment_type": comment_type,
            "comment": comment,
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
        if scope == "function":
            function = self._resolve_function(session_id, function_start or address)

            def mutate() -> None:
                if comment_type == "repeatable":
                    function.setRepeatableComment(comment)
                else:
                    function.setComment(comment)

            self._with_write(session_id, f"Set function comment {function.getName()}", mutate)
            return self.annotation_comment_get(
                session_id,
                function_start=function.getEntryPoint(),
                comment_type=comment_type,
                scope=scope,
            )

        if address is None:
            raise GhidraBackendError("address is required for listing comments")
        addr = self._coerce_address(session_id, address, "address")

        def mutate() -> None:
            self._get_program(session_id).getListing().setComment(
                addr, self._comment_type(comment_type), comment
            )

        self._with_write(session_id, f"Set comment {self._addr_str(addr)}", mutate)
        return self.annotation_comment_get(
            session_id,
            address=addr,
            comment_type=comment_type,
            scope=scope,
        )

    def annotation_symbol_rename(
        self,
        session_id: str,
        *,
        address: int | str,
        new_name: str,
        old_name: str | None = None,
    ) -> dict[str, Any]:
        if not new_name:
            raise GhidraBackendError("new_name is required")
        symbol = self._resolve_symbol(session_id, address, name=old_name)

        def mutate() -> None:
            from ghidra.program.model.symbol import SourceType

            symbol.setName(new_name, SourceType.USER_DEFINED)

        self._with_write(session_id, f"Rename symbol {symbol.getName(True)}", mutate)
        return {"session_id": session_id, "symbol": self._symbol_record(symbol)}

    def annotation_symbol_create(
        self,
        session_id: str,
        *,
        address: int | str,
        name: str,
        make_primary: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        addr = self._coerce_address(session_id, address, "address")
        created: Any = None

        def mutate() -> None:
            nonlocal created
            from ghidra.program.model.symbol import SourceType

            created = self._get_record(session_id).flat_api.createLabel(
                addr, name, make_primary, SourceType.USER_DEFINED
            )

        self._with_write(session_id, f"Create symbol {name}", mutate)
        return {"session_id": session_id, "symbol": self._symbol_record(created)}

    def annotation_symbol_delete(
        self,
        session_id: str,
        *,
        address: int | str,
        name: str | None = None,
    ) -> dict[str, Any]:
        symbol = self._resolve_symbol(session_id, address, name=name)

        def mutate() -> None:
            self._get_program(session_id).getSymbolTable().removeSymbolSpecial(symbol)

        deleted_name = symbol.getName(True)
        self._with_write(session_id, f"Delete symbol {deleted_name}", mutate)
        return {
            "session_id": session_id,
            "deleted": True,
            "address": self._addr_str(symbol.getAddress()),
            "name": deleted_name,
        }

    def memory_read(self, session_id: str, address: int | str, *, length: int) -> dict[str, Any]:
        if length <= 0:
            raise GhidraBackendError("length must be > 0")
        if length > MAX_MEMORY_READ_BYTES:
            raise GhidraBackendError(f"length must be <= {MAX_MEMORY_READ_BYTES}")
        addr = self._coerce_address(session_id, address, "address")
        raw = bytes(self._get_record(session_id).flat_api.getBytes(addr, length))
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
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
        payload = self._decode_payload(data_base64=data_base64, data_hex=data_hex)
        if len(payload) > MAX_MEMORY_READ_BYTES:
            raise GhidraBackendError(
                f"write payload too large ({len(payload)} bytes); max is {MAX_MEMORY_READ_BYTES}"
            )
        addr = self._coerce_address(session_id, address, "address")

        def mutate() -> int:
            from jpype.types import JArray, JByte

            written = (
                self._get_program(session_id).getMemory().setBytes(addr, JArray(JByte)(payload))
            )
            return len(payload) if written is None else int(written)

        written = self._with_write(session_id, f"Write memory {self._addr_str(addr)}", mutate)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "requested": len(payload),
            "written": written,
        }

    def data_typed_at(self, session_id: str, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        data = self._get_program(session_id).getListing().getDefinedDataContaining(addr)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "defined": data is not None,
            "data": self._data_record(data) if data is not None else None,
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
        if not data_type:
            raise GhidraBackendError("data_type is required")
        addr = self._coerce_address(session_id, address, "address")
        parsed = self._parse_data_type(session_id, data_type)
        created = None

        def mutate() -> None:
            nonlocal created
            listing = self._get_program(session_id).getListing()
            if clear_existing:
                end_addr = addr if length is None or length <= 1 else addr.add(length - 1)
                listing.clearCodeUnits(addr, end_addr, False)
            if length is None:
                created = listing.createData(addr, parsed)
            else:
                created = listing.createData(addr, parsed, length)

        self._with_write(session_id, f"Create data {data_type}", mutate)
        return {"session_id": session_id, "data": self._data_record(created)}

    def data_clear(self, session_id: str, address: int | str, *, length: int = 1) -> dict[str, Any]:
        if length <= 0:
            raise GhidraBackendError("length must be > 0")
        addr = self._coerce_address(session_id, address, "address")
        end_addr = addr.add(length - 1)

        def mutate() -> None:
            self._get_program(session_id).getListing().clearCodeUnits(addr, end_addr, False)

        self._with_write(session_id, f"Clear data {self._addr_str(addr)}", mutate)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "length": length,
            "cleared": True,
        }

    def type_list(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        query: str | None = None,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        types = sorted(self._get_all_data_types(session_id), key=lambda dt: dt.getPathName())
        if query:
            needle = query.lower()
            types = [dt for dt in types if needle in dt.getPathName().lower()]
        items = [self._data_type_record(dt) for dt in types[offset : offset + limit]]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(types),
            "count": len(items),
            "items": items,
        }

    def type_get(
        self, session_id: str, *, path: str | None = None, name: str | None = None
    ) -> dict[str, Any]:
        data_type = self._resolve_data_type(session_id, path=path, name=name)
        return {"session_id": session_id, "type": self._data_type_record(data_type)}

    def type_define_c(
        self,
        session_id: str,
        *,
        declaration: str,
        name: str | None = None,
        category: str = "/",
    ) -> dict[str, Any]:
        if not declaration:
            raise GhidraBackendError("declaration is required")
        resolved = None

        def mutate() -> None:
            nonlocal resolved
            from ghidra.app.util.cparser.C import CParserUtils
            from ghidra.program.model.data import (
                CategoryPath,
                DataTypeConflictHandler,
                TypedefDataType,
            )

            dtm = self._get_program(session_id).getDataTypeManager()
            normalized = declaration.strip().rstrip(";")
            if "(" in normalized and ")" in normalized:
                func_def = CParserUtils.parseSignature(
                    None, self._get_program(session_id), normalized, False
                )
                if func_def is None:
                    raise GhidraBackendError("failed to parse function declaration")
                resolved = dtm.addDataType(func_def, DataTypeConflictHandler.DEFAULT_HANDLER)
                return
            if not name:
                raise GhidraBackendError("name is required for non-function type definitions")
            base = self._parse_data_type(session_id, normalized)
            typedef = TypedefDataType(CategoryPath(category), name, base, dtm)
            resolved = dtm.addDataType(typedef, DataTypeConflictHandler.DEFAULT_HANDLER)

        self._with_write(session_id, f"Define type {name or declaration}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(resolved)}

    def type_rename(
        self, session_id: str, *, path: str | None = None, name: str | None = None, new_name: str
    ) -> dict[str, Any]:
        if not new_name:
            raise GhidraBackendError("new_name is required")
        data_type = self._resolve_data_type(session_id, path=path, name=name)

        def mutate() -> None:
            data_type.setName(new_name)

        self._with_write(session_id, f"Rename type {data_type.getName()}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(data_type)}

    def type_delete(
        self, session_id: str, *, path: str | None = None, name: str | None = None
    ) -> dict[str, Any]:
        data_type = self._resolve_data_type(session_id, path=path, name=name)

        def mutate() -> bool:
            return bool(self._get_program(session_id).getDataTypeManager().remove(data_type))

        deleted = self._with_write(session_id, f"Delete type {data_type.getName()}", mutate)
        return {
            "session_id": session_id,
            "deleted": deleted,
            "type": self._data_type_record(data_type),
        }

    def function_by_name(
        self,
        session_id: str,
        name: str,
        *,
        exact: bool = False,
        limit: int = 20,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        funcs = sorted(
            self._get_program(session_id).getFunctionManager().getFunctions(True),
            key=self._function_sort_key,
        )
        if exact:
            matched = [func for func in funcs if func.getName() == name]
        else:
            needle = name.lower()
            matched = [func for func in funcs if needle in func.getName().lower()]
        items = [self._function_record(func) for func in matched[:limit]]
        return {
            "session_id": session_id,
            "query": name,
            "exact": exact,
            "limit": limit,
            "total": len(matched),
            "count": len(items),
            "items": items,
        }

    def symbol_by_name(
        self,
        session_id: str,
        name: str,
        *,
        exact: bool = False,
        limit: int = 20,
        include_dynamic: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        symbols = list(
            self._get_program(session_id).getSymbolTable().getAllSymbols(include_dynamic)
        )
        if exact:
            matched = [
                symbol
                for symbol in symbols
                if symbol.getName(True) == name or symbol.getName() == name
            ]
        else:
            needle = name.lower()
            matched = [symbol for symbol in symbols if needle in symbol.getName(True).lower()]
        items = [self._symbol_record(symbol) for symbol in matched[:limit]]
        return {
            "session_id": session_id,
            "query": name,
            "exact": exact,
            "limit": limit,
            "total": len(matched),
            "count": len(items),
            "items": items,
        }

    def address_resolve(self, session_id: str, query: int | str) -> dict[str, Any]:
        if query is None or (isinstance(query, str) and not query.strip()):
            raise GhidraBackendError("query is required")
        payload: dict[str, Any] = {
            "session_id": session_id,
            "query": query,
            "resolved": False,
        }
        with suppress(GhidraBackendError):
            addr = self._coerce_address(session_id, query, "query")
            payload["resolved"] = True
            payload["address"] = self._addr_str(addr)
            with suppress(GhidraBackendError):
                payload["function"] = self.binary_get_function_at(session_id, addr)["function"]
            symbols = list(self._get_program(session_id).getSymbolTable().getSymbols(addr))
            payload["symbols"] = [self._symbol_record(symbol) for symbol in symbols]
            payload["data"] = self.data_typed_at(session_id, addr)["data"]
            return payload

        if not isinstance(query, str):
            raise GhidraBackendError("query must be a string or address")

        symbols = self.symbol_by_name(session_id, query, exact=True, limit=50)["items"]
        if not symbols:
            symbols = self.symbol_by_name(session_id, query, exact=False, limit=50)["items"]
        functions = self.function_by_name(session_id, query, exact=True, limit=50)["items"]
        if not functions:
            functions = self.function_by_name(session_id, query, exact=False, limit=50)["items"]
        payload["symbols"] = symbols
        payload["functions"] = functions
        addresses = sorted(
            {
                item["address"]
                for item in symbols
                if isinstance(item, dict) and item.get("address") is not None
            }
            | {
                item["entry_point"]
                for item in functions
                if isinstance(item, dict) and item.get("entry_point") is not None
            }
        )
        if addresses:
            payload["resolved"] = True
            payload["address"] = addresses[0]
            with suppress(GhidraBackendError):
                payload["data"] = self.data_typed_at(session_id, addresses[0])["data"]
        return payload

    def search_text(
        self,
        session_id: str,
        text: str,
        *,
        case_sensitive: bool = False,
        defined_strings_only: bool = False,
        encoding: str = "utf-8",
        start: int | str | None = None,
        end: int | str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if not text:
            raise GhidraBackendError("text is required")
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        try:
            needle_bytes = text.encode(encoding)
        except LookupError as exc:
            raise GhidraBackendError(f"unknown encoding: {encoding}") from exc
        except UnicodeEncodeError as exc:
            raise GhidraBackendError(str(exc)) from exc
        start_addr, end_addr, address_set = self._optional_address_range(
            session_id,
            start=start,
            end=end,
            arg_name="start",
        )
        items: list[dict[str, Any]] = []
        seen_addresses: set[str] = set()
        haystack = list(self._iter_strings(self._get_program(session_id), address_set=address_set))
        for item in haystack:
            candidate = item["value"]
            matched = text in candidate if case_sensitive else text.lower() in candidate.lower()
            if matched:
                record = {"kind": "defined_string", **item}
                items.append(record)
                seen_addresses.add(record["address"])
                if len(items) >= limit:
                    break
        if not defined_strings_only and len(items) < limit:
            for addr in self._find_byte_matches(
                session_id,
                needle_bytes,
                limit - len(items),
                address_set=address_set,
            ):
                addr_text = self._addr_str(addr)
                if addr_text in seen_addresses:
                    continue
                items.append(
                    {
                        "kind": "memory_match",
                        "address": addr_text,
                        "text": text,
                        "encoding": encoding,
                    }
                )
                seen_addresses.add(addr_text)
                if len(items) >= limit:
                    break
        return {
            "session_id": session_id,
            "query": text,
            "case_sensitive": case_sensitive,
            "defined_strings_only": defined_strings_only,
            "encoding": encoding,
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "count": len(items),
            "items": items,
        }

    def search_bytes(
        self,
        session_id: str,
        *,
        pattern_base64: str | None = None,
        pattern_hex: str | None = None,
        start: int | str | None = None,
        end: int | str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        payload = self._decode_payload(data_base64=pattern_base64, data_hex=pattern_hex)
        start_addr, end_addr, address_set = self._optional_address_range(
            session_id,
            start=start,
            end=end,
            arg_name="start",
        )
        matches = self._find_byte_matches(session_id, payload, limit, address_set=address_set)
        items = [
            {"address": self._addr_str(addr), "pattern_hex": payload.hex()} for addr in matches
        ]
        return {
            "session_id": session_id,
            "pattern_hex": payload.hex(),
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "count": len(items),
            "items": items,
        }

    def search_constants(
        self,
        session_id: str,
        value: int | str,
        *,
        start: int | str | None = None,
        end: int | str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        scalar_value = int(value, 0) if isinstance(value, str) else int(value)
        program = self._get_program(session_id)
        listing = program.getListing()
        start_addr, end_addr, address_set = self._optional_address_range(
            session_id,
            start=start,
            end=end,
            arg_name="start",
        )
        scope = program.getMemory() if address_set is None else address_set
        instructions = listing.getInstructions(scope, True)
        items: list[dict[str, Any]] = []
        for instruction in instructions:
            if len(items) >= limit:
                break
            for operand_index in range(int(instruction.getNumOperands())):
                scalar = None
                with suppress(Exception):
                    scalar = instruction.getScalar(operand_index)
                if scalar is None:
                    continue
                if int(scalar.getValue()) != scalar_value:
                    continue
                items.append(
                    {
                        "address": self._addr_str(instruction.getAddress()),
                        "instruction": instruction.toString(),
                        "operand_index": operand_index,
                        "scalar_value": int(scalar.getValue()),
                        "scalar_hex": hex(int(scalar.getValue())),
                    }
                )
                break
        return {
            "session_id": session_id,
            "query": scalar_value,
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "count": len(items),
            "items": items,
        }

    def search_instructions(
        self,
        session_id: str,
        query: str,
        *,
        case_sensitive: bool = False,
        function_start: int | str | None = None,
        start: int | str | None = None,
        end: int | str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if not query:
            raise GhidraBackendError("query is required")
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        if function_start is not None and start is not None:
            raise GhidraBackendError("function_start cannot be combined with start/end")
        program = self._get_program(session_id)
        listing = program.getListing()
        start_addr = None
        end_addr = None
        if function_start is None:
            start_addr, end_addr, address_set = self._optional_address_range(
                session_id,
                start=start,
                end=end,
                arg_name="start",
            )
            scope = program.getMemory() if address_set is None else address_set
            instructions = listing.getInstructions(scope, True)
        else:
            function = self._resolve_function(session_id, function_start)
            instructions = listing.getInstructions(function.getBody(), True)
        needle = query if case_sensitive else query.lower()
        items: list[dict[str, Any]] = []
        for instruction in instructions:
            if len(items) >= limit:
                break
            text = instruction.toString()
            haystack = text if case_sensitive else text.lower()
            mnemonic = instruction.getMnemonicString()
            if needle not in haystack and needle not in (
                mnemonic if case_sensitive else mnemonic.lower()
            ):
                continue
            items.append(
                {
                    "address": self._addr_str(instruction.getAddress()),
                    "mnemonic": mnemonic,
                    "text": text,
                    "bytes": bytes(instruction.getBytes()).hex(),
                }
            )
        return {
            "session_id": session_id,
            "query": query,
            "function_start": None
            if function_start is None
            else self._addr_str(self._coerce_address(session_id, function_start, "function_start")),
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "count": len(items),
            "items": items,
        }

    def search_pcode(
        self,
        session_id: str,
        query: str,
        *,
        case_sensitive: bool = False,
        function_start: int | str | None = None,
        start: int | str | None = None,
        end: int | str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if not query:
            raise GhidraBackendError("query is required")
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        if function_start is not None and start is not None:
            raise GhidraBackendError("function_start cannot be combined with start/end")
        program = self._get_program(session_id)
        listing = program.getListing()
        start_addr = None
        end_addr = None
        if function_start is None:
            start_addr, end_addr, address_set = self._optional_address_range(
                session_id,
                start=start,
                end=end,
                arg_name="start",
            )
            scope = program.getMemory() if address_set is None else address_set
            instructions = listing.getInstructions(scope, True)
        else:
            function = self._resolve_function(session_id, function_start)
            instructions = listing.getInstructions(function.getBody(), True)
        needle = query if case_sensitive else query.lower()
        items: list[dict[str, Any]] = []
        for instruction in instructions:
            if len(items) >= limit:
                break
            for op in instruction.getPcode():
                text = str(op)
                haystack = text if case_sensitive else text.lower()
                mnemonic = op.getMnemonic()
                if needle not in haystack and needle not in (
                    mnemonic if case_sensitive else mnemonic.lower()
                ):
                    continue
                items.append(
                    {
                        "address": self._addr_str(instruction.getAddress()),
                        "instruction": instruction.toString(),
                        "op": self._pcode_op_record(op),
                    }
                )
                if len(items) >= limit:
                    break
        return {
            "session_id": session_id,
            "query": query,
            "function_start": None
            if function_start is None
            else self._addr_str(self._coerce_address(session_id, function_start, "function_start")),
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "count": len(items),
            "items": items,
        }

    def function_basic_blocks(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        blocks = self._function_code_blocks(function)
        items = [self._code_block_record(block) for block in blocks]
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "count": len(items),
            "items": items,
        }

    def cfg_edges(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        blocks = self._function_code_blocks(function)
        block_keys = {self._code_block_key(block) for block in blocks}
        edges: list[dict[str, Any]] = []
        monitor = self._pyghidra.task_monitor()
        for block in blocks:
            destinations = block.getDestinations(monitor)
            while destinations.hasNext():
                ref = destinations.next()
                destination = ref.getDestinationBlock()
                if destination is None or self._code_block_key(destination) not in block_keys:
                    continue
                edges.append(
                    {
                        "source": self._code_block_record(block),
                        "target": self._code_block_record(destination),
                        "flow_type": str(ref.getFlowType()),
                        "referent": self._addr_str(ref.getReferent()),
                        "reference": self._addr_str(ref.getReference()),
                    }
                )
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "count": len(edges),
            "items": edges,
        }

    def callgraph_paths(
        self,
        session_id: str,
        source_function: int | str,
        target_function: int | str,
        *,
        max_depth: int = 4,
        limit: int = 10,
    ) -> dict[str, Any]:
        if max_depth <= 0:
            raise GhidraBackendError("max_depth must be > 0")
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        source = self._resolve_function(session_id, source_function)
        target = self._resolve_function(session_id, target_function)
        target_entry = self._addr_str(target.getEntryPoint())
        queue: deque[list[Any]] = deque([[source]])
        paths: list[list[dict[str, Any]]] = []
        while queue and len(paths) < limit:
            path = queue.popleft()
            current = path[-1]
            if self._addr_str(current.getEntryPoint()) == target_entry:
                paths.append([self._function_record(func) for func in path])
                continue
            if len(path) - 1 >= max_depth:
                continue
            callees = sorted(
                current.getCalledFunctions(self._pyghidra.task_monitor()),
                key=self._function_sort_key,
            )
            seen_in_path = {self._addr_str(func.getEntryPoint()) for func in path}
            for callee in callees:
                callee_entry = self._addr_str(callee.getEntryPoint())
                if callee_entry in seen_in_path:
                    continue
                queue.append([*path, callee])
        return {
            "session_id": session_id,
            "source": self._function_record(source),
            "target": self._function_record(target),
            "max_depth": max_depth,
            "count": len(paths),
            "items": paths,
        }

    def function_variable_rename(
        self,
        session_id: str,
        function_start: int | str,
        *,
        name: str,
        new_name: str,
        ordinal: int | None = None,
        storage: str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        if not new_name:
            raise GhidraBackendError("new_name is required")
        function = self._resolve_function(session_id, function_start)
        variable = self._resolve_variable(function, name=name, ordinal=ordinal, storage=storage)

        def mutate() -> None:
            high_symbol = self._find_high_symbol(
                session_id,
                function,
                name=name,
                ordinal=ordinal,
                storage=storage,
            )
            if high_symbol is not None:
                self._update_high_symbol(
                    session_id,
                    function,
                    high_symbol,
                    name=new_name,
                    data_type=None,
                )
                return
            from ghidra.program.model.symbol import SourceType

            variable.setName(new_name, SourceType.USER_DEFINED)

        self._with_write(session_id, f"Rename variable {name}", mutate)
        return self.function_variables(session_id, function.getEntryPoint())

    def function_variable_retype(
        self,
        session_id: str,
        function_start: int | str,
        *,
        name: str,
        data_type: str,
        ordinal: int | None = None,
        storage: str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        if not data_type:
            raise GhidraBackendError("data_type is required")
        function = self._resolve_function(session_id, function_start)
        variable = self._resolve_variable(function, name=name, ordinal=ordinal, storage=storage)
        parsed = self._parse_data_type(session_id, data_type)

        def mutate() -> None:
            high_symbol = self._find_high_symbol(
                session_id,
                function,
                name=name,
                ordinal=ordinal,
                storage=storage,
            )
            if high_symbol is not None:
                self._update_high_symbol(
                    session_id,
                    function,
                    high_symbol,
                    name=None,
                    data_type=parsed,
                )
                return
            from ghidra.program.model.symbol import SourceType

            variable.setDataType(parsed, SourceType.USER_DEFINED)

        self._with_write(session_id, f"Retype variable {name}", mutate)
        return self.function_variables(session_id, function.getEntryPoint())

    def function_return_type_set(
        self,
        session_id: str,
        function_start: int | str,
        *,
        data_type: str,
    ) -> dict[str, Any]:
        if not data_type:
            raise GhidraBackendError("data_type is required")
        function = self._resolve_function(session_id, function_start)
        parsed = self._parse_data_type(session_id, data_type)

        def mutate() -> None:
            from ghidra.program.model.symbol import SourceType

            function.setReturnType(parsed, SourceType.USER_DEFINED)

        self._with_write(session_id, f"Set return type {function.getName()}", mutate)
        return self.function_signature_get(session_id, function.getEntryPoint())

    def function_create(
        self,
        session_id: str,
        *,
        address: int | str,
        name: str | None = None,
    ) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        created = None

        def mutate() -> None:
            nonlocal created
            created = self._get_record(session_id).flat_api.createFunction(addr, name)
            if created is None:
                created = self._get_program(session_id).getFunctionManager().getFunctionAt(addr)
            if created is None:
                raise GhidraBackendError(f"failed to create function at {self._addr_str(addr)}")

        self._with_write(session_id, f"Create function {name or self._addr_str(addr)}", mutate)
        return {"session_id": session_id, "function": self._function_record(created)}

    def function_delete(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        entry = function.getEntryPoint()
        deleted_name = function.getName()

        def mutate() -> None:
            self._get_record(session_id).flat_api.removeFunctionAt(entry)

        self._with_write(session_id, f"Delete function {deleted_name}", mutate)
        return {
            "session_id": session_id,
            "deleted": True,
            "entry_point": self._addr_str(entry),
            "name": deleted_name,
        }

    def type_parse_c(
        self,
        session_id: str,
        *,
        declaration: str,
        name: str | None = None,
        category: str = "/",
    ) -> dict[str, Any]:
        if not declaration:
            raise GhidraBackendError("declaration is required")
        # Composite types delegate to type_define_c which manages its own
        # transaction via _with_write.  Handle that path *outside* any
        # outer transaction so there is no nested-commit-then-rollback conflict.
        if "{" in declaration and "}" in declaration:
            parsed = self.type_define_c(
                session_id,
                declaration=declaration,
                name=name,
                category=category,
            )["type"]
            return {"session_id": session_id, "kind": "composite", "type": parsed}

        # For read-only parsing paths, open a temporary transaction that is
        # always rolled back (some Ghidra parsers mutate internal state).
        program = self._get_program(session_id)
        tx_id = int(program.startTransaction("Parse C type"))
        try:
            if "(" in declaration and ")" in declaration:
                from ghidra.app.util.cparser.C import CParserUtils

                definition = CParserUtils.parseSignature(None, program, declaration, False)
                if definition is None:
                    raise GhidraBackendError("failed to parse function declaration")
                return {
                    "session_id": session_id,
                    "kind": "function_signature",
                    "signature": definition.getPrototypeString(False),
                    "type": self._data_type_record(definition),
                }
            parsed = self._parse_data_type(session_id, declaration.strip().rstrip(";"))
            return {
                "session_id": session_id,
                "kind": "data_type",
                "type": self._data_type_record(parsed),
            }
        finally:
            program.endTransaction(tx_id, False)

    def type_apply_at(
        self,
        session_id: str,
        address: int | str,
        *,
        data_type: str,
        length: int | None = None,
        clear_existing: bool = True,
    ) -> dict[str, Any]:
        return self.data_create(
            session_id,
            address,
            data_type=data_type,
            length=length,
            clear_existing=clear_existing,
        )

    def struct_create(
        self,
        session_id: str,
        *,
        name: str,
        category: str = "/",
        length: int = 0,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        if length < 0:
            raise GhidraBackendError("length must be >= 0")
        created = None

        def mutate() -> None:
            nonlocal created
            from ghidra.program.model.data import (
                CategoryPath,
                DataTypeConflictHandler,
                StructureDataType,
            )

            dtm = self._get_program(session_id).getDataTypeManager()
            struct = StructureDataType(CategoryPath(category), name, length, dtm)
            created = dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER)

        self._with_write(session_id, f"Create struct {name}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(created)}

    def struct_field_add(
        self,
        session_id: str,
        *,
        struct_path: str | None = None,
        struct_name: str | None = None,
        field_name: str | None = None,
        data_type: str,
        offset: int | None = None,
        length: int | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        if not data_type:
            raise GhidraBackendError("data_type is required")
        struct = self._resolve_data_type(session_id, path=struct_path, name=struct_name)
        if not hasattr(struct, "getComponents") or not hasattr(struct, "add"):
            raise GhidraBackendError("target type is not a structure")
        parsed = self._parse_data_type(session_id, data_type)
        field_length = length if length is not None else int(parsed.getLength())
        if field_length <= 0:
            field_length = 1

        def mutate() -> None:
            if offset is None:
                struct.add(parsed, field_length, field_name, comment)
            else:
                struct.insertAtOffset(offset, parsed, field_length, field_name, comment)

        self._with_write(session_id, f"Add struct field {field_name or data_type}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(struct)}

    def struct_field_rename(
        self,
        session_id: str,
        *,
        struct_path: str | None = None,
        struct_name: str | None = None,
        old_name: str | None = None,
        new_name: str,
        offset: int | None = None,
        ordinal: int | None = None,
    ) -> dict[str, Any]:
        if not new_name:
            raise GhidraBackendError("new_name is required")
        struct = self._resolve_data_type(session_id, path=struct_path, name=struct_name)
        if not hasattr(struct, "getComponents"):
            raise GhidraBackendError("target type is not a structure")
        component = None
        for candidate in struct.getComponents():
            if old_name is not None and candidate.getFieldName() == old_name:
                component = candidate
                break
            if offset is not None and int(candidate.getOffset()) == offset:
                component = candidate
                break
            if ordinal is not None and int(candidate.getOrdinal()) == ordinal:
                component = candidate
                break
        if component is None:
            raise GhidraBackendError("struct field not found")

        def mutate() -> None:
            component.setFieldName(new_name)

        self._with_write(session_id, f"Rename struct field {new_name}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(struct)}

    def enum_create(
        self,
        session_id: str,
        *,
        name: str,
        category: str = "/",
        size: int = 4,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        if size <= 0:
            raise GhidraBackendError("size must be > 0")
        created = None

        def mutate() -> None:
            nonlocal created
            from ghidra.program.model.data import (
                CategoryPath,
                DataTypeConflictHandler,
                EnumDataType,
            )

            dtm = self._get_program(session_id).getDataTypeManager()
            enum_type = EnumDataType(CategoryPath(category), name, size, dtm)
            created = dtm.addDataType(enum_type, DataTypeConflictHandler.DEFAULT_HANDLER)

        self._with_write(session_id, f"Create enum {name}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(created)}

    def enum_member_add(
        self,
        session_id: str,
        *,
        enum_path: str | None = None,
        enum_name: str | None = None,
        name: str,
        value: int | str,
        comment: str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        enum_type = self._resolve_data_type(session_id, path=enum_path, name=enum_name)
        if not hasattr(enum_type, "add") or not hasattr(enum_type, "getValues"):
            raise GhidraBackendError("target type is not an enum")
        numeric_value = int(value, 0) if isinstance(value, str) else int(value)

        def mutate() -> None:
            if comment is None:
                enum_type.add(name, numeric_value)
            else:
                enum_type.add(name, numeric_value, comment)

        self._with_write(session_id, f"Add enum member {name}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(enum_type)}

    def patch_assemble(
        self,
        session_id: str,
        *,
        address: int | str,
        assembly: str,
    ) -> dict[str, Any]:
        if not assembly:
            raise GhidraBackendError("assembly is required")
        addr = self._coerce_address(session_id, address, "address")
        assembled: list[dict[str, Any]] = []

        def mutate() -> None:
            nonlocal assembled
            from ghidra.app.plugin.assembler import Assemblers

            assembler = Assemblers.getAssembler(self._get_program(session_id))
            iterator = assembler.assemble(addr, assembly)
            assembled = self._disassemble_instructions(iterator, 128)

        self._with_write(session_id, f"Assemble at {self._addr_str(addr)}", mutate)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "assembly": assembly,
            "count": len(assembled),
            "items": assembled,
        }

    def patch_nop(
        self,
        session_id: str,
        *,
        address: int | str,
        count: int = 1,
    ) -> dict[str, Any]:
        if count <= 0:
            raise GhidraBackendError("count must be > 0")
        last_error: Exception | None = None
        for mnemonic in ("NOP", "nop", "hint #0"):
            try:
                return self.patch_assemble(
                    session_id,
                    address=address,
                    assembly="\n".join(mnemonic for _ in range(count)),
                )
            except Exception as exc:
                last_error = exc
        if last_error is None:  # pragma: no cover - defensive
            raise GhidraBackendError("failed to assemble NOP")
        raise last_error

    def patch_branch_invert(self, session_id: str, *, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        instruction = self._get_program(session_id).getListing().getInstructionAt(addr)
        if instruction is None:
            raise GhidraBackendError(f"no instruction at {self._addr_str(addr)}")
        text = instruction.toString()
        mnemonic, _, operands = text.partition(" ")
        normalized = mnemonic.upper()
        inverse = {
            "JE": "JNE",
            "JZ": "JNZ",
            "JNE": "JE",
            "JNZ": "JZ",
            "JA": "JBE",
            "JBE": "JA",
            "JAE": "JB",
            "JB": "JAE",
            "JG": "JLE",
            "JLE": "JG",
            "JGE": "JL",
            "JL": "JGE",
            "JS": "JNS",
            "JNS": "JS",
            "JO": "JNO",
            "JNO": "JO",
            "JP": "JNP",
            "JPE": "JPO",
            "JPO": "JPE",
            "JNP": "JP",
            "B.EQ": "B.NE",
            "B.NE": "B.EQ",
            "B.CS": "B.CC",
            "B.HS": "B.LO",
            "B.CC": "B.CS",
            "B.LO": "B.HS",
            "B.MI": "B.PL",
            "B.PL": "B.MI",
            "B.VS": "B.VC",
            "B.VC": "B.VS",
            "B.HI": "B.LS",
            "B.LS": "B.HI",
            "B.GE": "B.LT",
            "B.LT": "B.GE",
            "B.GT": "B.LE",
            "B.LE": "B.GT",
        }.get(normalized)
        if inverse is None:
            raise GhidraBackendError(f"unsupported conditional branch mnemonic: {mnemonic}")
        if mnemonic != mnemonic.upper():
            inverse = inverse.lower()
        assembly = f"{inverse} {operands}".strip()
        payload = self.patch_assemble(session_id, address=addr, assembly=assembly)
        payload["original_instruction"] = text
        return payload

    def session_save(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        if record.active_transaction_id is not None:
            raise GhidraBackendError("commit or revert the active transaction before save")
        try:
            record.project.save(record.program)
        except Exception as exc:
            raise GhidraBackendError(f"failed to save program: {exc}") from exc
        self._finalize_open_program(record.program, record.project)
        payload = self.binary_summary(session_id)
        payload["saved"] = True
        return payload

    def session_save_as(
        self,
        session_id: str,
        *,
        program_name: str,
        folder_path: str = "/",
        overwrite: bool = True,
    ) -> dict[str, Any]:
        if not program_name:
            raise GhidraBackendError("program_name is required")
        record = self._get_record(session_id)
        if record.active_transaction_id is not None:
            raise GhidraBackendError("commit or revert the active transaction before save_as")
        try:
            record.project.saveAs(record.program, folder_path, program_name, overwrite)
        except Exception as exc:
            raise GhidraBackendError(f"failed to save program as '{program_name}': {exc}") from exc
        self._finalize_open_program(record.program, record.project)
        record.program_name = program_name
        record.program_path = (
            f"{folder_path.rstrip('/')}/{program_name}"
            if folder_path != "/"
            else f"/{program_name}"
        )
        payload = self.binary_summary(session_id)
        payload["saved_as"] = True
        return payload

    def session_export_project(self, session_id: str, *, destination: str) -> dict[str, Any]:
        if not destination:
            raise GhidraBackendError("destination is required")
        record = self._get_record(session_id)
        if record.active_transaction_id is not None:
            raise GhidraBackendError("commit or revert the active transaction before export")
        self.session_save(session_id)
        dest_root = Path(destination).resolve()
        dest_root.mkdir(parents=True, exist_ok=True)
        copied: list[str] = []
        for source in self._project_artifacts(record):
            if not source.exists():
                continue
            target = dest_root / source.name
            if source.is_dir():
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(source, target)
            else:
                shutil.copy2(source, target)
            copied.append(str(target))
        return {
            "session_id": session_id,
            "destination": str(dest_root),
            "count": len(copied),
            "items": copied,
        }

    def session_export_binary(
        self,
        session_id: str,
        *,
        path: str,
        format: str = "original_file",
    ) -> dict[str, Any]:
        if not path:
            raise GhidraBackendError("path is required")
        record = self._get_record(session_id)
        if record.active_transaction_id is not None:
            raise GhidraBackendError("commit or revert the active transaction before export")
        self._ensure_started()
        from ghidra.app.util.exporter import BinaryExporter, OriginalFileExporter
        from java.io import File
        from java.util import ArrayList

        output_path = Path(path).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if format not in {"original_file", "raw"}:
            raise GhidraBackendError("format must be 'original_file' or 'raw'")
        exporter = OriginalFileExporter() if format == "original_file" else BinaryExporter()
        exporter.setOptions(ArrayList())
        try:
            ok = exporter.export(
                File(str(output_path)),
                record.program,
                None,
                self._pyghidra.task_monitor(DEFAULT_ANALYSIS_TIMEOUT),
            )
        except Exception as exc:
            raise GhidraBackendError(f"failed to export binary: {exc}") from exc
        if not ok:
            raise GhidraBackendError("failed to export binary")
        return {
            "session_id": session_id,
            "path": str(output_path),
            "format": format,
            "size": output_path.stat().st_size,
        }

    def bookmark_add(
        self,
        session_id: str,
        *,
        address: int | str,
        category: str,
        comment: str,
        bookmark_type: str = "NOTE",
    ) -> dict[str, Any]:
        if not category:
            raise GhidraBackendError("category is required")
        addr = self._coerce_address(session_id, address, "address")
        created = None

        def mutate() -> None:
            nonlocal created
            created = (
                self._get_program(session_id)
                .getBookmarkManager()
                .setBookmark(addr, bookmark_type, category, comment)
            )

        self._with_write(session_id, f"Add bookmark {category}", mutate)
        return {"session_id": session_id, "bookmark": self._bookmark_record(created)}

    def bookmark_list(
        self,
        session_id: str,
        *,
        address: int | str | None = None,
        bookmark_type: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        manager = self._get_program(session_id).getBookmarkManager()
        if address is not None:
            addr = self._coerce_address(session_id, address, "address")
            if bookmark_type:
                bookmarks = list(manager.getBookmarks(addr, bookmark_type))
            else:
                bookmarks = list(manager.getBookmarks(addr))
        elif bookmark_type:
            bookmarks = list(manager.getBookmarksIterator(bookmark_type))
        else:
            bookmarks = list(manager.getBookmarksIterator())
        items = [self._bookmark_record(bookmark) for bookmark in bookmarks[offset : offset + limit]]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(bookmarks),
            "count": len(items),
            "items": items,
        }

    def tag_add(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        comment: str = "",
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        function = self._resolve_function(session_id, function_start)

        def mutate() -> None:
            manager = self._get_program(session_id).getFunctionManager().getFunctionTagManager()
            if manager.getFunctionTag(name) is None:
                manager.createFunctionTag(name, comment)
            if not function.addTag(name):
                raise GhidraBackendError(f"failed to add tag '{name}' to function")

        self._with_write(session_id, f"Add tag {name}", mutate)
        return self.tag_list(session_id, function_start=function.getEntryPoint())

    def tag_list(
        self,
        session_id: str,
        *,
        function_start: int | str | None = None,
    ) -> dict[str, Any]:
        if function_start is not None:
            function = self._resolve_function(session_id, function_start)
            tags = sorted(function.getTags(), key=lambda tag: tag.getName())
            return {
                "session_id": session_id,
                "function": self._function_record(function),
                "count": len(tags),
                "items": [self._function_tag_record(tag) for tag in tags],
            }
        manager = self._get_program(session_id).getFunctionManager().getFunctionTagManager()
        tags = sorted(manager.getAllFunctionTags(), key=lambda tag: tag.getName())
        return {
            "session_id": session_id,
            "count": len(tags),
            "items": [self._function_tag_record(tag) for tag in tags],
        }

    def metadata_store(self, session_id: str, *, key: str, value: Any) -> dict[str, Any]:
        if not key:
            raise GhidraBackendError("key is required")
        options = self._metadata_options(session_id)
        serialized = json.dumps(value, sort_keys=True)

        def mutate() -> None:
            with suppress(Exception):
                options.registerOption(key, "", None, "Stored by Ghidra Headless MCP")
            options.setString(key, serialized)

        self._with_write(session_id, f"Store metadata {key}", mutate)
        return {"session_id": session_id, "key": key, "value": value}

    def metadata_query(
        self,
        session_id: str,
        *,
        key: str | None = None,
        prefix: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        options = self._metadata_options(session_id)
        names = sorted(str(name) for name in options.getOptionNames())
        if key is not None:
            names = [name for name in names if name == key]
        if prefix is not None:
            names = [name for name in names if name.startswith(prefix)]
        items = []
        for name in names[offset : offset + limit]:
            raw = options.getString(name, None)
            try:
                parsed = json.loads(raw) if raw is not None else None
            except json.JSONDecodeError:
                parsed = raw
            items.append({"key": name, "value": parsed, "raw": raw})
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(names),
            "count": len(items),
            "items": items,
        }

    def analysis_analyzers_list(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
        query: str | None = None,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        options = self._analysis_options(session_id)
        names = []
        for name in sorted(str(item) for item in options.getOptionNames()):
            current = self._option_object(options, name)
            if current is None:
                continue
            if current.__class__.__name__.lower().endswith("boolean"):
                names.append(name)
        if query:
            needle = query.lower()
            names = [name for name in names if needle in name.lower()]
        items = [
            self._analysis_option_record(options, name) for name in names[offset : offset + limit]
        ]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(names),
            "count": len(items),
            "items": items,
        }

    def analysis_analyzers_set(
        self, session_id: str, *, name: str, enabled: bool
    ) -> dict[str, Any]:
        return self.analysis_options_set(session_id, name, bool(enabled))

    def analysis_clear_cache(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        cleared = False
        if record.decompiler is not None:
            with suppress(Exception):
                record.decompiler.closeProgram()
                record.decompiler.dispose()
            record.decompiler = None
            cleared = True
        return {"session_id": session_id, "decompiler_cleared": cleared}

    def memory_block_create(
        self,
        session_id: str,
        *,
        name: str,
        address: int | str,
        length: int,
        initialized: bool = True,
        fill: int = 0,
        read: bool = True,
        write: bool = False,
        execute: bool = False,
        comment: str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        if length <= 0:
            raise GhidraBackendError("length must be > 0")
        addr = self._coerce_address(session_id, address, "address")
        block = None

        def mutate() -> None:
            nonlocal block
            from jpype.types import JByte

            memory = self._get_program(session_id).getMemory()
            if initialized:
                block = memory.createInitializedBlock(
                    name,
                    addr,
                    length,
                    JByte(fill & 0xFF),
                    self._pyghidra.task_monitor(),
                    False,
                )
            else:
                block = memory.createUninitializedBlock(name, addr, length, False)
            block.setRead(read)
            block.setWrite(write)
            block.setExecute(execute)
            if comment is not None:
                block.setComment(comment)

        self._with_write(session_id, f"Create memory block {name}", mutate)
        return {
            "session_id": session_id,
            "block": {
                "name": block.getName(),
                "start": self._addr_str(block.getStart()),
                "end": self._addr_str(block.getEnd()),
                "length": int(block.getSize()),
                "read": bool(block.isRead()),
                "write": bool(block.isWrite()),
                "execute": bool(block.isExecute()),
                "comment": block.getComment(),
            },
        }

    def memory_block_remove(
        self,
        session_id: str,
        *,
        name: str | None = None,
        address: int | str | None = None,
    ) -> dict[str, Any]:
        if not name and address is None:
            raise GhidraBackendError("name or address is required")
        memory = self._get_program(session_id).getMemory()
        block = memory.getBlock(name) if name else None
        if block is None and address is not None:
            addr = self._coerce_address(session_id, address, "address")
            block = memory.getBlock(addr)
        if block is None:
            raise GhidraBackendError("memory block not found")
        payload = {
            "name": block.getName(),
            "start": self._addr_str(block.getStart()),
            "end": self._addr_str(block.getEnd()),
        }

        def mutate() -> None:
            memory.removeBlock(block, self._pyghidra.task_monitor())

        self._with_write(session_id, f"Remove memory block {block.getName()}", mutate)
        return {"session_id": session_id, "deleted": True, "block": payload}

    def external_library_list(self, session_id: str) -> dict[str, Any]:
        manager = self._get_program(session_id).getExternalManager()
        items = []
        for library_name in manager.getExternalLibraryNames():
            item = {"name": str(library_name)}
            with suppress(Exception):
                item["path"] = manager.getExternalLibraryPath(library_name)
            items.append(item)
        return {"session_id": session_id, "count": len(items), "items": items}

    def external_location_get(
        self,
        session_id: str,
        *,
        address: int | str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        symbol = None
        if address is not None:
            symbol = self._resolve_symbol(session_id, address, name=name)
        elif name is not None:
            matches = self.symbol_by_name(session_id, name, exact=True, limit=1)["items"]
            if not matches:
                raise GhidraBackendError(f"external symbol '{name}' not found")
            symbol = self._resolve_symbol(session_id, matches[0]["address"], name=name)
        else:
            raise GhidraBackendError("address or name is required")
        location = self._get_program(session_id).getExternalManager().getExternalLocation(symbol)
        if location is None:
            raise GhidraBackendError("symbol does not have an external location")
        payload = {
            "symbol": self._symbol_record(symbol),
            "display": str(location),
        }
        for attr, field_name in (
            ("getLibraryName", "library_name"),
            ("getLabel", "label"),
            ("getAddress", "address"),
            ("getOriginalImportedName", "original_imported_name"),
        ):
            with suppress(Exception):
                value = getattr(location, attr)()
                payload[field_name] = (
                    self._addr_str(value) if field_name == "address" else str(value)
                )
        return {"session_id": session_id, "location": payload}

    def decomp_tokens(
        self,
        session_id: str,
        function_start: int | str,
        *,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        results = self._decompile_results(session_id, function, timeout_secs=timeout_secs)
        payload = self._decompile_payload(session_id, function, results)
        markup = results.getCCodeMarkup()
        payload["tokens"] = self._clang_node_record(markup)
        return payload

    def decomp_ast(
        self,
        session_id: str,
        function_start: int | str,
        *,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        results = self._decompile_results(session_id, function, timeout_secs=timeout_secs)
        payload = self._decompile_payload(session_id, function, results)
        payload["ast"] = self._clang_node_record(results.getCCodeMarkup())
        return payload

    def pcode_block(self, session_id: str, *, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        block = self._code_block_containing(session_id, addr)
        instructions = self._get_program(session_id).getListing().getInstructions(block, True)
        items = [self._pcode_instruction_record(instruction) for instruction in instructions]
        return {
            "session_id": session_id,
            "block": self._code_block_record(block),
            "count": len(items),
            "items": items,
        }

    def pcode_varnode_uses(
        self,
        session_id: str,
        *,
        function_start: int | str,
        varnode: str | None = None,
        address: int | str | None = None,
        space: str | None = None,
        size: int | None = None,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        high_function = self._high_function(session_id, function, timeout_secs=timeout_secs)
        items: list[dict[str, Any]] = []
        for op in self._collect_high_pcode_ops(high_function):
            output = op.getOutput()
            if output is not None and self._varnode_matches(
                session_id, output, query=varnode, address=address, space=space, size=size
            ):
                items.append(
                    {
                        "access": "write",
                        "op": self._pcode_op_record(op),
                    }
                )
            for input_varnode in op.getInputs():
                if self._varnode_matches(
                    session_id,
                    input_varnode,
                    query=varnode,
                    address=address,
                    space=space,
                    size=size,
                ):
                    items.append(
                        {
                            "access": "read",
                            "op": self._pcode_op_record(op),
                        }
                    )
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "count": len(items),
            "items": items,
        }

    def report_program_summary(self, session_id: str) -> dict[str, Any]:
        summary = self.binary_summary(session_id)
        functions = self.binary_functions(session_id, offset=0, limit=10)
        strings = self.binary_strings(session_id, offset=0, limit=10)
        imports = self.binary_imports(session_id, offset=0, limit=10)
        blocks = self.binary_memory_blocks(session_id)
        return {
            "session_id": session_id,
            "summary": summary,
            "function_count": functions["total"],
            "string_count": self.binary_strings(session_id, offset=0, limit=1)["total"],
            "import_count": imports["total"],
            "memory_block_count": blocks["count"],
            "sample_functions": functions["items"],
            "sample_strings": strings["items"],
            "sample_imports": imports["items"],
        }

    def report_function_summary(
        self, session_id: str, *, function_start: int | str
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        signature = self.function_signature_get(session_id, function.getEntryPoint())
        variables = self.function_variables(session_id, function.getEntryPoint())
        callers = self.function_callers(session_id, function.getEntryPoint())
        callees = self.function_callees(session_id, function.getEntryPoint())
        decomp = self.decomp_function(session_id, function.getEntryPoint())
        xrefs = self.xref_to(session_id, function.getEntryPoint())
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "signature": signature,
            "variables": {
                "parameter_count": len(variables["parameters"]),
                "local_count": len(variables["locals"]),
                "parameters": variables["parameters"],
                "locals": variables["locals"],
            },
            "callers": callers["items"],
            "callees": callees["items"],
            "xref_count": xrefs["count"],
            "decompile_completed": decomp["decompile_completed"],
            "c": decomp.get("c"),
        }

    def batch_run_on_functions(
        self,
        session_id: str,
        *,
        action: str,
        query: str | None = None,
        offset: int = 0,
        limit: int = 50,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        if not action:
            raise GhidraBackendError("action is required")
        funcs = sorted(
            self._get_program(session_id).getFunctionManager().getFunctions(True),
            key=self._function_sort_key,
        )
        if query:
            needle = query.lower()
            funcs = [func for func in funcs if needle in func.getName().lower()]
        selected = funcs[offset : offset + limit]
        actions: dict[str, Callable[[Any], Any]] = {
            "decomp.function": lambda func: self.decomp_function(
                session_id, func.getEntryPoint(), timeout_secs=timeout_secs
            ),
            "disasm.function": lambda func: self.disasm_function(session_id, func.getEntryPoint()),
            "function.signature.get": lambda func: self.function_signature_get(
                session_id, func.getEntryPoint()
            ),
            "function.variables": lambda func: self.function_variables(
                session_id, func.getEntryPoint()
            ),
            "function.callers": lambda func: self.function_callers(
                session_id, func.getEntryPoint()
            ),
            "function.callees": lambda func: self.function_callees(
                session_id, func.getEntryPoint()
            ),
            "report.function_summary": lambda func: self.report_function_summary(
                session_id, function_start=func.getEntryPoint()
            ),
        }
        if action not in actions:
            raise GhidraBackendError(
                "unsupported action; use one of: " + ", ".join(sorted(actions))
            )
        items = []
        for func in selected:
            items.append(
                {
                    "function": self._function_record(func),
                    "result": actions[action](func),
                }
            )
        return {
            "session_id": session_id,
            "action": action,
            "offset": offset,
            "limit": limit,
            "total": len(funcs),
            "count": len(items),
            "items": items,
        }

    def binary_rebase(
        self,
        session_id: str,
        *,
        image_base: int | str,
        commit: bool = True,
    ) -> dict[str, Any]:
        new_base = self._coerce_address(session_id, image_base, "image_base")
        old_base = self._get_program(session_id).getImageBase()

        def mutate() -> None:
            self._get_program(session_id).setImageBase(new_base, commit)

        self._with_write(session_id, f"Rebase program to {self._addr_str(new_base)}", mutate)
        return {
            "session_id": session_id,
            "old_image_base": self._addr_str(old_base),
            "new_image_base": self._addr_str(self._get_program(session_id).getImageBase()),
            "committed": commit,
        }

    def undo_begin(
        self, session_id: str, *, description: str = "MCP Transaction"
    ) -> dict[str, Any]:
        record = self._get_record(session_id)
        self._require_writable_session(session_id)
        if record.active_transaction_id is not None:
            raise GhidraBackendError("session already has an active transaction")
        tx_id = int(record.program.startTransaction(description))
        record.active_transaction_id = tx_id
        record.active_transaction_description = description
        return self.undo_status(session_id)

    def undo_commit(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        if record.active_transaction_id is None:
            raise GhidraBackendError("session has no active transaction")
        record.program.endTransaction(record.active_transaction_id, True)
        record.active_transaction_id = None
        record.active_transaction_description = None
        return self.undo_status(session_id)

    def undo_revert(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        if record.active_transaction_id is None:
            raise GhidraBackendError("session has no active transaction")
        record.program.endTransaction(record.active_transaction_id, False)
        record.active_transaction_id = None
        record.active_transaction_description = None
        return self.undo_status(session_id)

    def undo_undo(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        if record.active_transaction_id is not None:
            raise GhidraBackendError("commit or revert the active transaction before undo")
        if not record.program.canUndo():
            raise GhidraBackendError("program cannot undo")
        record.program.undo()
        return self.undo_status(session_id)

    def undo_redo(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        if record.active_transaction_id is not None:
            raise GhidraBackendError("commit or revert the active transaction before redo")
        if not record.program.canRedo():
            raise GhidraBackendError("program cannot redo")
        record.program.redo()
        return self.undo_status(session_id)

    def undo_status(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        payload = {
            "session_id": session_id,
            "can_undo": bool(record.program.canUndo()),
            "can_redo": bool(record.program.canRedo()),
            "active_transaction": self._transaction_summary(record),
        }
        with suppress(Exception):
            payload["undo_name"] = record.program.getUndoName()
        with suppress(Exception):
            payload["redo_name"] = record.program.getRedoName()
        return payload

    def task_analysis_update(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        monitor = self._pyghidra.task_monitor(DEFAULT_ANALYSIS_TIMEOUT)
        record.last_analysis_status = "running"
        record.last_analysis_started_at = time.time()
        record.last_analysis_completed_at = None
        record.last_analysis_error = None

        def run() -> dict[str, Any]:
            try:
                log = self._analyze_program(record.program, monitor)
            except Exception as exc:
                record.last_analysis_status = "failed"
                record.last_analysis_completed_at = time.time()
                record.last_analysis_error = str(exc)
                raise GhidraBackendError(f"analysis failed: {exc}") from exc
            self._finalize_open_program(record.program, record.project)
            record.last_analysis_status = "completed"
            record.last_analysis_completed_at = time.time()
            record.last_analysis_log = log or ""
            return {
                "session_id": session_id,
                "status": record.last_analysis_status,
                "log": record.last_analysis_log,
            }

        payload = self._submit_task(
            kind="analysis.update_and_wait",
            session_id=session_id,
            func=run,
            cancel_hook=lambda: monitor.cancel(),
        )
        record.last_analysis_task_id = payload["task_id"]
        return payload

    def task_status(self, task_id: str) -> dict[str, Any]:
        task = self._get_task(task_id)
        status = self._task_state(task)
        error: str | None = None
        if status == "failed":
            exc = task.future.exception()
            if exc is not None:
                error = str(exc)
        return {
            "task_id": task_id,
            "kind": task.kind,
            "session_id": task.session_id,
            "status": status,
            "cancel_requested": task.cancel_requested,
            "cancel_supported": task.cancel_hook is not None,
            "result_ready": status in {"completed", "failed", "cancelled"},
            "error": error,
            "created_at": task.created_at,
        }

    def task_result(self, task_id: str) -> dict[str, Any]:
        task = self._get_task(task_id)
        status = self._task_state(task)
        if status not in {"completed", "failed", "cancelled"}:
            raise GhidraBackendError(f"task {task_id} is not in a terminal state (status={status})")
        payload = {
            "task_id": task_id,
            "kind": task.kind,
            "session_id": task.session_id,
            "status": status,
        }
        if task.future.cancelled():
            return payload
        exc = task.future.exception()
        if exc is not None:
            payload["error"] = str(exc)
            return payload
        payload["result"] = task.future.result()
        return payload

    def task_cancel(self, task_id: str) -> dict[str, Any]:
        task = self._get_task(task_id)
        task.cancel_requested = True
        cancelled = task.future.cancel()
        if task.cancel_hook is not None:
            with suppress(Exception):
                task.cancel_hook()
        return {
            "task_id": task_id,
            "cancel_requested": True,
            "cancelled": cancelled,
            "status": self._task_state(task),
        }

    def call_api(
        self,
        target: str,
        *,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        if not target:
            raise GhidraBackendError("target is required")
        args = args or []
        kwargs = kwargs or {}
        root, attr_path = self._resolve_call_target(target, session_id)
        obj = self._resolve_attr_path(root, attr_path)
        transitioned_session_ids: list[str] = []
        if session_id is not None and target.split(".", 1)[0] in {
            "program",
            "project",
            "flat_api",
            "decompiler",
            "ghidra",
            "java",
        }:
            transitioned_session_ids = self._transition_sessions_to_writable([session_id])
        try:
            result = obj(*args, **kwargs) if callable(obj) else obj
        except Exception as exc:
            raise GhidraBackendError(f"API call failed: {exc}") from exc
        return {
            "target": target,
            "callable": callable(obj),
            "result": self._to_jsonable(result),
            "mode_transitioned": bool(transitioned_session_ids),
            "transitioned_session_ids": transitioned_session_ids,
        }

    def eval_code(self, code: str, *, session_id: str | None = None) -> dict[str, Any]:
        if not code:
            raise GhidraBackendError("code is required")
        self._ensure_started()
        transition_candidates = [session_id] if session_id else sorted(self._sessions)
        transitioned_session_ids = self._transition_sessions_to_writable(transition_candidates)
        context = self._eval_context(session_id)
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            try:
                compiled = compile(code, "<ghidra_headless_mcp>", "eval")
            except SyntaxError:
                compiled = compile(code, "<ghidra_headless_mcp>", "exec")
                exec(compiled, context, context)
                result = context.get("_")
            else:
                result = eval(compiled, context, context)
        payload: dict[str, Any] = {"result": self._to_jsonable(result)}
        if stdout_buffer.getvalue():
            payload["stdout"] = stdout_buffer.getvalue()
        if stderr_buffer.getvalue():
            payload["stderr"] = stderr_buffer.getvalue()
        payload["mode_transitioned"] = bool(transitioned_session_ids)
        payload["transitioned_session_ids"] = transitioned_session_ids
        return payload

    def run_script(
        self,
        path: str,
        *,
        session_id: str | None = None,
        script_args: list[str] | None = None,
    ) -> dict[str, Any]:
        if not path:
            raise GhidraBackendError("path is required")
        self._ensure_started()
        if session_id is None:
            raise GhidraBackendError("session_id is required")
        record = self._get_record(session_id)
        transitioned_session_ids = self._transition_sessions_to_writable([session_id])
        try:
            stdout_text, stderr_text = self._pyghidra.ghidra_script(
                path,
                record.project.getProject(),
                record.program,
                script_args=script_args or [],
                echo_stdout=False,
                echo_stderr=False,
            )
        except Exception as exc:
            raise GhidraBackendError(f"failed to run Ghidra script: {exc}") from exc
        payload: dict[str, Any] = {
            "path": path,
            "session_id": session_id,
            "mode_transitioned": bool(transitioned_session_ids),
            "transitioned_session_ids": transitioned_session_ids,
        }
        if stdout_text:
            payload["stdout"] = stdout_text
        if stderr_text:
            payload["stderr"] = stderr_text
        return payload

    def project_folders_list(
        self,
        session_id: str,
        *,
        folder_path: str = "/",
        recursive: bool = False,
    ) -> dict[str, Any]:
        folder = self._project_folder(session_id, folder_path)
        folders = self._walk_project_folders(folder) if recursive else list(folder.getFolders())
        items = [self._domain_folder_record(item) for item in folders]
        return {
            "session_id": session_id,
            "folder_path": folder.getPathname(),
            "recursive": recursive,
            "count": len(items),
            "items": items,
        }

    def project_files_list(
        self,
        session_id: str,
        *,
        folder_path: str = "/",
        recursive: bool = False,
        content_type: str | None = None,
        query: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        folder = self._project_folder(session_id, folder_path)
        files = self._walk_project_files(folder) if recursive else list(folder.getFiles())
        if content_type:
            files = [item for item in files if str(item.getContentType()) == content_type]
        if query:
            needle = query.lower()
            files = [
                item
                for item in files
                if needle in item.getPathname().lower() or needle in item.getName().lower()
            ]
        items = [self._domain_file_record(item) for item in files[offset : offset + limit]]
        return {
            "session_id": session_id,
            "folder_path": folder.getPathname(),
            "recursive": recursive,
            "offset": offset,
            "limit": limit,
            "total": len(files),
            "count": len(items),
            "items": items,
        }

    def project_file_info(self, session_id: str, *, path: str) -> dict[str, Any]:
        if not path:
            raise GhidraBackendError("path is required")
        return {
            "session_id": session_id,
            "file": self._domain_file_record(self._project_file(session_id, path)),
        }

    def project_program_open(
        self,
        session_id: str,
        *,
        path: str,
        read_only: bool | None = None,
        update_analysis: bool = False,
    ) -> dict[str, Any]:
        if not path:
            raise GhidraBackendError("path is required")
        record = self._get_record(session_id)
        clean_path = path if path.startswith("/") else f"/{path}"
        folder_path, _, program_name = clean_path.rpartition("/")
        return self.session_open_existing(
            record.project_location,
            record.project_name,
            program_path=clean_path,
            folder_path=folder_path or "/",
            program_name=program_name,
            read_only=record.read_only if read_only is None else read_only,
            update_analysis=update_analysis,
        )

    def project_search_programs(
        self,
        session_id: str,
        *,
        query: str | None = None,
        content_type: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        effective_type = content_type or "Program"
        return self.project_files_list(
            session_id,
            folder_path="/",
            recursive=True,
            content_type=effective_type,
            query=query,
            offset=offset,
            limit=limit,
        )

    def listing_code_units_list(
        self,
        session_id: str,
        *,
        start: int | str | None = None,
        end: int | str | None = None,
        offset: int = 0,
        limit: int = 100,
        forward: bool = True,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        listing = self._get_program(session_id).getListing()
        if start is None:
            iterator = listing.getCodeUnits(self._get_program(session_id).getMemory(), forward)
        else:
            start_addr, end_addr, address_set = self._coerce_address_range(
                session_id,
                start=start,
                end=end,
                arg_name="start",
            )
            iterator = listing.getCodeUnits(address_set, forward)
        code_units = list(iterator)
        items = [self._code_unit_record(item) for item in code_units[offset : offset + limit]]
        payload = {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(code_units),
            "count": len(items),
            "items": items,
        }
        if start is not None:
            payload["start"] = self._addr_str(start_addr)
            payload["end"] = self._addr_str(end_addr)
        return payload

    def listing_code_unit_at(self, session_id: str, *, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        code_unit = self._get_program(session_id).getListing().getCodeUnitAt(addr)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "code_unit": self._code_unit_record(code_unit),
        }

    def listing_code_unit_before(self, session_id: str, *, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        code_unit = self._get_program(session_id).getListing().getCodeUnitBefore(addr)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "code_unit": self._code_unit_record(code_unit),
        }

    def listing_code_unit_after(self, session_id: str, *, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        code_unit = self._get_program(session_id).getListing().getCodeUnitAfter(addr)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "code_unit": self._code_unit_record(code_unit),
        }

    def listing_code_unit_containing(
        self,
        session_id: str,
        *,
        address: int | str,
    ) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        code_unit = self._get_program(session_id).getListing().getCodeUnitContaining(addr)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "code_unit": self._code_unit_record(code_unit),
        }

    def listing_clear(
        self,
        session_id: str,
        *,
        start: int | str,
        end: int | str | None = None,
        length: int | None = None,
        clear_context: bool = False,
        clear_symbols: bool = False,
        clear_comments: bool = False,
        clear_properties: bool = False,
        clear_functions: bool = False,
        clear_registers: bool = False,
        clear_equates: bool = False,
        clear_user_references: bool = False,
        clear_analysis_references: bool = False,
        clear_import_references: bool = False,
        clear_default_references: bool = False,
        clear_bookmarks: bool = False,
    ) -> dict[str, Any]:
        start_addr, end_addr, address_set = self._coerce_address_range(
            session_id,
            start=start,
            end=end,
            length=length,
            arg_name="start",
        )

        def mutate() -> bool:
            if clear_context:
                self._get_program(session_id).getListing().clearCodeUnits(
                    start_addr,
                    end_addr,
                    True,
                )
                return True
            return bool(
                self._get_record(session_id).flat_api.clearListing(
                    address_set,
                    True,
                    clear_symbols,
                    clear_comments,
                    clear_properties,
                    clear_functions,
                    clear_registers,
                    clear_equates,
                    clear_user_references,
                    clear_analysis_references,
                    clear_import_references,
                    clear_default_references,
                    clear_bookmarks,
                )
            )

        cleared = self._with_write(
            session_id, f"Clear listing {self._addr_str(start_addr)}", mutate
        )
        return {
            "session_id": session_id,
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "cleared": cleared,
        }

    def listing_disassemble_seed(
        self,
        session_id: str,
        *,
        address: int | str,
        limit: int = 128,
        clear_existing: bool = False,
    ) -> dict[str, Any]:
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")
        addr = self._coerce_address(session_id, address, "address")

        def mutate() -> bool:
            if clear_existing:
                self._get_program(session_id).getListing().clearCodeUnits(addr, addr, True)
            return bool(self._get_record(session_id).flat_api.disassemble(addr))

        ok = self._with_write(session_id, f"Disassemble seed {self._addr_str(addr)}", mutate)
        instructions = self._get_program(session_id).getListing().getInstructions(addr, True)
        items = self._disassemble_instructions(instructions, limit)
        return {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "disassembled": ok,
            "count": len(items),
            "items": items,
        }

    def context_get(
        self,
        session_id: str,
        *,
        register: str,
        address: int | str,
        signed: bool = False,
    ) -> dict[str, Any]:
        reg = self._resolve_register(session_id, register)
        addr = self._coerce_address(session_id, address, "address")
        value = self._get_program(session_id).getProgramContext().getValue(reg, addr, signed)
        return {
            "session_id": session_id,
            "register": reg.getName(),
            "address": self._addr_str(addr),
            "signed": signed,
            "value": None if value is None else int(str(value), 10),
        }

    def context_set(
        self,
        session_id: str,
        *,
        register: str,
        start: int | str,
        end: int | str | None = None,
        length: int | None = None,
        value: int | str | None = None,
        clear: bool = False,
    ) -> dict[str, Any]:
        reg = self._resolve_register(session_id, register)
        start_addr, end_addr, _ = self._coerce_address_range(
            session_id,
            start=start,
            end=end,
            length=length,
            arg_name="start",
        )

        def mutate() -> None:
            from java.math import BigInteger

            context = self._get_program(session_id).getProgramContext()
            if clear:
                context.remove(start_addr, end_addr, reg)
                return
            if value is None:
                raise GhidraBackendError("value is required unless clear=true")
            numeric = int(value, 0) if isinstance(value, str) else int(value)
            context.setValue(reg, start_addr, end_addr, BigInteger.valueOf(numeric))

        self._with_write(session_id, f"Set context {reg.getName()}", mutate)
        return {
            "session_id": session_id,
            "register": reg.getName(),
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "cleared": clear,
        }

    def context_ranges(
        self,
        session_id: str,
        *,
        register: str,
        start: int | str | None = None,
        end: int | str | None = None,
    ) -> dict[str, Any]:
        reg = self._resolve_register(session_id, register)
        context = self._get_program(session_id).getProgramContext()
        if start is None:
            ranges = list(context.getRegisterValueAddressRanges(reg))
        else:
            start_addr, end_addr, _ = self._coerce_address_range(
                session_id,
                start=start,
                end=end,
                arg_name="start",
            )
            ranges = list(context.getRegisterValueAddressRanges(reg, start_addr, end_addr))
        items = [
            {
                "start": self._addr_str(item.getMinAddress()),
                "end": self._addr_str(item.getMaxAddress()),
            }
            for item in ranges
        ]
        return {
            "session_id": session_id,
            "register": reg.getName(),
            "count": len(items),
            "items": items,
        }

    def symbol_primary_set(
        self,
        session_id: str,
        *,
        address: int | str,
        name: str | None = None,
    ) -> dict[str, Any]:
        symbol = self._resolve_symbol(session_id, address, name=name)

        def mutate() -> None:
            symbol.setPrimary()

        self._with_write(session_id, f"Set primary symbol {symbol.getName(True)}", mutate)
        return {"session_id": session_id, "symbol": self._symbol_record(symbol)}

    def namespace_create(
        self,
        session_id: str,
        *,
        name: str,
        parent: str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        created = None

        def mutate() -> None:
            nonlocal created
            created = self._get_record(session_id).flat_api.createNamespace(
                self._resolve_namespace(session_id, parent),
                name,
            )

        self._with_write(session_id, f"Create namespace {name}", mutate)
        return {"session_id": session_id, "namespace": self._namespace_record(created)}

    def class_create(
        self,
        session_id: str,
        *,
        name: str,
        parent: str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        created = None

        def mutate() -> None:
            nonlocal created
            created = self._get_record(session_id).flat_api.createClass(
                self._resolve_namespace(session_id, parent),
                name,
            )

        self._with_write(session_id, f"Create class {name}", mutate)
        return {"session_id": session_id, "namespace": self._namespace_record(created)}

    def symbol_namespace_move(
        self,
        session_id: str,
        *,
        address: int | str,
        namespace: str,
        name: str | None = None,
    ) -> dict[str, Any]:
        symbol = self._resolve_symbol(session_id, address, name=name)
        target = self._resolve_namespace(session_id, namespace)

        def mutate() -> None:
            symbol.setNamespace(target)

        self._with_write(session_id, f"Move symbol {symbol.getName(True)}", mutate)
        return {"session_id": session_id, "symbol": self._symbol_record(symbol)}

    def external_library_create(self, session_id: str, *, name: str) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        created = None

        def mutate() -> None:
            nonlocal created
            from ghidra.program.model.symbol import SourceType

            created = (
                self._get_program(session_id)
                .getSymbolTable()
                .createExternalLibrary(
                    name,
                    SourceType.USER_DEFINED,
                )
            )

        self._with_write(session_id, f"Create external library {name}", mutate)
        return {"session_id": session_id, "library": self._namespace_record(created)}

    def external_library_set_path(
        self,
        session_id: str,
        *,
        name: str,
        path: str | None,
        user_defined: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")

        def mutate() -> None:
            self._get_program(session_id).getExternalManager().setExternalPath(
                name,
                path,
                bool(user_defined),
            )

        self._with_write(session_id, f"Set external path {name}", mutate)
        return self.external_library_list(session_id)

    def external_location_create(
        self,
        session_id: str,
        *,
        library_name: str,
        label: str | None = None,
        external_address: int | str | None = None,
    ) -> dict[str, Any]:
        manager = self._get_program(session_id).getExternalManager()
        location = None

        def mutate() -> None:
            nonlocal location
            from ghidra.program.model.symbol import SourceType

            addr = (
                self._coerce_address(session_id, external_address, "external_address")
                if external_address is not None
                else None
            )
            location = manager.addExtLocation(library_name, label, addr, SourceType.USER_DEFINED)

        self._with_write(session_id, f"Create external location {library_name}", mutate)
        return {"session_id": session_id, "location": self._external_location_record(location)}

    def external_function_create(
        self,
        session_id: str,
        *,
        library_name: str,
        name: str,
        external_address: int | str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        manager = self._get_program(session_id).getExternalManager()
        location = None

        def mutate() -> None:
            nonlocal location
            from ghidra.program.model.symbol import SourceType

            addr = (
                self._coerce_address(session_id, external_address, "external_address")
                if external_address is not None
                else None
            )
            location = manager.addExtFunction(library_name, name, addr, SourceType.USER_DEFINED)

        self._with_write(session_id, f"Create external function {name}", mutate)
        return {"session_id": session_id, "location": self._external_location_record(location)}

    def external_entrypoint_add(self, session_id: str, *, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")

        def mutate() -> None:
            self._get_program(session_id).getSymbolTable().addExternalEntryPoint(addr)

        self._with_write(session_id, f"Add external entrypoint {self._addr_str(addr)}", mutate)
        return self.external_entrypoint_list(session_id)

    def external_entrypoint_remove(self, session_id: str, *, address: int | str) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")

        def mutate() -> None:
            self._get_program(session_id).getSymbolTable().removeExternalEntryPoint(addr)

        self._with_write(session_id, f"Remove external entrypoint {self._addr_str(addr)}", mutate)
        return self.external_entrypoint_list(session_id)

    def external_entrypoint_list(self, session_id: str) -> dict[str, Any]:
        items = [
            self._addr_str(addr)
            for addr in self._get_program(session_id)
            .getSymbolTable()
            .getExternalEntryPointIterator()
        ]
        return {"session_id": session_id, "count": len(items), "items": items}

    def reference_create_memory(
        self,
        session_id: str,
        *,
        from_address: int | str,
        to_address: int | str,
        reference_type: str = "DATA",
        operand_index: int = 0,
        source_type: str = "USER_DEFINED",
    ) -> dict[str, Any]:
        created = None
        from_addr = self._coerce_address(session_id, from_address, "from_address")
        to_addr = self._coerce_address(session_id, to_address, "to_address")

        def mutate() -> None:
            nonlocal created
            created = (
                self._get_program(session_id)
                .getReferenceManager()
                .addMemoryReference(
                    from_addr,
                    to_addr,
                    self._ref_type(reference_type),
                    self._source_type(source_type),
                    operand_index,
                )
            )

        self._with_write(session_id, f"Add memory reference {self._addr_str(from_addr)}", mutate)
        return {"session_id": session_id, "reference": self._reference_record(created)}

    def reference_create_stack(
        self,
        session_id: str,
        *,
        from_address: int | str,
        stack_offset: int,
        reference_type: str = "DATA",
        operand_index: int = 0,
        source_type: str = "USER_DEFINED",
    ) -> dict[str, Any]:
        created = None
        from_addr = self._coerce_address(session_id, from_address, "from_address")

        def mutate() -> None:
            nonlocal created
            created = (
                self._get_program(session_id)
                .getReferenceManager()
                .addStackReference(
                    from_addr,
                    operand_index,
                    int(stack_offset),
                    self._ref_type(reference_type),
                    self._source_type(source_type),
                )
            )

        self._with_write(session_id, f"Add stack reference {self._addr_str(from_addr)}", mutate)
        return {"session_id": session_id, "reference": self._reference_record(created)}

    def reference_create_register(
        self,
        session_id: str,
        *,
        from_address: int | str,
        register: str,
        reference_type: str = "DATA",
        operand_index: int = 0,
        source_type: str = "USER_DEFINED",
    ) -> dict[str, Any]:
        created = None
        from_addr = self._coerce_address(session_id, from_address, "from_address")
        reg = self._resolve_register(session_id, register)

        def mutate() -> None:
            nonlocal created
            created = (
                self._get_program(session_id)
                .getReferenceManager()
                .addRegisterReference(
                    from_addr,
                    operand_index,
                    reg,
                    self._ref_type(reference_type),
                    self._source_type(source_type),
                )
            )

        self._with_write(session_id, f"Add register reference {self._addr_str(from_addr)}", mutate)
        return {"session_id": session_id, "reference": self._reference_record(created)}

    def reference_create_external(
        self,
        session_id: str,
        *,
        from_address: int | str,
        library_name: str,
        label: str | None = None,
        external_address: int | str | None = None,
        reference_type: str = "DATA",
        operand_index: int = 0,
        source_type: str = "USER_DEFINED",
    ) -> dict[str, Any]:
        created = None
        from_addr = self._coerce_address(session_id, from_address, "from_address")

        def mutate() -> None:
            nonlocal created
            addr = (
                self._coerce_address(session_id, external_address, "external_address")
                if external_address is not None
                else None
            )
            created = (
                self._get_program(session_id)
                .getReferenceManager()
                .addExternalReference(
                    from_addr,
                    library_name,
                    label,
                    addr,
                    self._source_type(source_type),
                    operand_index,
                    self._ref_type(reference_type),
                )
            )

        self._with_write(session_id, f"Add external reference {self._addr_str(from_addr)}", mutate)
        return {"session_id": session_id, "reference": self._reference_record(created)}

    def reference_delete(
        self,
        session_id: str,
        *,
        from_address: int | str,
        to_address: int | str | None = None,
        operand_index: int | None = None,
    ) -> dict[str, Any]:
        reference = self._resolve_reference(
            session_id,
            from_address=from_address,
            to_address=to_address,
            operand_index=operand_index,
        )

        def mutate() -> None:
            self._get_program(session_id).getReferenceManager().delete(reference)

        self._with_write(
            session_id, f"Delete reference {self._addr_str(reference.getFromAddress())}", mutate
        )
        return {"session_id": session_id, "deleted": True}

    def reference_clear_from(
        self,
        session_id: str,
        *,
        from_address: int | str,
        end_address: int | str | None = None,
    ) -> dict[str, Any]:
        from_addr = self._coerce_address(session_id, from_address, "from_address")

        def mutate() -> None:
            manager = self._get_program(session_id).getReferenceManager()
            if end_address is None:
                manager.removeAllReferencesFrom(from_addr)
                return
            manager.removeAllReferencesFrom(
                from_addr,
                self._coerce_address(session_id, end_address, "end_address"),
            )

        self._with_write(session_id, f"Clear references from {self._addr_str(from_addr)}", mutate)
        return {"session_id": session_id, "cleared": True}

    def reference_clear_to(self, session_id: str, *, to_address: int | str) -> dict[str, Any]:
        to_addr = self._coerce_address(session_id, to_address, "to_address")

        def mutate() -> None:
            self._get_program(session_id).getReferenceManager().removeAllReferencesTo(to_addr)

        self._with_write(session_id, f"Clear references to {self._addr_str(to_addr)}", mutate)
        return {"session_id": session_id, "cleared": True}

    def reference_primary_set(
        self,
        session_id: str,
        *,
        from_address: int | str,
        to_address: int | str,
        operand_index: int = 0,
    ) -> dict[str, Any]:
        reference = self._resolve_reference(
            session_id,
            from_address=from_address,
            to_address=to_address,
            operand_index=operand_index,
        )

        def mutate() -> None:
            self._get_program(session_id).getReferenceManager().setPrimary(reference, True)

        self._with_write(
            session_id,
            f"Set primary reference {self._addr_str(reference.getFromAddress())}",
            mutate,
        )
        return {"session_id": session_id, "reference": self._reference_record(reference)}

    def reference_association_set(
        self,
        session_id: str,
        *,
        from_address: int | str,
        to_address: int | str,
        operand_index: int = 0,
        symbol_address: int | str,
        symbol_name: str | None = None,
    ) -> dict[str, Any]:
        reference = self._resolve_reference(
            session_id,
            from_address=from_address,
            to_address=to_address,
            operand_index=operand_index,
        )
        symbol = self._resolve_symbol(session_id, symbol_address, name=symbol_name)

        def mutate() -> None:
            self._get_program(session_id).getReferenceManager().setAssociation(symbol, reference)

        self._with_write(
            session_id, f"Associate reference {self._addr_str(reference.getFromAddress())}", mutate
        )
        return {
            "session_id": session_id,
            "reference": self._reference_record(reference),
            "symbol": self._symbol_record(symbol),
        }

    def reference_association_remove(
        self,
        session_id: str,
        *,
        from_address: int | str,
        to_address: int | str,
        operand_index: int = 0,
    ) -> dict[str, Any]:
        reference = self._resolve_reference(
            session_id,
            from_address=from_address,
            to_address=to_address,
            operand_index=operand_index,
        )

        def mutate() -> None:
            self._get_program(session_id).getReferenceManager().removeAssociation(reference)

        self._with_write(
            session_id,
            f"Remove reference association {self._addr_str(reference.getFromAddress())}",
            mutate,
        )
        return {"session_id": session_id, "reference": self._reference_record(reference)}

    def equate_create(
        self,
        session_id: str,
        *,
        address: int | str,
        name: str,
        value: int | str,
        operand_index: int = 0,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        addr = self._coerce_address(session_id, address, "address")
        numeric = int(value, 0) if isinstance(value, str) else int(value)
        equate = None

        def mutate() -> None:
            nonlocal equate
            table = self._get_program(session_id).getEquateTable()
            equate = table.getEquate(name)
            if equate is None:
                equate = table.createEquate(name, numeric)
            equate.addReference(addr, operand_index)

        self._with_write(session_id, f"Create equate {name}", mutate)
        return {"session_id": session_id, "equate": self._equate_record(equate)}

    def equate_list(
        self,
        session_id: str,
        *,
        name: str | None = None,
        address: int | str | None = None,
        operand_index: int | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        table = self._get_program(session_id).getEquateTable()
        if name is not None:
            equates = [] if table.getEquate(name) is None else [table.getEquate(name)]
        elif address is not None:
            addr = self._coerce_address(session_id, address, "address")
            equates = (
                list(table.getEquates(addr))
                if operand_index is None
                else list(table.getEquates(addr, operand_index))
            )
        else:
            equates = list(table.getEquates())
        items = [self._equate_record(item) for item in equates[offset : offset + limit]]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(equates),
            "count": len(items),
            "items": items,
        }

    def equate_delete(
        self,
        session_id: str,
        *,
        name: str,
        address: int | str | None = None,
        operand_index: int | None = None,
    ) -> dict[str, Any]:
        table = self._get_program(session_id).getEquateTable()
        equate = table.getEquate(name)
        if equate is None:
            raise GhidraBackendError(f"equate not found: {name}")

        def mutate() -> None:
            if address is not None:
                addr = self._coerce_address(session_id, address, "address")
                if operand_index is None:
                    for ref in list(equate.getReferences(addr)):
                        equate.removeReference(ref.getAddress(), ref.getOpIndex())
                else:
                    equate.removeReference(addr, operand_index)
            if address is None or equate.getReferenceCount() == 0:
                table.removeEquate(name)

        self._with_write(session_id, f"Delete equate {name}", mutate)
        return {"session_id": session_id, "deleted": True, "name": name}

    def equate_clear_range(
        self,
        session_id: str,
        *,
        start: int | str,
        end: int | str | None = None,
        length: int | None = None,
    ) -> dict[str, Any]:
        start_addr, end_addr, _ = self._coerce_address_range(
            session_id,
            start=start,
            end=end,
            length=length,
            arg_name="start",
        )

        def mutate() -> int:
            removed = 0
            table = self._get_program(session_id).getEquateTable()
            for equate in list(table.getEquates()):
                for ref in list(equate.getReferences()):
                    ref_addr = ref.getAddress()
                    if ref_addr.compareTo(start_addr) < 0 or ref_addr.compareTo(end_addr) > 0:
                        continue
                    equate.removeReference(ref_addr, ref.getOpIndex())
                    removed += 1
                if equate.getReferenceCount() == 0:
                    table.removeEquate(equate.getName())
            return removed

        removed = self._with_write(
            session_id, f"Clear equates {self._addr_str(start_addr)}", mutate
        )
        return {
            "session_id": session_id,
            "start": self._addr_str(start_addr),
            "end": self._addr_str(end_addr),
            "removed": removed,
        }

    def comment_get_all(
        self,
        session_id: str,
        *,
        address: int | str,
        include_function: bool = True,
    ) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")
        comments = {
            name: self.annotation_comment_get(session_id, address=addr, comment_type=name)[
                "comment"
            ]
            for name in ("plate", "pre", "eol", "post", "repeatable")
        }
        payload: dict[str, Any] = {
            "session_id": session_id,
            "address": self._addr_str(addr),
            "comments": comments,
        }
        if include_function:
            with suppress(GhidraBackendError):
                function = self._resolve_function(session_id, addr)
                payload["function"] = {
                    "entry_point": self._addr_str(function.getEntryPoint()),
                    "comment": function.getComment(),
                    "repeatable_comment": function.getRepeatableComment(),
                }
        return payload

    def comment_list(
        self,
        session_id: str,
        *,
        start: int | str | None = None,
        end: int | str | None = None,
        comment_type: str | None = None,
        query: str | None = None,
        case_sensitive: bool = False,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        program = self._get_program(session_id)
        listing = program.getListing()
        if start is None:
            address_set = program.getMemory().getAllInitializedAddressSet()
        else:
            _, _, address_set = self._coerce_address_range(
                session_id,
                start=start,
                end=end,
                arg_name="start",
            )
        if comment_type is None:
            iterator = listing.getCommentAddressIterator(address_set, True)
        else:
            iterator = listing.getCommentAddressIterator(
                self._comment_type(comment_type),
                address_set,
                True,
            )
        addresses = list(iterator)
        if query:
            needle = query if case_sensitive else query.lower()
            matched: list[dict[str, Any]] = []
            for addr in addresses:
                payload = self.comment_get_all(session_id, address=addr, include_function=False)
                comments = [value for value in payload["comments"].values() if value]
                if not any(
                    needle in (comment if case_sensitive else comment.lower())
                    for comment in comments
                ):
                    continue
                matched.append(payload)
            total = len(matched)
            items = matched[offset : offset + limit]
        else:
            total = len(addresses)
            items = [
                self.comment_get_all(session_id, address=addr, include_function=False)
                for addr in addresses[offset : offset + limit]
            ]
        return {
            "session_id": session_id,
            "query": query,
            "case_sensitive": case_sensitive,
            "offset": offset,
            "limit": limit,
            "total": total,
            "count": len(items),
            "items": items,
        }

    def bookmark_remove(
        self,
        session_id: str,
        *,
        address: int | str,
        bookmark_type: str | None = None,
        category: str | None = None,
    ) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")

        def mutate() -> int:
            manager = self._get_program(session_id).getBookmarkManager()
            bookmarks = (
                list(manager.getBookmarks(addr, bookmark_type))
                if bookmark_type
                else list(manager.getBookmarks(addr))
            )
            removed = 0
            for bookmark in bookmarks:
                if category is not None and bookmark.getCategory() != category:
                    continue
                manager.removeBookmark(bookmark)
                removed += 1
            return removed

        removed = self._with_write(session_id, f"Remove bookmarks {self._addr_str(addr)}", mutate)
        return {"session_id": session_id, "removed": removed}

    def bookmark_clear(
        self,
        session_id: str,
        *,
        start: int | str,
        end: int | str | None = None,
        length: int | None = None,
        bookmark_type: str | None = None,
    ) -> dict[str, Any]:
        start_addr, end_addr, _ = self._coerce_address_range(
            session_id,
            start=start,
            end=end,
            length=length,
            arg_name="start",
        )

        def mutate() -> int:
            manager = self._get_program(session_id).getBookmarkManager()
            removed = 0
            iterator = (
                manager.getBookmarksIterator(bookmark_type)
                if bookmark_type
                else manager.getBookmarksIterator()
            )
            for bookmark in list(iterator):
                addr = bookmark.getAddress()
                if addr.compareTo(start_addr) < 0 or addr.compareTo(end_addr) > 0:
                    continue
                manager.removeBookmark(bookmark)
                removed += 1
            return removed

        removed = self._with_write(
            session_id, f"Clear bookmarks {self._addr_str(start_addr)}", mutate
        )
        return {"session_id": session_id, "removed": removed}

    def tag_remove(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        tag = None
        for candidate in function.getTags():
            if candidate.getName() == name:
                tag = candidate
                break
        if tag is None:
            raise GhidraBackendError(f"tag '{name}' not found")

        def mutate() -> None:
            function.removeTag(name)

        self._with_write(session_id, f"Remove tag {name}", mutate)
        return self.tag_list(session_id, function_start=function.getEntryPoint())

    def tag_stats(self, session_id: str) -> dict[str, Any]:
        manager = self._get_program(session_id).getFunctionManager().getFunctionTagManager()
        functions = list(self._get_program(session_id).getFunctionManager().getFunctions(True))
        items = []
        for tag in sorted(manager.getAllFunctionTags(), key=lambda item: item.getName()):
            count = sum(1 for func in functions if tag in func.getTags())
            items.append({"tag": self._function_tag_record(tag), "function_count": count})
        return {"session_id": session_id, "count": len(items), "items": items}

    def source_file_list(self, session_id: str) -> dict[str, Any]:
        manager = self._get_program(session_id).getSourceFileManager()
        items = [self._source_file_record(item) for item in manager.getAllSourceFiles()]
        return {"session_id": session_id, "count": len(items), "items": items}

    def source_file_add(
        self,
        session_id: str,
        *,
        path: str,
        id_type: str | None = None,
        identifier_hex: str | None = None,
    ) -> dict[str, Any]:
        source_file = self._source_file_from_args(
            path=path, id_type=id_type, identifier_hex=identifier_hex
        )

        def mutate() -> None:
            self._get_program(session_id).getSourceFileManager().addSourceFile(source_file)

        self._with_write(session_id, f"Add source file {path}", mutate)
        return self.source_file_list(session_id)

    def source_file_remove(
        self,
        session_id: str,
        *,
        path: str,
    ) -> dict[str, Any]:
        manager = self._get_program(session_id).getSourceFileManager()
        source_file = self._find_source_file(manager, path)

        def mutate() -> None:
            manager.removeSourceFile(source_file)

        self._with_write(session_id, f"Remove source file {path}", mutate)
        return self.source_file_list(session_id)

    def source_map_list(
        self,
        session_id: str,
        *,
        address: int | str | None = None,
        path: str | None = None,
        min_line: int | None = None,
        max_line: int | None = None,
    ) -> dict[str, Any]:
        manager = self._get_program(session_id).getSourceFileManager()
        if address is not None:
            addr = self._coerce_address(session_id, address, "address")
            entries = list(manager.getSourceMapEntries(addr))
        elif path is not None:
            source_file = self._find_source_file(manager, path)
            entries = list(
                manager.getSourceMapEntries(source_file, min_line or 0, max_line or 2**31 - 1)
            )
        else:
            entries = []
            for source_file in manager.getMappedSourceFiles():
                entries.extend(
                    list(
                        manager.getSourceMapEntries(
                            source_file, min_line or 0, max_line or 2**31 - 1
                        )
                    )
                )
        items = [self._source_map_entry_record(item) for item in entries]
        return {"session_id": session_id, "count": len(items), "items": items}

    def source_map_add(
        self,
        session_id: str,
        *,
        path: str,
        line_number: int,
        base_address: int | str,
        length: int,
    ) -> dict[str, Any]:
        if line_number <= 0:
            raise GhidraBackendError("line_number must be > 0")
        if length <= 0:
            raise GhidraBackendError("length must be > 0")
        manager = self._get_program(session_id).getSourceFileManager()
        source_file = self._find_source_file(manager, path)
        base_addr = self._coerce_address(session_id, base_address, "base_address")

        def mutate() -> None:
            manager.addSourceMapEntry(source_file, line_number, base_addr, length)

        self._with_write(session_id, f"Add source map {path}", mutate)
        return self.source_map_list(session_id, path=path)

    def source_map_remove(
        self,
        session_id: str,
        *,
        path: str,
        line_number: int,
        base_address: int | str,
    ) -> dict[str, Any]:
        manager = self._get_program(session_id).getSourceFileManager()
        source_file = self._find_source_file(manager, path)
        base_addr = self._coerce_address(session_id, base_address, "base_address")
        entry = None
        for candidate in manager.getSourceMapEntries(source_file, line_number, line_number):
            if str(candidate.getBaseAddress()) == self._addr_str(base_addr):
                entry = candidate
                break
        if entry is None:
            raise GhidraBackendError("source map entry not found")

        def mutate() -> None:
            manager.removeSourceMapEntry(entry)

        self._with_write(session_id, f"Remove source map {path}", mutate)
        return self.source_map_list(session_id, path=path)

    def relocation_list(
        self,
        session_id: str,
        *,
        start: int | str | None = None,
        end: int | str | None = None,
    ) -> dict[str, Any]:
        table = self._get_program(session_id).getRelocationTable()
        if start is None:
            relocations = list(table.getRelocations())
        else:
            _, _, address_set = self._coerce_address_range(
                session_id,
                start=start,
                end=end,
                arg_name="start",
            )
            relocations = list(table.getRelocations(address_set))
        items = [self._relocation_record(item) for item in relocations]
        return {"session_id": session_id, "count": len(items), "items": items}

    def relocation_add(
        self,
        session_id: str,
        *,
        address: int | str,
        status: str = "APPLIED",
        type: int = 0,
        values: list[int] | None = None,
        byte_length: int = 0,
        symbol_name: str | None = None,
    ) -> dict[str, Any]:
        addr = self._coerce_address(session_id, address, "address")

        def mutate() -> None:
            from ghidra.program.model.reloc import Relocation
            from jpype.types import JArray, JLong

            relocation_status = getattr(Relocation.Status, status)
            self._get_program(session_id).getRelocationTable().add(
                addr,
                relocation_status,
                int(type),
                JArray(JLong)(values or []),
                int(byte_length),
                symbol_name,
            )

        self._with_write(session_id, f"Add relocation {self._addr_str(addr)}", mutate)
        return self.relocation_list(session_id, start=addr, end=addr)

    def function_body_set(
        self,
        session_id: str,
        *,
        function_start: int | str,
        start: int | str,
        end: int | str | None = None,
        length: int | None = None,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        _start_addr, _end_addr, address_set = self._coerce_address_range(
            session_id,
            start=start,
            end=end,
            length=length,
            arg_name="start",
        )

        def mutate() -> None:
            function.setBody(address_set)

        self._with_write(session_id, f"Set body for {function.getName()}", mutate)
        return {"session_id": session_id, "function": self._function_record(function)}

    def function_calling_conventions_list(self, session_id: str) -> dict[str, Any]:
        compiler_spec = self._get_program(session_id).getCompilerSpec()
        items = [str(name) for name in compiler_spec.getCallingConventions()]
        return {"session_id": session_id, "count": len(items), "items": sorted(items)}

    def function_calling_convention_set(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)

        def mutate() -> None:
            function.setCallingConvention(name)

        self._with_write(session_id, f"Set calling convention {function.getName()}", mutate)
        return self.function_signature_get(session_id, function.getEntryPoint())

    def function_flags_set(
        self,
        session_id: str,
        *,
        function_start: int | str,
        varargs: bool | None = None,
        inline: bool | None = None,
        noreturn: bool | None = None,
        custom_storage: bool | None = None,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)

        def mutate() -> None:
            if varargs is not None:
                function.setVarArgs(bool(varargs))
            if inline is not None:
                function.setInline(bool(inline))
            if noreturn is not None:
                function.setNoReturn(bool(noreturn))
            if custom_storage is not None:
                function.setCustomVariableStorage(bool(custom_storage))

        self._with_write(session_id, f"Set flags {function.getName()}", mutate)
        return {"session_id": session_id, "function": self._function_record(function)}

    def function_thunk_set(
        self,
        session_id: str,
        *,
        function_start: int | str,
        thunk_target: int | str,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        target = self._resolve_function(session_id, thunk_target)

        def mutate() -> None:
            function.setThunkedFunction(target)

        self._with_write(session_id, f"Set thunk {function.getName()}", mutate)
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "target": self._function_record(target),
        }

    def parameter_add(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        data_type: str,
        ordinal: int | None = None,
        stack_offset: int | None = None,
        register: str | None = None,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        params = self._clone_parameters(function)
        param = self._parameter_from_spec(
            session_id,
            name=name,
            data_type=data_type,
            stack_offset=stack_offset,
            register=register,
        )
        index = len(params) if ordinal is None else max(0, min(len(params), ordinal))
        params.insert(index, param)
        self._write_parameters(session_id, function, params)
        return self.function_variables(session_id, function.getEntryPoint())

    def parameter_remove(
        self,
        session_id: str,
        *,
        function_start: int | str,
        ordinal: int | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        params = self._clone_parameters(function)
        index = self._parameter_index(params, ordinal=ordinal, name=name)
        del params[index]
        self._write_parameters(session_id, function, params)
        return self.function_variables(session_id, function.getEntryPoint())

    def parameter_move(
        self,
        session_id: str,
        *,
        function_start: int | str,
        ordinal: int,
        new_ordinal: int,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        params = self._clone_parameters(function)
        index = self._parameter_index(params, ordinal=ordinal, name=None)
        param = params.pop(index)
        params.insert(max(0, min(len(params), new_ordinal)), param)
        self._write_parameters(session_id, function, params)
        return self.function_variables(session_id, function.getEntryPoint())

    def parameter_replace(
        self,
        session_id: str,
        *,
        function_start: int | str,
        ordinal: int | None = None,
        name: str | None = None,
        new_name: str | None = None,
        data_type: str | None = None,
        stack_offset: int | None = None,
        register: str | None = None,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        params = self._clone_parameters(function)
        index = self._parameter_index(params, ordinal=ordinal, name=name)
        current = params[index]
        params[index] = self._parameter_from_spec(
            session_id,
            name=new_name or current.getName(),
            data_type=data_type or current.getDataType().getPathName(),
            stack_offset=stack_offset,
            register=register,
            fallback=current,
        )
        self._write_parameters(session_id, function, params)
        return self.function_variables(session_id, function.getEntryPoint())

    def variable_local_create(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        data_type: str,
        first_use_offset: int = 0,
        stack_offset: int | None = None,
        register: str | None = None,
        storage_address: int | str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        function = self._resolve_function(session_id, function_start)
        local = None
        parsed = self._parse_data_type(session_id, data_type)

        def mutate() -> None:
            nonlocal local
            import jpype
            from ghidra.program.model.address import Address
            from ghidra.program.model.listing import LocalVariableImpl
            from ghidra.program.model.symbol import SourceType

            program = self._get_program(session_id)
            if register is not None:
                local = LocalVariableImpl(
                    name,
                    int(first_use_offset),
                    parsed,
                    self._resolve_register(session_id, register),
                    program,
                    SourceType.USER_DEFINED,
                )
            elif storage_address is not None:
                local = LocalVariableImpl(
                    name,
                    int(first_use_offset),
                    parsed,
                    self._coerce_address(session_id, storage_address, "storage_address"),
                    program,
                    SourceType.USER_DEFINED,
                )
            elif stack_offset is not None:
                local = LocalVariableImpl(
                    name,
                    parsed,
                    int(stack_offset),
                    program,
                    SourceType.USER_DEFINED,
                )
            else:
                local = LocalVariableImpl(
                    name,
                    int(first_use_offset),
                    parsed,
                    jpype.JObject(None, Address),
                    program,
                    SourceType.USER_DEFINED,
                )
            local = function.addLocalVariable(local, SourceType.USER_DEFINED)
            if comment is not None:
                local.setComment(comment)

        self._with_write(session_id, f"Create local {name}", mutate)
        return self.function_variables(session_id, function.getEntryPoint())

    def variable_local_remove(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        storage: str | None = None,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        variable = self._resolve_variable(function, name=name, ordinal=None, storage=storage)
        if variable in function.getParameters():
            raise GhidraBackendError("selected variable is a parameter")

        def mutate() -> None:
            function.removeVariable(variable)

        self._with_write(session_id, f"Remove local {name}", mutate)
        return self.function_variables(session_id, function.getEntryPoint())

    def variable_comment_set(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        comment: str | None,
        ordinal: int | None = None,
        storage: str | None = None,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        variable = self._resolve_variable(function, name=name, ordinal=ordinal, storage=storage)

        def mutate() -> None:
            variable.setComment(comment)

        self._with_write(session_id, f"Set variable comment {name}", mutate)
        return self.function_variables(session_id, function.getEntryPoint())

    def stackframe_variable_create(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        stack_offset: int,
        data_type: str,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        created = None
        parsed = self._parse_data_type(session_id, data_type)

        def mutate() -> None:
            nonlocal created
            from ghidra.program.model.symbol import SourceType

            created = function.getStackFrame().createVariable(
                name,
                int(stack_offset),
                parsed,
                SourceType.USER_DEFINED,
            )

        self._with_write(session_id, f"Create stackframe variable {name}", mutate)
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "variable": self._variable_record(created),
        }

    def stackframe_variable_clear(
        self,
        session_id: str,
        *,
        function_start: int | str,
        stack_offset: int,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)

        def mutate() -> None:
            function.getStackFrame().clearVariable(int(stack_offset))

        self._with_write(session_id, f"Clear stackframe variable {stack_offset}", mutate)
        return self.stackframe_variables(session_id, function_start=function.getEntryPoint())

    def stackframe_variables(self, session_id: str, *, function_start: int | str) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        frame = function.getStackFrame()
        items = [self._variable_record(item) for item in frame.getStackVariables()]
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "count": len(items),
            "items": items,
        }

    def type_category_list(
        self,
        session_id: str,
        *,
        path: str = "/",
        recursive: bool = False,
    ) -> dict[str, Any]:
        category = self._resolve_category(session_id, path)
        categories = (
            self._walk_categories(category) if recursive else list(category.getCategories())
        )
        items = [self._category_record(item) for item in categories]
        return {
            "session_id": session_id,
            "path": str(category.getCategoryPath()),
            "recursive": recursive,
            "count": len(items),
            "items": items,
        }

    def type_category_create(self, session_id: str, *, path: str) -> dict[str, Any]:
        if not path:
            raise GhidraBackendError("path is required")
        created = None

        def mutate() -> None:
            nonlocal created
            from ghidra.program.model.data import CategoryPath

            created = (
                self._get_program(session_id)
                .getDataTypeManager()
                .createCategory(CategoryPath(path))
            )

        self._with_write(session_id, f"Create category {path}", mutate)
        return {"session_id": session_id, "category": self._category_record(created)}

    def type_archives_list(self, session_id: str) -> dict[str, Any]:
        dtm = self._get_program(session_id).getDataTypeManager()
        items = [
            {
                "name": dtm.getName(),
                "universal_id": None
                if dtm.getUniversalID() is None
                else int(dtm.getUniversalID().getValue()),
                "kind": "current_program",
            }
        ]
        items.extend(
            {
                "name": archive.getName(),
                "universal_id": int(archive.getSourceArchiveID().getValue()),
                "kind": "source_archive",
            }
            for archive in dtm.getSourceArchives()
        )
        return {"session_id": session_id, "count": len(items), "items": items}

    def type_source_archives_list(self, session_id: str) -> dict[str, Any]:
        dtm = self._get_program(session_id).getDataTypeManager()
        items = [self._source_archive_record(item) for item in dtm.getSourceArchives()]
        return {"session_id": session_id, "count": len(items), "items": items}

    def type_get_by_id(
        self,
        session_id: str,
        *,
        data_type_id: int | None = None,
        universal_id: int | None = None,
        source_archive_id: int | None = None,
    ) -> dict[str, Any]:
        dtm = self._get_program(session_id).getDataTypeManager()
        data_type = None
        if data_type_id is not None:
            with suppress(Exception):
                data_type = dtm.getDataType(int(data_type_id))
        if data_type is None and universal_id is not None:
            from ghidra.util import UniversalID

            data_type = dtm.findDataTypeForID(UniversalID(int(universal_id)))
        if data_type is None and universal_id is not None and source_archive_id is not None:
            from ghidra.util import UniversalID

            source_archive = dtm.getSourceArchive(UniversalID(int(source_archive_id)))
            if source_archive is not None:
                data_type = dtm.getDataType(source_archive, UniversalID(int(universal_id)))
        if data_type is None:
            raise GhidraBackendError("type not found")
        return {"session_id": session_id, "type": self._data_type_record(data_type)}

    def layout_struct_get(
        self,
        session_id: str,
        *,
        struct_path: str | None = None,
        struct_name: str | None = None,
    ) -> dict[str, Any]:
        struct = self._require_structure(
            self._resolve_data_type(session_id, path=struct_path, name=struct_name)
        )
        return {
            "session_id": session_id,
            "type": self._data_type_record(struct),
            "components": self._components_record(struct),
        }

    def layout_struct_resize(
        self,
        session_id: str,
        *,
        struct_path: str | None = None,
        struct_name: str | None = None,
        length: int,
    ) -> dict[str, Any]:
        if length < 0:
            raise GhidraBackendError("length must be >= 0")
        struct = self._require_structure(
            self._resolve_data_type(session_id, path=struct_path, name=struct_name)
        )

        def mutate() -> None:
            struct.setLength(int(length))

        self._with_write(session_id, f"Resize struct {struct.getName()}", mutate)
        return self.layout_struct_get(session_id, struct_path=struct.getPathName())

    def layout_struct_field_replace(
        self,
        session_id: str,
        *,
        struct_path: str | None = None,
        struct_name: str | None = None,
        offset: int,
        data_type: str,
        length: int | None = None,
        field_name: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        struct = self._require_structure(
            self._resolve_data_type(session_id, path=struct_path, name=struct_name)
        )
        parsed = self._parse_data_type(session_id, data_type)
        component_length = length if length is not None else max(1, int(parsed.getLength()))

        def mutate() -> None:
            struct.replaceAtOffset(int(offset), parsed, int(component_length), field_name, comment)

        self._with_write(session_id, f"Replace struct field {struct.getName()}", mutate)
        return self.layout_struct_get(session_id, struct_path=struct.getPathName())

    def layout_struct_field_clear(
        self,
        session_id: str,
        *,
        struct_path: str | None = None,
        struct_name: str | None = None,
        offset: int,
    ) -> dict[str, Any]:
        struct = self._require_structure(
            self._resolve_data_type(session_id, path=struct_path, name=struct_name)
        )

        def mutate() -> None:
            struct.clearAtOffset(int(offset))

        self._with_write(session_id, f"Clear struct field {struct.getName()}", mutate)
        return self.layout_struct_get(session_id, struct_path=struct.getPathName())

    def layout_struct_field_comment_set(
        self,
        session_id: str,
        *,
        struct_path: str | None = None,
        struct_name: str | None = None,
        offset: int | None = None,
        ordinal: int | None = None,
        field_name: str | None = None,
        comment: str | None,
    ) -> dict[str, Any]:
        struct = self._require_structure(
            self._resolve_data_type(session_id, path=struct_path, name=struct_name)
        )
        component = self._resolve_component(
            struct, offset=offset, ordinal=ordinal, field_name=field_name
        )

        def mutate() -> None:
            component.setComment(comment)

        self._with_write(session_id, f"Comment struct field {struct.getName()}", mutate)
        return self.layout_struct_get(session_id, struct_path=struct.getPathName())

    def layout_struct_bitfield_add(
        self,
        session_id: str,
        *,
        struct_path: str | None = None,
        struct_name: str | None = None,
        byte_offset: int,
        byte_width: int,
        bit_offset: int,
        data_type: str,
        bit_size: int,
        field_name: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        struct = self._require_structure(
            self._resolve_data_type(session_id, path=struct_path, name=struct_name)
        )
        parsed = self._parse_data_type(session_id, data_type)

        def mutate() -> None:
            struct.insertBitFieldAt(
                int(byte_offset),
                int(byte_width),
                int(bit_offset),
                parsed,
                int(bit_size),
                field_name,
                comment,
            )

        self._with_write(session_id, f"Add bitfield {struct.getName()}", mutate)
        return self.layout_struct_get(session_id, struct_path=struct.getPathName())

    def layout_union_create(
        self,
        session_id: str,
        *,
        name: str,
        category: str = "/",
    ) -> dict[str, Any]:
        if not name:
            raise GhidraBackendError("name is required")
        created = None

        def mutate() -> None:
            nonlocal created
            from ghidra.program.model.data import (
                CategoryPath,
                DataTypeConflictHandler,
                UnionDataType,
            )

            dtm = self._get_program(session_id).getDataTypeManager()
            created = dtm.addDataType(
                UnionDataType(CategoryPath(category), name, dtm),
                DataTypeConflictHandler.DEFAULT_HANDLER,
            )

        self._with_write(session_id, f"Create union {name}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(created)}

    def layout_union_member_add(
        self,
        session_id: str,
        *,
        union_path: str | None = None,
        union_name: str | None = None,
        field_name: str | None = None,
        data_type: str,
        length: int | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        union = self._require_union(
            self._resolve_data_type(session_id, path=union_path, name=union_name)
        )
        parsed = self._parse_data_type(session_id, data_type)
        member_length = length if length is not None else max(1, int(parsed.getLength()))

        def mutate() -> None:
            union.add(parsed, int(member_length), field_name, comment)

        self._with_write(session_id, f"Add union member {union.getName()}", mutate)
        return {
            "session_id": session_id,
            "type": self._data_type_record(union),
            "components": self._components_record(union),
        }

    def layout_union_member_remove(
        self,
        session_id: str,
        *,
        union_path: str | None = None,
        union_name: str | None = None,
        ordinal: int | None = None,
        field_name: str | None = None,
    ) -> dict[str, Any]:
        union = self._require_union(
            self._resolve_data_type(session_id, path=union_path, name=union_name)
        )
        component = self._resolve_component(
            union, offset=None, ordinal=ordinal, field_name=field_name
        )

        def mutate() -> None:
            union.delete(int(component.getOrdinal()))

        self._with_write(session_id, f"Remove union member {union.getName()}", mutate)
        return {
            "session_id": session_id,
            "type": self._data_type_record(union),
            "components": self._components_record(union),
        }

    def layout_enum_member_remove(
        self,
        session_id: str,
        *,
        enum_path: str | None = None,
        enum_name: str | None = None,
        name: str,
    ) -> dict[str, Any]:
        enum_type = self._require_enum(
            self._resolve_data_type(session_id, path=enum_path, name=enum_name)
        )

        def mutate() -> None:
            enum_type.remove(name)

        self._with_write(session_id, f"Remove enum member {name}", mutate)
        return {"session_id": session_id, "type": self._data_type_record(enum_type)}

    def layout_inspect_components(
        self,
        session_id: str,
        *,
        path: str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        data_type = self._resolve_data_type(session_id, path=path, name=name)
        if not hasattr(data_type, "getComponents"):
            raise GhidraBackendError("target type does not expose components")
        return {
            "session_id": session_id,
            "type": self._data_type_record(data_type),
            "components": self._components_record(data_type),
        }

    def layout_struct_fill_from_decompiler(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        ordinal: int | None = None,
        storage: str | None = None,
        create_new_structure: bool = True,
        create_class_if_needed: bool = False,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        high_symbol = self._find_high_symbol(
            session_id,
            function,
            name=name,
            ordinal=ordinal,
            storage=storage,
        )
        if high_symbol is None or high_symbol.getHighVariable() is None:
            raise GhidraBackendError("decompiler symbol not found")
        created = None

        def mutate() -> None:
            nonlocal created
            from ghidra.app.decompiler.util import FillOutStructureHelper

            helper = FillOutStructureHelper(
                self._get_program(session_id),
                self._pyghidra.task_monitor(timeout_secs),
            )
            created = helper.processStructure(
                high_symbol.getHighVariable(),
                function,
                bool(create_new_structure),
                bool(create_class_if_needed),
                self._get_decompiler(session_id),
            )
            if created is None:
                raise GhidraBackendError("failed to create structure from decompiler usage")

        self._with_write(session_id, f"Fill struct from {name}", mutate)
        return {
            "session_id": session_id,
            "type": self._data_type_record(created),
            "components": self._components_record(created),
        }

    def decomp_high_function_summary(
        self,
        session_id: str,
        *,
        function_start: int | str,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        high_function = self._high_function(session_id, function, timeout_secs=timeout_secs)
        local_symbols = [
            self._high_symbol_record(item)
            for item in high_function.getLocalSymbolMap().getSymbols()
        ]
        global_symbols = [
            self._high_symbol_record(item)
            for item in high_function.getGlobalSymbolMap().getSymbols()
        ]
        jump_tables = [str(item) for item in high_function.getJumpTables()]
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "local_symbol_count": len(local_symbols),
            "global_symbol_count": len(global_symbols),
            "block_count": len(list(high_function.getBasicBlocks())),
            "jump_table_count": len(jump_tables),
            "local_symbols": local_symbols,
            "global_symbols": global_symbols,
            "jump_tables": jump_tables,
        }

    def decomp_writeback_params(
        self,
        session_id: str,
        *,
        function_start: int | str,
        use_data_types: bool = True,
        commit_return: bool = False,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)

        def mutate() -> None:
            from ghidra.program.model.pcode import HighFunctionDBUtil
            from ghidra.program.model.pcode.HighFunctionDBUtil import ReturnCommitOption
            from ghidra.program.model.symbol import SourceType

            high_function = self._high_function(session_id, function, timeout_secs=timeout_secs)
            HighFunctionDBUtil.commitParamsToDatabase(
                high_function,
                bool(use_data_types),
                ReturnCommitOption.COMMIT if commit_return else ReturnCommitOption.NO_COMMIT,
                SourceType.USER_DEFINED,
            )

        self._with_write(session_id, f"Writeback params {function.getName()}", mutate)
        return self.function_signature_get(session_id, function.getEntryPoint())

    def decomp_writeback_locals(
        self,
        session_id: str,
        *,
        function_start: int | str,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)

        def mutate() -> None:
            from ghidra.program.model.pcode import HighFunctionDBUtil
            from ghidra.program.model.symbol import SourceType

            high_function = self._high_function(session_id, function, timeout_secs=timeout_secs)
            HighFunctionDBUtil.commitLocalNamesToDatabase(high_function, SourceType.USER_DEFINED)

        self._with_write(session_id, f"Writeback locals {function.getName()}", mutate)
        return self.function_variables(session_id, function.getEntryPoint())

    def decomp_override_get(
        self,
        session_id: str,
        *,
        function_start: int | str,
        callsite: int | str,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        callsite_addr = self._coerce_address(session_id, callsite, "callsite")
        symbol = self._find_override_symbol(session_id, function, callsite_addr)
        if symbol is None:
            return {
                "session_id": session_id,
                "function": self._function_record(function),
                "callsite": self._addr_str(callsite_addr),
                "override": None,
            }
        from ghidra.program.model.pcode import HighFunctionDBUtil

        override = HighFunctionDBUtil.readOverride(symbol)
        data_type = None if override is None else override.getDataType()
        return {
            "session_id": session_id,
            "function": self._function_record(function),
            "callsite": self._addr_str(callsite_addr),
            "override": None
            if data_type is None
            else {
                "symbol": self._symbol_record(symbol),
                "signature": data_type.getPrototypeString(),
                "type": self._data_type_record(data_type),
            },
        }

    def decomp_override_set(
        self,
        session_id: str,
        *,
        function_start: int | str,
        callsite: int | str,
        signature: str,
    ) -> dict[str, Any]:
        if not signature:
            raise GhidraBackendError("signature is required")
        function = self._resolve_function(session_id, function_start)
        callsite_addr = self._coerce_address(session_id, callsite, "callsite")

        def mutate() -> None:
            from ghidra.app.util.cparser.C import CParserUtils
            from ghidra.program.model.pcode import HighFunctionDBUtil

            definition = CParserUtils.parseSignature(
                None, self._get_program(session_id), signature, False
            )
            if definition is None:
                raise GhidraBackendError("failed to parse signature")
            existing = self._find_override_symbol(session_id, function, callsite_addr)
            if existing is not None:
                existing.delete()
            HighFunctionDBUtil.writeOverride(function, callsite_addr, definition)

        self._with_write(session_id, f"Set override {function.getName()}", mutate)
        return self.decomp_override_get(
            session_id, function_start=function.getEntryPoint(), callsite=callsite_addr
        )

    def decomp_trace_type_forward(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        ordinal: int | None = None,
        storage: str | None = None,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        return self._decomp_trace_type(
            session_id,
            function_start=function_start,
            name=name,
            ordinal=ordinal,
            storage=storage,
            timeout_secs=timeout_secs,
            direction="forward",
        )

    def decomp_trace_type_backward(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        ordinal: int | None = None,
        storage: str | None = None,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        return self._decomp_trace_type(
            session_id,
            function_start=function_start,
            name=name,
            ordinal=ordinal,
            storage=storage,
            timeout_secs=timeout_secs,
            direction="backward",
        )

    def decomp_global_rename(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        new_name: str,
        storage: str | None = None,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        high_symbol = self._find_high_symbol(
            session_id,
            function,
            name=name,
            ordinal=None,
            storage=storage,
            timeout_secs=timeout_secs,
            global_only=True,
        )
        if high_symbol is None:
            raise GhidraBackendError("global symbol not found")

        def mutate() -> None:
            self._update_high_symbol(
                session_id, function, high_symbol, name=new_name, data_type=None
            )

        self._with_write(session_id, f"Rename global {name}", mutate)
        return self.decomp_high_function_summary(
            session_id, function_start=function.getEntryPoint(), timeout_secs=timeout_secs
        )

    def decomp_global_retype(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        data_type: str,
        storage: str | None = None,
        timeout_secs: int = 30,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        high_symbol = self._find_high_symbol(
            session_id,
            function,
            name=name,
            ordinal=None,
            storage=storage,
            timeout_secs=timeout_secs,
            global_only=True,
        )
        if high_symbol is None:
            raise GhidraBackendError("global symbol not found")
        parsed = self._parse_data_type(session_id, data_type)

        def mutate() -> None:
            self._update_high_symbol(session_id, function, high_symbol, name=None, data_type=parsed)

        self._with_write(session_id, f"Retype global {name}", mutate)
        return self.decomp_high_function_summary(
            session_id, function_start=function.getEntryPoint(), timeout_secs=timeout_secs
        )

    def shutdown(self) -> None:
        task_ids = list(self._tasks)
        for task_id in task_ids:
            with suppress(Exception):
                self.task_cancel(task_id)
        session_ids = list(self._sessions)
        for session_id in session_ids:
            with suppress(Exception):
                self.session_close(session_id)
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _ensure_started(self) -> None:
        if self._started:
            return
        with self._startup_lock:
            if self._started:
                return
            self._prune_conflicting_sys_path_entries()
            self._launcher = self._pyghidra.start(
                verbose=False, install_dir=Path(self._install_dir) if self._install_dir else None
            )
            self._started = True

    def _prune_conflicting_sys_path_entries(self) -> None:
        removable: list[str] = []
        for entry in list(sys.path):
            if not entry:
                path = Path.cwd()
            else:
                path = Path(entry)
            with suppress(OSError):
                if (path / "ghidra" / "Ghidra" / "application.properties").exists():
                    removable.append(entry)
        for entry in removable:
            with suppress(ValueError):
                sys.path.remove(entry)

    def _allocate_project(
        self,
        seed_name: str,
        *,
        project_location: str | None,
        project_name: str | None,
    ) -> tuple[str, str, bool]:
        if project_location or project_name:
            if not project_location:
                raise GhidraBackendError(
                    "project_location is required when project_name is supplied"
                )
            return (
                str(Path(project_location).resolve()),
                project_name or self._default_project_name(seed_name),
                False,
            )
        temp_root = tempfile.mkdtemp(prefix="ghidra_headless_mcp-")
        return temp_root, self._default_project_name(seed_name), True

    def _default_project_name(self, seed_name: str) -> str:
        stem = Path(seed_name).name or "program"
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", stem) + "_ghidra"

    def _find_open_project(self, project_location: str, project_name: str) -> Any:
        resolved_location = str(Path(project_location).resolve())
        for record in self._sessions.values():
            if record.project_location == resolved_location and record.project_name == project_name:
                return record.project
        return None

    def _project_in_use(
        self,
        project_location: str,
        project_name: str,
        *,
        excluding_session_id: str | None = None,
    ) -> bool:
        resolved_location = str(Path(project_location).resolve())
        return any(
            session_id != excluding_session_id
            and record.project_location == resolved_location
            and record.project_name == project_name
            for session_id, record in self._sessions.items()
        )

    def _open_or_create_project(self, project_location: str, project_name: str) -> Any:
        from ghidra.base.project import GhidraProject
        from ghidra.framework.model import ProjectLocator

        existing = self._find_open_project(project_location, project_name)
        if existing is not None:
            return existing

        locator = ProjectLocator(project_location, project_name)
        try:
            if locator.exists():
                return GhidraProject.openProject(project_location, project_name)
            Path(project_location).mkdir(parents=True, exist_ok=True)
            return GhidraProject.createProject(project_location, project_name, False)
        except Exception as exc:
            raise GhidraBackendError(f"failed to open project: {exc}") from exc

    def _open_existing_project(self, project_location: str, project_name: str) -> Any:
        from ghidra.base.project import GhidraProject

        existing = self._find_open_project(project_location, project_name)
        if existing is not None:
            return existing

        try:
            return GhidraProject.openProject(project_location, project_name)
        except Exception as exc:
            raise GhidraBackendError(f"failed to open project: {exc}") from exc

    def _resolve_loader_class(self, loader_name: str | None) -> Any:
        if not loader_name:
            return None
        from jpype import JClass

        try:
            return JClass(loader_name)
        except Exception as exc:
            raise GhidraBackendError(f"invalid loader class '{loader_name}': {exc}") from exc

    def _get_language(self, language_id: str) -> Any:
        from ghidra.program.model.lang import LanguageID, LanguageNotFoundException
        from ghidra.program.util import DefaultLanguageService

        try:
            return DefaultLanguageService.getLanguageService().getLanguage(LanguageID(language_id))
        except LanguageNotFoundException as exc:
            raise GhidraBackendError(f"invalid language id: {language_id}") from exc

    def _get_compiler_spec(self, language: Any, compiler_id: str | None) -> Any:
        if compiler_id is None:
            return language.getDefaultCompilerSpec()
        from ghidra.program.model.lang import CompilerSpecID, CompilerSpecNotFoundException

        try:
            return language.getCompilerSpecByID(CompilerSpecID(compiler_id))
        except CompilerSpecNotFoundException as exc:
            raise GhidraBackendError(f"invalid compiler spec id: {compiler_id}") from exc

    def _import_or_open_program(
        self,
        project: Any,
        path: str,
        program_name: str,
        *,
        language: str | None,
        compiler: str | None,
        loader: str | None,
    ) -> Any:
        existing = project.getRootFolder().getFile(program_name)
        if existing is not None:
            try:
                return project.openProgram("/", program_name, False)
            except Exception as exc:
                raise GhidraBackendError(
                    f"failed to open existing program '{program_name}': {exc}"
                ) from exc

        from java.io import File

        loader_class = self._resolve_loader_class(loader)
        try:
            if language is None:
                if loader_class is None:
                    program = project.importProgram(File(path))
                else:
                    program = project.importProgram(File(path), loader_class)
            else:
                lang = self._get_language(language)
                comp = self._get_compiler_spec(lang, compiler)
                if loader_class is None:
                    program = project.importProgram(File(path), lang, comp)
                else:
                    program = project.importProgram(File(path), loader_class, lang, comp)
        except Exception as exc:
            raise GhidraBackendError(f"failed to import program: {exc}") from exc
        if program is None:
            raise GhidraBackendError("failed to import program")
        try:
            project.saveAs(program, "/", program_name, True)
        except Exception as exc:
            project.close(program)
            raise GhidraBackendError(f"failed to save imported program: {exc}") from exc
        return program

    def _load_program_from_bytes(
        self,
        project: Any,
        raw_bytes: bytes,
        program_name: str,
        *,
        language: str | None,
        compiler: str | None,
        loader: str | None,
    ) -> tuple[Any, Any]:
        from java.lang import Object
        from jpype.types import JArray, JByte

        builder = self._pyghidra.program_loader().project(project.getProject()).name(program_name)
        builder = builder.source(JArray(JByte)(raw_bytes))
        if loader:
            builder = builder.loaders(loader)
        if language:
            builder = builder.language(language)
        if compiler:
            builder = builder.compiler(compiler)
        try:
            results = builder.load()
            results.save(self._pyghidra.task_monitor())
            consumer = Object()
            program = results.getPrimaryDomainObject(consumer)
            results.close()
            return program, consumer
        except Exception as exc:
            raise GhidraBackendError(f"failed to import program from bytes: {exc}") from exc

    def _register_session(
        self,
        *,
        project: Any,
        program: Any,
        project_location: str,
        project_name: str,
        program_name: str,
        program_path: str,
        source_path: str | None,
        read_only: bool,
        managed_project: bool,
        managed_project_root: str | None = None,
        temp_source_path: str | None = None,
        program_consumer: Any = None,
    ) -> str:
        from ghidra.program.flatapi import FlatProgramAPI

        session_id = uuid4().hex
        self._sessions[session_id] = SessionRecord(
            session_id=session_id,
            project=project,
            program=program,
            flat_api=FlatProgramAPI(program),
            program_name=program_name,
            program_path=program_path,
            project_location=project_location,
            project_name=project_name,
            source_path=source_path,
            read_only=read_only,
            managed_project=managed_project,
            managed_project_root=managed_project_root,
            temp_source_path=temp_source_path,
            program_consumer=program_consumer,
        )
        return session_id

    def _get_record(self, session_id: str) -> SessionRecord:
        record = self._sessions.get(session_id)
        if record is None:
            raise GhidraBackendError(f"unknown session_id: {session_id}")
        return record

    def _get_program(self, session_id: str) -> Any:
        return self._get_record(session_id).program

    def _get_task(self, task_id: str) -> TaskRecord:
        with self._lock:
            task = self._tasks.get(task_id)
        if task is None:
            raise GhidraBackendError(f"unknown task_id: {task_id}")
        return task

    def _task_state(self, task: TaskRecord) -> str:
        future = task.future
        if future.cancelled():
            return "cancelled"
        if future.done():
            return "failed" if future.exception() is not None else "completed"
        if future.running():
            return "cancelling" if task.cancel_requested else "running"
        return "queued"

    def _submit_task(
        self,
        *,
        kind: str,
        session_id: str | None,
        func: Callable[[], Any],
        cancel_hook: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        task_id = uuid4().hex
        future = self._executor.submit(func)
        record = TaskRecord(
            task_id=task_id,
            kind=kind,
            future=future,
            session_id=session_id,
            cancel_hook=cancel_hook,
        )
        with self._lock:
            self._tasks[task_id] = record
        return {
            "task_id": task_id,
            "kind": kind,
            "session_id": session_id,
            "status": self._task_state(record),
        }

    def _require_writable_session(self, session_id: str) -> SessionRecord:
        record = self._get_record(session_id)
        if record.read_only:
            raise GhidraBackendError(f"session {session_id} is read-only")
        return record

    def _transition_sessions_to_writable(self, session_ids: Iterable[str]) -> list[str]:
        transitioned: list[str] = []
        for session_id in session_ids:
            if session_id is None:
                continue
            record = self._get_record(session_id)
            if record.read_only:
                record.read_only = False
                transitioned.append(session_id)
        return transitioned

    def _analyze_program(self, program: Any, monitor: Any) -> str:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
        from ghidra.program.util import GhidraProgramUtilities

        tx_id = int(program.startTransaction("Analysis"))
        try:
            manager = AutoAnalysisManager.getAnalysisManager(program)
            manager.initializeOptions()
            manager.reAnalyzeAll(None)
            manager.startAnalysis(monitor)
            GhidraProgramUtilities.markProgramAnalyzed(program)
            return str(manager.getMessageLog().toString())
        finally:
            program.endTransaction(tx_id, True)

    def _open_transaction_entry_ids(self, transaction: Any) -> list[int]:
        transaction_class = transaction.getClass()
        base_id_field = transaction_class.getDeclaredField("baseId")
        entries_field = transaction_class.getDeclaredField("list")
        base_id_field.setAccessible(True)
        entries_field.setAccessible(True)
        base_id = int(base_id_field.get(transaction))
        entries = entries_field.get(transaction)
        open_ids: list[int] = []
        for index in range(entries.size()):
            entry = entries.get(index)
            entry_class = entry.getClass()
            status_field = entry_class.getDeclaredField("status")
            status_field.setAccessible(True)
            if str(status_field.get(entry)) == "NOT_DONE":
                open_ids.append(base_id + index)
        return open_ids

    def _drain_internal_transactions(self, program: Any, *, commit: bool = True) -> None:
        allowed_descriptions = {
            "",
            "Analysis",
            "Analyze",
            "Batch Processing",
            "Mark Program Analyzed",
        }
        while True:
            transaction = program.getCurrentTransactionInfo()
            if transaction is None:
                return
            if str(transaction.getDescription() or "") not in allowed_descriptions:
                return
            entry_ids = self._open_transaction_entry_ids(transaction)
            if not entry_ids:
                return
            program.endTransaction(entry_ids[-1], commit)

    def _sync_project_open_transaction(
        self, project: Any, program: Any, transaction_id: int
    ) -> None:
        from java.lang import Integer

        project_class = project.getClass()
        open_programs_field = project_class.getDeclaredField("openPrograms")
        open_programs_field.setAccessible(True)
        open_programs = open_programs_field.get(project)
        if open_programs is not None and open_programs.containsKey(program):
            open_programs.put(program, Integer.valueOf(int(transaction_id)))

    def _finalize_open_program(self, program: Any, project: Any | None = None) -> None:
        with suppress(Exception):
            self._drain_internal_transactions(program, commit=True)
        if project is not None:
            with suppress(Exception):
                self._sync_project_open_transaction(project, program, -1)

    def _with_write(self, session_id: str, description: str, func: Callable[[], Any]) -> Any:
        record = self._require_writable_session(session_id)
        if record.active_transaction_id is not None:
            return func()
        tx_id = int(record.program.startTransaction(description))
        committed = False
        try:
            result = func()
            committed = True
            return result
        finally:
            record.program.endTransaction(tx_id, committed)

    def _transaction_summary(self, record: SessionRecord) -> dict[str, Any] | None:
        if record.active_transaction_id is None:
            return None
        return {
            "id": record.active_transaction_id,
            "description": record.active_transaction_description,
        }

    def _analysis_options(self, session_id: str) -> Any:
        return self._pyghidra.analysis_properties(self._get_program(session_id))

    def _option_object(self, options: Any, name: str) -> Any:
        return options.getObject(name, None)

    def _analysis_option_record(self, options: Any, name: str) -> dict[str, Any]:
        value = options.getValueAsString(name)
        default = options.getDefaultValue(name)
        current = self._option_object(options, name)
        java_type = None
        if current is not None:
            with suppress(Exception):
                java_type = current.getClass().getName()
            if java_type is None:
                java_type = f"python:{type(current).__name__}"
        return {
            "name": name,
            "value": value,
            "default": self._to_jsonable(default),
            "current": self._to_jsonable(current),
            "java_type": java_type,
        }

    def _require_option(self, options: Any, name: str) -> None:
        names = {str(option_name) for option_name in options.getOptionNames()}
        if name not in names:
            raise GhidraBackendError(f"unknown analysis option: {name}")

    def _validate_offset_limit(self, offset: int, limit: int) -> None:
        if offset < 0:
            raise GhidraBackendError("offset must be >= 0")
        if limit <= 0:
            raise GhidraBackendError("limit must be > 0")

    def _coerce_address(self, session_id: str, value: int | str | Any, arg_name: str) -> Any:
        program = self._get_program(session_id)
        factory = program.getAddressFactory()
        if value is None:
            raise GhidraBackendError(f"{arg_name} is required")
        if hasattr(value, "getAddressSpace") and hasattr(value, "getOffset"):
            return value
        if isinstance(value, int):
            return factory.getDefaultAddressSpace().getAddress(value)
        if isinstance(value, str):
            text = value.strip()
            if not text:
                raise GhidraBackendError(f"{arg_name} is required")
            with suppress(Exception):
                addr = factory.getAddress(text)
                if addr is not None:
                    return addr
            with suppress(Exception):
                return factory.getDefaultAddressSpace().getAddress(int(text, 0))
        raise GhidraBackendError(f"invalid {arg_name}: {value!r}")

    def _addr_str(self, address: Any) -> str | None:
        if address is None:
            return None
        return str(address)

    def _function_sort_key(self, function: Any) -> tuple[int, str]:
        return (int(function.getEntryPoint().getOffset()), function.getName())

    def _resolve_function(self, session_id: str, function_start: int | str | None) -> Any:
        if function_start is None:
            raise GhidraBackendError("function_start is required")
        addr = self._coerce_address(session_id, function_start, "function_start")
        manager = self._get_program(session_id).getFunctionManager()
        function = manager.getFunctionAt(addr)
        if function is None:
            function = manager.getFunctionContaining(addr)
        if function is None:
            raise GhidraBackendError(f"no function found at {self._addr_str(addr)}")
        return function

    def _resolve_symbol(self, session_id: str, address: int | str, *, name: str | None) -> Any:
        addr = self._coerce_address(session_id, address, "address")
        symbols = list(self._get_program(session_id).getSymbolTable().getSymbols(addr))
        if name is not None:
            for symbol in symbols:
                if symbol.getName(True) == name or symbol.getName() == name:
                    return symbol
            raise GhidraBackendError(f"symbol '{name}' not found at {self._addr_str(addr)}")
        if not symbols:
            raise GhidraBackendError(f"no symbol found at {self._addr_str(addr)}")
        for symbol in symbols:
            if symbol.isPrimary():
                return symbol
        return symbols[0]

    def _resolve_data_type(
        self,
        session_id: str,
        *,
        path: str | None,
        name: str | None,
    ) -> Any:
        dtm = self._get_program(session_id).getDataTypeManager()
        if path:
            data_type = dtm.getDataType(path)
            if data_type is None:
                raise GhidraBackendError(f"type not found: {path}")
            return data_type
        if not name:
            raise GhidraBackendError("path or name is required")
        from java.util import ArrayList

        matches = ArrayList()
        dtm.findDataTypes(name, matches)
        if matches.isEmpty():
            raise GhidraBackendError(f"type not found: {name}")
        if matches.size() > 1:
            raise GhidraBackendError(f"type name is ambiguous: {name}")
        return matches.get(0)

    def _parse_data_type(self, session_id: str, type_text: str) -> Any:
        from ghidra.util.data import DataTypeParser

        dtm = self._get_program(session_id).getDataTypeManager()
        parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)
        try:
            return parser.parse(type_text)
        except Exception as exc:
            raise GhidraBackendError(f"failed to parse data type '{type_text}': {exc}") from exc

    def _get_all_data_types(self, session_id: str) -> list[Any]:
        from java.util import ArrayList

        result = ArrayList()
        self._get_program(session_id).getDataTypeManager().getAllDataTypes(result)
        return list(result)

    def _comment_type(self, name: str) -> Any:
        from ghidra.program.model.listing import CommentType

        mapping = {
            "plate": CommentType.PLATE,
            "pre": CommentType.PRE,
            "post": CommentType.POST,
            "eol": CommentType.EOL,
            "repeatable": CommentType.REPEATABLE,
        }
        try:
            return mapping[name.lower()]
        except KeyError as exc:
            raise GhidraBackendError(f"unsupported comment_type: {name}") from exc

    def _decompile_function(
        self, session_id: str, function: Any, *, timeout_secs: int
    ) -> dict[str, Any]:
        if timeout_secs <= 0:
            raise GhidraBackendError("timeout_secs must be > 0")
        decompiler = self._get_decompiler(session_id)
        results = decompiler.decompileFunction(
            function, timeout_secs, self._pyghidra.task_monitor(timeout_secs)
        )
        payload = {
            "session_id": session_id,
            "function": self._function_record(function),
            "decompile_completed": bool(results.decompileCompleted()),
            "timed_out": bool(results.isTimedOut()),
            "cancelled": bool(results.isCancelled()),
            "error_message": results.getErrorMessage(),
        }
        decompiled = results.getDecompiledFunction()
        if decompiled is not None:
            payload["c"] = decompiled.getC()
            payload["signature"] = decompiled.getSignature()
        return payload

    def _get_decompiler(self, session_id: str) -> Any:
        record = self._get_record(session_id)
        if record.decompiler is None:
            from ghidra.app.decompiler import DecompInterface

            decompiler = DecompInterface()
            decompiler.toggleCCode(True)
            decompiler.toggleSyntaxTree(True)
            decompiler.setSimplificationStyle("decompile")
            if not decompiler.openProgram(record.program):
                decompiler.dispose()
                raise GhidraBackendError("failed to open decompiler for program")
            record.decompiler = decompiler
        return record.decompiler

    def _function_record(self, function: Any) -> dict[str, Any]:
        return {
            "name": function.getName(),
            "entry_point": self._addr_str(function.getEntryPoint()),
            "body_start": self._addr_str(function.getBody().getMinAddress()),
            "body_end": self._addr_str(function.getBody().getMaxAddress()),
            "signature": function.getPrototypeString(False, True),
            "calling_convention": function.getCallingConventionName(),
            "external": bool(function.isExternal()),
            "thunk": bool(function.isThunk()),
        }

    def _variable_record(self, variable: Any) -> dict[str, Any]:
        storage = None
        with suppress(Exception):
            storage = str(variable.getVariableStorage())
        return {
            "name": variable.getName(),
            "data_type": variable.getDataType().getPathName(),
            "storage": storage,
            "comment": variable.getComment(),
            "first_use_offset": getattr(variable, "getFirstUseOffset", lambda: None)(),
        }

    def _parameter_record(self, parameter: Any) -> dict[str, Any]:
        record = self._variable_record(parameter)
        record["ordinal"] = int(parameter.getOrdinal())
        record["auto_parameter"] = bool(getattr(parameter, "isAutoParameter", lambda: False)())
        return record

    def _symbol_record(self, symbol: Any) -> dict[str, Any] | None:
        if symbol is None:
            return None
        namespace = None
        with suppress(Exception):
            parent = symbol.getParentNamespace()
            namespace = parent.getName(True) if parent is not None else None
        return {
            "id": int(symbol.getID()),
            "name": symbol.getName(True),
            "short_name": symbol.getName(),
            "address": self._addr_str(symbol.getAddress()),
            "symbol_type": str(symbol.getSymbolType()),
            "source_type": str(symbol.getSource()),
            "namespace": namespace,
            "primary": bool(symbol.isPrimary()),
            "external": bool(symbol.isExternal()),
        }

    def _reference_record(self, reference: Any) -> dict[str, Any]:
        return {
            "from": self._addr_str(reference.getFromAddress()),
            "to": self._addr_str(reference.getToAddress()),
            "reference_type": str(reference.getReferenceType()),
            "operand_index": int(reference.getOperandIndex()),
            "primary": bool(reference.isPrimary()),
            "external": bool(reference.isExternalReference()),
        }

    def _data_record(self, data: Any) -> dict[str, Any] | None:
        if data is None:
            return None
        value = None
        with suppress(Exception):
            value = data.getDefaultValueRepresentation()
        return {
            "address": self._addr_str(data.getAddress()),
            "length": int(data.getLength()),
            "data_type": data.getDataType().getPathName(),
            "base_data_type": data.getBaseDataType().getPathName(),
            "value": value,
            "label": data.getLabel(),
            "path_name": data.getPathName(),
        }

    def _data_type_record(self, data_type: Any) -> dict[str, Any]:
        length = None
        with suppress(Exception):
            length = int(data_type.getLength())
        return {
            "name": data_type.getName(),
            "display_name": data_type.getDisplayName(),
            "path": data_type.getPathName(),
            "category": str(data_type.getCategoryPath()),
            "length": length,
            "description": data_type.getDescription(),
            "java_type": data_type.getClass().getName(),
        }

    def _pcode_instruction_record(self, instruction: Any) -> dict[str, Any]:
        return {
            "address": self._addr_str(instruction.getAddress()),
            "instruction": instruction.toString(),
            "ops": [self._pcode_op_record(op) for op in instruction.getPcode()],
        }

    def _pcode_op_record(self, op: Any) -> dict[str, Any]:
        inputs = []
        for varnode in op.getInputs():
            inputs.append(self._varnode_record(varnode))
        output = op.getOutput()
        return {
            "opcode": int(op.getOpcode()),
            "mnemonic": op.getMnemonic(),
            "sequence": str(op.getSeqnum()),
            "inputs": inputs,
            "output": self._varnode_record(output) if output is not None else None,
            "text": str(op),
        }

    def _varnode_record(self, varnode: Any) -> dict[str, Any]:
        return {
            "address": self._addr_str(varnode.getAddress()),
            "size": int(varnode.getSize()),
            "space": varnode.getAddress().getAddressSpace().getName(),
            "constant": bool(varnode.isConstant()),
            "register": bool(varnode.isRegister()),
            "unique": bool(varnode.isUnique()),
        }

    def _disassemble_instructions(self, instructions: Any, limit: int) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for instruction in instructions:
            if len(items) >= limit:
                break
            items.append(
                {
                    "address": self._addr_str(instruction.getAddress()),
                    "mnemonic": instruction.getMnemonicString(),
                    "text": instruction.toString(),
                    "bytes": bytes(instruction.getBytes()).hex(),
                }
            )
        return items

    def _iter_strings(
        self,
        program: Any,
        *,
        address_set: Any | None = None,
    ) -> Iterable[dict[str, Any]]:
        from ghidra.program.model.data import StringDataInstance
        from ghidra.program.util import DefinedDataIterator

        iterator = DefinedDataIterator.byDataInstance(
            program,
            lambda data: (
                StringDataInstance.getStringDataInstance(data) != StringDataInstance.NULL_INSTANCE
            ),
        )
        for data in iterator:
            if address_set is not None and not address_set.contains(data.getAddress()):
                continue
            instance = StringDataInstance.getStringDataInstance(data)
            yield {
                "address": self._addr_str(data.getAddress()),
                "length": int(data.getLength()),
                "value": instance.getStringValue(),
                "data_type": data.getDataType().getPathName(),
            }

    def _find_byte_matches(
        self,
        session_id: str,
        payload: bytes,
        limit: int,
        *,
        address_set: Any | None = None,
    ) -> list[Any]:
        if limit <= 0:
            return []
        pattern = " ".join(f"{byte:02x}" for byte in payload)
        with suppress(Exception):
            search_base = (
                self._get_program(session_id).getMemory() if address_set is None else address_set
            )
            results = self._get_record(session_id).flat_api.findBytes(
                search_base, pattern, limit, 1
            )
            return [] if results is None else list(results)
        return []

    def _function_code_blocks(self, function: Any) -> list[Any]:
        from ghidra.program.model.block import BasicBlockModel

        model = BasicBlockModel(function.getProgram())
        monitor = self._pyghidra.task_monitor()
        seen: set[tuple[str | None, str | None]] = set()
        items: list[Any] = []
        for block in model.getCodeBlocksContaining(function.getBody(), monitor):
            key = self._code_block_key(block)
            if key in seen:
                continue
            seen.add(key)
            items.append(block)
        return items

    def _code_block_containing(self, session_id: str, address: Any) -> Any:
        from ghidra.program.model.block import BasicBlockModel

        model = BasicBlockModel(self._get_program(session_id))
        monitor = self._pyghidra.task_monitor()
        blocks = model.getCodeBlocksContaining(address, monitor)
        if not blocks:
            raise GhidraBackendError(f"no basic block found at {self._addr_str(address)}")
        return blocks[0]

    def _code_block_key(self, block: Any) -> tuple[str | None, str | None]:
        return (self._addr_str(block.getMinAddress()), self._addr_str(block.getMaxAddress()))

    def _code_block_record(self, block: Any) -> dict[str, Any]:
        return {
            "start": self._addr_str(block.getMinAddress()),
            "end": self._addr_str(block.getMaxAddress()),
            "flow_type": str(block.getFlowType()),
            "name": str(block.getName()),
        }

    def _resolve_variable(
        self,
        function: Any,
        *,
        name: str | None,
        ordinal: int | None,
        storage: str | None,
    ) -> Any:
        candidates = list(function.getParameters()) + list(function.getLocalVariables())
        matched = []
        for variable in candidates:
            if name is not None and variable.getName() != name:
                continue
            if ordinal is not None and getattr(variable, "getOrdinal", lambda: None)() != ordinal:
                continue
            if storage is not None:
                serialized_storage = None
                with suppress(Exception):
                    serialized_storage = str(variable.getVariableStorage())
                if serialized_storage != storage:
                    continue
            matched.append(variable)
        if not matched:
            raise GhidraBackendError("variable not found")
        if len(matched) > 1:
            raise GhidraBackendError("variable selection is ambiguous")
        return matched[0]

    def _metadata_options(self, session_id: str) -> Any:
        return self._get_program(session_id).getOptions("GhidraHeadlessMCP Metadata")

    def _project_artifacts(self, record: SessionRecord) -> list[Path]:
        base = Path(record.project_location)
        return [
            base / f"{record.project_name}.gpr",
            base / f"{record.project_name}.rep",
        ]

    def _bookmark_record(self, bookmark: Any) -> dict[str, Any] | None:
        if bookmark is None:
            return None
        return {
            "address": self._addr_str(bookmark.getAddress()),
            "type": bookmark.getTypeString(),
            "category": bookmark.getCategory(),
            "comment": bookmark.getComment(),
        }

    def _function_tag_record(self, tag: Any) -> dict[str, Any]:
        payload = {"name": tag.getName(), "comment": tag.getComment()}
        with suppress(Exception):
            payload["id"] = int(tag.getId())
        return payload

    def _project_folder(self, session_id: str, folder_path: str) -> Any:
        project_data = self._get_record(session_id).project.getProjectData()
        if folder_path in {"", "/"}:
            return project_data.getRootFolder()
        folder = project_data.getFolder(folder_path)
        if folder is None:
            raise GhidraBackendError(f"project folder not found: {folder_path}")
        return folder

    def _project_file(self, session_id: str, path: str) -> Any:
        project_data = self._get_record(session_id).project.getProjectData()
        file = project_data.getFile(path)
        if file is None:
            raise GhidraBackendError(f"project file not found: {path}")
        return file

    def _walk_project_folders(self, folder: Any) -> list[Any]:
        items: list[Any] = []
        for child in folder.getFolders():
            items.append(child)
            items.extend(self._walk_project_folders(child))
        return items

    def _walk_project_files(self, folder: Any) -> list[Any]:
        items = list(folder.getFiles())
        for child in folder.getFolders():
            items.extend(self._walk_project_files(child))
        return items

    def _domain_folder_record(self, folder: Any) -> dict[str, Any]:
        payload = {
            "name": folder.getName(),
            "path": folder.getPathname(),
        }
        with suppress(Exception):
            payload["folder_count"] = len(folder.getFolders())
        with suppress(Exception):
            payload["file_count"] = len(folder.getFiles())
        with suppress(Exception):
            shared = folder.getSharedProjectURL()
            payload["shared_project_url"] = None if shared is None else str(shared)
        return payload

    def _domain_file_record(self, file: Any) -> dict[str, Any]:
        payload = {
            "name": file.getName(),
            "path": file.getPathname(),
            "content_type": file.getContentType(),
        }
        with suppress(Exception):
            payload["file_id"] = str(file.getFileID())
        with suppress(Exception):
            payload["domain_object_class"] = file.getDomainObjectClass().getName()
        with suppress(Exception):
            payload["versioned"] = bool(file.isVersioned())
        with suppress(Exception):
            payload["checked_out"] = bool(file.isCheckedOut())
        with suppress(Exception):
            payload["hijacked"] = bool(file.isHijacked())
        with suppress(Exception):
            payload["read_only"] = bool(file.isReadOnly())
        with suppress(Exception):
            payload["in_use"] = bool(file.isInUse())
        with suppress(Exception):
            payload["shared_project_url"] = (
                None
                if file.getSharedProjectURL(None) is None
                else str(file.getSharedProjectURL(None))
            )
        return payload

    def _coerce_address_range(
        self,
        session_id: str,
        *,
        start: int | str,
        end: int | str | None = None,
        length: int | None = None,
        arg_name: str,
    ) -> tuple[Any, Any, Any]:
        if length is not None and length <= 0:
            raise GhidraBackendError("length must be > 0")
        start_addr = self._coerce_address(session_id, start, arg_name)
        if end is not None:
            end_addr = self._coerce_address(session_id, end, "end")
        elif length is not None:
            end_addr = start_addr.add(int(length) - 1)
        else:
            end_addr = start_addr
        from ghidra.program.model.address import AddressSet

        return start_addr, end_addr, AddressSet(start_addr, end_addr)

    def _optional_address_range(
        self,
        session_id: str,
        *,
        start: int | str | None = None,
        end: int | str | None = None,
        length: int | None = None,
        arg_name: str,
    ) -> tuple[Any | None, Any | None, Any | None]:
        if start is None:
            if end is not None or length is not None:
                raise GhidraBackendError(f"{arg_name} is required when end or length is provided")
            return None, None, None
        return self._coerce_address_range(
            session_id,
            start=start,
            end=end,
            length=length,
            arg_name=arg_name,
        )

    def _code_unit_record(self, code_unit: Any) -> dict[str, Any] | None:
        if code_unit is None:
            return None
        payload = {
            "kind": code_unit.getClass().getSimpleName(),
            "address": self._addr_str(code_unit.getAddress()),
            "min_address": self._addr_str(code_unit.getMinAddress()),
            "max_address": self._addr_str(code_unit.getMaxAddress()),
            "length": int(code_unit.getLength()),
        }
        with suppress(Exception):
            payload["mnemonic"] = code_unit.getMnemonicString()
        with suppress(Exception):
            payload["text"] = code_unit.toString()
        with suppress(Exception):
            payload["bytes"] = bytes(code_unit.getBytes()).hex()
        with suppress(Exception):
            payload["label"] = code_unit.getLabel()
        return payload

    def _resolve_register(self, session_id: str, name: str) -> Any:
        if not name:
            raise GhidraBackendError("register is required")
        program = self._get_program(session_id)
        register = program.getRegister(name)
        if register is None:
            register = program.getLanguage().getRegister(name)
        if register is None:
            raise GhidraBackendError(f"unknown register: {name}")
        return register

    def _resolve_namespace(self, session_id: str, path: str | None) -> Any:
        if path in {None, "", "/", "::", "Global"}:
            return None
        symbol_table = self._get_program(session_id).getSymbolTable()
        current = None
        cleaned = path.replace("/", "::").strip(":")
        for part in [item for item in cleaned.split("::") if item]:
            current = symbol_table.getNamespace(part, current)
            if current is None:
                raise GhidraBackendError(f"namespace not found: {path}")
        return current

    def _namespace_record(self, namespace: Any) -> dict[str, Any] | None:
        if namespace is None:
            return {
                "name": "Global",
                "path": "::",
                "symbol_type": "Global",
            }
        payload = {
            "name": namespace.getName(),
            "path": namespace.getName(True),
        }
        with suppress(Exception):
            payload["symbol_type"] = str(namespace.getSymbol().getSymbolType())
        with suppress(Exception):
            payload["id"] = int(namespace.getID())
        return payload

    def _external_location_record(self, location: Any) -> dict[str, Any] | None:
        if location is None:
            return None
        payload = {"display": str(location)}
        for attr, field_name in (
            ("getLibraryName", "library_name"),
            ("getLabel", "label"),
            ("getAddress", "address"),
            ("getOriginalImportedName", "original_imported_name"),
        ):
            with suppress(Exception):
                value = getattr(location, attr)()
                payload[field_name] = (
                    self._addr_str(value) if field_name == "address" else str(value)
                )
        with suppress(Exception):
            payload["namespace"] = self._namespace_record(location.getParentNameSpace())
        return payload

    def _ref_type(self, name: str) -> Any:
        from ghidra.program.model.symbol import RefType

        candidate = name.upper()
        if not hasattr(RefType, candidate):
            raise GhidraBackendError(f"unsupported reference_type: {name}")
        return getattr(RefType, candidate)

    def _source_type(self, name: str) -> Any:
        from ghidra.program.model.symbol import SourceType

        candidate = name.upper()
        if not hasattr(SourceType, candidate):
            raise GhidraBackendError(f"unsupported source_type: {name}")
        return getattr(SourceType, candidate)

    def _resolve_reference(
        self,
        session_id: str,
        *,
        from_address: int | str,
        to_address: int | str | None,
        operand_index: int | None,
    ) -> Any:
        from_addr = self._coerce_address(session_id, from_address, "from_address")
        references = list(
            self._get_program(session_id).getReferenceManager().getReferencesFrom(from_addr)
        )
        if to_address is not None:
            to_addr = self._coerce_address(session_id, to_address, "to_address")
            references = [
                item
                for item in references
                if self._addr_str(item.getToAddress()) == self._addr_str(to_addr)
            ]
        if operand_index is not None:
            references = [
                item for item in references if int(item.getOperandIndex()) == operand_index
            ]
        if not references:
            raise GhidraBackendError("reference not found")
        if len(references) > 1:
            raise GhidraBackendError("reference selection is ambiguous")
        return references[0]

    def _equate_record(self, equate: Any) -> dict[str, Any] | None:
        if equate is None:
            return None
        return {
            "name": equate.getName(),
            "display_name": equate.getDisplayName(),
            "value": int(equate.getValue()),
            "display_value": equate.getDisplayValue(),
            "reference_count": int(equate.getReferenceCount()),
            "references": [
                {
                    "address": self._addr_str(ref.getAddress()),
                    "operand_index": int(ref.getOpIndex()),
                    "dynamic_hash": int(ref.getDynamicHashValue()),
                }
                for ref in equate.getReferences()
            ],
        }

    def _source_file_from_args(
        self,
        *,
        path: str,
        id_type: str | None,
        identifier_hex: str | None,
    ) -> Any:
        if not path:
            raise GhidraBackendError("path is required")
        from ghidra.program.database.sourcemap import SourceFile, SourceFileIdType

        if id_type is None:
            return SourceFile(path)
        candidate = id_type.upper()
        if not hasattr(SourceFileIdType, candidate):
            raise GhidraBackendError(f"unsupported id_type: {id_type}")
        try:
            identifier = None if identifier_hex is None else bytes.fromhex(identifier_hex)
        except ValueError as exc:
            raise GhidraBackendError(f"invalid identifier_hex: {exc}") from exc
        return SourceFile(path, getattr(SourceFileIdType, candidate), identifier)

    def _find_source_file(self, manager: Any, path: str) -> Any:
        for source_file in manager.getAllSourceFiles():
            if source_file.getPath() == path:
                return source_file
        raise GhidraBackendError(f"source file not found: {path}")

    def _source_file_record(self, source_file: Any) -> dict[str, Any]:
        identifier = source_file.getIdentifier()
        return {
            "path": source_file.getPath(),
            "filename": source_file.getFilename(),
            "id_type": source_file.getIdType().name(),
            "identifier_hex": None if identifier is None else bytes(identifier).hex(),
        }

    def _source_map_entry_record(self, entry: Any) -> dict[str, Any]:
        return {
            "source_file": self._source_file_record(entry.getSourceFile()),
            "line_number": int(entry.getLineNumber()),
            "base_address": self._addr_str(entry.getBaseAddress()),
            "length": int(entry.getLength()),
            "range": None
            if entry.getRange() is None
            else {
                "start": self._addr_str(entry.getRange().getMinAddress()),
                "end": self._addr_str(entry.getRange().getMaxAddress()),
            },
        }

    def _relocation_record(self, relocation: Any) -> dict[str, Any]:
        payload = {
            "address": self._addr_str(relocation.getAddress()),
            "status": relocation.getStatus().name(),
            "type": int(relocation.getType()),
            "symbol_name": relocation.getSymbolName(),
            "values": [int(value) for value in relocation.getValues()],
        }
        with suppress(Exception):
            payload["bytes"] = bytes(relocation.getBytes()).hex()
        return payload

    def _clone_parameters(self, function: Any) -> list[Any]:
        from ghidra.program.model.listing import ParameterImpl

        return [ParameterImpl(param, function.getProgram()) for param in function.getParameters()]

    def _parameter_from_spec(
        self,
        session_id: str,
        *,
        name: str,
        data_type: str,
        stack_offset: int | None,
        register: str | None,
        fallback: Any | None = None,
    ) -> Any:
        from ghidra.program.model.listing import ParameterImpl
        from ghidra.program.model.symbol import SourceType

        parsed = self._parse_data_type(session_id, data_type)
        program = self._get_program(session_id)
        if fallback is not None and stack_offset is None and register is None:
            param = ParameterImpl(fallback, program)
            param.setName(name, SourceType.USER_DEFINED)
            param.setDataType(parsed, SourceType.USER_DEFINED)
            return param
        if register is not None:
            return ParameterImpl(
                name,
                parsed,
                self._resolve_register(session_id, register),
                program,
                SourceType.USER_DEFINED,
            )
        if stack_offset is not None:
            return ParameterImpl(
                name,
                parsed,
                int(stack_offset),
                program,
                SourceType.USER_DEFINED,
            )
        return ParameterImpl(name, parsed, program, SourceType.USER_DEFINED)

    def _parameter_index(self, params: list[Any], *, ordinal: int | None, name: str | None) -> int:
        matches = []
        for index, param in enumerate(params):
            if (ordinal is not None and int(param.getOrdinal()) == ordinal) or (
                name is not None and param.getName() == name
            ):
                matches.append(index)
        if not matches:
            raise GhidraBackendError("parameter not found")
        if len(matches) > 1:
            raise GhidraBackendError("parameter selection is ambiguous")
        return matches[0]

    def _write_parameters(self, session_id: str, function: Any, params: list[Any]) -> None:
        def mutate() -> None:
            from ghidra.program.model.listing.Function import FunctionUpdateType
            from ghidra.program.model.symbol import SourceType
            from java.util import ArrayList

            java_params = ArrayList()
            for param in params:
                java_params.add(param)

            function.replaceParameters(
                java_params,
                FunctionUpdateType.CUSTOM_STORAGE
                if function.hasCustomVariableStorage()
                else FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                True,
                SourceType.USER_DEFINED,
            )

        self._with_write(session_id, f"Update parameters {function.getName()}", mutate)

    def _resolve_category(self, session_id: str, path: str) -> Any:
        dtm = self._get_program(session_id).getDataTypeManager()
        if path in {"", "/"}:
            return dtm.getRootCategory()
        from ghidra.program.model.data import CategoryPath

        category = dtm.getCategory(CategoryPath(path))
        if category is None:
            raise GhidraBackendError(f"category not found: {path}")
        return category

    def _walk_categories(self, category: Any) -> list[Any]:
        items: list[Any] = []
        for child in category.getCategories():
            items.append(child)
            items.extend(self._walk_categories(child))
        return items

    def _category_record(self, category: Any) -> dict[str, Any]:
        return {
            "name": category.getName(),
            "path": str(category.getCategoryPath()),
            "subcategory_count": len(category.getCategories()),
            "type_count": len(category.getDataTypes()),
        }

    def _source_archive_record(self, archive: Any) -> dict[str, Any]:
        payload = {
            "name": archive.getName(),
            "source_archive_id": int(archive.getSourceArchiveID().getValue()),
        }
        with suppress(Exception):
            payload["path"] = archive.getPath()
        return payload

    def _require_structure(self, data_type: Any) -> Any:
        if not hasattr(data_type, "replaceAtOffset"):
            raise GhidraBackendError("target type is not a structure")
        return data_type

    def _require_union(self, data_type: Any) -> Any:
        if not hasattr(data_type, "delete") or not hasattr(data_type, "add"):
            raise GhidraBackendError("target type is not a union")
        return data_type

    def _require_enum(self, data_type: Any) -> Any:
        if not hasattr(data_type, "remove") or not hasattr(data_type, "getNames"):
            raise GhidraBackendError("target type is not an enum")
        return data_type

    def _component_record(self, component: Any) -> dict[str, Any]:
        return {
            "ordinal": int(component.getOrdinal()),
            "offset": int(component.getOffset()),
            "length": int(component.getLength()),
            "field_name": component.getFieldName(),
            "comment": component.getComment(),
            "data_type": component.getDataType().getPathName(),
        }

    def _components_record(self, composite: Any) -> list[dict[str, Any]]:
        return [self._component_record(component) for component in composite.getComponents()]

    def _resolve_component(
        self,
        composite: Any,
        *,
        offset: int | None,
        ordinal: int | None,
        field_name: str | None,
    ) -> Any:
        matches = []
        for component in composite.getComponents():
            if (
                (offset is not None and int(component.getOffset()) == offset)
                or (ordinal is not None and int(component.getOrdinal()) == ordinal)
                or (field_name is not None and component.getFieldName() == field_name)
            ):
                matches.append(component)
        if not matches:
            raise GhidraBackendError("component not found")
        if len(matches) > 1:
            raise GhidraBackendError("component selection is ambiguous")
        return matches[0]

    def _high_symbol_record(self, high_symbol: Any) -> dict[str, Any]:
        payload = {
            "name": high_symbol.getName(),
            "data_type": high_symbol.getDataType().getPathName(),
            "category_index": int(high_symbol.getCategoryIndex()),
            "is_parameter": bool(high_symbol.isParameter()),
            "is_global": bool(high_symbol.isGlobal()),
            "storage": str(high_symbol.getStorage()),
            "pc_address": self._addr_str(high_symbol.getPCAddress()),
        }
        with suppress(Exception):
            payload["symbol"] = self._symbol_record(high_symbol.getSymbol())
        return payload

    def _find_high_symbol(
        self,
        session_id: str,
        function: Any,
        *,
        name: str,
        ordinal: int | None,
        storage: str | None,
        timeout_secs: int = 30,
        global_only: bool = False,
    ) -> Any:
        high_function = self._high_function(session_id, function, timeout_secs=timeout_secs)
        symbols = []
        if not global_only:
            symbols.extend(list(high_function.getLocalSymbolMap().getSymbols()))
        symbols.extend(list(high_function.getGlobalSymbolMap().getSymbols()))
        matches = []
        for symbol in symbols:
            if symbol is None:
                continue
            if name and symbol.getName() != name:
                continue
            if ordinal is not None and int(symbol.getCategoryIndex()) != ordinal:
                continue
            if storage is not None and str(symbol.getStorage()) != storage:
                continue
            if global_only and not symbol.isGlobal():
                continue
            matches.append(symbol)
        if not matches:
            return None
        if len(matches) > 1:
            raise GhidraBackendError("decompiler symbol selection is ambiguous")
        return matches[0]

    def _update_high_symbol(
        self,
        _session_id: str,
        function: Any,
        high_symbol: Any,
        *,
        name: str | None,
        data_type: Any | None,
    ) -> None:
        from ghidra.program.model.pcode import HighFunctionDBUtil
        from ghidra.program.model.symbol import SourceType

        _ = function
        HighFunctionDBUtil.updateDBVariable(high_symbol, name, data_type, SourceType.USER_DEFINED)

    def _find_override_symbol(self, session_id: str, function: Any, callsite: Any) -> Any:
        _ = function
        from ghidra.program.model.pcode import HighFunctionDBUtil

        for symbol in self._get_program(session_id).getSymbolTable().getSymbols(callsite):
            with suppress(Exception):
                if HighFunctionDBUtil.readOverride(symbol) is not None:
                    return symbol
        return None

    def _decomp_trace_type(
        self,
        session_id: str,
        *,
        function_start: int | str,
        name: str,
        ordinal: int | None,
        storage: str | None,
        timeout_secs: int,
        direction: str,
    ) -> dict[str, Any]:
        function = self._resolve_function(session_id, function_start)
        high_symbol = self._find_high_symbol(
            session_id,
            function,
            name=name,
            ordinal=ordinal,
            storage=storage,
            timeout_secs=timeout_secs,
        )
        if high_symbol is None or high_symbol.getHighVariable() is None:
            raise GhidraBackendError("decompiler symbol not found")
        representative = high_symbol.getHighVariable().getRepresentative()
        from ghidra.app.decompiler.component import DecompilerUtils

        ops = (
            DecompilerUtils.getForwardSliceToPCodeOps(representative)
            if direction == "forward"
            else DecompilerUtils.getBackwardSliceToPCodeOps(representative)
        )
        op_list = list(ops)
        return {
            "session_id": session_id,
            "direction": direction,
            "function": self._function_record(function),
            "symbol": self._high_symbol_record(high_symbol),
            "count": len(op_list),
            "items": [self._pcode_op_record(op) for op in op_list],
        }

    def _decompile_results(self, session_id: str, function: Any, *, timeout_secs: int) -> Any:
        if timeout_secs <= 0:
            raise GhidraBackendError("timeout_secs must be > 0")
        return self._get_decompiler(session_id).decompileFunction(
            function,
            timeout_secs,
            self._pyghidra.task_monitor(timeout_secs),
        )

    def _decompile_payload(self, session_id: str, function: Any, results: Any) -> dict[str, Any]:
        payload = {
            "session_id": session_id,
            "function": self._function_record(function),
            "decompile_completed": bool(results.decompileCompleted()),
            "timed_out": bool(results.isTimedOut()),
            "cancelled": bool(results.isCancelled()),
            "error_message": results.getErrorMessage(),
        }
        decompiled = results.getDecompiledFunction()
        if decompiled is not None:
            payload["c"] = decompiled.getC()
            payload["signature"] = decompiled.getSignature()
        return payload

    def _high_function(self, session_id: str, function: Any, *, timeout_secs: int) -> Any:
        results = self._decompile_results(session_id, function, timeout_secs=timeout_secs)
        high_function = results.getHighFunction()
        if high_function is None:
            raise GhidraBackendError(
                results.getErrorMessage() or "failed to obtain high function from decompiler"
            )
        return high_function

    def _collect_high_pcode_ops(self, high_function: Any) -> list[Any]:
        ops: list[Any] = []
        for block in high_function.getBasicBlocks():
            for op in block.getIterator():
                ops.append(op)
        return ops

    def _varnode_matches(
        self,
        session_id: str,
        candidate: Any,
        *,
        query: str | None,
        address: int | str | None,
        space: str | None,
        size: int | None,
    ) -> bool:
        if candidate is None:
            return False
        record = self._varnode_record(candidate)
        if query is not None:
            needle = query.lower()
            values = [
                str(record.get("address", "")).lower(),
                str(record.get("space", "")).lower(),
                str(record.get("size", "")).lower(),
            ]
            if not any(needle in value for value in values):
                return False
        if address is not None:
            addr = self._coerce_address(session_id, address, "address")
            if record["address"] != self._addr_str(addr):
                return False
        if space is not None and record["space"] != space:
            return False
        return not (size is not None and record["size"] != size)

    def _clang_node_record(self, node: Any) -> dict[str, Any] | None:
        if node is None:
            return None
        payload = {
            "type": node.getClass().getSimpleName(),
            "text": str(node),
            "min_address": self._addr_str(node.getMinAddress()),
            "max_address": self._addr_str(node.getMaxAddress()),
            "child_count": int(node.numChildren()),
        }
        if node.numChildren() > 0:
            payload["children"] = [
                self._clang_node_record(node.Child(index))
                for index in range(int(node.numChildren()))
            ]
        return payload

    def _resolve_call_target(self, target: str, session_id: str | None) -> tuple[Any, str]:
        self._ensure_started()
        if target.startswith("pyghidra."):
            return self._pyghidra, target[9:]
        if target.startswith("program."):
            if session_id is None:
                raise GhidraBackendError(
                    "session_id is required when target starts with 'program.'"
                )
            return self._get_program(session_id), target[8:]
        if target.startswith("project."):
            if session_id is None:
                raise GhidraBackendError(
                    "session_id is required when target starts with 'project.'"
                )
            return self._get_record(session_id).project.getProject(), target[8:]
        if target.startswith("flat_api."):
            if session_id is None:
                raise GhidraBackendError(
                    "session_id is required when target starts with 'flat_api.'"
                )
            return self._get_record(session_id).flat_api, target[9:]
        if target.startswith("decompiler."):
            if session_id is None:
                raise GhidraBackendError(
                    "session_id is required when target starts with 'decompiler.'"
                )
            return self._get_decompiler(session_id), target[11:]
        if target.startswith("ghidra."):
            import ghidra

            return ghidra, target[7:]
        if target.startswith("java."):
            import java

            return java, target[5:]
        raise GhidraBackendError(
            "target must start with pyghidra., program., project., flat_api., decompiler., ghidra., or java."
        )

    def _resolve_attr_path(self, root: Any, attr_path: str) -> Any:
        if not attr_path:
            return root
        obj = root
        for part in attr_path.split("."):
            if not part:
                raise GhidraBackendError("invalid target path")
            if not hasattr(obj, part):
                raise GhidraBackendError(f"attribute not found: {part}")
            obj = getattr(obj, part)
        return obj

    def _eval_context(self, session_id: str | None) -> dict[str, Any]:
        self._ensure_started()
        import ghidra
        import java

        context: dict[str, Any] = {
            "pyghidra": self._pyghidra,
            "ghidra": ghidra,
            "java": java,
            "sessions": {sid: record.program for sid, record in self._sessions.items()},
        }
        if session_id is not None:
            record = self._get_record(session_id)
            context.update(
                {
                    "session_id": session_id,
                    "program": record.program,
                    "project": record.project.getProject(),
                    "ghidra_project": record.project,
                    "flat_api": record.flat_api,
                    "decompiler": self._get_decompiler(session_id),
                    "listing": record.program.getListing(),
                    "memory": record.program.getMemory(),
                    "symbol_table": record.program.getSymbolTable(),
                }
            )
        return context

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

    def _to_jsonable(self, value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, bytes):
            return base64.b64encode(value).decode("ascii")
        if isinstance(value, dict):
            return {str(key): self._to_jsonable(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set, frozenset)):
            return [self._to_jsonable(item) for item in value]
        if hasattr(value, "items"):
            with suppress(Exception):
                return {str(key): self._to_jsonable(item) for key, item in value.items()}
        if hasattr(value, "getEntryPoint") and hasattr(value, "getProgram"):
            return self._function_record(value)
        if hasattr(value, "getPathName") and hasattr(value, "getDisplayName"):
            return self._data_type_record(value)
        if hasattr(value, "getSymbolType") and hasattr(value, "getAddress"):
            return self._symbol_record(value)
        if hasattr(value, "getAddressSpace") and hasattr(value, "getOffset"):
            return self._addr_str(value)
        if hasattr(value, "getBytes") and hasattr(value, "toString"):
            with suppress(Exception):
                return str(value)
        if hasattr(value, "toArray"):
            with suppress(Exception):
                return [self._to_jsonable(item) for item in value.toArray()]
        if hasattr(value, "iterator"):
            with suppress(Exception):
                return [self._to_jsonable(item) for item in value]
        return str(value)
