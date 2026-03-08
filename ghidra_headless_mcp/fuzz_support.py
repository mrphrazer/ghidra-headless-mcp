"""Shared fuzz fixtures and argument generation for fake and live backends."""

from __future__ import annotations

import base64
import os
import shutil
import tempfile
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .backend import GhidraBackend
from .fake_ghidra import FakeGhidraBackend
from .server import ALL_TOOL_SPECS, SimpleMcpServer

TOOL_SPECS_BY_NAME = {spec["name"]: spec for spec in ALL_TOOL_SPECS}
DEFAULT_SAMPLE_BINARY_PATH = Path(__file__).resolve().parents[1] / "samples" / "ls"


@dataclass
class ToolContext:
    backend: Any
    server: SimpleMcpServer
    session_id: str
    task_id: str | None
    mode: str = "fake"
    live_case: LiveCaseState | None = None
    cleanup: Callable[[], None] | None = None


@dataclass(frozen=True)
class LiveSeedState:
    sample_path: str
    sample_bytes_base64: str
    project_name: str
    program_name: str
    program_path: str
    primary_function_start: str
    primary_function_name: str
    primary_function_end: str
    primary_local_name: str
    decomp_local_name: str
    decomp_global_name: str
    param_function_start: str
    param_function_name: str
    param_name: str
    local_function_start: str
    local_function_name: str
    local_name: str
    callsite: str
    call_target: str
    reference_seed_from: str
    reference_create_from: str
    conditional_branch: str
    writable_address: str
    data_address: str
    string_address: str
    string_text: str
    free_memory_address: str
    external_address: str
    helper_function_start: str
    helper_function_name: str
    create_function_start: str
    create_function_name: str
    context_address: str
    context_register: str
    instruction_address: str
    next_instruction_address: str
    instruction_mnemonic: str
    equate_address: str
    equate_operand_index: int
    image_base: str
    rebased_image_base: str
    calling_convention_name: str | None
    analysis_boolean_option_name: str


@dataclass(frozen=True)
class LiveFuzzEnvironment:
    backend: GhidraBackend
    server: SimpleMcpServer
    template_root: str
    ghidra_install_dir: str
    seed: LiveSeedState


@dataclass(frozen=True)
class LiveCaseState:
    seed: LiveSeedState
    project_location: str
    project_name: str
    program_name: str
    program_path: str
    script_path: str
    export_binary_path: str
    export_project_destination: str
    external_library_path: str
    created_category_path: str
    created_struct_name: str
    created_union_name: str
    created_enum_name: str
    created_namespace_name: str
    created_class_name: str
    created_symbol_name: str
    renamed_symbol_name: str
    created_tag_name: str
    created_bookmark_category: str
    created_source_path: str
    created_external_library_name: str
    seed_external_library_name: str
    seed_external_label: str
    created_external_label: str
    created_external_function_name: str
    seed_type_name: str
    seed_type_path: str
    seed_type_id: int | None
    seed_type_universal_id: int | None
    seed_type_source_archive_id: int | None
    renamed_type_name: str
    task_id: str | None


def tool_spec(name: str) -> dict[str, Any]:
    try:
        return TOOL_SPECS_BY_NAME[name]
    except KeyError as exc:  # pragma: no cover - defensive guard
        raise AssertionError(f"tool spec not found: {name}") from exc


def resolve_sample_binary_path(sample_path: str | None = None) -> str:
    path = Path(sample_path) if sample_path is not None else DEFAULT_SAMPLE_BINARY_PATH
    return str(path.resolve())


def seed_common_state(backend: FakeGhidraBackend, session_id: str) -> None:
    backend.context_set(session_id, register="TMode", start="0x1000", length=16, value=1)
    backend.namespace_create(session_id, name="MovedNs")
    backend.symbol_create(session_id, address="0x1040", name="main_label")
    backend.comment_set(
        session_id,
        address="0x1040",
        comment_type="eol",
        scope="listing",
        comment="demo comment",
    )
    backend.comment_set(
        session_id,
        function_start="0x1040",
        comment_type="plate",
        scope="function",
        comment="demo function comment",
    )
    backend.bookmark_add(
        session_id,
        address="0x1040",
        bookmark_type="Info",
        category="RE",
        comment="demo",
    )
    backend.tag_add(session_id, function_start="0x1040", name="entrypoint")
    backend.reference_create_memory(session_id, from_address="0x1048", to_address="0x1010")
    backend.equate_create(session_id, address="0x1044", name="ANSWER", value=42)
    backend.source_file_add(session_id, path="/tmp/demo.c")
    backend.source_map_add(
        session_id,
        path="/tmp/demo.c",
        line_number=12,
        base_address="0x1040",
        length=4,
    )
    backend.external_library_create(session_id, name="libdemo.so")
    backend.external_library_set_path(session_id, name="libdemo.so", path="/tmp/libdemo.so")
    backend.external_location_create(
        session_id,
        library_name="libdemo.so",
        label="puts",
        external_address="0x4000",
    )
    backend.external_entrypoint_add(session_id, address="0x4000")
    backend.type_category_create(session_id, path="/mcp")
    backend.layout_struct_create(session_id, name="demo_struct", category="/mcp")
    backend.layout_struct_field_add(
        session_id,
        struct_path="/mcp/demo_struct",
        field_name="field0",
        data_type="/int",
    )
    backend.layout_union_create(session_id, name="demo_union", category="/mcp")
    backend.layout_union_member_add(
        session_id,
        union_path="/mcp/demo_union",
        field_name="member0",
        data_type="/int",
    )
    backend.layout_enum_create(session_id, name="demo_enum", category="/mcp")
    backend.layout_enum_member_add(
        session_id,
        enum_path="/mcp/demo_enum",
        name="ITEM",
        value=1,
    )
    backend.function_create(session_id, address="0x1200", name="helper_stub")
    backend.parameter_add(session_id, function_start="0x1200", name="x", data_type="/int")
    backend.variable_local_create(session_id, function_start="0x1200", name="tmp", data_type="/int")
    backend.stackframe_variable_create(
        session_id,
        function_start="0x1200",
        name="saved_rbp",
        stack_offset=8,
        data_type="/int",
    )


def create_tool_context(*, seed: bool = True, sample_path: str | None = None) -> ToolContext:
    backend = FakeGhidraBackend()
    opened = backend.program_open(
        resolve_sample_binary_path(sample_path),
        read_only=False,
        update_analysis=False,
    )
    session_id = opened["session_id"]
    task_id = backend.task_analysis_update(session_id)["task_id"]
    if seed:
        seed_common_state(backend, session_id)
    return ToolContext(
        backend=backend,
        server=SimpleMcpServer(backend),
        session_id=session_id,
        task_id=task_id,
    )


def resolve_ghidra_install_dir(install_dir: str | None = None) -> str:
    if install_dir:
        return str(Path(install_dir).resolve())
    env_value = os.environ.get("GHIDRA_INSTALL_DIR")
    if env_value:
        return str(Path(env_value).resolve())
    system_install = Path("/usr/share/ghidra")
    if system_install.exists():
        return str(system_install.resolve())
    raise RuntimeError("GHIDRA_INSTALL_DIR is not set and /usr/share/ghidra is unavailable")


def _ensure_live_ghidra_env() -> None:
    config_root = os.environ.setdefault("XDG_CONFIG_HOME", "/tmp/codex-config")
    Path(config_root).mkdir(parents=True, exist_ok=True)


def _address_to_int(address: Any) -> int:
    try:
        return int(address.getOffset())
    except Exception:
        text = str(address)
        if ":" in text:
            _, _, text = text.rpartition(":")
        return int(text, 16)


def _format_address(value: int) -> str:
    return f"{int(value):08x}"


def _select_primary_function(
    backend: GhidraBackend,
    session_id: str,
    functions: list[dict[str, Any]],
) -> dict[str, Any]:
    preferred = backend.function_by_name(session_id, "FUN_00104900", exact=True, limit=1)["items"]
    if preferred:
        return preferred[0]
    ranked: list[tuple[int, dict[str, Any]]] = []
    for item in functions:
        variables = backend.function_variables(session_id, item["entry_point"])
        score = len(variables["locals"]) * 4 + len(variables["parameters"])
        with suppress(Exception):
            summary = backend.decomp_high_function_summary(
                session_id, function_start=item["entry_point"]
            )
            score += int(summary.get("global_symbol_count", 0))
        ranked.append((score, item))
    ranked.sort(key=lambda pair: pair[0], reverse=True)
    if not ranked:
        raise RuntimeError("no functions available in live sample")
    return ranked[0][1]


def _select_param_function(
    backend: GhidraBackend,
    session_id: str,
    functions: list[dict[str, Any]],
) -> tuple[dict[str, Any], str]:
    preferred_names = ("memcpy", "getcwd", "fwrite_unlocked")
    for name in preferred_names:
        matches = backend.function_by_name(session_id, name, exact=True, limit=1)["items"]
        if matches:
            variables = backend.function_variables(session_id, matches[0]["entry_point"])
            if variables["parameters"]:
                return matches[0], variables["parameters"][0]["name"]
    for item in functions:
        variables = backend.function_variables(session_id, item["entry_point"])
        if variables["parameters"]:
            return item, variables["parameters"][0]["name"]
    raise RuntimeError("no function with parameters found in live sample")


def _select_local_function(
    backend: GhidraBackend,
    session_id: str,
    functions: list[dict[str, Any]],
) -> tuple[dict[str, Any], str]:
    for item in functions:
        variables = backend.function_variables(session_id, item["entry_point"])
        if variables["locals"]:
            return item, variables["locals"][0]["name"]
    raise RuntimeError("no function with locals found in live sample")


def _find_call_reference(
    backend: GhidraBackend,
    session_id: str,
    function_start: str,
    function_end: str,
) -> tuple[str, str]:
    refs = backend.xref_from(session_id, start=function_start, end=function_end, limit=1_000)[
        "items"
    ]
    for item in refs:
        if "CALL" not in str(item.get("reference_type", "")).upper():
            continue
        target = str(item.get("to", ""))
        with suppress(Exception):
            backend.binary_get_function_at(session_id, target)
            return str(item["from"]), target
    raise RuntimeError("no callable xref found in live sample")


def _find_function_gaps(functions: list[dict[str, Any]]) -> list[tuple[int, int]]:
    ordered = sorted(functions, key=lambda item: int(item["entry_point"], 16))
    gaps: list[tuple[int, int]] = []
    previous_end: int | None = None
    for item in ordered:
        start = int(item["entry_point"], 16)
        if previous_end is not None and start - previous_end > 8:
            gaps.append((previous_end + 1, start - 1))
        previous_end = int(item["body_end"], 16)
    return gaps


def _find_instruction_points(
    backend: GhidraBackend, session_id: str, function_start: str
) -> tuple[str, str, str]:
    program = backend._get_program(session_id)
    listing = program.getListing()
    address_factory = program.getAddressFactory()
    instruction = listing.getInstructionAt(address_factory.getAddress(function_start))
    if instruction is None:
        raise RuntimeError("no instruction at primary function start")
    next_instruction = instruction.getNext()
    if next_instruction is None:
        raise RuntimeError("primary function has only one instruction")
    return (
        _format_address(_address_to_int(instruction.getAddress())),
        _format_address(_address_to_int(next_instruction.getAddress())),
        instruction.getMnemonicString().lower(),
    )


def _find_scalar_operand(
    backend: GhidraBackend, session_id: str, function_start: str
) -> tuple[str, int]:
    program = backend._get_program(session_id)
    listing = program.getListing()
    address_factory = program.getAddressFactory()
    instruction = listing.getInstructionAt(address_factory.getAddress(function_start))
    while instruction is not None:
        for operand_index in range(int(instruction.getNumOperands())):
            with suppress(Exception):
                scalar = instruction.getScalar(operand_index)
                if scalar is not None:
                    return _format_address(_address_to_int(instruction.getAddress())), operand_index
        instruction = instruction.getNext()
    raise RuntimeError("no scalar operand found for live equate seeding")


def _find_conditional_branch(backend: GhidraBackend, session_id: str, function_start: str) -> str:
    program = backend._get_program(session_id)
    listing = program.getListing()
    address_factory = program.getAddressFactory()
    instruction = listing.getInstructionAt(address_factory.getAddress(function_start))
    while instruction is not None:
        mnemonic = instruction.getMnemonicString().lower()
        if (mnemonic.startswith("b.") and mnemonic not in {"b", "bl"}) or mnemonic in {
            "cbz",
            "cbnz",
            "tbz",
            "tbnz",
            "je",
            "jne",
            "jz",
            "jnz",
        }:
            return _format_address(_address_to_int(instruction.getAddress()))
        instruction = instruction.getNext()
    raise RuntimeError("no conditional branch found in live sample")


def _select_decompiler_struct_symbol(
    backend: GhidraBackend,
    session_id: str,
    function_start: str,
    candidate_names: list[str],
) -> str:
    function = backend._resolve_function(session_id, function_start)
    program = backend._get_program(session_id)
    from ghidra.app.decompiler.util import FillOutStructureHelper

    for candidate_name in candidate_names:
        high_symbol = backend._find_high_symbol(
            session_id,
            function,
            name=candidate_name,
            ordinal=None,
            storage=None,
        )
        if high_symbol is None or high_symbol.getHighVariable() is None:
            continue
        tx_id = int(program.startTransaction(f"Probe struct fill {candidate_name}"))
        try:
            helper = FillOutStructureHelper(program, backend._pyghidra.task_monitor(5))
            created = helper.processStructure(
                high_symbol.getHighVariable(),
                function,
                True,
                False,
                backend._get_decompiler(session_id),
            )
            if created is not None:
                return candidate_name
        except Exception:
            continue
        finally:
            program.endTransaction(tx_id, False)
    return candidate_names[0]


def _find_memory_gap(backend: GhidraBackend, session_id: str) -> str:
    program = backend._get_program(session_id)
    blocks = sorted(
        program.getMemory().getBlocks(), key=lambda item: _address_to_int(item.getStart())
    )
    previous = None
    for block in blocks:
        space_name = block.getStart().getAddressSpace().getName()
        start = _address_to_int(block.getStart())
        end = _address_to_int(block.getEnd())
        if previous is not None and previous[2] == space_name and start - previous[1] > 0x100:
            candidate = previous[1] + 0x20
            return _format_address(candidate)
        previous = (start, end, space_name)
    raise RuntimeError("no free memory gap found for live fuzzing")


def _derive_live_seed_state(
    backend: GhidraBackend,
    session_id: str,
    *,
    sample_path: str,
    sample_bytes_base64: str,
    project_name: str,
    program_name: str,
    program_path: str,
) -> LiveSeedState:
    functions = backend.binary_functions(session_id, offset=0, limit=2_000)["items"]
    primary = _select_primary_function(backend, session_id, functions)
    param_function, param_name = _select_param_function(backend, session_id, functions)
    local_function, local_name = _select_local_function(backend, session_id, functions)
    primary_summary = backend.decomp_high_function_summary(
        session_id, function_start=primary["entry_point"]
    )
    local_symbols = [
        item
        for item in primary_summary["local_symbols"]
        if not item.get("is_global") and not item.get("is_parameter")
    ]
    global_symbols = [item for item in primary_summary["global_symbols"] if item.get("name")]
    if not local_symbols:
        raise RuntimeError("no decompiler local symbols found in live sample")
    if not global_symbols:
        raise RuntimeError("no decompiler global symbols found in live sample")
    decomp_local_name = _select_decompiler_struct_symbol(
        backend,
        session_id,
        primary["entry_point"],
        [str(item["name"]) for item in local_symbols if item.get("name")],
    )
    callsite, call_target = _find_call_reference(
        backend,
        session_id,
        primary["entry_point"],
        primary["body_end"],
    )
    writable_blocks = [
        item for item in backend.binary_memory_blocks(session_id)["items"] if item["write"]
    ]
    if not writable_blocks:
        raise RuntimeError("no writable memory blocks found in live sample")
    strings = backend.binary_strings(session_id, query="Usage", limit=1)["items"]
    if not strings:
        strings = backend.binary_strings(session_id, offset=0, limit=1)["items"]
    if not strings:
        raise RuntimeError("no strings found in live sample")
    gaps = _find_function_gaps(functions)
    aligned_gaps = [
        (_format_address(start + ((4 - (start % 4)) % 4)), end)
        for start, end in gaps
        if end - start >= 0x20
    ]
    if len(aligned_gaps) < 2:
        raise RuntimeError("not enough function gaps found for live fuzzing")
    helper_function_start = aligned_gaps[0][0]
    create_function_start = aligned_gaps[1][0]
    context_address = create_function_start
    instruction_address, next_instruction_address, instruction_mnemonic = _find_instruction_points(
        backend,
        session_id,
        primary["entry_point"],
    )
    equate_address, equate_operand_index = _find_scalar_operand(
        backend,
        session_id,
        primary["entry_point"],
    )
    conditional_branch = _find_conditional_branch(backend, session_id, primary["entry_point"])
    free_memory_address = _find_memory_gap(backend, session_id)
    context_register = (
        backend._get_program(session_id).getProgramContext().getBaseContextRegister().getName()
    )
    calling_conventions = backend.function_calling_conventions_list(session_id)["items"]
    analysis_boolean_options = backend.analysis_analyzers_list(session_id, offset=0, limit=100)[
        "items"
    ]
    external_blocks = [
        item
        for item in backend.binary_memory_blocks(session_id)["items"]
        if item["name"] == "EXTERNAL"
    ]
    image_base_int = int(str(backend.binary_summary(session_id)["image_base"]), 16)
    return LiveSeedState(
        sample_path=sample_path,
        sample_bytes_base64=sample_bytes_base64,
        project_name=project_name,
        program_name=program_name,
        program_path=program_path,
        primary_function_start=primary["entry_point"],
        primary_function_name=primary["name"],
        primary_function_end=primary["body_end"],
        primary_local_name=backend.function_variables(session_id, primary["entry_point"])["locals"][
            0
        ]["name"],
        decomp_local_name=decomp_local_name,
        decomp_global_name=global_symbols[0]["name"],
        param_function_start=param_function["entry_point"],
        param_function_name=param_function["name"],
        param_name=param_name,
        local_function_start=local_function["entry_point"],
        local_function_name=local_function["name"],
        local_name=local_name,
        callsite=callsite,
        call_target=call_target,
        reference_seed_from=helper_function_start,
        reference_create_from=create_function_start,
        conditional_branch=conditional_branch,
        writable_address=writable_blocks[0]["start"],
        data_address=writable_blocks[0]["start"],
        string_address=str(strings[0]["address"]),
        string_text=str(strings[0]["value"]),
        free_memory_address=free_memory_address,
        external_address=external_blocks[0]["start"] if external_blocks else call_target,
        helper_function_start=helper_function_start,
        helper_function_name="helper_stub",
        create_function_start=create_function_start,
        create_function_name="helper_stub_2",
        context_address=context_address,
        context_register=context_register,
        instruction_address=instruction_address,
        next_instruction_address=next_instruction_address,
        instruction_mnemonic=instruction_mnemonic,
        equate_address=equate_address,
        equate_operand_index=equate_operand_index,
        image_base=_format_address(image_base_int),
        rebased_image_base=_format_address(image_base_int + 0x100000),
        calling_convention_name=calling_conventions[0] if calling_conventions else None,
        analysis_boolean_option_name=analysis_boolean_options[0]["name"]
        if analysis_boolean_options
        else "Decompiler Parameter ID",
    )


def create_live_fuzz_environment(
    *,
    sample_path: str | None = None,
    ghidra_install_dir: str | None = None,
) -> LiveFuzzEnvironment:
    _ensure_live_ghidra_env()
    import pyghidra

    resolved_sample_path = resolve_sample_binary_path(sample_path)
    resolved_install_dir = resolve_ghidra_install_dir(ghidra_install_dir)
    template_root = tempfile.mkdtemp(prefix="ghidra_headless_mcp_live_fuzz_template_")
    project_name = "live_fuzz_template"
    with open(resolved_sample_path, "rb") as handle:
        sample_bytes_base64 = base64.b64encode(handle.read()).decode("ascii")
    backend = GhidraBackend(pyghidra, install_dir=resolved_install_dir)
    server = SimpleMcpServer(backend)
    session_id = None
    try:
        opened = backend.session_open(
            resolved_sample_path,
            read_only=False,
            update_analysis=False,
            project_location=template_root,
            project_name=project_name,
        )
        session_id = opened["session_id"]
        backend.analysis_update_and_wait(session_id)
        backend.session_save(session_id)
        seed = _derive_live_seed_state(
            backend,
            session_id,
            sample_path=resolved_sample_path,
            sample_bytes_base64=sample_bytes_base64,
            project_name=project_name,
            program_name=opened["program_name"],
            program_path=opened["program_path"],
        )
    finally:
        if session_id is not None:
            with suppress(Exception):
                backend.session_close(session_id)
    return LiveFuzzEnvironment(
        backend=backend,
        server=server,
        template_root=template_root,
        ghidra_install_dir=resolved_install_dir,
        seed=seed,
    )


def _lookup_data_type_ids(
    backend: GhidraBackend, session_id: str, type_name: str
) -> tuple[int | None, int | None, int | None]:
    program = backend._get_program(session_id)
    data_type = program.getDataTypeManager().findDataType(f"/{type_name}")
    if data_type is None:
        matches = backend.type_get(session_id, name=type_name)
        data_type = program.getDataTypeManager().findDataType(matches["type"]["path"])
    data_type_id = None
    universal_id = None
    source_archive_id = None
    with suppress(Exception):
        data_type_id = int(data_type.getID())
    with suppress(Exception):
        uid = data_type.getUniversalID()
        universal_id = None if uid is None else int(uid.getValue())
    with suppress(Exception):
        source = data_type.getSourceArchive()
        if source is not None and source.getSourceArchiveID() is not None:
            source_archive_id = int(source.getSourceArchiveID().getValue())
    return data_type_id, universal_id, source_archive_id


def seed_live_state(backend: GhidraBackend, session_id: str, seed: LiveSeedState) -> LiveCaseState:
    seed_external_library_name = "libdemo.so"
    seed_external_label = "mcp_puts"
    backend.context_set(
        session_id,
        register=seed.context_register,
        start=seed.context_address,
        length=16,
        value=1,
    )
    backend.namespace_create(session_id, name="MovedNs")
    backend.annotation_symbol_create(
        session_id, address=seed.primary_function_start, name="main_label"
    )
    backend.annotation_comment_set(
        session_id,
        address=seed.primary_function_start,
        comment_type="eol",
        scope="listing",
        comment="demo comment",
    )
    backend.annotation_comment_set(
        session_id,
        function_start=seed.primary_function_start,
        comment_type="plate",
        scope="function",
        comment="demo function comment",
    )
    backend.bookmark_add(
        session_id,
        address=seed.primary_function_start,
        bookmark_type="Info",
        category="RE",
        comment="demo",
    )
    backend.tag_add(session_id, function_start=seed.primary_function_start, name="entrypoint")
    backend.reference_create_memory(
        session_id,
        from_address=seed.reference_seed_from,
        to_address=seed.call_target,
    )
    backend.equate_create(
        session_id,
        address=seed.equate_address,
        name="ANSWER",
        value=42,
        operand_index=seed.equate_operand_index,
    )
    backend.source_file_add(session_id, path="/tmp/demo.c")
    backend.source_map_add(
        session_id,
        path="/tmp/demo.c",
        line_number=12,
        base_address=seed.primary_function_start,
        length=4,
    )
    backend.external_library_create(session_id, name=seed_external_library_name)
    backend.external_library_set_path(
        session_id,
        name=seed_external_library_name,
        path="/tmp/libdemo.so",
    )
    backend.external_location_create(
        session_id,
        library_name=seed_external_library_name,
        label=seed_external_label,
        external_address=seed.external_address,
    )
    backend.external_entrypoint_add(session_id, address=seed.call_target)
    backend.type_category_create(session_id, path="/mcp")
    backend.struct_create(session_id, name="demo_struct", category="/mcp")
    backend.struct_field_add(
        session_id,
        struct_path="/mcp/demo_struct",
        field_name="field0",
        data_type="int",
    )
    backend.layout_union_create(session_id, name="demo_union", category="/mcp")
    backend.layout_union_member_add(
        session_id,
        union_path="/mcp/demo_union",
        field_name="member0",
        data_type="int",
    )
    backend.enum_create(session_id, name="demo_enum", category="/mcp")
    backend.enum_member_add(
        session_id,
        enum_path="/mcp/demo_enum",
        name="ITEM",
        value=1,
    )
    backend.type_define_c(session_id, declaration="int", name="seed_demo_int")
    backend.listing_disassemble_seed(session_id, address=seed.helper_function_start, limit=8)
    backend.function_create(
        session_id, address=seed.helper_function_start, name=seed.helper_function_name
    )
    backend.parameter_add(
        session_id,
        function_start=seed.helper_function_start,
        name="x",
        data_type="int",
    )
    backend.variable_local_create(
        session_id,
        function_start=seed.helper_function_start,
        name="tmp",
        data_type="int",
    )
    backend.stackframe_variable_create(
        session_id,
        function_start=seed.helper_function_start,
        name="saved_fp",
        stack_offset=8,
        data_type="int",
    )
    data_type_id, universal_id, source_archive_id = _lookup_data_type_ids(
        backend,
        session_id,
        "seed_demo_int",
    )
    project_root = backend.binary_summary(session_id)["project_location"]
    script_path = str(Path(project_root) / "demo_live_script.py")
    Path(script_path).write_text(
        "print(currentProgram.getName())\n",
        encoding="utf-8",
    )
    return LiveCaseState(
        seed=seed,
        project_location=project_root,
        project_name=seed.project_name,
        program_name=seed.program_name,
        program_path=seed.program_path,
        script_path=script_path,
        export_binary_path=str(Path(project_root) / "out.bin"),
        export_project_destination=str(Path(project_root) / "exported_project"),
        external_library_path="/tmp/libdemo.so",
        created_category_path="/mcp2",
        created_struct_name="fresh_struct",
        created_union_name="fresh_union",
        created_enum_name="fresh_enum",
        created_namespace_name="ExtraNs",
        created_class_name="ExtraClass",
        created_symbol_name="extra_label",
        renamed_symbol_name="main_label_2",
        created_tag_name="triage",
        created_bookmark_category="QA",
        created_source_path="/tmp/demo2.c",
        created_external_library_name="libdemo_extra.so",
        seed_external_library_name=seed_external_library_name,
        seed_external_label=seed_external_label,
        created_external_label="mcp_puts_2",
        created_external_function_name="mcp_puts_3",
        seed_type_name="seed_demo_int",
        seed_type_path="/seed_demo_int",
        seed_type_id=data_type_id,
        seed_type_universal_id=universal_id,
        seed_type_source_archive_id=source_archive_id,
        renamed_type_name="seed_demo_int2",
        task_id=None,
    )


def create_live_tool_context(
    env: LiveFuzzEnvironment,
    *,
    seed: bool = True,
) -> ToolContext:
    case_root = tempfile.mkdtemp(prefix="ghidra_headless_mcp_live_case_")
    shutil.copytree(env.template_root, case_root, dirs_exist_ok=True)
    opened = env.backend.session_open_existing(
        case_root,
        env.seed.project_name,
        program_name=env.seed.program_name,
        read_only=False,
        update_analysis=False,
    )
    session_id = opened["session_id"]
    live_case = seed_live_state(env.backend, session_id, env.seed) if seed else None

    def cleanup() -> None:
        session_ids = [
            current_session_id
            for current_session_id, record in list(env.backend._sessions.items())
            if record.project_location == case_root
        ]
        for current_session_id in session_ids:
            with suppress(Exception):
                env.backend.session_close(current_session_id)
        shutil.rmtree(case_root, ignore_errors=True)

    return ToolContext(
        backend=env.backend,
        server=env.server,
        session_id=session_id,
        task_id=live_case.task_id if live_case is not None else None,
        mode="live",
        live_case=live_case,
        cleanup=cleanup,
    )


def close_live_fuzz_environment(env: LiveFuzzEnvironment) -> None:
    for session_id in list(env.backend._sessions):
        with suppress(Exception):
            env.backend.session_close(session_id)
    env.backend.shutdown()
    shutil.rmtree(env.template_root, ignore_errors=True)


def _schema_type(schema: dict[str, Any]) -> Any:
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        return next((item for item in schema_type if item != "null"), None)
    return schema_type


def default_value(
    tool_name: str,
    key: str,
    session_id: str,
    task_id: str | None,
    *,
    schema: dict[str, Any] | None = None,
    sample_path: str | None = None,
) -> Any:
    resolved_sample_path = resolve_sample_binary_path(sample_path)
    sample_program_path = f"/{Path(resolved_sample_path).name}"
    base: dict[str, Any] = {
        "action": "report",
        "address": "0x1040",
        "args": [],
        "assembly": "nop",
        "base_address": "0x1040",
        "bit_offset": 0,
        "bit_size": 1,
        "bookmark_type": "Info",
        "byte_length": 4,
        "byte_offset": 0,
        "byte_width": 4,
        "callsite": "0x1048",
        "case_sensitive": False,
        "category": "/mcp",
        "clear": False,
        "clear_analysis_references": False,
        "clear_bookmarks": False,
        "clear_comments": False,
        "clear_context": False,
        "clear_default_references": False,
        "clear_equates": False,
        "clear_existing": True,
        "clear_functions": False,
        "clear_import_references": False,
        "clear_properties": False,
        "clear_registers": False,
        "clear_symbols": False,
        "clear_undo": False,
        "clear_user_references": False,
        "code": "1+1",
        "comment": "demo comment",
        "comment_type": "eol",
        "commit": True,
        "commit_return": True,
        "compiler": "gcc",
        "content_type": "Program",
        "count": 4,
        "create_class_if_needed": False,
        "create_new_structure": True,
        "custom_storage": False,
        "data_base64": "AA==",
        "data_hex": "9090",
        "data_type": "/int",
        "data_type_id": 1,
        "declaration": "typedef int demo_int;",
        "defined_strings_only": False,
        "description": "demo namespace",
        "destination": "/tmp/export.gpr",
        "deterministic": True,
        "enabled": True,
        "encoding": "utf-8",
        "end": "0x1008",
        "end_address": "0x1008",
        "endian": "little",
        "enum_name": "demo_enum",
        "enum_path": "/mcp/demo_enum",
        "exact": False,
        "execute": True,
        "external_address": "0x4010",
        "favorite": True,
        "field_name": "field1",
        "filename": "sample.bin",
        "fill": 0,
        "first_use_offset": None,
        "folder_path": "/",
        "format": "binary",
        "forward": True,
        "from_address": "0x1048",
        "function_start": "0x1040",
        "id_type": "md5",
        "identifier_hex": "00112233445566778899aabbccddeeff",
        "image_base": "0x2000",
        "include_dynamic": False,
        "include_function": True,
        "initialized": True,
        "inline": False,
        "key": "triage.owner",
        "kwargs": {},
        "label": "puts2",
        "language": "x86:LE:64:default",
        "length": 4,
        "library_name": "libdemo.so",
        "line_number": 12,
        "loader": "default",
        "make_primary": True,
        "max_depth": 4,
        "max_line": 50,
        "min_line": 1,
        "name": "demo_name",
        "namespace": "MovedNs",
        "new_name": "demo_name_2",
        "new_ordinal": 0,
        "noreturn": False,
        "offset": 0,
        "old_name": "main_label",
        "operand_index": 0,
        "ordinal": 0,
        "overwrite": True,
        "parent": "Global",
        "prefix": "main",
        "program_name": "saved.bin",
        "program_path": sample_program_path,
        "project_location": "/tmp/project",
        "project_name": "demo_project",
        "query": "main",
        "read": True,
        "read_only": False,
        "recursive": True,
        "reference_type": "CALL",
        "register": "TMode",
        "revert_active": True,
        "scope": "listing",
        "script_args": [],
        "session_id": session_id,
        "signature": "int puts(char *s)",
        "signed": False,
        "size": 4,
        "source_archive_id": 1,
        "source_function": "0x1040",
        "source_type": "USER_DEFINED",
        "space": "ram",
        "stack_offset": 8,
        "start": "0x1000",
        "status": "completed",
        "storage": "stack[0x0]:4",
        "storage_address": "stack:0x0",
        "struct_name": "demo_struct",
        "struct_path": "/mcp/demo_struct",
        "symbol_address": "0x1040",
        "symbol_name": "main_label",
        "target": "fake.target",
        "target_function": "0x1010",
        "task_id": task_id or "pending-task",
        "text": "Hello",
        "thunk_target": "0x1010",
        "timeout_secs": 1,
        "to_address": "0x1010",
        "type": 7,
        "union_name": "demo_union",
        "union_path": "/mcp/demo_union",
        "universal_id": 1,
        "update_analysis": False,
        "use_data_types": True,
        "user_defined": True,
        "value": 1,
        "values": [1, 2],
        "varargs": False,
        "varnode": "register:RAX",
        "write": True,
    }
    if key == "path":
        if tool_name == "program.open":
            return resolved_sample_path
        if tool_name == "project.program.open":
            return sample_program_path
        if tool_name == "program.export_binary":
            return "/tmp/out.bin"
        if tool_name.startswith("source.file.") or tool_name.startswith("source.map."):
            return "/tmp/demo.c"
        if tool_name.startswith("type.category."):
            return "/mcp"
        if tool_name.startswith("type.favorite."):
            return "/int"
        if tool_name == "type.get":
            return "/int"
        if tool_name == "external.library.set_path":
            return "/tmp/libdemo.so"
        if tool_name == "ghidra.script":
            return "/tmp/demo.py"
        return "/mcp/demo_struct"
    if key in base:
        return base[key]
    schema = schema or {}
    schema_type = _schema_type(schema)
    if schema_type == "boolean":
        return False
    if schema_type == "integer":
        return 1
    if schema_type == "number":
        return 1
    if schema_type == "array":
        return []
    if schema_type == "object":
        return {}
    return "demo"


def _ensure_live_task_id(context: ToolContext) -> str:
    if context.task_id is None:
        context.task_id = context.backend.task_analysis_update(context.session_id)["task_id"]
    return context.task_id


def _apply_live_tool_overrides(
    tool_name: str,
    arguments: dict[str, Any],
    context: ToolContext,
) -> dict[str, Any]:
    if context.live_case is None:
        return arguments
    case = context.live_case
    seed = case.seed
    task_id = context.task_id
    if tool_name.startswith("task."):
        task_id = _ensure_live_task_id(context)

    text_query = "Usage"
    pattern_hex = text_query.encode("utf-8").hex()
    helper_end = _format_address(int(seed.helper_function_start, 16) + 0x10)
    live_overrides: dict[str, dict[str, Any]] = {
        "ghidra.call": {
            "session_id": context.session_id,
            "target": "program.getName",
            "args": [],
            "kwargs": {},
        },
        "ghidra.eval": {
            "session_id": context.session_id,
            "code": "program.getName()",
        },
        "ghidra.script": {
            "session_id": context.session_id,
            "path": case.script_path,
            "script_args": [],
        },
        "analysis.options.get": {
            "session_id": context.session_id,
            "name": seed.analysis_boolean_option_name,
        },
        "analysis.options.set": {
            "session_id": context.session_id,
            "name": seed.analysis_boolean_option_name,
            "value": False,
        },
        "analysis.analyzers.set": {
            "session_id": context.session_id,
            "name": seed.analysis_boolean_option_name,
            "enabled": False,
        },
        "bookmark.add": {
            "session_id": context.session_id,
            "address": seed.helper_function_start,
            "bookmark_type": "Info",
            "category": case.created_bookmark_category,
            "comment": "live bookmark",
        },
        "bookmark.clear": {
            "session_id": context.session_id,
            "start": seed.primary_function_start,
            "length": 1,
            "bookmark_type": "Info",
        },
        "bookmark.remove": {
            "session_id": context.session_id,
            "address": seed.primary_function_start,
            "bookmark_type": "Info",
            "category": "RE",
        },
        "comment.get": {
            "session_id": context.session_id,
            "address": seed.primary_function_start,
            "scope": "listing",
            "comment_type": "eol",
        },
        "comment.set": {
            "session_id": context.session_id,
            "address": seed.primary_function_start,
            "scope": "listing",
            "comment_type": "eol",
            "comment": "demo comment",
        },
        "comment.get_all": {
            "session_id": context.session_id,
            "address": seed.primary_function_start,
        },
        "comment.render": {
            "session_id": context.session_id,
            "address": seed.primary_function_start,
        },
        "comment.list": {
            "session_id": context.session_id,
            "query": "demo",
        },
        "context.get": {
            "session_id": context.session_id,
            "register": seed.context_register,
            "address": seed.context_address,
        },
        "context.ranges": {"session_id": context.session_id, "register": seed.context_register},
        "context.set": {
            "session_id": context.session_id,
            "register": seed.context_register,
            "start": seed.context_address,
            "length": 16,
            "value": 1,
        },
        "program.open": {
            "path": seed.sample_path,
            "read_only": False,
            "update_analysis": False,
        },
        "decomp.function": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
        },
        "decomp.function.by_address": {
            "session_id": context.session_id,
            "address": seed.primary_function_start,
        },
        "decomp.tokens": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
            "timeout_secs": 120,
        },
        "decomp.ast": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
            "timeout_secs": 120,
        },
        "decomp.high_function.summary": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
            "timeout_secs": 120,
        },
        "decomp.trace_type.forward": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
            "name": seed.decomp_local_name,
            "timeout_secs": 120,
        },
        "decomp.trace_type.backward": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
            "name": seed.decomp_local_name,
            "timeout_secs": 120,
        },
        "decomp.writeback.params": {
            "session_id": context.session_id,
            "function_start": seed.param_function_start,
            "timeout_secs": 120,
        },
        "decomp.writeback.locals": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
            "timeout_secs": 120,
        },
        "decomp.override.get": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
            "callsite": seed.callsite,
        },
        "decomp.override.set": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
            "callsite": seed.callsite,
            "signature": "int mcp_override(void)",
        },
        "decomp.global.rename": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
            "name": seed.decomp_global_name,
            "new_name": f"{seed.decomp_global_name}_renamed",
            "timeout_secs": 120,
        },
        "decomp.global.retype": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
            "name": seed.decomp_global_name,
            "data_type": "int",
            "timeout_secs": 120,
        },
        "equate.create": {
            "session_id": context.session_id,
            "address": seed.equate_address,
            "name": "LIVE_EQ",
            "value": 7,
            "operand_index": seed.equate_operand_index,
        },
        "equate.delete": {"session_id": context.session_id, "name": "ANSWER"},
        "equate.list": {"session_id": context.session_id, "name": "ANSWER"},
        "equate.clear_range": {
            "session_id": context.session_id,
            "start": seed.equate_address,
            "length": 4,
        },
        "external.library.create": {
            "session_id": context.session_id,
            "name": case.created_external_library_name,
        },
        "external.library.set_path": {
            "session_id": context.session_id,
            "name": case.seed_external_library_name,
            "path": case.external_library_path,
        },
        "external.location.get": {
            "session_id": context.session_id,
            "name": case.seed_external_label,
        },
        "external.location.create": {
            "session_id": context.session_id,
            "library_name": case.seed_external_library_name,
            "label": case.created_external_label,
            "external_address": seed.external_address,
        },
        "external.function.create": {
            "session_id": context.session_id,
            "library_name": case.seed_external_library_name,
            "name": case.created_external_function_name,
            "external_address": seed.external_address,
        },
        "external.entrypoint.add": {
            "session_id": context.session_id,
            "address": seed.call_target,
        },
        "external.entrypoint.remove": {
            "session_id": context.session_id,
            "address": seed.call_target,
        },
        "function.at": {"session_id": context.session_id, "address": seed.primary_function_start},
        "function.by_name": {"session_id": context.session_id, "name": seed.helper_function_name},
        "function.callers": {"session_id": context.session_id, "function_start": seed.call_target},
        "function.callees": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
        },
        "function.signature.get": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
        },
        "function.signature.set": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "signature": "int helper_stub(int x)",
        },
        "function.variables": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
        },
        "function.list": {"session_id": context.session_id, "query": seed.primary_function_name},
        "function.create": {
            "session_id": context.session_id,
            "address": seed.create_function_start,
            "name": seed.create_function_name,
        },
        "function.delete": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
        },
        "function.body.set": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "start": seed.helper_function_start,
            "end": helper_end,
        },
        "function.rename": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "name": f"{seed.helper_function_name}_renamed",
        },
        "function.calling_convention.set": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "name": seed.calling_convention_name or "unknown",
        },
        "function.flags.set": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "noreturn": True,
        },
        "function.thunk.set": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "thunk_target": seed.call_target,
        },
        "function.return_type.set": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "data_type": "int",
        },
        "function.batch.run": {
            "session_id": context.session_id,
            "action": "report.function_summary",
            "query": seed.primary_function_name,
            "limit": 2,
        },
        "graph.basic_blocks": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
        },
        "graph.cfg.edges": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
        },
        "graph.call_paths": {
            "session_id": context.session_id,
            "source_function": seed.primary_function_start,
            "target_function": seed.call_target,
        },
        "layout.struct.create": {
            "session_id": context.session_id,
            "name": case.created_struct_name,
            "category": case.created_category_path,
        },
        "layout.struct.get": {"session_id": context.session_id, "struct_path": "/mcp/demo_struct"},
        "layout.struct.resize": {
            "session_id": context.session_id,
            "struct_path": "/mcp/demo_struct",
            "length": 16,
        },
        "layout.struct.field.add": {
            "session_id": context.session_id,
            "struct_path": "/mcp/demo_struct",
            "field_name": "field1",
            "data_type": "int",
        },
        "layout.struct.field.rename": {
            "session_id": context.session_id,
            "struct_path": "/mcp/demo_struct",
            "old_name": "field0",
            "new_name": "field1",
        },
        "layout.struct.field.replace": {
            "session_id": context.session_id,
            "struct_path": "/mcp/demo_struct",
            "offset": 0,
            "data_type": "int",
        },
        "layout.struct.field.clear": {
            "session_id": context.session_id,
            "struct_path": "/mcp/demo_struct",
            "offset": 0,
        },
        "layout.struct.field.comment.set": {
            "session_id": context.session_id,
            "struct_path": "/mcp/demo_struct",
            "offset": 0,
            "comment": "seed",
        },
        "layout.struct.bitfield.add": {
            "session_id": context.session_id,
            "struct_path": "/mcp/demo_struct",
            "byte_offset": 0,
            "byte_width": 4,
            "bit_offset": 0,
            "data_type": "int",
            "bit_size": 1,
            "field_name": "flags",
        },
        "layout.struct.fill_from_decompiler": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
            "name": seed.decomp_local_name,
        },
        "layout.union.create": {
            "session_id": context.session_id,
            "name": case.created_union_name,
            "category": case.created_category_path,
        },
        "layout.union.member.add": {
            "session_id": context.session_id,
            "union_path": "/mcp/demo_union",
            "field_name": "member1",
            "data_type": "int",
        },
        "layout.union.member.remove": {
            "session_id": context.session_id,
            "union_path": "/mcp/demo_union",
            "field_name": "member0",
        },
        "layout.enum.create": {
            "session_id": context.session_id,
            "name": case.created_enum_name,
            "category": case.created_category_path,
        },
        "layout.enum.member.add": {
            "session_id": context.session_id,
            "enum_path": "/mcp/demo_enum",
            "name": "ITEM2",
            "value": 2,
        },
        "layout.enum.member.remove": {
            "session_id": context.session_id,
            "enum_path": "/mcp/demo_enum",
            "name": "ITEM",
        },
        "layout.inspect.components": {
            "session_id": context.session_id,
            "path": "/mcp/demo_struct",
        },
        "listing.data.at": {"session_id": context.session_id, "address": seed.string_address},
        "listing.data.create": {
            "session_id": context.session_id,
            "address": seed.data_address,
            "data_type": "int",
            "clear_existing": True,
        },
        "listing.data.clear": {
            "session_id": context.session_id,
            "address": seed.data_address,
            "length": 4,
        },
        "listing.disassemble.function": {
            "session_id": context.session_id,
            "address": seed.primary_function_start,
        },
        "listing.disassemble.range": {
            "session_id": context.session_id,
            "start": seed.primary_function_start,
            "length": 32,
            "limit": 32,
        },
        "listing.code_unit.at": {
            "session_id": context.session_id,
            "address": seed.instruction_address,
        },
        "listing.code_unit.before": {
            "session_id": context.session_id,
            "address": seed.next_instruction_address,
        },
        "listing.code_unit.after": {
            "session_id": context.session_id,
            "address": seed.instruction_address,
        },
        "listing.code_unit.containing": {
            "session_id": context.session_id,
            "address": seed.string_address,
        },
        "listing.clear": {
            "session_id": context.session_id,
            "start": seed.create_function_start,
            "length": 1,
        },
        "listing.disassemble.seed": {
            "session_id": context.session_id,
            "address": seed.create_function_start,
        },
        "memory.read": {
            "session_id": context.session_id,
            "address": seed.writable_address,
            "length": 4,
        },
        "memory.write": {
            "session_id": context.session_id,
            "address": seed.writable_address,
            "data_hex": "9090",
        },
        "memory.scalars.read": {
            "session_id": context.session_id,
            "address": seed.writable_address,
            "size": 4,
        },
        "memory.scalars.write": {
            "session_id": context.session_id,
            "address": seed.writable_address,
            "size": 4,
            "value": 1,
        },
        "memory.block.create": {
            "session_id": context.session_id,
            "name": "scratch",
            "address": seed.free_memory_address,
            "length": 32,
            "initialized": True,
        },
        "memory.block.remove": {
            "session_id": context.session_id,
            "name": "scratch",
        },
        "metadata.store": {
            "session_id": context.session_id,
            "key": "triage.owner",
            "value": {"name": "mcp"},
        },
        "namespace.create": {
            "session_id": context.session_id,
            "name": case.created_namespace_name,
        },
        "class.create": {
            "session_id": context.session_id,
            "name": case.created_class_name,
        },
        "parameter.add": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "name": "y",
            "data_type": "int",
        },
        "parameter.move": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "ordinal": 0,
            "new_ordinal": 0,
        },
        "parameter.remove": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "name": "x",
        },
        "parameter.replace": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "name": "x",
            "data_type": "int",
        },
        "patch.assemble": {
            "session_id": context.session_id,
            "address": seed.create_function_start,
            "assembly": "nop",
        },
        "patch.nop": {
            "session_id": context.session_id,
            "address": seed.create_function_start,
            "count": 2,
        },
        "patch.branch_invert": {
            "session_id": context.session_id,
            "address": seed.conditional_branch,
        },
        "program.export_binary": {
            "session_id": context.session_id,
            "path": case.export_binary_path,
            "format": "raw",
        },
        "project.export": {
            "session_id": context.session_id,
            "destination": case.export_project_destination,
        },
        "program.image_base.set": {
            "session_id": context.session_id,
            "image_base": seed.rebased_image_base,
        },
        "program.open_bytes": {
            "data_base64": seed.sample_bytes_base64,
            "filename": "ls-bytes",
            "read_only": False,
            "update_analysis": False,
        },
        "program.save_as": {
            "session_id": context.session_id,
            "program_name": "saved_live.bin",
            "folder_path": "/",
            "overwrite": True,
        },
        "project.file.info": {"session_id": context.session_id, "path": case.program_path},
        "project.files.list": {
            "session_id": context.session_id,
            "query": case.program_name,
        },
        "project.program.open": {"session_id": context.session_id, "path": case.program_path},
        "project.program.open_existing": {
            "project_location": case.project_location,
            "project_name": case.project_name,
            "program_name": case.program_name,
        },
        "project.search.programs": {
            "session_id": context.session_id,
            "query": case.program_name,
        },
        "reference.to": {"session_id": context.session_id, "address": seed.call_target},
        "reference.from": {"session_id": context.session_id, "address": seed.reference_seed_from},
        "reference.create.memory": {
            "session_id": context.session_id,
            "from_address": seed.reference_create_from,
            "to_address": seed.call_target,
            "reference_type": "DATA",
        },
        "reference.create.stack": {
            "session_id": context.session_id,
            "from_address": seed.instruction_address,
            "stack_offset": 8,
            "reference_type": "DATA",
        },
        "reference.create.register": {
            "session_id": context.session_id,
            "from_address": seed.reference_create_from,
            "register": seed.context_register,
            "reference_type": "DATA",
        },
        "reference.create.external": {
            "session_id": context.session_id,
            "from_address": seed.reference_create_from,
            "library_name": case.seed_external_library_name,
            "label": case.seed_external_label,
            "external_address": seed.external_address,
        },
        "reference.delete": {
            "session_id": context.session_id,
            "from_address": seed.reference_seed_from,
            "to_address": seed.call_target,
            "operand_index": 0,
        },
        "reference.clear_from": {
            "session_id": context.session_id,
            "from_address": seed.reference_seed_from,
        },
        "reference.clear_to": {
            "session_id": context.session_id,
            "to_address": seed.call_target,
        },
        "reference.primary.set": {
            "session_id": context.session_id,
            "from_address": seed.reference_seed_from,
            "to_address": seed.call_target,
            "operand_index": 0,
        },
        "reference.association.set": {
            "session_id": context.session_id,
            "from_address": seed.reference_seed_from,
            "to_address": seed.call_target,
            "symbol_address": seed.call_target,
        },
        "reference.association.remove": {
            "session_id": context.session_id,
            "from_address": seed.reference_seed_from,
            "to_address": seed.call_target,
        },
        "reference.count_to": {"session_id": context.session_id, "address": seed.call_target},
        "reference.count_from": {
            "session_id": context.session_id,
            "address": seed.reference_seed_from,
        },
        "relocation.add": {
            "session_id": context.session_id,
            "address": seed.primary_function_start,
            "status": "APPLIED",
            "type": 7,
            "values": [4],
            "byte_length": 8,
            "symbol_name": "main_label",
        },
        "search.bytes": {"session_id": context.session_id, "pattern_hex": pattern_hex},
        "search.text": {"session_id": context.session_id, "text": text_query},
        "search.instructions": {
            "session_id": context.session_id,
            "query": seed.instruction_mnemonic,
        },
        "search.pcode": {
            "session_id": context.session_id,
            "query": "copy",
            "function_start": seed.primary_function_start,
        },
        "search.resolve": {"session_id": context.session_id, "query": "main_label"},
        "search.defined_strings": {"session_id": context.session_id, "query": text_query},
        "pcode.function": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
        },
        "pcode.op.at": {"session_id": context.session_id, "address": seed.instruction_address},
        "pcode.block": {"session_id": context.session_id, "address": seed.instruction_address},
        "pcode.varnode_uses": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
            "timeout_secs": 120,
        },
        "function.report": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
        },
        "source.file.add": {"session_id": context.session_id, "path": case.created_source_path},
        "source.file.remove": {"session_id": context.session_id, "path": "/tmp/demo.c"},
        "source.map.add": {
            "session_id": context.session_id,
            "path": case.created_source_path,
            "line_number": 1,
            "base_address": seed.helper_function_start,
            "length": 4,
        },
        "source.map.remove": {
            "session_id": context.session_id,
            "path": "/tmp/demo.c",
            "line_number": 12,
            "base_address": seed.primary_function_start,
        },
        "stackframe.variable.clear": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "stack_offset": 8,
        },
        "stackframe.variable.create": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "name": "saved_fp_2",
            "stack_offset": 16,
            "data_type": "int",
        },
        "stackframe.variables": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
        },
        "symbol.by_name": {"session_id": context.session_id, "name": "main_label"},
        "symbol.create": {
            "session_id": context.session_id,
            "address": seed.primary_function_start,
            "name": case.created_symbol_name,
        },
        "symbol.delete": {
            "session_id": context.session_id,
            "address": seed.primary_function_start,
            "name": "main_label",
        },
        "symbol.history": {
            "session_id": context.session_id,
            "address": seed.primary_function_start,
        },
        "symbol.list": {"session_id": context.session_id, "query": "main_label"},
        "symbol.namespace.move": {
            "session_id": context.session_id,
            "address": seed.primary_function_start,
            "namespace": "MovedNs",
            "name": "main_label",
        },
        "symbol.primary.set": {
            "session_id": context.session_id,
            "address": seed.primary_function_start,
            "name": "main_label",
        },
        "symbol.rename": {
            "session_id": context.session_id,
            "address": seed.primary_function_start,
            "old_name": "main_label",
            "new_name": case.renamed_symbol_name,
        },
        "tag.add": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "name": case.created_tag_name,
        },
        "tag.remove": {
            "session_id": context.session_id,
            "function_start": seed.primary_function_start,
            "name": "entrypoint",
        },
        "task.cancel": {"task_id": task_id},
        "task.result": {"task_id": task_id},
        "task.status": {"task_id": task_id},
        "type.apply_at": {
            "session_id": context.session_id,
            "address": seed.data_address,
            "data_type": "int",
        },
        "type.category.create": {
            "session_id": context.session_id,
            "path": case.created_category_path,
        },
        "type.define_c": {
            "session_id": context.session_id,
            "declaration": "int",
            "name": "demo_int",
        },
        "type.delete": {"session_id": context.session_id, "name": case.seed_type_name},
        "type.favorite.set": {
            "session_id": context.session_id,
            "path": case.seed_type_path,
            "favorite": True,
        },
        "type.get": {"session_id": context.session_id, "name": case.seed_type_name},
        "type.get_by_id": {
            "session_id": context.session_id,
            "data_type_id": case.seed_type_id,
            "universal_id": case.seed_type_universal_id,
            "source_archive_id": case.seed_type_source_archive_id,
        },
        "type.list": {"session_id": context.session_id, "query": case.seed_type_name},
        "type.parse_c": {
            "session_id": context.session_id,
            "declaration": "int",
        },
        "type.rename": {
            "session_id": context.session_id,
            "name": case.seed_type_name,
            "new_name": case.renamed_type_name,
        },
        "variable.comment.set": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "name": "tmp",
            "comment": "demo",
        },
        "variable.local.create": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "name": "tmp2",
            "data_type": "int",
        },
        "variable.local.remove": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "name": "tmp",
        },
        "variable.rename": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "name": "x",
            "new_name": "x2",
        },
        "variable.retype": {
            "session_id": context.session_id,
            "function_start": seed.helper_function_start,
            "name": "x",
            "data_type": "int",
        },
    }
    arguments.update(live_overrides.get(tool_name, {}))
    if tool_name == "memory.write":
        arguments.pop("data_base64", None)
    if tool_name == "search.bytes":
        arguments.pop("pattern_base64", None)
    if tool_name in {"reference.from", "reference.to"} and "address" in arguments:
        arguments.pop("start", None)
        arguments.pop("end", None)
    if tool_name == "type.get_by_id":
        if case.seed_type_id is None:
            arguments.pop("data_type_id", None)
        if case.seed_type_universal_id is None:
            arguments.pop("universal_id", None)
        if case.seed_type_source_archive_id is None:
            arguments.pop("source_archive_id", None)
    return arguments


def tool_arguments(
    spec: dict[str, Any],
    session_id: str,
    task_id: str | None,
    *,
    include_optional: bool = False,
    sample_path: str | None = None,
    context: ToolContext | None = None,
) -> dict[str, Any]:
    tool_name = spec["name"]
    sample_program_path = f"/{Path(resolve_sample_binary_path(sample_path)).name}"
    properties = spec.get("properties", {})
    if include_optional and context is not None and context.mode == "live":
        # Live fuzzing relies on explicit per-tool overrides; pulling every optional field from the
        # fake-backend defaults introduces conflicting addresses, storage selectors, loaders, and
        # project paths that are invalid against a real analyzed program.
        selected_keys = {key: properties[key] for key in spec.get("required", [])}
    else:
        selected_keys = (
            properties
            if include_optional
            else {key: properties[key] for key in spec.get("required", [])}
        )
    arguments = {
        key: default_value(
            tool_name,
            key,
            session_id,
            task_id,
            schema=schema,
            sample_path=sample_path,
        )
        for key, schema in selected_keys.items()
    }
    overrides = {
        "health.ping": {},
        "mcp.response_format": {},
        "ghidra.call": {
            "session_id": session_id,
            "target": "fake.target",
            "args": [],
            "kwargs": {},
        },
        "ghidra.eval": {"session_id": session_id, "code": "1+1"},
        "ghidra.script": {
            "session_id": session_id,
            "path": "/tmp/demo.py",
            "script_args": [],
        },
        "analysis.options.get": {
            "session_id": session_id,
            "name": "Decompiler Parameter ID",
        },
        "analysis.options.set": {
            "session_id": session_id,
            "name": "Decompiler Parameter ID",
            "value": False,
        },
        "comment.get": {
            "session_id": session_id,
            "address": "0x1040",
            "scope": "listing",
            "comment_type": "eol",
        },
        "comment.set": {
            "session_id": session_id,
            "address": "0x1040",
            "scope": "listing",
            "comment_type": "eol",
            "comment": "demo comment",
        },
        "comment.get_all": {"session_id": session_id, "address": "0x1040"},
        "comment.render": {"session_id": session_id, "address": "0x1040"},
        "context.get": {
            "session_id": session_id,
            "register": "TMode",
            "address": "0x1000",
        },
        "context.ranges": {"session_id": session_id, "register": "TMode"},
        "context.set": {
            "session_id": session_id,
            "register": "TMode",
            "start": "0x1000",
            "length": 16,
            "value": 1,
        },
        "decomp.function": {"session_id": session_id, "function_start": "0x1040"},
        "decomp.function.by_address": {"session_id": session_id, "address": "0x1040"},
        "decomp.tokens": {"session_id": session_id, "function_start": "0x1040"},
        "decomp.ast": {"session_id": session_id, "function_start": "0x1040"},
        "decomp.high_function.summary": {
            "session_id": session_id,
            "function_start": "0x1200",
        },
        "decomp.trace_type.forward": {
            "session_id": session_id,
            "function_start": "0x1200",
            "name": "x",
        },
        "decomp.trace_type.backward": {
            "session_id": session_id,
            "function_start": "0x1200",
            "name": "x",
        },
        "decomp.writeback.params": {
            "session_id": session_id,
            "function_start": "0x1200",
        },
        "decomp.writeback.locals": {
            "session_id": session_id,
            "function_start": "0x1200",
        },
        "decomp.override.get": {
            "session_id": session_id,
            "function_start": "0x1040",
            "callsite": "0x1048",
        },
        "decomp.override.set": {
            "session_id": session_id,
            "function_start": "0x1040",
            "callsite": "0x1048",
            "signature": "int puts(char *s)",
        },
        "decomp.global.rename": {
            "session_id": session_id,
            "function_start": "0x1040",
            "name": "main",
            "new_name": "main_renamed",
        },
        "decomp.global.retype": {
            "session_id": session_id,
            "function_start": "0x1040",
            "name": "main",
            "data_type": "/int",
        },
        "equate.delete": {"session_id": session_id, "name": "ANSWER"},
        "external.location.get": {"session_id": session_id, "name": "puts"},
        "external.location.create": {
            "session_id": session_id,
            "library_name": "libdemo.so",
            "label": "puts2",
            "external_address": "0x4010",
        },
        "external.function.create": {
            "session_id": session_id,
            "library_name": "libdemo.so",
            "name": "puts3",
            "external_address": "0x4020",
        },
        "external.library.set_path": {
            "session_id": session_id,
            "name": "libdemo.so",
            "path": "/tmp/libdemo.so",
        },
        "function.at": {"session_id": session_id, "address": "0x1040"},
        "function.by_name": {"session_id": session_id, "name": "main"},
        "function.callers": {"session_id": session_id, "function_start": "0x1010"},
        "function.callees": {"session_id": session_id, "function_start": "0x1040"},
        "function.signature.get": {
            "session_id": session_id,
            "function_start": "0x1040",
        },
        "function.signature.set": {
            "session_id": session_id,
            "function_start": "0x1040",
            "signature": "int main(void)",
        },
        "function.variables": {"session_id": session_id, "function_start": "0x1200"},
        "function.create": {
            "session_id": session_id,
            "address": "0x1300",
            "name": "helper_stub_2",
        },
        "function.delete": {"session_id": session_id, "function_start": "0x1200"},
        "function.body.set": {
            "session_id": session_id,
            "function_start": "0x1200",
            "start": "0x1200",
            "end": "0x1210",
        },
        "function.calling_convention.set": {
            "session_id": session_id,
            "function_start": "0x1200",
            "name": "__stdcall",
        },
        "function.flags.set": {
            "session_id": session_id,
            "function_start": "0x1200",
            "noreturn": True,
        },
        "function.thunk.set": {
            "session_id": session_id,
            "function_start": "0x1200",
            "thunk_target": "0x1010",
        },
        "function.return_type.set": {
            "session_id": session_id,
            "function_start": "0x1200",
            "data_type": "/int",
        },
        "graph.basic_blocks": {"session_id": session_id, "function_start": "0x1040"},
        "graph.cfg.edges": {"session_id": session_id, "function_start": "0x1040"},
        "graph.call_paths": {
            "session_id": session_id,
            "source_function": "0x1040",
            "target_function": "0x1010",
        },
        "layout.struct.get": {
            "session_id": session_id,
            "struct_path": "/mcp/demo_struct",
        },
        "layout.struct.resize": {
            "session_id": session_id,
            "struct_path": "/mcp/demo_struct",
            "length": 16,
        },
        "layout.struct.field.add": {
            "session_id": session_id,
            "struct_path": "/mcp/demo_struct",
            "field_name": "field1",
            "data_type": "/int",
        },
        "layout.struct.field.rename": {
            "session_id": session_id,
            "struct_path": "/mcp/demo_struct",
            "old_name": "field0",
            "new_name": "field1",
        },
        "layout.struct.field.replace": {
            "session_id": session_id,
            "struct_path": "/mcp/demo_struct",
            "offset": 0,
            "data_type": "/int",
        },
        "layout.struct.field.clear": {
            "session_id": session_id,
            "struct_path": "/mcp/demo_struct",
            "offset": 0,
        },
        "layout.struct.field.comment.set": {
            "session_id": session_id,
            "struct_path": "/mcp/demo_struct",
            "offset": 0,
            "comment": "seed",
        },
        "layout.struct.bitfield.add": {
            "session_id": session_id,
            "struct_path": "/mcp/demo_struct",
            "byte_offset": 0,
            "byte_width": 4,
            "bit_offset": 0,
            "data_type": "/int",
            "bit_size": 1,
            "field_name": "flags",
        },
        "layout.struct.fill_from_decompiler": {
            "session_id": session_id,
            "function_start": "0x1040",
            "name": "demo_struct",
        },
        "layout.union.member.add": {
            "session_id": session_id,
            "union_path": "/mcp/demo_union",
            "field_name": "member1",
            "data_type": "/int",
        },
        "layout.union.member.remove": {
            "session_id": session_id,
            "union_path": "/mcp/demo_union",
            "field_name": "member0",
        },
        "layout.enum.member.add": {
            "session_id": session_id,
            "enum_path": "/mcp/demo_enum",
            "name": "ITEM2",
            "value": 2,
        },
        "layout.enum.member.remove": {
            "session_id": session_id,
            "enum_path": "/mcp/demo_enum",
            "name": "ITEM",
        },
        "layout.inspect.components": {"session_id": session_id, "path": "/mcp/demo_struct"},
        "listing.code_unit.at": {"session_id": session_id, "address": "0x1000"},
        "listing.code_unit.before": {"session_id": session_id, "address": "0x1001"},
        "listing.code_unit.after": {"session_id": session_id, "address": "0x1000"},
        "listing.code_unit.containing": {"session_id": session_id, "address": "0x2000"},
        "listing.code_units.list": {"session_id": session_id},
        "listing.clear": {"session_id": session_id, "start": "0x1000", "length": 1},
        "listing.disassemble.seed": {"session_id": session_id, "address": "0x1100"},
        "memory.read": {"session_id": session_id, "address": "0x1000", "length": 4},
        "memory.write": {"session_id": session_id, "address": "0x1000", "data_hex": "9090"},
        "memory.scalars.read": {"session_id": session_id, "address": "0x1000", "size": 4},
        "memory.scalars.write": {
            "session_id": session_id,
            "address": "0x1000",
            "size": 4,
            "value": 1,
        },
        "metadata.store": {
            "session_id": session_id,
            "key": "triage.owner",
            "value": {"name": "mcp"},
        },
        "parameter.add": {
            "session_id": session_id,
            "function_start": "0x1200",
            "name": "y",
            "data_type": "/int",
        },
        "parameter.move": {
            "session_id": session_id,
            "function_start": "0x1200",
            "ordinal": 0,
            "new_ordinal": 0,
        },
        "parameter.remove": {
            "session_id": session_id,
            "function_start": "0x1200",
            "name": "x",
        },
        "parameter.replace": {
            "session_id": session_id,
            "function_start": "0x1200",
            "name": "x",
            "data_type": "/int",
        },
        "program.export_binary": {"session_id": session_id, "path": "/tmp/out.bin"},
        "program.image_base.set": {"session_id": session_id, "image_base": "0x2000"},
        "program.open_bytes": {
            "data_base64": "AA==",
            "filename": "sample.bin",
            "read_only": False,
            "update_analysis": False,
        },
        "project.file.info": {"session_id": session_id, "path": sample_program_path},
        "project.program.open": {"session_id": session_id, "path": sample_program_path},
        "project.program.open_existing": {
            "project_location": "/tmp/project",
            "project_name": "demo_project",
        },
        "reference.to": {"session_id": session_id, "address": "0x1010"},
        "reference.from": {"session_id": session_id, "address": "0x1048"},
        "reference.clear_from": {"session_id": session_id, "from_address": "0x1048"},
        "reference.clear_to": {"session_id": session_id, "to_address": "0x1010"},
        "reference.association.set": {
            "session_id": session_id,
            "from_address": "0x1048",
            "to_address": "0x1010",
            "symbol_address": "0x1010",
        },
        "reference.association.remove": {
            "session_id": session_id,
            "from_address": "0x1048",
            "to_address": "0x1010",
        },
        "reference.create.external": {
            "session_id": session_id,
            "from_address": "0x1048",
            "library_name": "libdemo.so",
            "label": "puts",
        },
        "relocation.add": {
            "session_id": session_id,
            "address": "0x1040",
            "status": "APPLIED",
            "type": 7,
            "values": [4],
            "byte_length": 8,
            "symbol_name": "main_label",
        },
        "search.bytes": {"session_id": session_id, "pattern_hex": "48656c6c6f"},
        "search.text": {"session_id": session_id, "text": "Hello"},
        "search.pcode": {
            "session_id": session_id,
            "query": "copy",
            "function_start": "0x1040",
        },
        "source.map.add": {
            "session_id": session_id,
            "path": "/tmp/demo2.c",
            "line_number": 13,
            "base_address": "0x1050",
            "length": 4,
        },
        "source.map.remove": {
            "session_id": session_id,
            "path": "/tmp/demo.c",
            "line_number": 12,
            "base_address": "0x1040",
        },
        "stackframe.variable.clear": {
            "session_id": session_id,
            "function_start": "0x1200",
            "stack_offset": 8,
        },
        "stackframe.variables": {"session_id": session_id, "function_start": "0x1200"},
        "symbol.by_name": {"session_id": session_id, "name": "main"},
        "symbol.delete": {
            "session_id": session_id,
            "address": "0x1040",
            "name": "main_label",
        },
        "symbol.history": {"session_id": session_id, "address": "0x1040"},
        "symbol.namespace.move": {
            "session_id": session_id,
            "address": "0x1040",
            "namespace": "MovedNs",
            "name": "main_label",
        },
        "symbol.primary.set": {"session_id": session_id, "address": "0x1040"},
        "symbol.rename": {
            "session_id": session_id,
            "address": "0x1040",
            "old_name": "main_label",
            "new_name": "main_label_2",
        },
        "task.cancel": {"task_id": task_id},
        "task.result": {"task_id": task_id},
        "task.status": {"task_id": task_id},
        "type.apply_at": {"session_id": session_id, "address": "0x2000", "data_type": "/int"},
        "type.category.create": {"session_id": session_id, "path": "/mcp2"},
        "type.define_c": {"session_id": session_id, "declaration": "typedef int demo_int;"},
        "type.delete": {"session_id": session_id, "name": "int"},
        "type.favorite.set": {
            "session_id": session_id,
            "path": "/int",
            "favorite": True,
        },
        "type.get": {"session_id": session_id, "name": "int"},
        "type.get_by_id": {"session_id": session_id, "data_type_id": 1},
        "type.rename": {
            "session_id": session_id,
            "name": "int",
            "new_name": "int2",
        },
        "variable.comment.set": {
            "session_id": session_id,
            "function_start": "0x1200",
            "name": "tmp",
            "comment": "demo",
        },
        "variable.local.create": {
            "session_id": session_id,
            "function_start": "0x1200",
            "name": "tmp2",
            "data_type": "/int",
        },
        "variable.local.remove": {
            "session_id": session_id,
            "function_start": "0x1200",
            "name": "tmp",
        },
        "variable.rename": {
            "session_id": session_id,
            "function_start": "0x1200",
            "name": "x",
            "new_name": "x2",
        },
        "variable.retype": {
            "session_id": session_id,
            "function_start": "0x1200",
            "name": "x",
            "data_type": "/int",
        },
    }
    arguments.update(overrides.get(tool_name, {}))
    if tool_name == "memory.write":
        arguments.pop("data_base64", None)
    if tool_name == "search.bytes":
        arguments.pop("pattern_base64", None)
    if tool_name in {"reference.from", "reference.to"} and "address" in arguments:
        arguments.pop("start", None)
        arguments.pop("end", None)
    if tool_name == "symbol.primary.set":
        arguments["name"] = "main_label"
    if context is not None and context.mode == "live":
        arguments = _apply_live_tool_overrides(tool_name, arguments, context)
    return arguments


def pre_actions(backend: Any, tool_name: str, session_id: str) -> None:
    begin = getattr(backend, "transaction_begin", None) or getattr(backend, "undo_begin", None)
    commit = getattr(backend, "transaction_commit", None) or getattr(backend, "undo_commit", None)
    undo = getattr(backend, "transaction_undo", None) or getattr(backend, "undo_undo", None)
    if tool_name in {"transaction.commit", "transaction.revert"}:
        begin(session_id, description="demo")
        return
    if tool_name in {"transaction.redo", "transaction.undo"}:
        begin(session_id, description="demo")
        commit(session_id)
        if tool_name == "transaction.redo":
            undo(session_id)


def build_args(ctx: ToolContext, tool_name: str, **overrides: Any) -> dict[str, Any]:
    arguments = tool_arguments(tool_spec(tool_name), ctx.session_id, ctx.task_id, context=ctx)
    arguments.update(overrides)
    return arguments


def branch_variant_arguments(
    spec: dict[str, Any], session_id: str, _task_id: str
) -> list[dict[str, Any]]:
    tool_name = spec["name"]
    variants: list[dict[str, Any]] = []
    if tool_name == "memory.write":
        variants.append(
            {
                "variant": "base64",
                "arguments": {
                    "session_id": session_id,
                    "address": "0x1000",
                    "data_base64": "kJA=",
                },
            }
        )
    if tool_name == "search.bytes":
        variants.append(
            {
                "variant": "base64",
                "arguments": {
                    "session_id": session_id,
                    "pattern_base64": "SGVsbG8=",
                    "start": "0x2000",
                    "end": "0x2008",
                    "limit": 10,
                },
            }
        )
    if tool_name == "reference.from":
        variants.append(
            {
                "variant": "range",
                "arguments": {
                    "session_id": session_id,
                    "start": "0x1040",
                    "end": "0x1050",
                    "limit": 10,
                },
            }
        )
    if tool_name == "reference.to":
        variants.append(
            {
                "variant": "range",
                "arguments": {
                    "session_id": session_id,
                    "start": "0x1010",
                    "end": "0x1020",
                    "limit": 10,
                },
            }
        )
    if tool_name == "comment.get":
        variants.append(
            {
                "variant": "function_scope",
                "arguments": {
                    "session_id": session_id,
                    "scope": "function",
                    "function_start": "0x1040",
                    "comment_type": "plate",
                },
            }
        )
    if tool_name == "comment.set":
        variants.append(
            {
                "variant": "function_scope",
                "arguments": {
                    "session_id": session_id,
                    "scope": "function",
                    "function_start": "0x1040",
                    "comment_type": "plate",
                    "comment": "demo function comment 2",
                },
            }
        )
    if tool_name == "type.get":
        variants.append(
            {
                "variant": "path_lookup",
                "arguments": {
                    "session_id": session_id,
                    "path": "/int",
                },
            }
        )
    return variants
