"""Stateful MCP fuzzer for fake and live Ghidra backends."""

from __future__ import annotations

import argparse
import json
import random
import time
from typing import Any

from .fuzz_support import (
    ToolContext,
    close_live_fuzz_environment,
    create_live_fuzz_environment,
    create_live_tool_context,
    create_tool_context,
    pre_actions,
    resolve_sample_binary_path,
    tool_arguments,
)
from .server import ALL_TOOL_SPECS, SimpleMcpServer

SAFE_BOOL_MUTATIONS = {
    "case_sensitive",
    "clear",
    "clear_analysis_references",
    "clear_bookmarks",
    "clear_comments",
    "clear_context",
    "clear_default_references",
    "clear_equates",
    "clear_existing",
    "clear_functions",
    "clear_import_references",
    "clear_properties",
    "clear_registers",
    "clear_symbols",
    "clear_undo",
    "clear_user_references",
    "commit",
    "commit_return",
    "custom_storage",
    "defined_strings_only",
    "enabled",
    "exact",
    "execute",
    "favorite",
    "forward",
    "include_dynamic",
    "include_function",
    "initialized",
    "inline",
    "make_primary",
    "noreturn",
    "overwrite",
    "read",
    "read_only",
    "recursive",
    "revert_active",
    "signed",
    "update_analysis",
    "use_data_types",
    "user_defined",
    "varargs",
    "write",
}

SAFE_INT_MUTATIONS = {
    "bit_offset",
    "bit_size",
    "byte_length",
    "byte_offset",
    "byte_width",
    "count",
    "fill",
    "length",
    "limit",
    "line_number",
    "max_depth",
    "max_line",
    "min_line",
    "new_ordinal",
    "offset",
    "operand_index",
    "ordinal",
    "size",
    "source_archive_id",
    "stack_offset",
    "timeout_secs",
    "type",
    "universal_id",
}


def _call(server: SimpleMcpServer, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": random.randint(1, 1_000_000),
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    if response is None:
        raise RuntimeError(f"no response for tool {name}")
    if "result" in response:
        return response["result"]
    error = response.get("error", {})
    message = str(error.get("message", "unknown MCP error"))
    return {
        "isError": True,
        "structuredContent": {"error": error},
        "content": [{"type": "text", "text": message}],
    }


def _summary_text(result: dict[str, Any]) -> str:
    content = result.get("content") or []
    if not content:
        return ""
    return str(content[0].get("text", ""))


def _selected_tool_specs(
    limit: int | None = None, prefix: str | None = None
) -> list[dict[str, Any]]:
    specs = list(ALL_TOOL_SPECS)
    if prefix:
        specs = [spec for spec in specs if spec["name"].startswith(prefix)]
    if limit is not None:
        specs = specs[:limit]
    return specs


def _mutate_arguments(
    tool_name: str,
    arguments: dict[str, Any],
    round_index: int,
    _rng: random.Random,
    context: ToolContext | None = None,
) -> dict[str, Any]:
    if round_index == 0:
        return arguments

    mutated = dict(arguments)
    helper_function_start = "0x1200"
    calling_convention = "__fastcall"
    instruction_query = "mov"
    type_name = "int"
    type_path = "/int"
    type_id = 1
    query_overrides = {
        "comment.list": "main",
        "project.files.list": "main",
        "project.search.programs": "main",
        "search.resolve": "main",
        "symbol.list": "main",
    }
    if context is not None and context.mode == "live" and context.live_case is not None:
        helper_function_start = context.live_case.seed.helper_function_start
        calling_convention = context.live_case.seed.calling_convention_name or calling_convention
        instruction_query = context.live_case.seed.instruction_mnemonic
        type_name = context.live_case.seed_type_name
        type_path = context.live_case.seed_type_path
        type_id = context.live_case.seed_type_id or type_id
        query_overrides = {
            "comment.list": "demo",
            "project.files.list": context.live_case.program_name,
            "project.search.programs": context.live_case.program_name,
            "search.resolve": "main_label",
            "symbol.list": "main_label",
        }

    if tool_name == "memory.write" and round_index % 2 == 0:
        mutated.pop("data_hex", None)
        mutated["data_base64"] = "kJA="
    if tool_name == "search.bytes" and round_index % 2 == 0:
        mutated.pop("pattern_hex", None)
        mutated["pattern_base64"] = "SGVsbG8="
    if tool_name == "comment.get" and round_index >= 2:
        mutated.pop("address", None)
        mutated["scope"] = "function"
        mutated["function_start"] = helper_function_start
    if tool_name == "comment.set" and round_index >= 2:
        mutated.pop("address", None)
        mutated["scope"] = "function"
        mutated["function_start"] = helper_function_start
        mutated["comment"] = f"function fuzz comment {round_index}"
    if tool_name == "function.body.set" and round_index >= 2:
        mutated.pop("end", None)
        mutated["length"] = 0x10
    if tool_name == "function.calling_convention.set" and round_index >= 2:
        mutated["name"] = calling_convention
    if tool_name == "function.flags.set" and round_index >= 2:
        mutated.update(
            {
                "varargs": True,
                "inline": True,
                "noreturn": True,
                "custom_storage": False,
            }
        )
    if tool_name == "function.return_type.set" and round_index >= 2:
        mutated["data_type"] = "/long"
    if tool_name == "program.mode.set" and round_index >= 2:
        mutated["read_only"] = True
        mutated["deterministic"] = True
    if tool_name == "relocation.add":
        mutated["type"] = 7 + round_index
        mutated["values"] = [round_index, round_index + 1]
        mutated["byte_length"] = 4 + round_index
    if tool_name == "search.instructions":
        mutated["query"] = instruction_query
    if tool_name == "search.pcode":
        mutated["query"] = "copy"
    if tool_name == "type.get":
        if round_index % 2 == 0:
            mutated.pop("name", None)
            mutated["path"] = type_path
        else:
            mutated.pop("path", None)
            mutated["name"] = type_name
    if tool_name == "type.get_by_id":
        if context is not None and context.mode == "live" and context.live_case is not None:
            if context.live_case.seed_type_id is not None:
                mutated["data_type_id"] = context.live_case.seed_type_id
                mutated.pop("universal_id", None)
                mutated.pop("source_archive_id", None)
            else:
                mutated.pop("data_type_id", None)
                mutated["universal_id"] = context.live_case.seed_type_universal_id
                mutated["source_archive_id"] = context.live_case.seed_type_source_archive_id
        else:
            mutated["data_type_id"] = type_id
            mutated.pop("universal_id", None)
            mutated.pop("source_archive_id", None)
    if context is not None and context.mode == "live" and context.live_case is not None:
        if tool_name == "source.map.add":
            mutated["path"] = context.live_case.created_source_path
            mutated["base_address"] = context.live_case.seed.helper_function_start
            mutated["length"] = 4
        if tool_name == "source.map.remove":
            mutated["path"] = "/tmp/demo.c"
            mutated["line_number"] = 12
            mutated["base_address"] = context.live_case.seed.primary_function_start
        if tool_name == "layout.struct.field.comment.set":
            mutated["offset"] = 0

    for key in sorted(SAFE_BOOL_MUTATIONS.intersection(mutated)):
        if key == "deterministic":
            mutated[key] = True
            continue
        if round_index % 2 == 0:
            mutated[key] = not bool(mutated[key])

    for key in sorted(SAFE_INT_MUTATIONS.intersection(mutated)):
        value = mutated[key]
        if value is None:
            continue
        if isinstance(value, bool):
            continue
        try:
            int_value = int(value)
        except (TypeError, ValueError):
            continue
        mutated[key] = max(0, int_value) + round_index + (1 if round_index >= 2 else 0)

    if context is not None and context.mode == "live" and context.live_case is not None:
        if tool_name == "source.map.add":
            mutated["line_number"] = max(1, round_index + 1)
            mutated["length"] = 4
        if tool_name == "source.map.remove":
            mutated["line_number"] = 12
            mutated["base_address"] = context.live_case.seed.primary_function_start
        if tool_name == "layout.struct.field.comment.set":
            mutated["offset"] = 0
        if tool_name in {"reference.delete", "reference.primary.set"}:
            mutated["operand_index"] = 0
        if tool_name == "type.get_by_id":
            if context.live_case.seed_type_id is not None:
                mutated["data_type_id"] = context.live_case.seed_type_id
                mutated.pop("universal_id", None)
                mutated.pop("source_archive_id", None)
            else:
                mutated.pop("data_type_id", None)
                mutated["universal_id"] = context.live_case.seed_type_universal_id
                mutated["source_archive_id"] = context.live_case.seed_type_source_archive_id

    if tool_name == "parameter.move":
        mutated["ordinal"] = 0
        mutated["new_ordinal"] = 0

    if "new_name" in mutated and round_index >= 2:
        mutated["new_name"] = f"{mutated['new_name']}_{round_index}"
    if "comment" in mutated and tool_name != "comment.set" and round_index >= 2:
        mutated["comment"] = f"{mutated['comment']} #{round_index}"
    if "text" in mutated and round_index >= 2:
        mutated["text"] = "demo"
    if "query" in mutated and tool_name in {
        "comment.list",
        "project.files.list",
        "project.search.programs",
        "search.resolve",
        "symbol.list",
    }:
        mutated["query"] = query_overrides[tool_name]

    return mutated


def _arguments_for_case(
    spec: dict[str, Any],
    context: ToolContext,
    round_index: int,
    rng: random.Random,
    *,
    sample_path: str | None = None,
) -> dict[str, Any]:
    include_optional = round_index > 0
    arguments = tool_arguments(
        spec,
        context.session_id,
        context.task_id,
        include_optional=include_optional,
        sample_path=sample_path,
        context=context,
    )
    return _mutate_arguments(spec["name"], arguments, round_index, rng, context=context)


def _prepare_context(ctx: ToolContext, tool_name: str) -> None:
    if ctx.mode == "fake":
        pre_actions(ctx.backend, tool_name, ctx.session_id)
        return
    if ctx.live_case is None:
        return
    if tool_name in {"transaction.commit", "transaction.revert"}:
        ctx.backend.undo_begin(ctx.session_id, description="demo")
        ctx.backend.annotation_comment_set(
            ctx.session_id,
            address=ctx.live_case.seed.primary_function_start,
            scope="listing",
            comment_type="eol",
            comment="tx seed",
        )
        return
    if tool_name in {"transaction.undo", "transaction.redo"}:
        ctx.backend.annotation_symbol_create(
            ctx.session_id,
            address=ctx.live_case.seed.primary_function_start,
            name="undo_seed_label",
        )
        if tool_name == "transaction.redo":
            ctx.backend.undo_undo(ctx.session_id)
        return
    if tool_name in {"task.status", "task.result", "task.cancel"}:
        ctx.task_id = ctx.backend.task_analysis_update(ctx.session_id)["task_id"]
    if tool_name == "memory.block.remove":
        ctx.backend.memory_block_create(
            ctx.session_id,
            name="scratch",
            address=ctx.live_case.seed.free_memory_address,
            length=32,
            initialized=True,
        )
    if tool_name == "function.create":
        ctx.backend.listing_disassemble_seed(
            ctx.session_id,
            address=ctx.live_case.seed.create_function_start,
            limit=8,
        )
    if tool_name == "source.map.add":
        ctx.backend.source_file_add(ctx.session_id, path=ctx.live_case.created_source_path)


def _stabilize_live_result(ctx: ToolContext, tool_name: str, result: dict[str, Any]) -> None:
    if ctx.mode != "live":
        return
    structured = result.get("structuredContent") or {}
    if tool_name in {"analysis.update", "task.analysis_update"} and structured.get("task_id"):
        task_id = str(structured["task_id"])
        deadline = time.time() + 30
        while time.time() < deadline:
            status = ctx.backend.task_status(task_id)["status"]
            if status in {"completed", "failed", "cancelled"}:
                break
            time.sleep(0.1)


def run(
    limit: int | None = None,
    prefix: str | None = None,
    seed: int = 0,
    rounds: int = 3,
    fail_fast: bool = False,
    sample_path: str | None = None,
    backend_mode: str = "fake",
    ghidra_install_dir: str | None = None,
) -> dict[str, Any]:
    rng = random.Random(seed)
    selected_specs = _selected_tool_specs(limit=limit, prefix=prefix)
    rounds = max(1, int(rounds))
    resolved_sample_path = resolve_sample_binary_path(sample_path)

    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    selected_names = [spec["name"] for spec in selected_specs]

    env = None
    try:
        if backend_mode == "live":
            env = create_live_fuzz_environment(
                sample_path=resolved_sample_path,
                ghidra_install_dir=ghidra_install_dir,
            )
        for spec in selected_specs:
            for round_index in range(rounds):
                ctx = (
                    create_live_tool_context(env, seed=True)
                    if backend_mode == "live"
                    else create_tool_context(seed=True, sample_path=resolved_sample_path)
                )
                try:
                    tool_name = spec["name"]
                    _prepare_context(ctx, tool_name)
                    arguments = _arguments_for_case(
                        spec,
                        ctx,
                        round_index,
                        rng,
                        sample_path=resolved_sample_path,
                    )
                    result = _call(ctx.server, tool_name, arguments)
                    _stabilize_live_result(ctx, tool_name, result)
                    case = {
                        "name": tool_name,
                        "round": round_index,
                        "include_optional": round_index > 0,
                        "arguments": arguments,
                        "is_error": bool(result.get("isError")),
                        "summary": _summary_text(result),
                    }
                    results.append(case)
                    if case["is_error"]:
                        failures.append(case)
                        if fail_fast:
                            raise RuntimeError(
                                f"fuzzer failed for {tool_name} round={round_index}: {case['summary']}"
                            )
                finally:
                    if ctx.cleanup is not None:
                        ctx.cleanup()
    finally:
        if env is not None:
            close_live_fuzz_environment(env)

    covered_names = sorted({item["name"] for item in results})
    missing_tools = [name for name in selected_names if name not in covered_names]

    return {
        "seed": seed,
        "backend_mode": backend_mode,
        "sample_path": resolved_sample_path,
        "rounds": rounds,
        "tool_count": len(selected_specs),
        "case_count": len(results),
        "covered_tools": covered_names,
        "missing_tools": missing_tools,
        "error_count": len(failures),
        "failures": failures,
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the MCP fuzzer against fake or live backends")
    parser.add_argument("--limit", type=int, help="Limit the number of tools fuzzed")
    parser.add_argument("--prefix", help="Only fuzz tools with this prefix")
    parser.add_argument(
        "--backend-mode",
        choices=("fake", "live"),
        default="fake",
        help="Backend mode. 'live' uses pyghidra and a copied analyzed project template.",
    )
    parser.add_argument(
        "--ghidra-install-dir",
        help="Explicit Ghidra installation directory for live mode. Defaults to GHIDRA_INSTALL_DIR or /usr/share/ghidra.",
    )
    parser.add_argument("--seed", type=int, default=0, help="Random seed")
    parser.add_argument(
        "--sample-path",
        default=resolve_sample_binary_path(),
        help="Binary path used for seeded fuzzer sessions. Default: repo samples/ls.",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=3,
        help="Number of cases to run per tool. Round 0 uses required-only args; later rounds add richer optional coverage.",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop on the first failing case instead of collecting all failures.",
    )
    parser.add_argument(
        "--verbose-results",
        action="store_true",
        help="Include per-case results in CLI JSON output.",
    )
    args = parser.parse_args(argv)
    try:
        payload = run(
            limit=args.limit,
            prefix=args.prefix,
            seed=args.seed,
            rounds=args.rounds,
            fail_fast=args.fail_fast,
            sample_path=args.sample_path,
            backend_mode=args.backend_mode,
            ghidra_install_dir=args.ghidra_install_dir,
        )
    except RuntimeError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, indent=2))
        return 1

    if not args.verbose_results:
        payload = {key: value for key, value in payload.items() if key != "results"}
    print(json.dumps(payload, indent=2))
    return 1 if payload["error_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
