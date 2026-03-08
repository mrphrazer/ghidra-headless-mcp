from __future__ import annotations

import pytest
from ghidra_headless_mcp.fuzz_support import create_tool_context, resolve_sample_binary_path
from ghidra_headless_mcp.fuzzer import run
from ghidra_headless_mcp.server import ALL_TOOL_SPECS


def test_fuzzer_covers_all_tools_with_required_and_optional_cases() -> None:
    result = run(rounds=2, seed=0)

    assert result["sample_path"] == resolve_sample_binary_path()
    assert result["tool_count"] == len(ALL_TOOL_SPECS)
    assert result["case_count"] == len(ALL_TOOL_SPECS) * 2
    assert result["missing_tools"] == []
    assert result["error_count"] == 0


def test_fuzzer_prefix_mode_exercises_deeper_round_variants() -> None:
    result = run(prefix="function.", rounds=3, seed=1)

    assert result["tool_count"] > 0
    assert result["case_count"] == result["tool_count"] * 3
    assert result["error_count"] == 0
    assert all(item["name"].startswith("function.") for item in result["results"])

    round_two = [
        item
        for item in result["results"]
        if item["name"] == "function.return_type.set" and item["round"] == 2
    ]
    assert round_two
    assert round_two[0]["arguments"]["data_type"] == "/long"


def test_fuzzer_seed_context_opens_repo_ls_sample() -> None:
    ctx = create_tool_context()

    assert ctx.backend._sessions[ctx.session_id].filename == resolve_sample_binary_path()


@pytest.mark.live
@pytest.mark.slow
def test_live_fuzzer_covers_all_tools_on_repo_ls_sample() -> None:
    pytest.importorskip("pyghidra")

    result = run(rounds=1, seed=0, backend_mode="live", fail_fast=True)

    assert result["backend_mode"] == "live"
    assert result["sample_path"] == resolve_sample_binary_path()
    assert result["tool_count"] == len(ALL_TOOL_SPECS)
    assert result["case_count"] == len(ALL_TOOL_SPECS)
    assert result["missing_tools"] == []
    assert result["error_count"] == 0


@pytest.mark.live
@pytest.mark.slow
def test_live_fuzzer_exercises_deeper_function_mutations() -> None:
    pytest.importorskip("pyghidra")

    result = run(prefix="function.", rounds=2, seed=1, backend_mode="live", fail_fast=True)

    assert result["backend_mode"] == "live"
    assert result["tool_count"] > 0
    assert result["case_count"] == result["tool_count"] * 2
    assert result["error_count"] == 0


@pytest.mark.live
@pytest.mark.slow
def test_live_fuzzer_regression_prefixes_remain_clean() -> None:
    pytest.importorskip("pyghidra")

    for prefix in ("analysis.", "patch.", "graph.", "reference.", "function.", "type.", "layout."):
        result = run(prefix=prefix, rounds=1, seed=0, backend_mode="live", fail_fast=True)

        assert result["backend_mode"] == "live"
        assert result["tool_count"] > 0
        assert result["error_count"] == 0
