# Ghidra Headless MCP

A headless [Ghidra](https://ghidra-sre.org/) server that speaks [MCP](https://modelcontextprotocol.io/) (Model Context Protocol), giving AI agents full access to deep reverse-engineering workflows: program lifecycle, disassembly, decompilation, patching, types, xrefs, scripting, and more, without a GUI.

Designed to run in the same Docker container as the agent runtime. No sidecars, no extra services.

This entire project---code, tests, and documentation---is 100% vibe coded.

## Why

Existing Ghidra automation usually assumes either interactive GUI use or ad hoc scripts with a narrow workflow. This server is headless-only and designed for agent-driven workflows in sandboxed VM/container environments: the agent gets full control over the analysis system, automating large parts of reverse engineering while you interactively discuss and steer the process.

The goal is an interface where agents can inspect, refine, and extend an analysis over time: updating types, symbols, and metadata, improving the analysis database incrementally, applying patches and iterating safely with transactions and undo/redo, and running custom scripts when a workflow needs something bespoke.

## Features

- **212 tools** across **34 feature groups**: project and program lifecycle, disassembly, decompilation, patching, transactions, types, layouts, memory, search, graph extraction, scripting, and more.
- **Read-only by default** with safe mutation workflows (transactions, undo/redo, explicit save paths).
- **Scripting access** via `ghidra.eval`, `ghidra.call`, and `ghidra.script` for anything the tool catalog doesn't cover.
- **Stdio and TCP transports.**
- **Real `pyghidra` backend** for live headless Ghidra workflows.
- **Fake backend mode** for CI and development without a Ghidra install.

## Prerequisites

- Python `3.11+`
- A [Ghidra](https://ghidra-sre.org/) installation plus `pyghidra` in your runtime (for real analysis)
- For CI/development without Ghidra, use fake backend mode

## Installation

From the repo root:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install .
```

For development:

```bash
pip install -e ".[dev]"
```

## Quick Start

Stdio transport (default):

```bash
GHIDRA_INSTALL_DIR=/ABSOLUTE/PATH/TO/ghidra python3 ghidra_headless_mcp.py
```

TCP transport:

```bash
GHIDRA_INSTALL_DIR=/ABSOLUTE/PATH/TO/ghidra python3 ghidra_headless_mcp.py --transport tcp --host 127.0.0.1 --port 8765
```

Fake backend mode (no Ghidra required):

```bash
python3 ghidra_headless_mcp.py --fake-backend
```

Installed console script:

```bash
ghidra-headless-mcp --version
```

## Use With AI Agents

This server speaks standard MCP over `stdio` (default) or `tcp`, so any MCP-capable agent host can use it.

### Claude Code

```bash
claude mcp add ghidra_headless_mcp -- python3 /path/to/ghidra-headless-mcp/ghidra_headless_mcp.py --ghidra-install-dir /ABSOLUTE/PATH/TO/ghidra
```

Or add it to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "ghidra_headless_mcp": {
      "command": "python3",
      "args": [
        "ghidra_headless_mcp.py",
        "--ghidra-install-dir",
        "/ABSOLUTE/PATH/TO/ghidra"
      ],
      "cwd": "/path/to/ghidra-headless-mcp"
    }
  }
}
```

For fake mode, append `--fake-backend` and omit the install dir.

### Codex

```bash
codex mcp add ghidra_headless_mcp -- python3 ghidra_headless_mcp.py --ghidra-install-dir /ABSOLUTE/PATH/TO/ghidra
```

### Generic MCP Host

- Register a server named `ghidra_headless_mcp`.
- Use command `python3` with args `["ghidra_headless_mcp.py", "--ghidra-install-dir", "/ABSOLUTE/PATH/TO/ghidra"]` when `cwd` is the repo root, or use an absolute script path in `args`.
- Set `cwd` to the repo path if you want relative paths like `samples/ls` to resolve correctly.
- Use stdio transport unless your host requires TCP.
- For fake mode (no Ghidra installed), append `--fake-backend`.
- Verify connectivity by calling `health.ping`, then `program.open`.

## Docker Co-Location Pattern

Recommended deployment model: run the agent process and this MCP server in the same container image.

Example baseline:

```dockerfile
FROM kalilinux/kali-rolling:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip ghidra
WORKDIR /app
COPY . /app
RUN python3 -m pip install --upgrade pip --break-system-packages \
 && python3 -m pip install ".[dev]" --break-system-packages
CMD ["python3", "ghidra_headless_mcp.py", "--fake-backend"]
```

If you need real Ghidra analysis in-container, keep Ghidra installed in that same image and set `GHIDRA_INSTALL_DIR` or pass `--ghidra-install-dir`.

## MCP Methods

- `initialize`
- `ping`
- `tools/list`
- `tools/call`
- `shutdown`

`tools/list` behavior:

- Without explicit pagination params, returns the full tool catalog.
- If `offset` or `limit` is provided, uses paginated output (`offset=0`, `limit=50` default in paged mode).
- Supports filtering via:
  - `prefix` (for example `program.`)
  - `query` (substring match against tool name/description)
- Returns pagination metadata: `offset`, `limit`, `total`, `has_more`.
- When a page is truncated (`has_more=true`), includes `next_offset` and a `notice` hint.

Tool call response behavior:

- `structuredContent` is the canonical full payload.
- `content[0].text` is a compact summary string (not full JSON duplication).
- This split is intentional to keep context usage smaller while still exposing full machine-readable data.

## Quality And Testing

This repository is well tested and has enforced quality gates.

- Test suite: run `pytest --collect-only -q` for the current collected test count.
- CI workflow enforces:
  - `ruff format --check .`
  - `ruff check .`
  - `pytest -m "not live"`
  - `pytest -m live`
  - clean-copy wheel build and install verification
- Fake backend coverage runs without requiring a Ghidra install.
- Additional structural tests verify tool registry consistency, server behavior, and backend reachability.

## Context Controls

- Read-only mode is the default for opened programs (`read_only=true`).
- Deterministic process-level startup is enabled by default and can be disabled with `--no-deterministic`.
- Many list/search surfaces are paginated with `offset` and `limit`.

## Limitations

- Debugger-oriented Ghidra workflows are not currently covered.
- Version Tracking, FID, BSim, and emulator workflows are not currently exposed.

## Security Model

- MCP communication (`stdio`/`tcp`) is unauthenticated by default.
- The server exposes arbitrary scripting via `ghidra.eval` and broad API access via `ghidra.call`.
- This is by design for trusted, containerized agent environments.
- Do not expose this server directly to untrusted users or networks.

## Local Dev Workflow

```bash
python3 -m ruff format --check .
python3 -m ruff check .
python3 -m pytest -m "not live"
GHIDRA_INSTALL_DIR=/usr/share/ghidra python3 -m pytest -m live
```

Release process notes live in `RELEASING.md`. Public GitHub source releases remain blocked until an explicit repository license is chosen.

## Feature Fuzzer

Use the built-in MCP feature fuzzer to exercise a broad tool surface against `samples/ls`.

Real Ghidra backend:

```bash
python3 -m ghidra_headless_mcp.fuzzer --backend-mode live --sample-path samples/ls --rounds 1 --seed 1337 --ghidra-install-dir /ABSOLUTE/PATH/TO/ghidra
```

Fake backend smoke run:

```bash
python3 -m ghidra_headless_mcp.fuzzer --backend-mode fake --sample-path samples/ls --rounds 2 --limit 40
```

Target a specific tool family:

```bash
python3 -m ghidra_headless_mcp.fuzzer --backend-mode live --prefix function. --rounds 2 --fail-fast --ghidra-install-dir /ABSOLUTE/PATH/TO/ghidra
```

Useful flags:

- `--limit N`: fuzz only the first `N` tools from the selected set.
- `--prefix PREFIX`: restrict fuzzing to one tool family.
- `--rounds N`: run richer optional-argument coverage in later rounds.
- `--fail-fast`: stop on the first failing case.
- `--verbose-results`: include per-case results in CLI JSON output.

## Feature Catalog

The server currently exposes `212` tools across `34` feature groups. The broader capability matrix by feature family lives in `FEATURE_SUPPORT.md`.

### Core and Infrastructure

## analysis
- `analysis.analyzers.list`: analysis analyzers list.
- `analysis.analyzers.set`: analysis analyzers set.
- `analysis.clear_cache`: analysis clear cache.
- `analysis.options.get`: Get the value of an analysis option.
- `analysis.options.list`: List available analysis options.
- `analysis.options.set`: Set an analysis option value.
- `analysis.status`: Get the current analysis status.
- `analysis.update`: Start auto-analysis (non-blocking).
- `analysis.update_and_wait`: Run auto-analysis and wait for completion.

## health
- `health.ping`: Health check.

## mcp
- `mcp.response_format`: Explain MCP tool result fields (`structuredContent` full payload, `content[0].text` summary).

## task
- `task.analysis_update`: task analysis update.
- `task.cancel`: Cancel a running or queued task.
- `task.result`: Get the result of a completed task.
- `task.status`: Get the status of an asynchronous task.

### Project, Program, and Transactions

## program
- `program.close`: Close an open program session and release resources.
- `program.export_binary`: Export program as a binary file.
- `program.image_base.set`: Set the program image base address.
- `program.list_open`: List all currently open program sessions.
- `program.mode.get`: Get the current read/write mode of a session.
- `program.mode.set`: Set a session to read-only or read-write mode.
- `program.open`: Open a binary file for analysis and return a session ID.
- `program.open_bytes`: Open a binary from base64-encoded bytes and return a session ID.
- `program.report`: program report.
- `program.save`: Save the current program state to the project.
- `program.save_as`: Save the program under a new name or location.
- `program.summary`: Return a summary of the program in a session (architecture, memory, entry point).

## project
- `project.export`: project export.
- `project.file.info`: project file info.
- `project.files.list`: project files list.
- `project.folders.list`: project folders list.
- `project.program.open`: project program open.
- `project.program.open_existing`: project program open existing.
- `project.search.programs`: project search programs.

## transaction
- `transaction.begin`: Begin an explicit undo transaction.
- `transaction.commit`: Commit the active transaction.
- `transaction.redo`: Redo the last undone change.
- `transaction.revert`: Revert (roll back) the active transaction.
- `transaction.status`: Get the current transaction status.
- `transaction.undo`: Undo the last committed change.

### Listing, Memory, Disassembly, and Patching

## context
- `context.get`: context get.
- `context.ranges`: context ranges.
- `context.set`: context set.

## listing
- `listing.clear`: listing clear.
- `listing.code_unit.after`: listing code unit after.
- `listing.code_unit.at`: listing code unit at.
- `listing.code_unit.before`: listing code unit before.
- `listing.code_unit.containing`: listing code unit containing.
- `listing.code_units.list`: listing code units list.
- `listing.data.at`: listing data at.
- `listing.data.clear`: listing data clear.
- `listing.data.create`: listing data create.
- `listing.data.list`: listing data list.
- `listing.disassemble.function`: Disassemble an entire function.
- `listing.disassemble.range`: Disassemble a range of addresses.
- `listing.disassemble.seed`: Disassemble starting from a seed address.

## memory
- `memory.block.create`: memory block create.
- `memory.block.remove`: memory block remove.
- `memory.blocks.list`: List all memory blocks in the program.
- `memory.read`: Read raw bytes from program memory.
- `memory.write`: Write raw bytes to program memory.

## patch
- `patch.assemble`: patch assemble.
- `patch.branch_invert`: patch branch invert.
- `patch.nop`: patch nop.

### Symbols, Namespaces, Externals, and References

## class
- `class.create`: class create.

## equate
- `equate.clear_range`: equate clear range.
- `equate.create`: equate create.
- `equate.delete`: equate delete.
- `equate.list`: equate list.

## external
- `external.entrypoint.add`: external entrypoint add.
- `external.entrypoint.list`: external entrypoint list.
- `external.entrypoint.remove`: external entrypoint remove.
- `external.exports.list`: List exported symbols.
- `external.function.create`: external function create.
- `external.imports.list`: List imported symbols.
- `external.library.create`: external library create.
- `external.library.list`: external library list.
- `external.library.set_path`: external library set path.
- `external.location.create`: external location create.
- `external.location.get`: external location get.

## namespace
- `namespace.create`: namespace create.

## reference
- `reference.association.remove`: reference association remove.
- `reference.association.set`: reference association set.
- `reference.clear_from`: reference clear from.
- `reference.clear_to`: reference clear to.
- `reference.create.external`: reference create external.
- `reference.create.memory`: reference create memory.
- `reference.create.register`: reference create register.
- `reference.create.stack`: reference create stack.
- `reference.delete`: reference delete.
- `reference.from`: List cross-references from an address.
- `reference.primary.set`: reference primary set.
- `reference.to`: List cross-references to an address.

## symbol
- `symbol.by_name`: Look up a symbol by its name.
- `symbol.create`: Create a new symbol (label) at an address.
- `symbol.delete`: Delete a symbol at an address.
- `symbol.list`: List symbols with optional filtering and pagination.
- `symbol.namespace.move`: symbol namespace move.
- `symbol.primary.set`: symbol primary set.
- `symbol.rename`: Rename an existing symbol.

### Comments, Bookmarks, Tags, Metadata, Source, and Relocations

## bookmark
- `bookmark.add`: bookmark add.
- `bookmark.clear`: bookmark clear.
- `bookmark.list`: bookmark list.
- `bookmark.remove`: bookmark remove.

## comment
- `comment.get`: Get the comment at a specific address.
- `comment.get_all`: Get all comment types at an address.
- `comment.list`: List comments matching optional filters.
- `comment.set`: Set or clear a comment at an address.

## metadata
- `metadata.query`: metadata query.
- `metadata.store`: metadata store.

## relocation
- `relocation.add`: relocation add.
- `relocation.list`: relocation list.

## source
- `source.file.add`: source file add.
- `source.file.list`: source file list.
- `source.file.remove`: source file remove.
- `source.map.add`: source map add.
- `source.map.list`: source map list.
- `source.map.remove`: source map remove.

## tag
- `tag.add`: tag add.
- `tag.list`: tag list.
- `tag.remove`: tag remove.
- `tag.stats`: tag stats.

### Functions, Variables, Types, and Layout Reconstruction

## function
- `function.at`: Get function information at a specific address.
- `function.batch.run`: function batch run.
- `function.body.set`: function body set.
- `function.by_name`: Look up a function by its name.
- `function.callees`: List functions called by a given function.
- `function.callers`: List functions that call a given function.
- `function.calling_convention.set`: function calling convention set.
- `function.calling_conventions.list`: function calling conventions list.
- `function.create`: Create a new function at a given address.
- `function.delete`: Delete a function at a given address.
- `function.flags.set`: function flags set.
- `function.list`: List functions in the program with optional filtering and pagination.
- `function.rename`: Rename a function.
- `function.report`: function report.
- `function.return_type.set`: function return type set.
- `function.signature.get`: Get the full signature of a function.
- `function.signature.set`: Set the signature of a function from a C declaration.
- `function.thunk.set`: function thunk set.
- `function.variables`: List local variables and parameters of a function.

## layout
- `layout.enum.create`: layout enum create.
- `layout.enum.member.add`: layout enum member add.
- `layout.enum.member.remove`: layout enum member remove.
- `layout.inspect.components`: layout inspect components.
- `layout.struct.bitfield.add`: layout struct bitfield add.
- `layout.struct.create`: layout struct create.
- `layout.struct.field.add`: layout struct field add.
- `layout.struct.field.clear`: layout struct field clear.
- `layout.struct.field.comment.set`: layout struct field comment set.
- `layout.struct.field.rename`: layout struct field rename.
- `layout.struct.field.replace`: layout struct field replace.
- `layout.struct.fill_from_decompiler`: layout struct fill from decompiler.
- `layout.struct.get`: layout struct get.
- `layout.struct.resize`: layout struct resize.
- `layout.union.create`: layout union create.
- `layout.union.member.add`: layout union member add.
- `layout.union.member.remove`: layout union member remove.

## parameter
- `parameter.add`: parameter add.
- `parameter.move`: parameter move.
- `parameter.remove`: parameter remove.
- `parameter.replace`: parameter replace.

## stackframe
- `stackframe.variable.clear`: stackframe variable clear.
- `stackframe.variable.create`: stackframe variable create.
- `stackframe.variables`: stackframe variables.

## type
- `type.apply_at`: Apply a data type at an address.
- `type.archives.list`: type archives list.
- `type.category.create`: type category create.
- `type.category.list`: type category list.
- `type.define_c`: Define a new data type from a C declaration.
- `type.delete`: Delete a data type by name or path.
- `type.get`: Get details of a data type by name or path.
- `type.get_by_id`: type get by id.
- `type.list`: List data types with optional filtering and pagination.
- `type.parse_c`: Parse a C type declaration without committing it (unless composite).
- `type.rename`: Rename an existing data type.
- `type.source_archives.list`: type source archives list.

## variable
- `variable.comment.set`: variable comment set.
- `variable.local.create`: variable local create.
- `variable.local.remove`: variable local remove.
- `variable.rename`: variable rename.
- `variable.retype`: variable retype.

### Decompiler, P-Code, Search, and Graph Extraction

## decomp
- `decomp.ast`: decomp ast.
- `decomp.function`: Decompile a function and return C source code.
- `decomp.global.rename`: decomp global rename.
- `decomp.global.retype`: decomp global retype.
- `decomp.high_function.summary`: decomp high function summary.
- `decomp.override.get`: decomp override get.
- `decomp.override.set`: decomp override set.
- `decomp.tokens`: decomp tokens.
- `decomp.trace_type.backward`: decomp trace type backward.
- `decomp.trace_type.forward`: decomp trace type forward.
- `decomp.writeback.locals`: decomp writeback locals.
- `decomp.writeback.params`: decomp writeback params.

## ghidra
- `ghidra.call`: Generic API bridge for direct Ghidra and Java access.
- `ghidra.eval`: Evaluate Python code inside the Ghidra runtime context.
- `ghidra.info`: Return Ghidra and PyGhidra runtime information.
- `ghidra.script`: Run a Ghidra script against an open program session.

## graph
- `graph.basic_blocks`: graph basic blocks.
- `graph.call_paths`: graph call paths.
- `graph.cfg.edges`: graph cfg edges.

## pcode
- `pcode.block`: pcode block.
- `pcode.function`: pcode function.
- `pcode.op.at`: pcode op at.
- `pcode.varnode_uses`: pcode varnode uses.

## search
- `search.bytes`: Search for a byte pattern in program memory.
- `search.constants`: Search for scalar constants in instructions and data.
- `search.defined_strings`: List defined strings in the program.
- `search.instructions`: Search for instructions matching a pattern.
- `search.pcode`: Search for p-code operations matching criteria.
- `search.resolve`: Resolve a symbol name or expression to an address.
- `search.text`: Search for a text string in the program.

## Contact

For more information, contact Tim Blazytko ([@mr_phrazer](https://x.com/mr_phrazer)).
