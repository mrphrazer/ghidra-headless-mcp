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

#### analysis
- `analysis.analyzers.list`: List boolean analyzers available for the current program and show whether each one is enabled.
- `analysis.analyzers.set`: Enable or disable a specific boolean analyzer for the current program.
- `analysis.clear_cache`: Clear cached decompiler state for the current session so later requests rebuild it cleanly.
- `analysis.options.get`: Return the current value of a specific analysis option.
- `analysis.options.list`: List available analysis options together with their current values.
- `analysis.options.set`: Update the value of an analysis option for the current session.
- `analysis.status`: Return the current auto-analysis status for the session.
- `analysis.update`: Start auto-analysis in the background and return immediately.
- `analysis.update_and_wait`: Run auto-analysis and wait until it completes.

#### health
- `health.ping`: Confirm that the server is reachable and responding.

#### mcp
- `mcp.response_format`: Explain how MCP tool responses split full structured data and human-readable summary text.

#### task
- `task.analysis_update`: Start auto-analysis as a tracked background task and return a task ID.
- `task.cancel`: Request cancellation for a running or queued asynchronous task.
- `task.result`: Return the terminal result or error payload for a completed task.
- `task.status`: Return status, timing, and cancellation details for an asynchronous task.

### Project, Program, and Transactions

#### program
- `program.close`: Close an open program session and release its associated resources.
- `program.export_binary`: Export the program to disk as either the original-file format or raw bytes.
- `program.image_base.set`: Change the program image base and optionally commit the rebasing operation.
- `program.list_open`: List all program sessions currently held open by the server.
- `program.mode.get`: Return whether a session is currently read-only or read-write.
- `program.mode.set`: Switch a session between read-only and read-write mode.
- `program.open`: Open a binary file for analysis and return a new session.
- `program.open_bytes`: Open a binary from base64-encoded bytes and return a new session.
- `program.report`: Return a compact program report with counts plus sample functions, strings, imports, and memory blocks.
- `program.save`: Save the current program state back into the project.
- `program.save_as`: Save the current program under a new project path or name.
- `program.summary`: Return core program metadata such as architecture, memory layout, and entry point.

#### project
- `project.export`: Export the current Ghidra project artifacts to a destination directory.
- `project.file.info`: Return metadata and state flags for a specific project file.
- `project.files.list`: List project files with folder, content-type, query, and pagination filters.
- `project.folders.list`: List project folders, optionally walking the tree recursively.
- `project.program.open`: Open a program already stored in the current project and return a new session.
- `project.program.open_existing`: Open a program from a named existing Ghidra project and return a new session.
- `project.search.programs`: Search program files in the project by name or path.

#### transaction
- `transaction.begin`: Begin an explicit undo transaction for grouped changes.
- `transaction.commit`: Commit the active transaction so its changes become undoable.
- `transaction.redo`: Reapply the most recently undone change.
- `transaction.revert`: Roll back the active transaction without committing it.
- `transaction.status`: Return undo, redo, and active-transaction status for the session.
- `transaction.undo`: Undo the most recently committed change.

### Listing, Memory, Disassembly, and Patching

#### context
- `context.get`: Return processor context register values at a specific address.
- `context.ranges`: List address ranges where a processor context register value applies.
- `context.set`: Set processor context register values across an address range.

#### listing
- `listing.clear`: Clear listing content over a range, including optional symbols, comments, references, functions, or context.
- `listing.code_unit.after`: Return the nearest code unit that follows a given address.
- `listing.code_unit.at`: Return the code unit that starts exactly at a given address.
- `listing.code_unit.before`: Return the nearest code unit that precedes a given address.
- `listing.code_unit.containing`: Return the code unit that contains a given address.
- `listing.code_units.list`: List code units in a range with pagination and direction controls.
- `listing.data.at`: Return the defined data item at a specific address.
- `listing.data.clear`: Clear one or more data definitions starting at an address.
- `listing.data.create`: Create a data definition of a chosen type at an address.
- `listing.data.list`: List defined data items in the program with range and pagination controls.
- `listing.disassemble.function`: Disassemble all instructions that belong to a function body.
- `listing.disassemble.range`: Disassemble instructions across a selected address range.
- `listing.disassemble.seed`: Start disassembly from a seed address and follow discovered flows.

#### memory
- `memory.block.create`: Create a memory block with permissions, initialization, and an optional comment.
- `memory.block.remove`: Remove an existing memory block from the program.
- `memory.blocks.list`: List memory blocks together with addresses, permissions, and sizes.
- `memory.read`: Read raw bytes directly from program memory.
- `memory.write`: Write raw bytes directly into program memory.

#### patch
- `patch.assemble`: Assemble instruction text at an address and write the resulting bytes.
- `patch.branch_invert`: Invert a conditional branch instruction in place.
- `patch.nop`: Replace instructions in a range with NOP bytes.

### Symbols, Namespaces, Externals, and References

#### class
- `class.create`: Create a class namespace for recovered methods or fields.

#### equate
- `equate.clear_range`: Remove equate references across an address range and delete empty equates.
- `equate.create`: Create an equate and attach it to an operand at an address.
- `equate.delete`: Delete an equate entirely, or remove one of its references before deletion.
- `equate.list`: List equates together with values and attached references.

#### external
- `external.entrypoint.add`: Add an address to the program's external entry point set.
- `external.entrypoint.list`: List addresses currently marked as external entry points.
- `external.entrypoint.remove`: Remove an address from the external entry point set.
- `external.exports.list`: List symbols exported by the program.
- `external.function.create`: Create an external function symbol under an external location.
- `external.imports.list`: List symbols imported by the program.
- `external.library.create`: Create a new external library record.
- `external.library.list`: List external libraries known to the program.
- `external.library.set_path`: Set or update the filesystem path associated with an external library.
- `external.location.create`: Create an external location for a symbol within a library.
- `external.location.get`: Return details for a specific external location.

#### namespace
- `namespace.create`: Create a namespace under an optional parent namespace.

#### reference
- `reference.association.remove`: Remove the symbol association attached to a specific reference.
- `reference.association.set`: Associate a specific reference with a symbol.
- `reference.clear_from`: Remove references originating from one address or an address range.
- `reference.clear_to`: Remove all references that target a specific address.
- `reference.create.external`: Create a reference from an address to an external location.
- `reference.create.memory`: Create a memory reference between two program addresses.
- `reference.create.register`: Create a reference from an address to a register.
- `reference.create.stack`: Create a reference from an address to a stack location.
- `reference.delete`: Delete a specific reference selected by source, destination, and operand.
- `reference.from`: List cross-references that originate from an address.
- `reference.primary.set`: Mark a specific reference as the primary one for its operand.
- `reference.to`: List cross-references that target an address.

#### symbol
- `symbol.by_name`: Look up a symbol by name and return its details.
- `symbol.create`: Create a new symbol or label at an address.
- `symbol.delete`: Delete a symbol at an address, optionally by name.
- `symbol.list`: List symbols with filtering and pagination support.
- `symbol.namespace.move`: Move a symbol into a different namespace.
- `symbol.primary.set`: Mark a selected symbol as the primary symbol at its address.
- `symbol.rename`: Rename an existing symbol.

### Comments, Bookmarks, Tags, Metadata, Source, and Relocations

#### bookmark
- `bookmark.add`: Add a bookmark at an address with a type, category, and comment.
- `bookmark.clear`: Remove bookmarks in an address range, optionally filtered by bookmark type.
- `bookmark.list`: List bookmarks, optionally scoped to an address or bookmark type.
- `bookmark.remove`: Remove bookmarks at an address, optionally filtered by type or category.

#### comment
- `comment.get`: Return one comment type from a specific address.
- `comment.get_all`: Return all available comment types at an address, with optional function comments.
- `comment.list`: List comments matching range, type, text, and pagination filters.
- `comment.set`: Set or clear a comment of a selected type at an address.

#### metadata
- `metadata.query`: Read metadata entries stored by this server, optionally filtered by key or prefix.
- `metadata.store`: Store a JSON-serializable metadata value under a program-scoped key.

#### relocation
- `relocation.add`: Add a relocation entry at an address with type, status, values, and symbol metadata.
- `relocation.list`: List relocation entries, optionally limited to an address range.

#### source
- `source.file.add`: Register a source file record with the program's source file manager.
- `source.file.list`: List all source files currently registered with the program.
- `source.file.remove`: Remove a source file record by path.
- `source.map.add`: Add a source mapping entry from a source line to an address range.
- `source.map.list`: List source mapping entries by address, source file, or line filters.
- `source.map.remove`: Remove a specific source mapping entry by file, line, and base address.

#### tag
- `tag.add`: Create or reuse a function tag and attach it to a function.
- `tag.list`: List tags for one function or across the whole program.
- `tag.remove`: Remove a function tag from a function.
- `tag.stats`: Summarize function tags and the number of functions using each one.

### Functions, Variables, Types, and Layout Reconstruction

#### function
- `function.at`: Return the function that starts at, or contains, a specific address.
- `function.batch.run`: Run one supported action across a filtered batch of functions.
- `function.body.set`: Replace the body range of an existing function.
- `function.by_name`: Look up a function by name and return its details.
- `function.callees`: List the functions called by a specific function.
- `function.callers`: List the functions that call a specific function.
- `function.calling_convention.set`: Set the calling convention used by a function.
- `function.calling_conventions.list`: List calling conventions available in the current program.
- `function.create`: Create a new function at a given address.
- `function.delete`: Delete a function at a given address.
- `function.flags.set`: Update function flags such as varargs, inline, noreturn, or custom storage.
- `function.list`: List functions in the program with filtering and pagination support.
- `function.rename`: Rename an existing function.
- `function.report`: Return a richer function report with signature, variables, call graph edges, xrefs, and decompilation output.
- `function.return_type.set`: Set the return type of a function.
- `function.signature.get`: Return the full signature of a function.
- `function.signature.set`: Apply a full C-style signature declaration to a function.
- `function.thunk.set`: Mark a function as a thunk to another function.
- `function.variables`: List parameters and local variables for a function.

#### layout
- `layout.enum.create`: Create an enum data type in a chosen category.
- `layout.enum.member.add`: Add a named value to an enum data type.
- `layout.enum.member.remove`: Remove a named member from an enum data type.
- `layout.inspect.components`: Inspect the component layout of a composite data type.
- `layout.struct.bitfield.add`: Insert a bitfield into a structure at a byte and bit offset.
- `layout.struct.create`: Create a structure data type in a chosen category.
- `layout.struct.field.add`: Add a field to a structure at a specific offset or append position.
- `layout.struct.field.clear`: Clear a field from a structure by offset, ordinal, or field name.
- `layout.struct.field.comment.set`: Set or clear the comment on a structure field.
- `layout.struct.field.rename`: Rename a structure field.
- `layout.struct.field.replace`: Replace an existing structure field with a new type, size, name, or comment.
- `layout.struct.fill_from_decompiler`: Build or extend a structure from decompiler-observed usage of a variable.
- `layout.struct.get`: Return a structure definition together with its components.
- `layout.struct.resize`: Resize a structure to a specific total length.
- `layout.union.create`: Create a union data type in a chosen category.
- `layout.union.member.add`: Add a member to a union data type.
- `layout.union.member.remove`: Remove a member from a union data type.

#### parameter
- `parameter.add`: Add a new parameter to a function with a chosen type and storage.
- `parameter.move`: Reorder a parameter to a new ordinal within the signature.
- `parameter.remove`: Remove a parameter from a function by ordinal or name.
- `parameter.replace`: Replace an existing parameter definition by ordinal or name.

#### stackframe
- `stackframe.variable.clear`: Clear a stack-frame variable at a specific stack offset.
- `stackframe.variable.create`: Create a stack-frame variable at a specific stack offset.
- `stackframe.variables`: List stack-frame variables for a function.

#### type
- `type.apply_at`: Apply a data type at an address in the listing.
- `type.archives.list`: List the current program archive plus attached source archives.
- `type.category.create`: Create a new data type category path.
- `type.category.list`: List data type categories under a path, optionally recursively.
- `type.define_c`: Define a new data type from a C declaration.
- `type.delete`: Delete a data type by name or full path.
- `type.get`: Return details for a data type by name or full path.
- `type.get_by_id`: Look up a data type by internal ID, universal ID, or source archive ID.
- `type.list`: List data types with filtering and pagination support.
- `type.parse_c`: Parse a C declaration and return the resulting type without necessarily committing it.
- `type.rename`: Rename an existing data type.
- `type.source_archives.list`: List source archives referenced by the current data type manager.

#### variable
- `variable.comment.set`: Set or clear the comment attached to a local variable or parameter.
- `variable.local.create`: Create a local variable with explicit type, storage, and optional comment.
- `variable.local.remove`: Remove a local variable from a function.
- `variable.rename`: Rename a local variable or parameter.
- `variable.retype`: Change the data type of a local variable or parameter.

### Decompiler, P-Code, Search, and Graph Extraction

#### decomp
- `decomp.ast`: Decompile a function and return the Clang markup tree for the result.
- `decomp.function`: Decompile a function and return recovered C source code.
- `decomp.global.rename`: Rename a global symbol selected through decompiler high-symbol information.
- `decomp.global.retype`: Retype a global symbol selected through decompiler high-symbol information.
- `decomp.high_function.summary`: Summarize the high-function view, including local symbols, globals, blocks, and jump tables.
- `decomp.override.get`: Return the decompiler call override, if any, for a specific callsite.
- `decomp.override.set`: Set or replace the decompiler call override signature for a specific callsite.
- `decomp.tokens`: Decompile a function and return tokenized Clang markup for the output.
- `decomp.trace_type.backward`: Trace type propagation backward from a selected decompiler symbol.
- `decomp.trace_type.forward`: Trace type propagation forward from a selected decompiler symbol.
- `decomp.writeback.locals`: Commit decompiler-recovered local names back into the program database.
- `decomp.writeback.params`: Commit decompiler-recovered parameter information back into the program database.

#### ghidra
- `ghidra.call`: Invoke Ghidra or Java APIs directly through a generic bridge.
- `ghidra.eval`: Evaluate Python code inside the live Ghidra runtime context.
- `ghidra.info`: Return runtime information about Ghidra, PyGhidra, and the server environment.
- `ghidra.script`: Run a Ghidra script against an open program session.

#### graph
- `graph.basic_blocks`: List the basic blocks that make up a function.
- `graph.call_paths`: Find call graph paths between two functions up to a chosen depth.
- `graph.cfg.edges`: List control-flow edges between the basic blocks of a function.

#### pcode
- `pcode.block`: Return per-instruction p-code for the basic block containing an address.
- `pcode.function`: Return per-instruction p-code for a function.
- `pcode.op.at`: Return the p-code ops generated by the instruction at an address.
- `pcode.varnode_uses`: Find p-code reads and writes that match a selected varnode.

#### search
- `search.bytes`: Search program memory for an exact byte pattern.
- `search.constants`: Search instructions for scalar constant operands that match a value.
- `search.defined_strings`: List defined strings discovered in the program.
- `search.instructions`: Search instructions by mnemonic or rendered instruction text.
- `search.pcode`: Search p-code operations by mnemonic or rendered op text.
- `search.resolve`: Resolve a symbol name or expression into an address.
- `search.text`: Search for text across defined strings and raw memory matches.

## Contact

For more information, contact Tim Blazytko ([@mr_phrazer](https://x.com/mr_phrazer)).
