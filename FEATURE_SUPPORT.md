# Ghidra Headless MCP Feature Support

This file tracks the scoped implementation status for the category-aligned MCP surface in this repository.

`supported` here means the planned MCP tool families for this repo pass exist as first-class tools. It does not claim that every adjacent Ghidra subsystem in the broader taxonomy from `/codex/features.md` is exposed.

Scope for this matrix:

- Categories covered here: `1` and `3` through `11`
- Status is based on explicit MCP tools first
- `ghidra.call`, `ghidra.eval`, and `ghidra.script` remain escape hatches, not category-complete coverage

## Summary Matrix

| Category | Status | Current explicit support |
| --- | --- | --- |
| `1. Project, Program, and Transaction Lifecycle` | `supported` | Canonical `program.*`, `project.*`, and `transaction.*` surfaces cover open/save/export, project traversal, project-program reopen, project file metadata, and transaction begin/commit/revert/undo/redo/status |
| `3. Listing, Memory, Disassembly, and Patching` | `supported` | `listing.*`, `memory.*`, `patch.*`, and `context.*` cover code-unit navigation, selective listing clears, disassembly seeding, block CRUD, raw memory mutation, and patch helpers |
| `4. Symbols, Namespaces, and External Linkage` | `supported` | `symbol.*`, `namespace.create`, `class.create`, and `external.*` cover symbol CRUD, primary-symbol changes, namespace moves, library/location/function creation, library-path updates, and external entrypoint management |
| `5. References, Xrefs, and Equates` | `supported` | `reference.*` and `equate.*` cover memory/stack/register/external reference creation, deletion, primary assignment, association changes, clears, and equate CRUD over single locations and ranges |
| `6. Comments, Bookmarks, Tags, and Persistent Annotations` | `supported` | `comment.*`, `bookmark.*`, `tag.*`, `metadata.*`, `source.*`, and `relocation.*` cover comment aggregation/search, bookmark CRUD, tag stats/removal, persistent metadata, source file/map CRUD, and relocation listing/addition |
| `7. Functions, Signatures, Parameters, and Variable Storage` | `supported` | `function.*`, `parameter.*`, `variable.*`, and `stackframe.*` cover function CRUD, body edits, calling conventions, thunking, flags, structured parameter edits, local/stack variables, variable comments, and signature/return updates |
| `8. Data Types, Type Libraries, and Type Application` | `supported` | `type.*` covers type list/get/define/parse/rename/delete/apply plus category CRUD, archive/source-archive listing, and lookup by type ID |
| `9. Struct, Union, Enum, and Layout Reconstruction` | `supported` | `layout.struct.*`, `layout.union.*`, `layout.enum.*`, and `layout.inspect.*` cover struct resize/field replace/clear/comments, bitfields, unions, enum member removal, component inspection, and decompiler-backed structure filling |
| `10. Decompiler, High-Level Symbols, and P-code Writeback` | `supported` | `decomp.*` and `pcode.*` cover decompilation, tokens/AST, high-function summaries, decompiler writeback for params/locals, callsite overrides, type tracing, decompiler-aware rename/retype flows, and p-code inspection |
| `11. Search, Bulk Query, and Graph Extraction` | `supported` | `search.*`, `graph.*`, `project.search.programs`, `reference.to/from`, and `function.batch.run` cover scoped text/byte/constant/instruction/pcode search, encoding-selectable text search, comment search, project-wide program traversal, range xref sweeps, CFG/basic blocks, and call-path extraction |

## 1. Project, Program, and Transaction Lifecycle

- `program.open`, `program.open_bytes`, `program.close`, `program.list_open`, `program.summary`, and `program.report`
- `program.mode.get` and `program.mode.set`
- `program.save`, `program.save_as`, `program.export_binary`, and `project.export`
- `project.folders.list`, `project.files.list`, `project.file.info`, `project.program.open`, `project.program.open_existing`, and `project.search.programs`
- `transaction.begin`, `transaction.commit`, `transaction.revert`, `transaction.undo`, `transaction.redo`, and `transaction.status`

## 3. Listing, Memory, Disassembly, and Patching

- `listing.code_units.list`
- `listing.code_unit.at`, `listing.code_unit.before`, `listing.code_unit.after`, and `listing.code_unit.containing`
- `listing.clear`
- `listing.disassemble.function`, `listing.disassemble.range`, and `listing.disassemble.seed`
- `memory.read` and `memory.write`
- `memory.blocks.list`, `memory.block.create`, and `memory.block.remove`
- `patch.assemble`, `patch.nop`, and `patch.branch_invert`
- `context.get`, `context.set`, and `context.ranges`

## 4. Symbols, Namespaces, and External Linkage

- `symbol.list`, `symbol.by_name`, `symbol.create`, `symbol.rename`, and `symbol.delete`
- `symbol.primary.set` and `symbol.namespace.move`
- `namespace.create` and `class.create`
- `external.imports.list` and `external.exports.list`
- `external.library.list`, `external.library.create`, and `external.library.set_path`
- `external.location.get`, `external.location.create`, and `external.function.create`
- `external.entrypoint.add`, `external.entrypoint.remove`, and `external.entrypoint.list`

## 5. References, Xrefs, and Equates

- `reference.to` and `reference.from` support both single-address queries and range sweeps
- `reference.create.memory`, `reference.create.stack`, `reference.create.register`, and `reference.create.external`
- `reference.delete`, `reference.clear_from`, `reference.clear_to`, `reference.primary.set`, `reference.association.set`, and `reference.association.remove`
- `equate.create`, `equate.list`, `equate.delete`, and `equate.clear_range`

## 6. Comments, Bookmarks, Tags, and Persistent Annotations

- `comment.get`, `comment.set`, `comment.get_all`, and `comment.list`
- `bookmark.add`, `bookmark.list`, `bookmark.remove`, and `bookmark.clear`
- `tag.add`, `tag.list`, `tag.remove`, and `tag.stats`
- `metadata.store` and `metadata.query`
- `source.file.list`, `source.file.add`, and `source.file.remove`
- `source.map.list`, `source.map.add`, and `source.map.remove`
- `relocation.list` and `relocation.add`

## 7. Functions, Signatures, Parameters, and Variable Storage

- `function.list`, `function.at`, `function.by_name`, `function.report`, `function.create`, `function.rename`, and `function.delete`
- `function.signature.get`, `function.signature.set`, `function.return_type.set`, and `function.body.set`
- `function.calling_conventions.list` and `function.calling_convention.set`
- `function.flags.set` and `function.thunk.set`
- `function.variables`, `variable.rename`, `variable.retype`, `variable.local.create`, `variable.local.remove`, and `variable.comment.set`
- `parameter.add`, `parameter.remove`, `parameter.move`, and `parameter.replace`
- `stackframe.variable.create`, `stackframe.variable.clear`, and `stackframe.variables`
- `function.callers` and `function.callees`

## 8. Data Types, Type Libraries, and Type Application

- `type.list`, `type.get`, `type.get_by_id`, `type.define_c`, `type.parse_c`, `type.rename`, `type.delete`, and `type.apply_at`
- `type.category.list` and `type.category.create`
- `type.archives.list` and `type.source_archives.list`
- `listing.data.list`, `listing.data.at`, `listing.data.create`, and `listing.data.clear`

## 9. Struct, Union, Enum, and Layout Reconstruction

- `layout.struct.create`, `layout.struct.get`, and `layout.struct.resize`
- `layout.struct.field.add`, `layout.struct.field.rename`, `layout.struct.field.replace`, `layout.struct.field.clear`, and `layout.struct.field.comment.set`
- `layout.struct.bitfield.add`
- `layout.union.create`, `layout.union.member.add`, and `layout.union.member.remove`
- `layout.enum.create`, `layout.enum.member.add`, and `layout.enum.member.remove`
- `layout.inspect.components`
- `layout.struct.fill_from_decompiler`

## 10. Decompiler, High-Level Symbols, and P-code Writeback

- `decomp.function`, `decomp.tokens`, and `decomp.ast`
- `decomp.high_function.summary`
- `decomp.writeback.params` and `decomp.writeback.locals`
- `decomp.override.get` and `decomp.override.set`
- `decomp.trace_type.forward` and `decomp.trace_type.backward`
- `decomp.global.rename` and `decomp.global.retype`
- `variable.rename` and `variable.retype` use decompiler-backed writeback when a high symbol is available
- `pcode.function`, `pcode.block`, `pcode.op.at`, and `pcode.varnode_uses`

## 11. Search, Bulk Query, and Graph Extraction

- `search.resolve`
- `search.text` supports `encoding`, `defined_strings_only`, and optional `start`/`end` scoping
- `search.bytes`, `search.constants`, `search.instructions`, and `search.pcode` support optional address-range scoping
- `comment.list` supports range filtering plus text-query filtering
- `reference.to` and `reference.from` support range sweeps for bulk xref extraction
- `graph.basic_blocks`, `graph.cfg.edges`, and `graph.call_paths`
- `project.search.programs`
- `function.batch.run`

## Intentional Exclusions

- Category `2` and categories `12+` remain outside this implementation pass
- The broader `/codex/features.md` taxonomy still includes adjacent Ghidra capabilities that are not surfaced here as first-class MCP tools
