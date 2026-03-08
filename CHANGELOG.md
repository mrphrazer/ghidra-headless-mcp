# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project uses Semantic Versioning.

## [Unreleased]

### Added
- GitHub Actions release gates for linting, packaging, fake-backend coverage, and live Ghidra coverage.
- Contributor-facing development and release documentation.
- Shared package version wiring across the CLI and MCP initialize response.

### Changed
- Pytest now distinguishes `live`, `slow`, and `socket` coverage so CI can run the right gates for each environment.
- Ruff policy now targets real defects while allowing the intentional large dispatcher-style modules and scenario-style tests.
